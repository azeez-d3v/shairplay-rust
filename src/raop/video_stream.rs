//! Video stream receiver for AirPlay 2 screen mirroring (stream type 110).
//!
//! Accepts a TCP connection, reads 128-byte headers + variable-length payloads,
//! classifies packets, decrypts Payload types, and delivers to VideoSession.

use std::time::Duration;

use bytes::BytesMut;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, trace, warn};

use crate::crypto::video_cipher::VideoCipher;
use crate::raop::video::{PacketKind, VideoPacket, VideoSession};

const VIDEO_HEADER_LEN: usize = 128;
const MAX_VIDEO_PAYLOAD_LEN: usize = 32 * 1024 * 1024;
/// Drop a video connection whose peer stalls mid-read, freeing the task and port.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct VideoHeader {
    payload_len: usize,
    packet_type: u16,
    timestamp: u64,
}

fn parse_header(header: &[u8; VIDEO_HEADER_LEN]) -> VideoHeader {
    VideoHeader {
        payload_len: u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize,
        packet_type: u16::from_le_bytes([header[4], header[5]]),
        timestamp: u64::from_le_bytes([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15],
        ]),
    }
}

fn classify_packet(packet_type: u16, payload: &[u8]) -> PacketKind {
    match packet_type {
        1 if payload.len() >= 8 && &payload[4..8] == b"hvc1" => PacketKind::HvcC,
        1 => PacketKind::AvcC,
        0 | 4096 => PacketKind::Payload,
        5 => PacketKind::Plist,
        other => PacketKind::Other(other),
    }
}

struct VideoExit {
    reason: &'static str,
    part: &'static str,
    packets: u64,
    frames: u64,
}
impl Drop for VideoExit {
    fn drop(&mut self) {
        super::diagnostics::emit(format_args!(
            "stage=video_exit reason={} part={} packets={} frames={}",
            self.reason, self.part, self.packets, self.frames
        ));
    }
}

async fn read_with_timeout(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    part: &'static str,
    exit: &mut VideoExit,
) -> bool {
    match tokio::time::timeout(READ_TIMEOUT, stream.read_exact(buffer)).await {
        Ok(Ok(_)) => true,
        Ok(Err(error)) => {
            exit.part = part;
            exit.reason = match error.kind() {
                std::io::ErrorKind::UnexpectedEof => "peer_eof",
                std::io::ErrorKind::ConnectionReset => "peer_reset",
                std::io::ErrorKind::ConnectionAborted => "connection_aborted",
                _ => "read_io",
            };
            debug!(part, "Video stream ended during read");
            false
        }
        Err(_) => {
            exit.part = part;
            exit.reason = "read_timeout";
            debug!(part, "Video stream read timed out");
            false
        }
    }
}

/// Run the video stream receiver. Accepts one TCP connection and processes packets.
pub(crate) async fn run(
    listener: TcpListener,
    cipher: VideoCipher,
    session: Box<dyn VideoSession>,
    media: std::sync::Arc<super::media::MediaContext>,
    remote: std::net::IpAddr,
    lease: super::media::VideoLease,
) {
    // Inner future owns every socket; normal completion drops them before retiring the lease.
    let mut exit = VideoExit {
        reason: "task_cancelled",
        part: "accept",
        packets: 0,
        frames: 0,
    };
    run_transport(listener, cipher, session, media, remote, &mut exit).await;
    drop(exit);
    drop(lease);
}

async fn run_transport(
    listener: TcpListener,
    cipher: VideoCipher,
    session: Box<dyn VideoSession>,
    media: std::sync::Arc<super::media::MediaContext>,
    remote: std::net::IpAddr,
    exit: &mut VideoExit,
) {
    let (stream, addr) = match listener.accept().await {
        Ok(s) => s,
        Err(e) => {
            exit.reason = "accept_io";
            warn!("Video stream accept failed: {e}");
            return;
        }
    };
    if addr.ip() != remote {
        exit.reason = "peer_mismatch";
        return;
    }
    info!(%addr, "Video stream client connected");
    exit.part = "header";
    process(stream, cipher, session, media, exit).await;
}

async fn process(
    mut stream: TcpStream,
    mut cipher: VideoCipher,
    mut session: Box<dyn VideoSession>,
    media: std::sync::Arc<super::media::MediaContext>,
    exit: &mut VideoExit,
) {
    let stream_session = media.session();
    let mut header = [0u8; VIDEO_HEADER_LEN];

    loop {
        if !read_with_timeout(&mut stream, &mut header, "header", exit).await {
            break;
        }
        let metadata = parse_header(&header);
        if metadata.payload_len == 0 {
            continue;
        }
        if metadata.payload_len > MAX_VIDEO_PAYLOAD_LEN {
            exit.reason = "oversized_payload";
            exit.part = "header";
            warn!(
                payload_len = metadata.payload_len,
                "Video payload exceeds maximum allowed size"
            );
            break;
        }

        let mut payload = BytesMut::zeroed(metadata.payload_len);
        if !read_with_timeout(&mut stream, &mut payload, "payload", exit).await {
            break;
        }
        let kind = classify_packet(metadata.packet_type, &payload);
        if matches!(kind, PacketKind::Payload) {
            cipher.decrypt(&mut payload);
        }

        trace!(
            ?kind,
            timestamp = metadata.timestamp,
            payload_len = metadata.payload_len,
            "Video packet"
        );
        if exit.packets == 0 {
            let kind = match kind {
                PacketKind::AvcC => "avcc",
                PacketKind::HvcC => "hvcc",
                PacketKind::Payload => "frame",
                PacketKind::Plist => "plist",
                PacketKind::Other(_) => "other",
            };
            super::diagnostics::emit(format_args!("stage=video_first_packet kind={kind}"));
        }
        if matches!(kind, PacketKind::Payload) {
            if exit.frames == 0 {
                super::diagnostics::emit(format_args!("stage=video_first_frame"));
            }
            exit.frames = exit.frames.saturating_add(1);
        }
        exit.packets = exit.packets.saturating_add(1);
        session.on_video_timed(
            VideoPacket {
                kind,
                timestamp: metadata.timestamp,
                payload: payload.freeze(),
            },
            super::video::VideoTiming {
                session: stream_session,
                presentation_time_ns: super::ntp::video_time(metadata.timestamp),
            },
        );
    }
    session.on_video_end();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_little_endian_header_fields() {
        let mut header = [0u8; VIDEO_HEADER_LEN];
        header[..4].copy_from_slice(&0x1234_u32.to_le_bytes());
        header[4..6].copy_from_slice(&0x5678_u16.to_le_bytes());
        header[8..16].copy_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());

        let parsed = parse_header(&header);
        assert_eq!(parsed.payload_len, 0x1234);
        assert_eq!(parsed.packet_type, 0x5678);
        assert_eq!(parsed.timestamp, 0x0102_0304_0506_0708);
    }

    #[test]
    fn classifies_supported_packet_types() {
        assert_eq!(classify_packet(1, b"....hvc1"), PacketKind::HvcC);
        assert_eq!(classify_packet(1, b"short"), PacketKind::AvcC);
        assert_eq!(classify_packet(0, b""), PacketKind::Payload);
        assert_eq!(classify_packet(4096, b""), PacketKind::Payload);
        assert_eq!(classify_packet(5, b""), PacketKind::Plist);
        assert_eq!(classify_packet(42, b""), PacketKind::Other(42));
    }
}
