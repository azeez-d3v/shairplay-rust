//! Video (screen mirroring) support for AirPlay 2.
//!
//! The library receives encrypted H.264/H.265 video packets, decrypts them,
//! and delivers raw NAL units to the application via [`VideoSession`].
//! The application is responsible for decoding and rendering.

use bytes::Bytes;

/// Video timing in the same sender clock domain as audio.
#[derive(Debug, Clone, Copy)]
pub struct VideoTiming {
    /// Receiver-owned media identity and generation.
    pub session: super::MediaSession,
    /// Sender NTP era-local nanoseconds (not Unix time).
    pub presentation_time_ns: Option<u64>,
}

/// Classification of a video packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// AVC (H.264) decoder configuration record.
    AvcC,
    /// HEVC (H.265) decoder configuration record.
    HvcC,
    /// Encoded video payload (decrypted by the library).
    Payload,
    /// Auxiliary binary plist data.
    Plist,
    /// Unknown packet type.
    Other(u16),
}

/// A decrypted video packet delivered to the application.
#[derive(Debug)]
pub struct VideoPacket {
    /// Packet classification.
    pub kind: PacketKind,
    /// Presentation timestamp (NTP-based, in stream time units).
    pub timestamp: u64,
    /// Packet payload (raw NAL units for Payload, config bytes for AvcC/HvcC).
    pub payload: Bytes,
}

/// Factory for creating video sessions. Implement this to receive video data.
pub trait VideoHandler: Send + Sync + 'static {
    /// Called when a new video stream is established.
    fn video_init(&self) -> Box<dyn VideoSession>;
    /// Start a video stream sharing an audio media identity.
    fn video_init_timed(&self, _session: super::MediaSession) -> Box<dyn VideoSession> {
        self.video_init()
    }
}

/// Per-stream video session receiving decrypted video packets.
///
/// Created by [`VideoHandler::video_init`]. Dropped when the stream ends.
pub trait VideoSession: Send + Sync {
    /// Called for each decrypted video packet.
    fn on_video(&mut self, packet: VideoPacket);

    /// Receive a packet with normalized sender presentation time.
    fn on_video_timed(&mut self, packet: VideoPacket, _timing: VideoTiming) {
        self.on_video(packet);
    }

    /// Called when the video stream ends (client disconnected or error).
    fn on_video_end(&mut self) {}
}
