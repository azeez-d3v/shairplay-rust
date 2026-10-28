//! AP1 RTP audio streaming — UDP and TCP receiver with ALAC decode.
//!
//! Manages the full AP1 audio receive pipeline:
//!
//! ```text
//! iPhone → RTP/UDP or RTP/TCP → RaopRtp → RaopBuffer (decrypt+decode) → AudioSession
//! ```
//!
//! Two transport modes:
//! - **UDP** (default): data, control, and timing on separate UDP sockets.
//!   Control channel carries retransmit responses (payload type 0x56).
//! - **TCP**: single TCP connection with `$`-prefixed interleaved framing.
//!   No retransmits (reliable transport).

use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicU8, Ordering},
};

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, watch};
use tracing::info;

use crate::error::{NetworkError, ShairplayError};
use crate::raop::buffer::{RAOP_PACKET_LEN, RaopBuffer, StreamFormat};
use crate::raop::{AudioCodec, AudioFormat, AudioHandler};

/// Sentinel value for [`RtpState::flush`] indicating no flush is pending.
const NO_FLUSH: i32 = -42;

/// RTP payload type for retransmit (RESEND) responses on the control channel.
const CTRL_PAYLOAD_TYPE: u8 = 0x56;
/// Bytes of retransmit header preceding the original RTP packet in a RESEND.
const RETRANSMIT_HEADER_LEN: usize = 4;

/// Determine the bind address for RTP sockets.
/// Uses the specific local IP for routable addresses (respects BindConfig).
/// Falls back to unspecified for link-local IPv6 — the iPhone may send RTP
/// packets from a different address than the RTSP connection used.
fn rtp_bind_addr(local: IpAddr) -> IpAddr {
    match local {
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }
        other => other,
    }
}

fn bind_udp(addr: SocketAddr) -> Result<UdpSocket, ShairplayError> {
    let socket = std::net::UdpSocket::bind(addr).map_err(NetworkError::Io)?;
    socket.set_nonblocking(true).map_err(NetworkError::Io)?;
    UdpSocket::from_std(socket)
        .map_err(NetworkError::Io)
        .map_err(Into::into)
}

fn bind_tcp(addr: SocketAddr) -> Result<TcpListener, ShairplayError> {
    let listener = std::net::TcpListener::bind(addr).map_err(NetworkError::Io)?;
    listener.set_nonblocking(true).map_err(NetworkError::Io)?;
    TcpListener::from_std(listener)
        .map_err(NetworkError::Io)
        .map_err(Into::into)
}

/// Parse the SDP `c=` remote address to raw IP bytes for DACP callbacks.
/// Handles "IP6 ::1" prefix and IPv4-mapped IPv6 addresses.
pub(crate) fn remote_addr_bytes(remote: &str) -> Vec<u8> {
    let addr_str = remote.strip_prefix("IP6 ").unwrap_or(remote);
    if let Ok(ip) = addr_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    } else {
        vec![]
    }
}

/// Mutable state shared between the RTP receive loop and the RTSP handler thread.
/// Updated via async message passing (tokio Mutex), consumed in the receive loop.
struct RtpState {
    /// Current volume in dB (0.0 = max, -144.0 = mute).
    /// Set to true when volume changes; cleared after delivery.
    /// Pending DMAP track metadata (binary).
    /// Pending album artwork (JPEG/PNG).
    /// DACP ID for remote control discovery.
    /// Active-Remote token for DACP authentication.
    /// Pending playback progress (start, current, end in RTP timestamps).
    /// Sequence number to flush to, or [`NO_FLUSH`] if no flush pending.
    flush: i32,
}

/// Configuration for creating an AP1 RTP session, parsed from SDP.
pub(crate) struct RtpConfig {
    pub(crate) encoded_format: Option<super::EncodedAudioFormat>,
    pub(crate) media: Arc<super::media::MediaContext>,
    pub(crate) tasks: Arc<super::media::Tasks>,
    /// SDP `c=` remote address string (e.g. "192.168.1.5").
    pub(crate) remote: String,
    /// Local IP address to bind sockets to.
    pub(crate) local_addr: IpAddr,
    /// SDP `a=rtpmap` attribute.
    pub(crate) rtpmap: String,
    /// Optional SDP `a=fmtp` attribute. Required for ALAC and unused for L16.
    pub(crate) fmtp: Option<String>,
    /// AES-CBC parameters when encryption was negotiated; `None` for plaintext RTP.
    pub(crate) encryption: Option<RtpEncryption>,
    /// If set, resample decoded audio to this rate.
    pub(crate) output_sample_rate: Option<u32>,
    /// Full socket address of the remote peer (preserves scope_id for link-local IPv6).
    pub(crate) remote_socket: std::net::SocketAddr,
}

/// Validated AES-CBC parameters for an encrypted RTP session.
pub(crate) struct RtpEncryption {
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 16],
}

/// AP1 RTP streaming session.
///
/// Owns the UDP/TCP sockets, the packet buffer, and the ALAC decoder.
/// Created when the iPhone sends the SDP ANNOUNCE. Started during RTSP SETUP,
/// which binds ports and spawns the receive task.
///
/// Dropped when the RTSP connection closes, which sends a shutdown signal
/// to the receive task via the [`watch`] channel.
/// One connection's audio lifetime, shared only through its authenticated media context.
/// The callback Option fences old packets; the lifecycle also fences late stop/FLUSH actions.
pub(crate) struct AudioOwner {
    state: AtomicU8,
    session: Arc<std::sync::Mutex<Option<StreamSession>>>,
    children: Vec<tokio::task::AbortHandle>,
    shutdown: watch::Sender<bool>,
    media: Weak<super::media::MediaContext>,
}
impl AudioOwner {
    pub(crate) fn stop(&self) -> bool {
        match self
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(2) => return true,
            Err(_) => return false, // A host flush is still running; a new factory must wait/retry.
        }
        let _ = self.shutdown.send(true);
        for child in &self.children {
            child.abort();
        }
        let session = self
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(mut session) = session
            && let Some(media) = self.media.upgrade()
        {
            media
                .clock
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .reset();
            session.audio_flush_timed(media.session());
        }
        self.state.store(2, Ordering::Release);
        true
    }
}

pub(crate) struct RaopRtp {
    owner: Option<Arc<AudioOwner>>,
    encoded_format: Option<super::EncodedAudioFormat>,
    wire_codec: super::WireAudioCodec,
    flush_notify: Arc<tokio::sync::Notify>,
    media: Arc<super::media::MediaContext>,
    tasks: Arc<super::media::Tasks>,
    children: Vec<tokio::task::AbortHandle>,
    session: Option<Arc<std::sync::Mutex<Option<StreamSession>>>>,
    handler: Arc<dyn AudioHandler>,
    /// SDP `c=` remote address string (e.g. "192.168.1.5").
    remote: String,
    /// Local IP address to bind sockets to (matches the RTSP connection's interface).
    local_addr: IpAddr,
    /// If set, resample decoded audio to this rate before delivery.
    output_sample_rate: Option<u32>,
    /// Decoded output stream format (channels + source sample rate).
    format: StreamFormat,
    /// Shared packet buffer (decrypt + decode on queue, dequeue in order).
    buffer: Arc<Mutex<RaopBuffer>>,
    /// Shared mutable state for cross-task event delivery.
    state: Arc<std::sync::Mutex<RtpState>>,
    /// Send `true` to shut down the receive task.
    shutdown_tx: Option<watch::Sender<bool>>,
    /// iPhone's control port (0 = no retransmits).
    control_rport: u16,
    /// Local control port (bound by us).
    pub(crate) control_lport: u16,
    /// Local timing port (bound by us).
    pub(crate) timing_lport: u16,
    /// Local data port (bound by us).
    pub(crate) data_lport: u16,
    /// Full socket address of the remote peer.
    remote_socket: std::net::SocketAddr,
}

/// Build a resampler for the AP1 RTP path: `Some` when an explicit output rate
/// differs from the source rate, otherwise `None` (native-rate passthrough).
/// Shared by the UDP and TCP receive arms of [`RaopRtp::start`].
#[cfg(feature = "resample")]
fn make_resampler(
    output_sample_rate: Option<u32>,
    src_sample_rate: u32,
    channels: usize,
) -> Option<crate::codec::resample::StreamResampler> {
    match output_sample_rate {
        Some(target) if target != src_sample_rate => {
            crate::codec::resample::StreamResampler::new(src_sample_rate, target, channels)
        }
        _ => None,
    }
}

impl RaopRtp {
    /// Create a new RTP session from SDP parameters and AES session keys.
    /// Does not bind sockets or start receiving — call [`start`](Self::start) for that.
    ///
    /// Returns `None` if the peer-supplied codec configuration is unsupported or malformed.
    pub(crate) fn new(callbacks: Arc<dyn AudioHandler>, config: RtpConfig) -> Option<Self> {
        let fmtp = config.fmtp.as_deref().unwrap_or_default();
        let buffer = if let Some(format) = &config.encoded_format {
            RaopBuffer::new_encoded(format.clone(), config.encryption.map(|e| (e.key, e.iv)))
        } else {
            match config.encryption {
                Some(encryption) => {
                    RaopBuffer::new(&config.rtpmap, fmtp, &encryption.key, &encryption.iv)
                }
                None => RaopBuffer::new_unencrypted(&config.rtpmap, fmtp),
            }
        }?;
        let format = buffer.format();
        Some(Self {
            owner: None,
            wire_codec: config.encoded_format.as_ref().map_or_else(
                || {
                    if config.rtpmap.to_ascii_lowercase().contains("applelossless") {
                        super::WireAudioCodec::Alac
                    } else {
                        super::WireAudioCodec::Pcm
                    }
                },
                |format| format.codec,
            ),
            encoded_format: config.encoded_format,
            flush_notify: Arc::new(tokio::sync::Notify::new()),
            media: config.media,
            tasks: config.tasks,
            children: Vec::new(),
            session: None,
            handler: callbacks,
            remote: config.remote,
            local_addr: config.local_addr,
            output_sample_rate: config.output_sample_rate,
            remote_socket: config.remote_socket,
            format,
            buffer: Arc::new(Mutex::new(buffer)),
            state: Arc::new(std::sync::Mutex::new(RtpState { flush: NO_FLUSH })),
            shutdown_tx: None,
            control_rport: 0,
            control_lport: 0,
            timing_lport: 0,
            data_lport: 0,
        })
    }

    fn create_session(&self) -> Result<StreamSession, ShairplayError> {
        self.media.attach_handler(self.handler.clone());
        self.handler
            .on_audio_codec(self.media.session(), self.wire_codec);
        if let Some(format) = &self.encoded_format {
            return self
                .handler
                .audio_init_encoded(format.clone(), self.media.session())
                .map(StreamSession::Encoded)
                .ok_or_else(|| {
                    crate::error::CodecError::UnsupportedFormat(
                        "application has no decoder for negotiated encoded audio".into(),
                    )
                    .into()
                });
        }
        Ok(StreamSession::Pcm(self.handler.audio_init_timed(
            AudioFormat {
                codec: AudioCodec::Pcm,
                bits: 32,
                channels: self.format.num_channels,
                sample_rate: self.output_sample_rate.unwrap_or(self.format.sample_rate),
            },
            self.media.session(),
        )))
    }

    /// Bind UDP/TCP sockets and spawn the async receive task.
    ///
    /// Returns `(control_port, timing_port, data_port)` — the local ports
    /// that the iPhone should send RTP packets to.
    ///
    /// # Transport modes
    ///
    /// - `use_udp = true`: binds 3 UDP sockets (data, control, timing).
    ///   Control channel receives retransmit responses (RTP payload type 0x56).
    /// - `use_udp = false`: binds 1 TCP listener. iPhone connects and sends
    ///   `$`-prefixed interleaved RTP frames.
    pub(crate) fn start(
        &mut self,
        use_udp: bool,
        control_rport: u16,
        timing_rport: u16,
    ) -> Result<(u16, u16, u16), ShairplayError> {
        self.stop();
        let mut reservation = self.media.begin_audio_setup().ok_or_else(|| {
            crate::error::ProtocolError::InvalidRtsp(
                "media audio replacement is busy or retired".into(),
            )
        })?;
        self.control_rport = control_rport;
        info!(use_udp, control_rport, timing_rport, remote = %self.remote, "AP1 RTP starting");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        if use_udp {
            let bind_addr = SocketAddr::new(rtp_bind_addr(self.local_addr), 0);
            let csock = bind_udp(bind_addr)?;
            let tsock = bind_udp(bind_addr)?;
            let dsock = bind_udp(bind_addr)?;
            self.control_lport = csock.local_addr().map_err(NetworkError::Io)?.port();
            self.timing_lport = tsock.local_addr().map_err(NetworkError::Io)?.port();
            self.data_lport = dsock.local_addr().map_err(NetworkError::Io)?.port();

            let session = Arc::new(std::sync::Mutex::new(Some(self.create_session()?)));
            self.session = Some(session.clone());
            reservation.replay_volume(&*self.handler);
            // Spawn NTP timing responder for this connection.
            let remote_sockaddr = self.remote_socket;
            let mut timing_addr = remote_sockaddr;
            timing_addr.set_port(timing_rport);
            self.children
                .push(self.tasks.track(super::ntp::spawn_ntp_responder(
                    tsock,
                    timing_addr,
                    self.media.clone(),
                )));

            let format = self.format;

            #[cfg(feature = "resample")]
            let mut resampler = make_resampler(
                self.output_sample_rate,
                format.sample_rate,
                format.num_channels as usize,
            );

            let buffer = self.buffer.clone();
            let state = self.state.clone();
            // If control_rport is 0, the iPhone doesn't support retransmits.
            let no_resend = control_rport == 0;
            let _remote_for_task = self.remote.clone();

            let media = self.media.clone();
            let flush_notify = self.flush_notify.clone();
            super::diagnostics::emit(format_args!(
                "stage=audio_transport transport=udp ipv6={} data_port_present={} control_port_present={} remote_control_port_present={}",
                remote_sockaddr.is_ipv6(),
                self.data_lport != 0,
                self.control_lport != 0,
                control_rport != 0
            ));
            self.children.push(self.tasks.track(tokio::spawn(async move {
                let mut probe = super::diagnostics::AudioProbe::default();
                let mut shutdown_rx = shutdown_rx;
                let mut data_packet = [0u8; RAOP_PACKET_LEN];
                let mut ctrl_packet = [0u8; RAOP_PACKET_LEN];
                loop {
                    // Drain flush events only — metadata goes through AudioHandler now.
                    {
                        let flush = { let mut st = state.lock().unwrap_or_else(|e| e.into_inner()); let flush = st.flush; st.flush = NO_FLUSH; flush };
                        if flush != NO_FLUSH {
                            buffer.lock().await.flush(flush);
                            if let Some(session) = session.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                                session.audio_flush_timed(media.session());
                            }
                        }
                    }

                    tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => break,
                        _ = flush_notify.notified() => continue,
                        // Data channel: audio RTP packets.
                        result = dsock.recv_from(&mut data_packet) => {
                            if let Ok((len, addr)) = result {
                                let source_matches = addr.ip() == remote_sockaddr.ip();
                                let queued = if source_matches && len >= 12 {
                                    Some(buffer.lock().await.queue(&data_packet[..len], true))
                                } else { None };
                                probe.data(&data_packet[..len], source_matches, addr.is_ipv6() == remote_sockaddr.is_ipv6(), queued);
                            } else { probe.io_error(); }
                        }
                        // Control channel: retransmit responses (payload type 0x56).
                        result = csock.recv_from(&mut ctrl_packet) => {
                            if let Ok((len, addr)) = result {
                                let source_matches = addr.ip() == remote_sockaddr.ip();
                                let mut sync = None;
                                if source_matches && len >= 12 {
                                    if (ctrl_packet[1] & 0x7f) == 0x54 {
                                        let active = session.lock().unwrap_or_else(|e| e.into_inner());
                                        if active.is_some() {
                                            sync = Some(media.clock.lock().unwrap_or_else(|e| e.into_inner()).sync(&ctrl_packet[..len], format.sample_rate));
                                        }
                                    } else if (ctrl_packet[1] & 0x7f) == CTRL_PAYLOAD_TYPE {
                                        let mut buf = buffer.lock().await;
                                        // Retransmit packets have a 4-byte header before the original RTP.
                                        if len > RETRANSMIT_HEADER_LEN { buf.queue(&ctrl_packet[RETRANSMIT_HEADER_LEN..len], true); }
                                    }
                                }
                                probe.control(&ctrl_packet[..len], format.sample_rate, source_matches, addr.is_ipv6() == remote_sockaddr.is_ipv6(), sync);
                            } else { probe.io_error(); }
                        }
                    }
                    let mut buf = buffer.lock().await;
                    while let Some(frame) = buf.dequeue_timed(no_resend) {
                        let mut active = session.lock().unwrap_or_else(|e| e.into_inner());
                        let Some(session) = active.as_mut() else { continue; };
                        if let StreamSession::Encoded(encoded) = session {
                            if let Some(payload) = frame.encoded {
                                let timing = audio_timing(&media, &frame, format.sample_rate);
                                probe.callback(timing.presentation_time_ns.is_some());
                                encoded.audio_process_encoded(payload, timing);
                            }
                            continue;
                        }
                        let samples = frame.samples;
                        let timing = audio_timing(&media, &frame, format.sample_rate);
                        probe.callback(timing.presentation_time_ns.is_some());
                        {
                            #[cfg(feature = "resample")]
                            if let Some(ref mut rs) = resampler {
                                let resampled = rs.process(samples);
                                session.audio_process_timed(&resampled, timing);
                            } else {
                                session.audio_process_timed(samples, timing);
                            }
                            #[cfg(not(feature = "resample"))]
                            session.audio_process_timed(samples, timing);
                        }
                    }
                }
                // AudioSession dropped here → triggers cleanup in the app.
            })));
        } else {
            // TCP interleaved mode: single connection, `$`-prefixed framing.
            let listener = bind_tcp(SocketAddr::new(rtp_bind_addr(self.local_addr), 0))?;
            self.data_lport = listener.local_addr().map_err(NetworkError::Io)?.port();

            let format = self.format;
            let session = Arc::new(std::sync::Mutex::new(Some(self.create_session()?)));
            self.session = Some(session.clone());
            reservation.replay_volume(&*self.handler);

            #[cfg(feature = "resample")]
            let mut resampler = make_resampler(
                self.output_sample_rate,
                format.sample_rate,
                format.num_channels as usize,
            );

            let buffer = self.buffer.clone();
            let state = self.state.clone();
            let _remote_for_tcp = self.remote.clone();

            let media = self.media.clone();
            let flush_notify = self.flush_notify.clone();
            self.children.push(self.tasks.track(tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut shutdown_rx = shutdown_rx;

                // Wait for the iPhone to connect.
                let stream = tokio::select! {
                    result = listener.accept() => match result {
                        Ok((s, _)) => s,
                        Err(_) => return,
                    },
                    _ = shutdown_rx.changed() => return,
                };

                let mut reader = tokio::io::BufReader::new(stream);
                let mut packet_buf = Vec::with_capacity(RAOP_PACKET_LEN + 4);
                let mut read_buf = [0u8; 4096];

                'tcp: loop {
                    // Drain flush events only — metadata goes through AudioHandler now.
                    {
                        let flush = { let mut st = state.lock().unwrap_or_else(|e| e.into_inner()); let flush = st.flush; st.flush = NO_FLUSH; flush };
                        if flush != NO_FLUSH {
                            buffer.lock().await.flush(flush);
                            if let Some(session) = session.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                                session.audio_flush_timed(media.session());
                            }
                        }
                    }

                    tokio::select! {
                        biased;
                        _ = flush_notify.notified() => {},
                        result = reader.read(&mut read_buf) => {
                            match result {
                                Ok(0) | Err(_) => break,
                                Ok(n) => packet_buf.extend_from_slice(&read_buf[..n]),
                            }
                            if packet_buf.len() > RAOP_PACKET_LEN * 4 {
                                tracing::warn!("TCP RTP buffer exceeded safety limit");
                                break;
                            }
                            // TCP interleaved: each frame is `$ <channel> <len_hi> <len_lo> <rtp...>`.
                            while packet_buf.len() >= 4 {
                                if packet_buf[0] != b'$' || packet_buf[1] != 0 {
                                    packet_buf.drain(..1);
                                    continue;
                                }
                                let rtp_len = ((packet_buf[2] as usize) << 8) | packet_buf[3] as usize;
                                if rtp_len > RAOP_PACKET_LEN {
                                    tracing::warn!(rtp_len, "TCP RTP frame exceeded maximum size, closing");
                                    packet_buf.clear();
                                    break 'tcp;
                                }
                                if packet_buf.len() < 4 + rtp_len { break; }
                                let mut buf = buffer.lock().await;
                                buf.queue(&packet_buf[4..4 + rtp_len], false);
                                if let Some(frame) = buf.dequeue_timed(true) {
                                    let mut active = session.lock().unwrap_or_else(|e| e.into_inner());
                                    let Some(session) = active.as_mut() else { break 'tcp; };
                                    let samples = frame.samples;
                                    let timing = audio_timing(&media, &frame, format.sample_rate);
                                    if let StreamSession::Encoded(encoded) = session && let Some(payload) = frame.encoded { encoded.audio_process_encoded(payload, timing); }
                                    {
                                            #[cfg(feature = "resample")]
                                            if let Some(ref mut rs) = resampler {
                                                let resampled = rs.process(samples);
                                                session.audio_process_timed(&resampled, timing);
                                            } else {
                                                session.audio_process_timed(samples, timing);
                                            }
                                            #[cfg(not(feature = "resample"))]
                                            session.audio_process_timed(samples, timing);
                                        }
                                }
                                drop(buf);
                                packet_buf.drain(..4 + rtp_len);
                            }
                        }
                        _ = shutdown_rx.changed() => break,
                    }
                }
            })));
        }

        for child in &self.children {
            self.media.own_transport(child.clone());
        }
        let owner = Arc::new(AudioOwner {
            state: AtomicU8::new(0),
            session: self.session.as_ref().expect("started callback").clone(),
            children: self.children.clone(),
            shutdown: self.shutdown_tx.as_ref().expect("started shutdown").clone(),
            media: Arc::downgrade(&self.media),
        });
        self.media.own_audio(&owner);
        self.owner = Some(owner);
        Ok((self.control_lport, self.timing_lport, self.data_lport))
    }

    /// Request a buffer flush up to the given sequence number.
    pub(crate) fn flush(&self, next_seq: i32) {
        let Some(active) = &self.session else {
            return;
        };
        let active = active.lock().unwrap_or_else(|e| e.into_inner());
        if active.is_none() {
            return;
        }
        self.media
            .clock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .reset();
        self.state.lock().unwrap_or_else(|e| e.into_inner()).flush = next_seq;
        self.flush_notify.notify_one();
    }

    /// Stop the receive task and flush the buffer.
    pub(crate) fn stop(&mut self) {
        let owner = self.owner.take();
        if let Some(owner) = &owner {
            owner.stop();
        }
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        for child in self.children.drain(..) {
            child.abort();
        }
        if let Some(active) = self.session.take()
            && owner.is_none()
        {
            let session = active.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(mut session) = session {
                self.media
                    .clock
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .reset();
                session.audio_flush_timed(self.media.session());
            }
        }
    }
}

impl Drop for RaopRtp {
    fn drop(&mut self) {
        self.stop();
    }
}

fn audio_timing(
    media: &super::media::MediaContext,
    frame: &super::buffer::AudioFrame<'_>,
    rate: u32,
) -> super::AudioTiming {
    super::AudioTiming {
        session: media.session(),
        sequence: frame.sequence,
        rtp_timestamp: frame.timestamp,
        sample_count: frame.sample_count,
        source_sample_rate: rate,
        concealed: frame.concealed,
        presentation_time_ns: media
            .clock
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .audio_time(frame.timestamp, rate),
    }
}

enum StreamSession {
    Pcm(Box<dyn super::AudioSession>),
    Encoded(Box<dyn super::EncodedAudioSession>),
}
impl StreamSession {
    fn audio_process_timed(&mut self, samples: &[f32], timing: super::AudioTiming) {
        if let Self::Pcm(session) = self {
            session.audio_process_timed(samples, timing);
        }
    }
    fn audio_flush_timed(&mut self, media: super::MediaSession) {
        match self {
            Self::Pcm(session) => session.audio_flush_timed(media),
            Self::Encoded(session) => session.audio_flush_timed(media),
        }
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use std::sync::{Mutex, atomic::AtomicUsize, mpsc};
    struct BlockingAudio {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        flushes: Arc<AtomicUsize>,
    }
    impl crate::raop::EncodedAudioSession for BlockingAudio {
        fn audio_process_encoded(&mut self, _: &[u8], _: crate::raop::AudioTiming) {}
        fn audio_flush_timed(&mut self, _: crate::raop::MediaSession) {
            self.flushes.fetch_add(1, Ordering::SeqCst);
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
        }
    }
    fn held_owner(
        media: &Arc<super::super::media::MediaContext>,
    ) -> (
        Arc<AudioOwner>,
        mpsc::Receiver<()>,
        mpsc::Sender<()>,
        Arc<AtomicUsize>,
    ) {
        let (entered, wait) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let flushes = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(AudioOwner {
            state: AtomicU8::new(0),
            session: Arc::new(Mutex::new(Some(StreamSession::Encoded(Box::new(
                BlockingAudio {
                    entered,
                    release: Mutex::new(resume),
                    flushes: flushes.clone(),
                },
            ))))),
            children: vec![],
            shutdown: watch::channel(false).0,
            media: Arc::downgrade(media),
        });
        media.own_audio(&owner);
        (owner, wait, release, flushes)
    }
    #[test]
    fn takeover_waits_for_complete_old_flush_without_holding_context_lock() {
        let media = Arc::new(super::super::media::MediaContext::default());
        let other = Arc::new(super::super::media::MediaContext::default());
        let (owner, entered, release, flushes) = held_owner(&media);
        let worker = media.clone();
        let thread = std::thread::spawn(move || assert!(worker.begin_audio_setup().is_some()));
        entered
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(
            media.begin_audio_setup().is_none(),
            "concurrent/reentrant setup must not run another factory"
        );
        assert!(
            other.begin_audio_setup().is_some(),
            "one phone's audio retirement must not block a different context"
        );
        assert!(
            !owner.stop(),
            "retirement is not complete until the callback returns"
        );
        release.send(()).unwrap();
        thread.join().unwrap();
        assert!(media.begin_audio_setup().is_some());
        assert!(owner.stop());
        assert_eq!(flushes.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn connection_stop_in_progress_rejects_takeover_until_its_flush_completes() {
        let media = Arc::new(super::super::media::MediaContext::default());
        let (owner, entered, release, flushes) = held_owner(&media);
        let stopping = owner.clone();
        let thread = std::thread::spawn(move || assert!(stopping.stop()));
        entered
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(media.begin_audio_setup().is_none());
        release.send(()).unwrap();
        thread.join().unwrap();
        assert!(
            media.begin_audio_setup().is_some(),
            "rejected reservation must be released for retry"
        );
        assert_eq!(flushes.load(Ordering::SeqCst), 1);
    }
}
