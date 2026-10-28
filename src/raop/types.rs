//! Public types and traits for the AirPlay server.

use std::sync::Arc;

/// Receiver-owned media identity and discontinuity generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MediaSession {
    /// Opaque identity, not a network address.
    pub id: u64,
    /// Changes when a common audio/video timeline is invalidated.
    pub generation: u64,
}

/// Original audio timing, independent of output resampling.
#[derive(Debug, Clone, Copy)]
pub struct AudioTiming {
    /// Media identity and generation.
    pub session: MediaSession,
    /// Wrapping RTP sequence.
    pub sequence: u16,
    /// Wrapping RTP sample-clock timestamp.
    pub rtp_timestamp: u32,
    /// Original samples per channel.
    pub sample_count: u32,
    /// Original sample rate in Hz.
    pub source_sample_rate: u32,
    /// Sender NTP era-local nanoseconds; absent until anchored (not Unix time).
    pub presentation_time_ns: Option<u64>,
    /// True for loss-concealment silence.
    pub concealed: bool,
}

/// Negotiated source wire codec (distinct from decoded PCM output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireAudioCodec {
    /// Apple Lossless.
    Alac,
    /// Network-order PCM.
    Pcm,
    /// MPEG-4 AAC Enhanced Low Delay, not AAC-LC or ADTS.
    AacEld,
}
/// Decrypted encoded-audio format for an application-owned decoder.
#[derive(Debug, Clone)]
pub struct EncodedAudioFormat {
    /// Negotiated wire codec.
    pub codec: WireAudioCodec,
    /// Source rate in Hz.
    pub sample_rate: u32,
    /// Interleaved channel count.
    pub channels: u8,
    /// Samples per packet per channel.
    pub samples_per_frame: u32,
    /// Decoder-specific configuration (AudioSpecificConfig for AAC).
    pub codec_config: Vec<u8>,
}
/// Encoded packets retaining the original RTP timing.
pub trait EncodedAudioSession: Send + Sync {
    /// Receive one decrypted codec packet, without an RTP or ADTS header.
    fn audio_process_encoded(&mut self, packet: &[u8], timing: AudioTiming);
    /// Invalidate the old generation.
    fn audio_flush_timed(&mut self, _session: MediaSession) {}
}

/// Runtime protocol mode selection.
///
/// When the `ap2` feature is enabled, this controls whether the server
/// advertises itself as an AirPlay 1 (classic) or AirPlay 2 receiver.
/// Both modes share the same RTSP listener — the difference is in mDNS
/// advertisement and feature negotiation.
#[cfg(feature = "ap2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AirPlayMode {
    /// Classic AirPlay 1: ALAC/AAC over RTP, RSA encryption, NTP timing.
    AirPlay1,
    /// AirPlay 2: buffered audio, ChaCha20 encryption, SRP pairing, PTP timing.
    #[default]
    AirPlay2,
}

/// Audio codec type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// Decoded PCM (f32 interleaved). Always delivered regardless of AP1/AP2.
    Pcm,
}

/// AirPlay 1 wire codec advertised in the `_raop._tcp` `cn` TXT record.
///
/// The receiver auto-detects the actual codec per connection from the SDP
/// `rtpmap`; this only controls what is *advertised*. When several are
/// advertised, their order is preserved because sender selection policies vary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ap1Codec {
    /// Raw linear PCM / `L16` (`cn=0`).
    Pcm,
    /// Apple Lossless (`cn=1`).
    Alac,
}

impl Ap1Codec {
    /// The `cn` TXT record digit for this codec.
    pub(crate) const fn txt_value(self) -> &'static str {
        match self {
            Ap1Codec::Pcm => "0",
            Ap1Codec::Alac => "1",
        }
    }
}

/// AirPlay 1 encryption / authentication mode advertised in the `et` TXT record.
///
/// The receiver auto-dispatches on what a sender actually negotiates (RSA
/// `rsaaeskey`, FairPlay `fpaeskey`, or no key at all); this only controls what
/// is *advertised*. Sender preference rules vary, so advertise only modes the
/// deployment intends to accept.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ap1Encryption {
    /// No encryption (`et=0`). Audio passes through undecrypted.
    None,
    /// RSA session-key exchange (`et=1`, `a=rsaaeskey`).
    Rsa,
    /// FairPlay DRM (`et=3`, `POST /fp-setup` + `a=fpaeskey`).
    FairPlay,
}

impl Ap1Encryption {
    /// The `et` TXT record digit for this mode.
    pub(crate) const fn txt_value(self) -> &'static str {
        match self {
            Ap1Encryption::None => "0",
            Ap1Encryption::Rsa => "1",
            Ap1Encryption::FairPlay => "3",
        }
    }
}

/// Audio format descriptor passed to [`AudioHandler::audio_init`].
#[derive(Debug, Clone, Copy)]
pub struct AudioFormat {
    /// Audio codec (always PCM for decoded output).
    pub codec: AudioCodec,
    /// Bits per sample (always 32 — samples are delivered as `&[f32]`).
    pub bits: u8,
    /// Number of channels.
    pub channels: u8,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Trait for receiving AirPlay events and creating audio sessions.
///
/// `AudioHandler` is `Send + Sync` — all callbacks can be called from any thread
/// without blocking audio delivery. Metadata, volume, and artwork callbacks are
/// called directly from the RTSP handler thread, never from the audio path.
///
/// A new [`AudioSession`] is created for each audio stream via
/// [`audio_init`](AudioHandler::audio_init). The session only receives PCM samples.
pub trait AudioHandler: Send + Sync + 'static {
    /// Called when a new audio stream starts. Return a session to receive PCM data.
    fn audio_init(&self, format: AudioFormat) -> Box<dyn AudioSession>;

    /// Start an audio stream with a receiver-owned media identity.
    fn audio_init_timed(
        &self,
        format: AudioFormat,
        _session: MediaSession,
    ) -> Box<dyn AudioSession> {
        self.audio_init(format)
    }

    /// Opt into a negotiated encoded codec. None rejects the unsupported stream explicitly.
    fn audio_init_encoded(
        &self,
        _format: EncodedAudioFormat,
        _session: MediaSession,
    ) -> Option<Box<dyn EncodedAudioSession>> {
        None
    }

    // --- Metadata events (called from RTSP thread, never blocks audio) ---

    /// Volume change in dB (0.0 = max, -144.0 = mute).
    fn on_volume(&self, _volume: f32) {}
    /// Session-aware sender volume in dB; defaults to the legacy callback.
    /// RTP receivers replay explicitly set volume after their factory, before packets.
    /// No initial callback is emitted until the sender sets a volume.
    fn on_volume_timed(&self, volume: f32, _session: MediaSession) {
        self.on_volume(volume);
    }
    /// Track metadata (parsed from DMAP).
    fn on_metadata(&self, _metadata: &crate::proto::dmap::TrackMetadata) {}
    /// Album artwork (JPEG or PNG).
    fn on_coverart(&self, _coverart: &[u8]) {}
    /// Playback progress (start, current, end in RTP timestamps at 44100 Hz).
    fn on_progress(&self, _start: u32, _current: u32, _end: u32) {}
    /// A remote control interface is available (AP1 DACP).
    fn on_remote_control(&self, _remote: Arc<dyn RemoteControl>) {}

    // --- Connection lifecycle ---

    /// Reports the negotiated source wire codec (decoded output may still be PCM).
    fn on_audio_codec(&self, _session: MediaSession, _codec: WireAudioCodec) {}

    /// Called once when the last owner of a media session ends, not on auxiliary disconnect.
    fn on_media_session_ended(&self, _session: MediaSession) {}

    /// Called when a client connects.
    fn on_client_connected(&self, _addr: &str) {}
    /// Called when a client disconnects.
    fn on_client_disconnected(&self, _addr: &str) {}
    /// Called when the library hits a runtime error on a connection — e.g. a
    /// pairing/pair-verify failure, a FairPlay or session-key decrypt failure, a
    /// rejected stream format, or an audio-decoder init failure. Fired at most
    /// once per failure (never per audio packet). Default: log at warn level.
    fn on_error(&self, error: &crate::error::ShairplayError) {
        tracing::warn!(%error, "AirPlay error");
    }
}

/// Storage for paired device keys. Implement this to persist pairing across restarts.
///
/// Without persistence, iPhones that previously paired will send encrypted data
/// on connect and fail because the server has no cached keys.
#[cfg(feature = "ap2")]
pub trait PairingStore: Send + Sync + 'static {
    /// Look up a paired device's Ed25519 public key by device ID.
    fn get(&self, device_id: &str) -> Option<[u8; 32]>;
    /// Save a paired device's Ed25519 public key.
    fn put(&self, device_id: &str, public_key: [u8; 32]);
    /// Remove a paired device.
    fn remove(&self, device_id: &str);

    /// Returns `true` once at least one controller is paired.
    ///
    /// Used to advertise `OneTimePairingRequired` (statusFlags bit 9) only until
    /// the first successful pairing, so already-paired controllers reconnect via
    /// pair-verify instead of being nudged back into setup. The default returns
    /// `false` (always advertise setup-required when a PIN is configured); the
    /// built-in [`MemoryPairingStore`] overrides it, and persistent stores should
    /// too.
    fn has_any_pairing(&self) -> bool {
        false
    }

    /// Load the accessory's persistent Ed25519 **identity** seed, if one was saved.
    ///
    /// This is the server's *own* long-term secret (distinct from the paired peer
    /// keys handled by [`get`](Self::get)/[`put`](Self::put)). Returning `Some`
    /// keeps the accessory's identity — and therefore its advertised `pk` — stable
    /// across restarts so already-paired devices don't need to re-pair.
    ///
    /// The default returns `None`: the server then generates a fresh random
    /// identity on each start and offers it to [`save_identity`](Self::save_identity).
    /// Implement both methods to persist the identity. (To reproduce the legacy
    /// insecure behaviour, return the zero-padded device id as the seed.)
    fn load_identity(&self) -> Option<[u8; 32]> {
        None
    }

    /// Persist the accessory's Ed25519 identity seed generated at startup.
    ///
    /// The default is a no-op (identity is not persisted). Implement together with
    /// [`load_identity`](Self::load_identity) to keep a stable identity.
    fn save_identity(&self, _seed: [u8; 32]) {}
}

/// In-memory pairing store (lost on restart). Use for testing or wrap with file I/O.
#[cfg(feature = "ap2")]
#[derive(Default)]
pub struct MemoryPairingStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>,
}

#[cfg(feature = "ap2")]
impl PairingStore for MemoryPairingStore {
    fn get(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.lock().ok()?.get(device_id).copied()
    }
    fn put(&self, device_id: &str, public_key: [u8; 32]) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.insert(device_id.to_string(), public_key);
        }
    }
    fn has_any_pairing(&self) -> bool {
        self.keys.lock().map(|k| !k.is_empty()).unwrap_or(false)
    }
    fn remove(&self, device_id: &str) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.remove(device_id);
        }
    }
}

/// Per-connection audio session — hot path only.
///
/// Created by [`AudioHandler::audio_init`]. Dropped when the client disconnects.
/// Only receives decoded PCM samples and flush events. All metadata, volume,
/// and artwork events go to [`AudioHandler`] instead.
pub trait AudioSession: Send + Sync {
    /// Receive decoded f32 interleaved PCM audio samples.
    fn audio_process(&mut self, samples: &[f32]);
    /// Receive audio with its original source timing.
    fn audio_process_timed(&mut self, samples: &[f32], _timing: AudioTiming) {
        self.audio_process(samples);
    }
    /// Invalidate the previous generation and flush pending audio.
    fn audio_flush_timed(&mut self, _session: MediaSession) {
        self.audio_flush();
    }
    /// Flush the audio buffer (e.g. on seek).
    fn audio_flush(&mut self) {}
}

/// Playback command to send to the source device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteCommand {
    /// Start playback.
    Play,
    /// Pause playback.
    Pause,
    /// Skip to next track.
    NextTrack,
    /// Skip to previous track.
    PreviousTrack,
    /// Set volume (0-100).
    SetVolume(u8),
    /// Toggle shuffle mode.
    ToggleShuffle,
    /// Toggle repeat mode.
    ToggleRepeat,
    /// Stop playback.
    Stop,
}

/// Unified remote control interface for AP1 (DACP) and AP2 (MediaRemote).
pub trait RemoteControl: Send + Sync {
    /// Send a playback command to the source device.
    fn send_command(&self, cmd: RemoteCommand) -> Result<(), crate::error::ShairplayError>;
    /// Commands the source device supports. AP1 returns all; AP2 returns advertised set.
    fn available_commands(&self) -> Vec<RemoteCommand>;
}

#[cfg(test)]
mod volume_compat_tests {
    use super::*;
    struct Legacy(std::sync::Mutex<Vec<f32>>);
    impl AudioHandler for Legacy {
        fn audio_init(&self, _: AudioFormat) -> Box<dyn AudioSession> {
            unreachable!()
        }
        fn on_volume(&self, value: f32) {
            self.0.lock().unwrap().push(value);
        }
    }
    #[test]
    fn timed_volume_default_preserves_legacy_callback() {
        let handler = Legacy(std::sync::Mutex::new(vec![]));
        handler.on_volume_timed(
            -12.0,
            MediaSession {
                id: 1,
                generation: 0,
            },
        );
        assert_eq!(*handler.0.lock().unwrap(), vec![-12.0]);
    }
}
