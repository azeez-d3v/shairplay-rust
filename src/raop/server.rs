//! AirPlay server builder and lifecycle.

use super::config::Ap1Advertisement;
use super::connection::RaopShared;
use super::types::*;
use crate::crypto::pairing::Pairing;
use crate::crypto::rsa::RsaKey;
use crate::error::{ServerError, ShairplayError};
use crate::net::mdns::{AirPlayServiceInfo, MdnsService};
#[cfg(feature = "diagnostic-headers")]
use crate::net::protocol_diagnostics::HeaderDiagnostics;
use crate::net::server::{BindConfig, HttpServer};
use std::sync::Arc;

const AIRPORT_KEY: &str = include_str!("../../airport.key");

fn airport_rsakey() -> Arc<RsaKey> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Arc<RsaKey>> = OnceLock::new();
    KEY.get_or_init(|| {
        Arc::new(RsaKey::from_pem(AIRPORT_KEY).expect("built-in airport.key is invalid"))
    })
    .clone()
}

fn random_hwaddr() -> Vec<u8> {
    use rand::RngCore;

    let mut hwaddr = [0u8; super::MAX_HWADDR_LEN];
    rand::thread_rng().fill_bytes(&mut hwaddr);
    // Locally administered, unicast MAC address.
    hwaddr[0] = (hwaddr[0] | 0x02) & !0x01;
    hwaddr.to_vec()
}

#[cfg(feature = "ap2")]
fn derive_pi_from_hwaddr(hwaddr: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(hwaddr);
    let hash = hasher.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        hash[0],
        hash[1],
        hash[2],
        hash[3],
        hash[4],
        hash[5],
        (hash[6] & 0x0f) | 0x40, // version 4
        hash[7],
        (hash[8] & 0x3f) | 0x80, // variant 1
        hash[9],
        hash[10],
        hash[11],
        hash[12],
        hash[13],
        hash[14],
        hash[15]
    )
}

/// Builder for [`RaopServer`].
pub struct RaopServerBuilder {
    #[cfg(feature = "video")]
    video_display: (u32, u32, u32),
    max_clients: usize,
    hwaddr: Option<Vec<u8>>,
    password: Option<String>,
    #[cfg(feature = "pipewire-auth-setup-compat")]
    pipewire_auth_setup_compat: bool,
    name: String,
    bind: BindConfig,
    #[cfg(feature = "diagnostic-headers")]
    header_diagnostics: HeaderDiagnostics,
    #[cfg(feature = "ap2")]
    pairing_store: Option<Arc<dyn PairingStore>>,
    #[cfg(feature = "ap2")]
    mode: AirPlayMode,
    output_sample_rate: Option<u32>,
    output_max_channels: Option<u8>,
    ap1_codecs: Option<Vec<Ap1Codec>>,
    ap1_encryption: Option<Vec<Ap1Encryption>>,
    #[cfg(feature = "ap2")]
    pin: Option<String>,
    #[cfg(feature = "video")]
    video_handler: Option<Arc<dyn crate::raop::video::VideoHandler>>,
    #[cfg(feature = "hls")]
    hls_handler: Option<Arc<dyn crate::raop::hls::HlsHandler>>,
}

impl Default for RaopServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RaopServerBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "video")]
            video_display: (
                super::config::MIRRORING_WIDTH as u32,
                super::config::MIRRORING_HEIGHT as u32,
                super::config::MIRRORING_FPS as u32,
            ),
            max_clients: 10,
            hwaddr: None,
            password: None,
            #[cfg(feature = "pipewire-auth-setup-compat")]
            pipewire_auth_setup_compat: false,
            name: "Shairplay".to_string(),
            bind: BindConfig::default(),
            #[cfg(feature = "diagnostic-headers")]
            header_diagnostics: HeaderDiagnostics::default(),
            #[cfg(feature = "ap2")]
            pairing_store: None,
            #[cfg(feature = "ap2")]
            mode: AirPlayMode::default(),
            output_sample_rate: None,
            output_max_channels: None,
            ap1_codecs: None,
            ap1_encryption: None,
            #[cfg(feature = "ap2")]
            pin: None,
            #[cfg(feature = "video")]
            video_handler: None,
            #[cfg(feature = "hls")]
            hls_handler: None,
        }
    }

    /// Set the advertised mirroring display, accepting either orientation up to 1080p/60.
    #[cfg(feature = "video")]
    pub fn video_display(mut self, width: u32, height: u32, fps: u32) -> Self {
        self.video_display = (width, height, fps);
        self
    }

    /// Set the maximum number of concurrent connections. Default: 10.
    pub fn max_clients(mut self, n: usize) -> Self {
        self.max_clients = n;
        self
    }
    /// Set the 6-byte hardware address for mDNS registration.
    pub fn hwaddr(mut self, addr: impl Into<Vec<u8>>) -> Self {
        self.hwaddr = Some(addr.into());
        self
    }
    /// Set an optional HTTP Digest authentication password.
    pub fn password(mut self, pw: impl Into<String>) -> Self {
        self.password = Some(pw.into());
        self
    }

    /// Opt into the fixed PipeWire `/auth-setup` probe acknowledgement.
    ///
    /// Disabled by default, even when the Cargo feature is compiled in. This is
    /// experimental classic-RAOP compatibility, not MFi receiver authentication
    /// or audio encryption. Discovery and HTTP Digest requirements stay unchanged.
    /// Password-protected PipeWire interoperability is not established.
    ///
    /// With `ap2` compiled in, enabling this requires `AirPlayMode::AirPlay1`;
    /// already AP2-paired connections remain excluded. Debug builds use the same gates.
    #[cfg(feature = "pipewire-auth-setup-compat")]
    pub fn pipewire_auth_setup_compat(mut self, enabled: bool) -> Self {
        self.pipewire_auth_setup_compat = enabled;
        self
    }
    /// Set the RTSP listening port. Default: 5000.
    pub fn port(mut self, port: u16) -> Self {
        self.bind.port = port;
        self
    }
    /// Set full bind configuration (address, port, auto-sensing, IPv6).
    pub fn bind(mut self, config: BindConfig) -> Self {
        self.bind = config;
        self
    }
    /// Set the AirPlay display name. Default: "Shairplay".
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Configure structured RTSP request and response header diagnostics.
    ///
    /// Diagnostics remain silent unless the `shairplay::protocol_headers`
    /// tracing target is enabled at `TRACE`. The default is
    /// [`HeaderDiagnostics::Disabled`].
    #[cfg(feature = "diagnostic-headers")]
    pub fn header_diagnostics(mut self, diagnostics: HeaderDiagnostics) -> Self {
        self.header_diagnostics = diagnostics;
        self
    }

    /// Set a pairing store for persisting device keys across restarts.
    /// Without this, iPhones must re-pair on every server restart.
    #[cfg(feature = "ap2")]
    pub fn pairing_store(mut self, store: Arc<dyn PairingStore>) -> Self {
        self.pairing_store = Some(store);
        self
    }

    /// Set the AirPlay protocol mode. Default: [`AirPlayMode::AirPlay2`].
    ///
    /// Use [`AirPlayMode::AirPlay1`] to advertise as a classic receiver even
    /// when the `ap2` feature is compiled in.
    #[cfg(feature = "ap2")]
    pub fn mode(mut self, mode: AirPlayMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the desired output sample rate. The library resamples to this rate.
    /// Default: source native rate (no resampling).
    pub fn output_sample_rate(mut self, rate: u32) -> Self {
        self.output_sample_rate = Some(rate);
        self
    }

    /// Set the maximum output channels. Sources with more channels are mixed down.
    /// Sources with fewer channels are passed through (no upmixing).
    /// Default: pass through native channel count.
    pub fn output_max_channels(mut self, channels: u8) -> Self {
        self.output_max_channels = Some(channels);
        self
    }

    /// Set the AP1 codecs advertised in the `_raop._tcp` `cn` TXT record.
    ///
    /// The receiver auto-detects the actual codec per connection from the SDP,
    /// so this only affects discovery and negotiation. The supplied order is
    /// preserved. By default, PCM and ALAC are advertised (`cn=0,1`). Empty or
    /// duplicate lists are rejected by [`build`](Self::build).
    ///
    /// When the `ap2` feature is enabled, also select
    /// `AirPlayMode::AirPlay1`. AP2 has a separate, fixed capability profile.
    pub fn advertise_codecs(mut self, codecs: impl Into<Vec<Ap1Codec>>) -> Self {
        self.ap1_codecs = Some(codecs.into());
        self
    }

    /// Set the AP1 encryption/auth modes advertised in the `et` TXT record.
    ///
    /// The receiver auto-dispatches on what a sender actually negotiates, so
    /// this only affects discovery and negotiation. The supplied order is
    /// preserved. The interoperability-focused default advertises unencrypted
    /// transport only (`et=0`); pass [`Ap1Encryption::Rsa`] and/or
    /// [`Ap1Encryption::FairPlay`] to opt into encrypted AP1 transport. Empty or
    /// duplicate lists are rejected by [`build`](Self::build).
    ///
    /// When the `ap2` feature is enabled, also select
    /// `AirPlayMode::AirPlay1`. AP2 has a separate, fixed capability profile.
    pub fn advertise_encryption(mut self, encryption: impl Into<Vec<Ap1Encryption>>) -> Self {
        self.ap1_encryption = Some(encryption.into());
        self
    }

    #[cfg(feature = "ap2")]
    /// Require normal HomeKit pair-setup with this one-time PIN.
    ///
    /// Without a PIN, AP2 uses the shairport-sync-style transient pairing
    /// profile. Setting a PIN changes mDNS/GET /info status flags so clients
    /// perform persistent M1-M6 pair-setup and later use pair-verify.
    pub fn pin(mut self, pin: impl Into<String>) -> Self {
        self.pin = Some(pin.into());
        self
    }

    #[cfg(feature = "video")]
    /// Set a video handler for screen mirroring (experimental).
    pub fn video_handler(mut self, handler: Arc<dyn crate::raop::video::VideoHandler>) -> Self {
        self.video_handler = Some(handler);
        self
    }

    #[cfg(feature = "hls")]
    /// Set an HLS handler for YouTube/video URL playback.
    pub fn hls_handler(mut self, handler: Arc<dyn crate::raop::hls::HlsHandler>) -> Self {
        self.hls_handler = Some(handler);
        self
    }

    /// Build the server with the given audio handler.
    pub fn build(self, handler: Arc<dyn AudioHandler>) -> Result<RaopServer, ShairplayError> {
        #[cfg(feature = "diagnostic-headers")]
        self.header_diagnostics.validate()?;
        if self.max_clients == 0 {
            return Err(ServerError::MaxClients(0).into());
        }
        if let Some(password) = self.password.as_ref()
            && password.len() > super::MAX_PASSWORD_LEN
        {
            return Err(ServerError::InvalidPassword(password.len()).into());
        }
        #[cfg(feature = "ap2")]
        if self.mode == AirPlayMode::AirPlay2
            && (self.ap1_codecs.is_some() || self.ap1_encryption.is_some())
        {
            return Err(ServerError::InvalidConfiguration(
                "AP1 advertisement options require AirPlayMode::AirPlay1",
            )
            .into());
        }
        #[cfg(all(feature = "ap2", feature = "pipewire-auth-setup-compat"))]
        if self.pipewire_auth_setup_compat && self.mode != AirPlayMode::AirPlay1 {
            return Err(ServerError::InvalidConfiguration(
                "PipeWire auth-setup compatibility requires AirPlayMode::AirPlay1",
            )
            .into());
        }
        #[cfg(feature = "video")]
        {
            let (w, h, fps) = self.video_display;
            if w.min(h) == 0 || w.min(h) > 1080 || w.max(h) > 1920 || !(1..=60).contains(&fps) {
                return Err(ServerError::InvalidConfiguration(
                    "invalid mirroring display (maximum 1080p at 60 fps)",
                )
                .into());
            }
        }
        let ap1_advertisement = Ap1Advertisement::try_new(self.ap1_codecs, self.ap1_encryption)?;
        let rsakey = airport_rsakey();
        #[cfg(not(feature = "ap2"))]
        let pairing = Arc::new(Pairing::generate()?);
        let hwaddr = match self.hwaddr {
            Some(addr) if addr.len() == super::MAX_HWADDR_LEN => addr,
            Some(addr) => return Err(ServerError::InvalidHwAddr(addr.len()).into()),
            None => random_hwaddr(),
        };

        #[cfg(feature = "ap2")]
        let pairing_id = derive_pi_from_hwaddr(&hwaddr);
        #[cfg(feature = "ap2")]
        let device_id = crate::util::hwaddr_airplay(&hwaddr);
        #[cfg(feature = "ap2")]
        let airplay_name = self.name.clone();

        #[cfg(feature = "ap2")]
        let pairing_store: Arc<dyn PairingStore> = self
            .pairing_store
            .unwrap_or_else(|| Arc::new(MemoryPairingStore::default()));
        // Resolve the accessory's long-term identity once: reuse a persisted seed
        // if the store has one, otherwise generate a random seed and hand it back
        // for persistence. (A store with no identity persistence — e.g. the default
        // in-memory one — yields a fresh identity each start; persist it via
        // `PairingStore::load_identity`/`save_identity` to avoid re-pairing.)
        #[cfg(feature = "ap2")]
        let identity_seed = pairing_store.load_identity().unwrap_or_else(|| {
            let seed = crate::crypto::pairing_homekit::generate_identity_seed();
            pairing_store.save_identity(seed);
            seed
        });

        #[cfg(feature = "ap2")]
        let pairing = Arc::new(Pairing::from_seed(&identity_seed));

        let shared = Arc::new(RaopShared {
            #[cfg(feature = "video")]
            video_display: self.video_display,
            tasks: Arc::new(super::media::Tasks::default()),
            media: std::sync::Mutex::default(),
            rsakey,
            pairing,
            hwaddr: hwaddr.clone(),
            password: self.password.unwrap_or_default(),
            #[cfg(feature = "pipewire-auth-setup-compat")]
            pipewire_auth_setup_compat: self.pipewire_auth_setup_compat,
            handler,
            #[cfg(feature = "ap2")]
            pairing_store,
            #[cfg(feature = "ap2")]
            identity_seed,
            output_sample_rate: self.output_sample_rate,
            output_max_channels: self.output_max_channels,
            #[cfg(feature = "ap2")]
            pin: self.pin,
            #[cfg(feature = "video")]
            video_handler: self.video_handler,
            #[cfg(feature = "ap2")]
            pairing_id,
            #[cfg(feature = "ap2")]
            device_id,
            #[cfg(feature = "ap2")]
            airplay_name,
            #[cfg(feature = "ap2")]
            active_audio: std::sync::Mutex::new(None),
            #[cfg(feature = "hls")]
            hls_handler: self.hls_handler,
        });

        let mut httpd = HttpServer::new(shared.clone(), self.max_clients);
        httpd.set_bind_config(self.bind.clone());
        #[cfg(feature = "diagnostic-headers")]
        httpd.set_header_diagnostics(self.header_diagnostics);

        Ok(RaopServer {
            shared,
            httpd,
            mdns: None,
            bind: self.bind,
            name: self.name,
            hwaddr,
            ap1_advertisement,
            #[cfg(feature = "ap2")]
            mode: self.mode,
        })
    }
}

/// The main AirPlay/RAOP server.
///
/// Listens for RTSP connections, handles pairing and encryption,
/// decodes audio, and delivers f32 PCM samples via [`AudioSession`].
/// Automatically registers mDNS services for network discovery.
pub struct RaopServer {
    shared: Arc<RaopShared>,
    httpd: HttpServer,
    mdns: Option<MdnsService>,
    bind: BindConfig,
    name: String,
    hwaddr: Vec<u8>,
    ap1_advertisement: Ap1Advertisement,
    #[cfg(feature = "ap2")]
    mode: AirPlayMode,
}

impl RaopServer {
    /// Create a new server builder.
    pub fn builder() -> RaopServerBuilder {
        RaopServerBuilder::new()
    }

    /// Start the server: bind ports, register mDNS services, begin accepting connections.
    ///
    /// mDNS registration is skipped when the `CI` environment variable is set
    /// (Bonjour/Avahi is typically unavailable on CI runners).
    pub async fn start(&mut self) -> Result<(), ShairplayError> {
        if self.httpd.is_running() {
            return Ok(());
        }
        let _actual_port = self.httpd.start(self.bind.port).await?;

        let discovery = (|| -> Result<(), ShairplayError> {
            if std::env::var("CI").is_err() {
                let info = self.service_info();
                let mut mdns = MdnsService::new()?;
                mdns.register_raop(&info)?;
                #[cfg(feature = "ap2")]
                if self.mode == AirPlayMode::AirPlay2 {
                    mdns.register_airplay(&info)?;
                }
                self.mdns = Some(mdns);
            }
            Ok(())
        })();
        if let Err(error) = discovery {
            self.httpd.stop().await;
            self.shared.tasks.stop().await;
            return Err(error);
        }
        #[cfg(feature = "ap2")]
        if self.mode == AirPlayMode::AirPlay2 {
            crate::net::ptp::spawn_ptp_sink(&self.shared.tasks).await;
        }

        Ok(())
    }

    /// Whether the server is currently running.
    pub fn is_running(&self) -> bool {
        self.httpd.is_running()
    }

    /// Stop the server: unregister mDNS services and close all listeners.
    pub async fn stop(&mut self) {
        super::diagnostics::emit(format_args!("stage=receiver_stop source=host_request"));
        if let Some(mut mdns) = self.mdns.take() {
            mdns.unregister_raop();
            mdns.unregister_airplay();
        }
        self.httpd.stop().await;
        self.shared.tasks.stop().await;
    }

    /// Get the mDNS service info for this server.
    pub fn service_info(&self) -> AirPlayServiceInfo {
        #[cfg(feature = "ap2")]
        {
            if self.mode == AirPlayMode::AirPlay2 {
                let (_, vk) =
                    crate::crypto::pairing_homekit::identity_keypair(&self.shared.identity_seed);
                let pk_hex: String = vk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                let pi = self.shared.pairing_id.clone();
                return AirPlayServiceInfo::new_airplay2(
                    &self.name,
                    self.httpd.port(),
                    &self.hwaddr,
                    !self.shared.password.is_empty(),
                    &pk_hex,
                    &pi,
                    self.shared.pin.is_some(),
                    self.shared.pairing_store.has_any_pairing(),
                );
            }
        }
        AirPlayServiceInfo::new_with_ap1_advertisement(
            &self.name,
            self.httpd.port(),
            &self.hwaddr,
            !self.shared.password.is_empty(),
            &self.ap1_advertisement,
        )
    }
}

impl Drop for RaopServer {
    fn drop(&mut self) {
        self.shared.tasks.abort_all();
    }
}

#[cfg(all(test, feature = "video"))]
mod native_protocol_tests {
    use super::*;
    struct Handler;
    struct Session;
    impl AudioHandler for Handler {
        fn audio_init(&self, _: AudioFormat) -> Box<dyn AudioSession> {
            Box::new(Session)
        }
    }
    impl AudioSession for Session {
        fn audio_process(&mut self, _: &[f32]) {}
    }
    #[tokio::test]
    async fn advertised_legacy_control_port_is_live_and_owned() {
        let server = RaopServer::builder().build(Arc::new(Handler)).unwrap();
        let shared = server.shared.clone();
        let mut conn = super::super::connection::new_raop_connection(
            shared.clone(),
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
        );
        conn.ekey = Some([0; 16]);
        conn.eiv = Some([0; 16]);
        let stream = plist::Dictionary::from_iter([
            ("type".to_string(), plist::Value::Integer(96.into())),
            ("ct".to_string(), plist::Value::Integer(2.into())),
            ("sr".to_string(), plist::Value::Integer(44100.into())),
            ("spf".to_string(), plist::Value::Integer(352.into())),
        ]);
        let response = super::super::handlers_ap2::setup_streams(
            &mut conn,
            &[plist::Value::Dictionary(stream)],
        )
        .unwrap();
        let port = response["streams"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap()["controlPort"]
            .as_unsigned_integer()
            .unwrap() as u16;
        assert!(
            std::net::UdpSocket::bind(("127.0.0.1", port)).is_err(),
            "advertised control port is closed"
        );
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sync = [0u8; 20];
        sync[0] = 0x80;
        sync[1] = 0xd4;
        sync[8..16].copy_from_slice(&((2_208_988_800u64 + 100) << 32).to_be_bytes());
        socket.send_to(&sync, ("127.0.0.1", port)).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if conn.media.clock.lock().unwrap().audio_time(0, 44100) == Some(100_000_000_000) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let session = conn.media.session();
        conn.raop_rtp.as_ref().unwrap().flush(10);
        assert_eq!(
            session,
            conn.media.session(),
            "audio FLUSH must not retire video"
        );
        drop(conn);
        shared.tasks.stop().await;
        assert!(std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok());
    }
    #[test]
    fn unsupported_encoded_setup_is_not_acknowledged_as_success() {
        use crate::proto::http::{HttpRequest, HttpResponse};
        let server = RaopServer::builder().build(Arc::new(Handler)).unwrap();
        let mut conn = super::super::connection::new_raop_connection(
            server.shared.clone(),
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
        );
        conn.ekey = Some([0; 16]);
        conn.eiv = Some([0; 16]);
        let stream = plist::Dictionary::from_iter([
            ("type", plist::Value::Integer(96.into())),
            ("ct", plist::Value::Integer(99.into())),
        ]);
        let dict = plist::Dictionary::from_iter([(
            "streams",
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        )]);
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, &dict).unwrap();
        let mut raw=format!("SETUP / RTSP/1.0\r\nCSeq: 9\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
        raw.extend(body);
        let mut request = HttpRequest::new();
        request.add_data(&raw).unwrap();
        let mut response = HttpResponse::new("RTSP/1.0", 200, "OK");
        assert!(
            super::super::handlers_ap2::handle_setup(&mut conn, &request, &mut response).is_none()
        );
        assert_eq!(response.status_code(), 400);
    }
    fn setup_request(dict: &plist::Dictionary) -> crate::proto::http::HttpRequest {
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, dict).unwrap();
        let mut raw=format!("SETUP / RTSP/1.0\r\nCSeq: 10\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
        raw.extend(body);
        let mut request = crate::proto::http::HttpRequest::new();
        request.add_data(&raw).unwrap();
        request
    }
    #[tokio::test]
    async fn persistent_verified_mirror_uses_negotiated_ntp_not_auth_transport() {
        let server = RaopServer::builder()
            .pin("1234")
            .build(Arc::new(Handler))
            .unwrap();
        let mut conn = super::super::connection::new_raop_connection(
            server.shared.clone(),
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
        );
        // State installed by successful persistent pair verification / SRP identity verification.
        conn.authenticated_peer = Some([7; 32]);
        conn.is_ap2 = true;
        conn.ekey = Some([0; 16]);
        conn.eiv = Some([0; 16]);
        let request = setup_request(&plist::Dictionary::from_iter([(
            "timingProtocol",
            plist::Value::String("NTP".into()),
        )]));
        let mut response = crate::proto::http::HttpResponse::new("RTSP/1.0", 200, "OK");
        let body =
            super::super::handlers_ap2::handle_setup(&mut conn, &request, &mut response).unwrap();
        let dict: plist::Dictionary = plist::from_bytes(&body).unwrap();
        let port = dict["timingPort"].as_unsigned_integer().unwrap() as u16;
        assert_ne!(
            port, 0,
            "persistent authentication must not disable NTP mirroring"
        );
        assert!(std::net::UdpSocket::bind(("127.0.0.1", port)).is_err());
        drop(conn);
        server.shared.tasks.stop().await;
        assert!(std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok());
    }
    #[tokio::test]
    async fn pin_protection_cannot_be_bypassed_by_plaintext_announce_setup() {
        use crate::proto::http::{HttpRequest, HttpResponse};
        struct CountHandler(Arc<std::sync::atomic::AtomicUsize>);
        impl AudioHandler for CountHandler {
            fn audio_init(&self, _: AudioFormat) -> Box<dyn AudioSession> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::new(Session)
            }
        }
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = RaopServer::builder()
            .pin("1234")
            .build(Arc::new(CountHandler(count.clone())))
            .unwrap();
        let mut conn = super::super::connection::new_raop_connection(
            server.shared.clone(),
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
        );
        let sdp =
            "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 0 RTP/AVP 96\r\na=rtpmap:96 L16/44100/2\r\n";
        let mut request = HttpRequest::new();
        request
            .add_data(
                format!(
                    "ANNOUNCE / RTSP/1.0\r\nCSeq: 1\r\nContent-Length: {}\r\n\r\n{sdp}",
                    sdp.len()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut response = HttpResponse::new("RTSP/1.0", 200, "OK");
        super::super::handlers_ap1::handle_announce(&mut conn, &request, &mut response);
        let mut setup = HttpRequest::new();
        setup.add_data(b"SETUP / RTSP/1.0\r\nCSeq: 2\r\nTransport: RTP/AVP/UDP;unicast;mode=record\r\n\r\n").unwrap();
        let mut response = HttpResponse::new("RTSP/1.0", 200, "OK");
        super::super::handlers_ap1::handle_setup(&mut conn, &setup, &mut response);
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "unauthenticated AP1 route initialized media"
        );
        assert_eq!(response.status_code(), 403);
        assert!(conn.raop_rtp.is_none());
    }

    struct VideoRecorder(tokio::sync::mpsc::UnboundedSender<(MediaSession, Vec<u8>)>);
    impl super::super::video::VideoHandler for VideoRecorder {
        fn video_init(&self) -> Box<dyn super::super::video::VideoSession> {
            panic!("timed path required")
        }
        fn video_init_timed(&self, id: MediaSession) -> Box<dyn super::super::video::VideoSession> {
            Box::new(VideoRecordSession(self.0.clone(), id))
        }
    }
    struct VideoRecordSession(
        tokio::sync::mpsc::UnboundedSender<(MediaSession, Vec<u8>)>,
        MediaSession,
    );
    impl super::super::video::VideoSession for VideoRecordSession {
        fn on_video(&mut self, _: super::super::video::VideoPacket) {
            panic!("timed path required")
        }
        fn on_video_timed(
            &mut self,
            packet: super::super::video::VideoPacket,
            timing: super::super::video::VideoTiming,
        ) {
            assert_eq!(timing.session, self.1);
            let _ = self.0.send((timing.session, packet.payload.to_vec()));
        }
    }
    fn setup_video(conn: &mut super::super::handlers_ap1::RaopConnection) -> Option<u16> {
        setup_video_id(conn, Some(plist::Value::Integer(1.into())))
    }
    fn setup_video_id(
        conn: &mut super::super::handlers_ap1::RaopConnection,
        id: Option<plist::Value>,
    ) -> Option<u16> {
        let mut stream =
            plist::Dictionary::from_iter([("type", plist::Value::Integer(110.into()))]);
        if let Some(id) = id {
            stream.insert("streamConnectionID".into(), id);
        }
        let req = setup_request(&plist::Dictionary::from_iter([(
            "streams",
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        )]));
        let mut response = crate::proto::http::HttpResponse::new("RTSP/1.0", 200, "OK");
        let body = super::super::handlers_ap2::handle_setup(conn, &req, &mut response)?;
        let dict: plist::Dictionary = plist::from_bytes(&body).unwrap();
        Some(
            dict["streams"].as_array().unwrap()[0]
                .as_dictionary()
                .unwrap()["dataPort"]
                .as_unsigned_integer()
                .unwrap() as u16,
        )
    }
    async fn send_video_config(stream: &mut tokio::net::TcpStream, marker: u8) {
        use tokio::io::AsyncWriteExt;
        let mut packet = vec![0u8; 132];
        packet[..4].copy_from_slice(&4u32.to_le_bytes());
        packet[4] = 1;
        packet[128..].fill(marker);
        stream.write_all(&packet).await.unwrap();
    }
    #[tokio::test]
    async fn video_setup_preserves_full_connection_id_for_decryption() {
        use tokio::io::AsyncWriteExt;
        for id in [
            plist::Value::Integer((1_u64 << 63).into()),
            plist::Value::Integer(u64::MAX.into()),
            plist::Value::Integer((-1_i64).into()),
        ] {
            let expected_id = id
                .as_unsigned_integer()
                .or_else(|| id.as_signed_integer().map(|id| id as u64))
                .unwrap();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let server = RaopServer::builder()
                .video_handler(Arc::new(VideoRecorder(tx)))
                .build(Arc::new(Handler))
                .unwrap();
            let mut conn = super::super::connection::new_raop_connection(
                server.shared.clone(),
                "127.0.0.1:5000".parse().unwrap(),
                "127.0.0.1:6000".parse().unwrap(),
            );
            conn.ekey = Some([7; 16]);
            conn.eiv = Some([0; 16]);
            let port = setup_video_id(&mut conn, Some(id)).unwrap();
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let (key, iv) = crate::crypto::video_key::derive_stream_key_iv(&[7; 16], expected_id);
            let mut encrypted = b"a complete video payload".to_vec();
            crate::crypto::video_cipher::VideoCipher::new(&key, &iv).decrypt(&mut encrypted);
            let mut header = [0u8; 128];
            header[..4].copy_from_slice(&(encrypted.len() as u32).to_le_bytes());
            stream.write_all(&header).await.unwrap();
            stream.write_all(&encrypted).await.unwrap();
            let (_, decoded) = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
                .await
                .unwrap()
                .unwrap();
            drop(conn);
            server.shared.tasks.stop().await;
            assert_eq!(decoded, b"a complete video payload");
        }
    }
    #[tokio::test]
    async fn video_setup_rejects_missing_or_noninteger_connection_id() {
        for id in [
            None,
            Some(plist::Value::String("1".into())),
            Some(plist::Value::Real(1.0)),
        ] {
            let (tx, _) = tokio::sync::mpsc::unbounded_channel();
            let server = RaopServer::builder()
                .video_handler(Arc::new(VideoRecorder(tx)))
                .build(Arc::new(Handler))
                .unwrap();
            let mut conn = super::super::connection::new_raop_connection(
                server.shared.clone(),
                "127.0.0.1:5000".parse().unwrap(),
                "127.0.0.1:6000".parse().unwrap(),
            );
            conn.ekey = Some([7; 16]);
            conn.eiv = Some([0; 16]);
            let port = setup_video_id(&mut conn, id);
            drop(conn);
            server.shared.tasks.stop().await;
            assert!(
                port.is_none(),
                "a malformed connection ID must not become zero"
            );
        }
    }
    #[tokio::test]
    async fn mirror_retry_after_close_gets_fresh_identity_with_old_auxiliary_alive() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let server = RaopServer::builder()
            .pin("1234")
            .video_handler(Arc::new(VideoRecorder(tx)))
            .build(Arc::new(Handler))
            .unwrap();
        let connect = || {
            super::super::connection::new_raop_connection(
                server.shared.clone(),
                "127.0.0.1:5000".parse().unwrap(),
                "127.0.0.1:6000".parse().unwrap(),
            )
        };
        let mut first = connect();
        first.authenticated_peer = Some([7; 32]);
        first.ekey = Some([0; 16]);
        first.eiv = Some([0; 16]);
        let port = setup_video(&mut first).unwrap();
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        send_video_config(&mut client, 1).await;
        let old = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(old.1, vec![1; 4]);
        let audio = plist::Dictionary::from_iter([
            ("type", plist::Value::Integer(96.into())),
            ("ct", plist::Value::Integer(2.into())),
        ]);
        let audio_reply = super::super::handlers_ap2::setup_streams(
            &mut first,
            &[plist::Value::Dictionary(audio)],
        )
        .unwrap();
        let audio_port = audio_reply["streams"].as_array().unwrap()[0]
            .as_dictionary()
            .unwrap()["dataPort"]
            .as_unsigned_integer()
            .unwrap() as u16;
        assert!(std::net::UdpSocket::bind(("127.0.0.1", audio_port)).is_err());
        let mut auxiliary = connect();
        auxiliary.authenticated_peer = Some([7; 32]);
        auxiliary.ekey = Some([0; 16]);
        auxiliary.eiv = Some([0; 16]);
        assert!(
            setup_video(&mut auxiliary).is_none(),
            "overlapping SETUP must not create another producer"
        );
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if first.media.is_retired() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .is_ok(),
            "retirement must close old video transport"
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if std::net::UdpSocket::bind(("127.0.0.1", audio_port)).is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let next_port = setup_video(&mut auxiliary).unwrap();
        let mut next_client = tokio::net::TcpStream::connect(("127.0.0.1", next_port))
            .await
            .unwrap();
        send_video_config(&mut next_client, 2).await;
        let next = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(next.0.id > old.0.id);
        assert_eq!(next.1, vec![2; 4]);
        assert_eq!(
            first.media.session(),
            old.0,
            "old auxiliary must retain old identity"
        );
        assert!(rx.try_recv().is_err());
        drop(first);
        drop(auxiliary);
        server.shared.tasks.stop().await;
    }

    #[tokio::test]
    async fn ap2_realtime_rejects_oversized_spf_before_starting_decoder() {
        let server = RaopServer::builder().build(Arc::new(Handler)).unwrap();
        let mut conn = super::super::connection::new_raop_connection(
            server.shared.clone(),
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
        );
        let stream = plist::Dictionary::from_iter([
            ("type", plist::Value::Integer(96.into())),
            ("spf", plist::Value::Integer(u64::MAX.into())),
            ("shk", plist::Value::Data(vec![0; 32])),
        ]);
        assert!(
            super::super::handlers_ap2::setup_streams(
                &mut conn,
                &[plist::Value::Dictionary(stream)]
            )
            .is_none()
        );
        assert!(
            conn.children.is_empty(),
            "invalid format must not spawn audio work"
        );
    }

    #[test]
    fn legacy_pair_verify_identity_uses_persisted_receiver_seed() {
        struct FixedStore;
        impl PairingStore for FixedStore {
            fn get(&self, _: &str) -> Option<[u8; 32]> {
                None
            }
            fn put(&self, _: &str, _: [u8; 32]) {}
            fn remove(&self, _: &str) {}
            fn load_identity(&self) -> Option<[u8; 32]> {
                Some([17; 32])
            }
        }
        let server = RaopServer::builder()
            .pairing_store(Arc::new(FixedStore))
            .build(Arc::new(Handler))
            .unwrap();
        assert_eq!(
            server.shared.pairing.public_key(),
            Pairing::from_seed(&[17; 32]).public_key()
        );
    }

    fn legacy_pin_request(dict: &plist::Dictionary) -> crate::proto::http::HttpRequest {
        let mut body = Vec::new();
        plist::to_writer_binary(&mut body, dict).unwrap();
        let mut raw=format!("POST /pair-setup-pin RTSP/1.0\r\nCSeq: 8\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
        raw.extend(body);
        let mut request = crate::proto::http::HttpRequest::new();
        request.add_data(&raw).unwrap();
        request
    }
    #[test]
    fn legacy_pin_route_rejects_out_of_order_confirmation_with_auth_failure() {
        let server = RaopServer::builder()
            .pin("1234")
            .build(Arc::new(Handler))
            .unwrap();
        let mut conn = super::super::connection::new_raop_connection(
            server.shared.clone(),
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:6000".parse().unwrap(),
        );
        let request = legacy_pin_request(&plist::Dictionary::from_iter([
            ("epk", plist::Value::Data(vec![0; 32])),
            ("authTag", plist::Value::Data(vec![0; 16])),
        ]));
        let response = super::super::rtsp::dispatch(&mut conn, &request);
        assert_eq!(response.status_code(), 470);
        assert!(conn.authenticated_peer.is_none());
        assert!(!server.shared.pairing_store.has_any_pairing());
    }

    fn response_plist(response: &crate::proto::http::HttpResponse) -> plist::Dictionary {
        let raw = response.get_data();
        let start = raw.windows(4).position(|part| part == b"\r\n\r\n").unwrap() + 4;
        plist::from_bytes(&raw[start..]).unwrap()
    }
    fn raw_post(path: &str, body: &[u8]) -> crate::proto::http::HttpRequest {
        let mut raw = format!(
            "POST {path} RTSP/1.0\r\nCSeq: 11\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend(body);
        let mut request = crate::proto::http::HttpRequest::new();
        request.add_data(&raw).unwrap();
        request
    }
    #[test]
    fn legacy_pin_plist_stages_register_trust_then_persistent_legacy_verify_authenticates() {
        use ed25519_dalek::Signer;
        use sha2::{Digest, Sha512};
        use std::collections::BTreeMap;
        let server = RaopServer::builder()
            .pin("1234")
            .build(Arc::new(Handler))
            .unwrap();
        let new_conn = || {
            super::super::connection::new_raop_connection(
                server.shared.clone(),
                "127.0.0.1:5000".parse().unwrap(),
                "127.0.0.1:6000".parse().unwrap(),
            )
        };
        let mut conn = new_conn();
        let start = legacy_pin_request(&plist::Dictionary::from_iter([
            ("method", plist::Value::String("pin".into())),
            ("user", plist::Value::String("A1B2C3D4E5F6".into())),
        ]));
        let challenge = super::super::rtsp::dispatch(&mut conn, &start);
        assert_eq!(challenge.status_code(), 200);
        let fields = response_plist(&challenge);
        assert_eq!(fields["salt"].as_data().unwrap().len(), 16);
        assert!((1..=256).contains(&fields["pk"].as_data().unwrap().len()));
        assert!(!server.shared.pairing_store.has_any_pairing());
        // Deterministic material uses the independent working C/OpenSSL fixture.
        let f: BTreeMap<_, _> = include_str!("../../tests/support/pin_reference.txt")
            .split("CASE=")
            .nth(1)
            .unwrap()
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once('='))
            .map(|(k, v)| (k, hex::decode(v).unwrap()))
            .collect();
        conn.pin_setup = Some(
            crate::crypto::pairing_pin::PinSetup::from_test_material(
                "A1B2C3D4E5F6",
                "1234",
                hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                f["salt"].clone().try_into().unwrap(),
                f["b"].clone().try_into().unwrap(),
            )
            .unwrap(),
        );
        let proof = legacy_pin_request(&plist::Dictionary::from_iter([
            ("pk", plist::Value::Data(f["A"].clone())),
            ("proof", plist::Value::Data(f["M1"].clone())),
        ]));
        let response = super::super::rtsp::dispatch(&mut conn, &proof);
        assert_eq!(response.status_code(), 200);
        assert_eq!(
            response_plist(&response)["proof"].as_data().unwrap(),
            f["M2"].as_slice()
        );
        assert!(!server.shared.pairing_store.has_any_pairing());
        assert!(conn.authenticated_peer.is_none());
        let finish = legacy_pin_request(&plist::Dictionary::from_iter([
            ("epk", plist::Value::Data(f["client_epk"].clone())),
            ("authTag", plist::Value::Data(f["client_tag"].clone())),
        ]));
        let response = super::super::rtsp::dispatch(&mut conn, &finish);
        assert_eq!(response.status_code(), 200);
        assert_eq!(
            response_plist(&response)["authTag"].as_data().unwrap(),
            f["server_tag"].as_slice()
        );
        let peer: [u8; 32] =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            server
                .shared
                .pairing_store
                .get(&super::super::handlers_ap1::legacy_pairing_id(&peer)),
            Some(peer)
        );
        // Fresh auxiliary connection proves possession of the registered key, not IP/order.
        let mut verified = new_conn();
        let client_secret = x25519_dalek::StaticSecret::from([7; 32]);
        let client_public = x25519_dalek::PublicKey::from(&client_secret);
        let mut m1 = vec![1, 0, 0, 0];
        m1.extend(client_public.as_bytes());
        m1.extend(peer);
        let response = super::super::rtsp::dispatch(&mut verified, &raw_post("/pair-verify", &m1));
        assert_eq!(response.status_code(), 200);
        let raw = response.get_data();
        let offset = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let server_eph: [u8; 32] = raw[offset..offset + 32].try_into().unwrap();
        let shared = client_secret.diffie_hellman(&x25519_dalek::PublicKey::from(server_eph));
        let client_seed =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signing =
            ed25519_dalek::SigningKey::from_bytes(client_seed.as_slice().try_into().unwrap());
        let message = [client_public.as_bytes().as_slice(), server_eph.as_slice()].concat();
        let mut sig = signing.sign(&message).to_bytes();
        let derive = |label: &[u8]| {
            let mut hash = Sha512::new();
            hash.update(label);
            hash.update(shared.as_bytes());
            <[u8; 16]>::try_from(&hash.finalize()[..16]).unwrap()
        };
        let mut cipher = crate::crypto::aes::AesCtr::new(
            &derive(b"Pair-Verify-AES-Key"),
            &derive(b"Pair-Verify-AES-IV"),
        );
        cipher.encrypt(&mut [0u8; 64]);
        cipher.encrypt(&mut sig);
        let mut m3 = vec![0, 0, 0, 0];
        m3.extend(sig);
        let response = super::super::rtsp::dispatch(&mut verified, &raw_post("/pair-verify", &m3));
        assert_eq!(response.status_code(), 200);
        assert_eq!(verified.authenticated_peer, Some(peer));
        assert_eq!(verified.pairing.shared_secret(), Some(shared.as_bytes()));
        assert!(verified.admit_media());
    }
}

#[cfg(all(test, feature = "video"))]
#[path = "teardown_tests.rs"]
mod teardown_tests;
