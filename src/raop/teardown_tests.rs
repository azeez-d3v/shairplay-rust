use super::*;
use crate::net::server::{ConnectionHandler, HttpdCallbacks};
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::raop::{AudioTiming, EncodedAudioFormat, EncodedAudioSession};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

struct Handler {
    volumes: Arc<std::sync::Mutex<Vec<(MediaSession, Option<f32>)>>>,
    audio: UnboundedSender<AudioTiming>,
    video: UnboundedSender<MediaSession>,
    flushes: Arc<AtomicUsize>,
    ended: Arc<AtomicUsize>,
}
struct Audio(UnboundedSender<AudioTiming>, Arc<AtomicUsize>);
impl EncodedAudioSession for Audio {
    fn audio_process_encoded(&mut self, _: &[u8], timing: AudioTiming) {
        self.0.send(timing).unwrap();
    }
    fn audio_flush_timed(&mut self, _: MediaSession) {
        self.1.fetch_add(1, Ordering::SeqCst);
    }
}
impl AudioHandler for Handler {
    fn audio_init(&self, _: AudioFormat) -> Box<dyn AudioSession> {
        unreachable!()
    }
    fn audio_init_encoded(
        &self,
        _: EncodedAudioFormat,
        session: MediaSession,
    ) -> Option<Box<dyn EncodedAudioSession>> {
        self.volumes.lock().unwrap().push((session, None));
        Some(Box::new(Audio(self.audio.clone(), self.flushes.clone())))
    }
    fn on_volume_timed(&self, value: f32, session: MediaSession) {
        self.volumes.lock().unwrap().push((session, Some(value)));
    }
    fn on_media_session_ended(&self, _: MediaSession) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }
}
struct Video(UnboundedSender<MediaSession>);
impl crate::raop::video::VideoHandler for Handler {
    fn video_init(&self) -> Box<dyn crate::raop::video::VideoSession> {
        unreachable!()
    }
    fn video_init_timed(&self, _: MediaSession) -> Box<dyn crate::raop::video::VideoSession> {
        Box::new(Video(self.video.clone()))
    }
}
impl crate::raop::video::VideoSession for Video {
    fn on_video(&mut self, _: crate::raop::video::VideoPacket) {
        unreachable!()
    }
    fn on_video_timed(
        &mut self,
        _: crate::raop::video::VideoPacket,
        timing: crate::raop::video::VideoTiming,
    ) {
        self.0.send(timing.session).unwrap();
    }
}
// Only authentication/key setup is substituted; production RTSP dispatch and TCP ownership run unchanged.
struct Callbacks(Arc<RaopShared>);
struct Connection(crate::raop::handlers_ap1::RaopConnection);
impl HttpdCallbacks for Callbacks {
    fn conn_init(
        self: Arc<Self>,
        local: std::net::SocketAddr,
        remote: std::net::SocketAddr,
    ) -> Option<Box<dyn ConnectionHandler>> {
        let mut conn = crate::raop::connection::new_raop_connection(self.0.clone(), local, remote);
        conn.authenticated_peer = Some([1; 32]);
        conn.ekey = Some([0; 16]);
        conn.eiv = Some([0; 16]);
        Some(Box::new(Connection(conn)))
    }
}
impl ConnectionHandler for Connection {
    fn conn_request(&mut self, request: &HttpRequest) -> HttpResponse {
        crate::raop::rtsp::dispatch(&mut self.0, request)
    }
}
struct Harness {
    volumes: Arc<std::sync::Mutex<Vec<(MediaSession, Option<f32>)>>>,
    server: RaopServer,
    http: HttpServer,
    rtsp: TcpStream,
    audio: UnboundedReceiver<AudioTiming>,
    video: UnboundedReceiver<MediaSession>,
    flushes: Arc<AtomicUsize>,
    ended: Arc<AtomicUsize>,
}
impl Harness {
    async fn start() -> Self {
        let (atx, audio) = mpsc::unbounded_channel();
        let (vtx, video) = mpsc::unbounded_channel();
        let flushes = Arc::new(AtomicUsize::new(0));
        let ended = Arc::new(AtomicUsize::new(0));
        let volumes = Arc::new(std::sync::Mutex::new(vec![]));
        let handler = Arc::new(Handler {
            volumes: volumes.clone(),
            audio: atx,
            video: vtx,
            flushes: flushes.clone(),
            ended: ended.clone(),
        });
        let server = RaopServer::builder()
            .video_handler(handler.clone())
            .build(handler)
            .unwrap();
        let mut http = HttpServer::new(Arc::new(Callbacks(server.shared.clone())), 3);
        http.set_bind_config(
            BindConfig::new()
                .addrs(["127.0.0.1".parse().unwrap()])
                .port(0),
        );
        let port = http.start(0).await.unwrap();
        let rtsp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        Self {
            volumes,
            server,
            http,
            rtsp,
            audio,
            video,
            flushes,
            ended,
        }
    }
    async fn request(&mut self, method: &str, body: &[u8]) -> (String, Vec<u8>) {
        let flush = if method == "FLUSH" {
            "RTP-Info: seq=50\r\n"
        } else {
            ""
        };
        let content_type = if method.ends_with("_PARAMETER") {
            "text/parameters"
        } else {
            "application/x-apple-binary-plist"
        };
        let wire = format!(
            "{method} / RTSP/1.0\r\nCSeq: 1\r\n{flush}Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        self.rtsp.write_all(wire.as_bytes()).await.unwrap();
        self.rtsp.write_all(body).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(self.rtsp.read_u8().await.unwrap());
            }
            let header = String::from_utf8(header).unwrap();
            let length = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .map_or(0, |s| s.parse::<usize>().unwrap());
            let mut body = vec![0; length];
            self.rtsp.read_exact(&mut body).await.unwrap();
            (header, body)
        })
        .await
        .unwrap()
    }
    async fn setup(&mut self, kind: u64) -> (u16, u16) {
        let mut stream =
            plist::Dictionary::from_iter([("type", plist::Value::Integer(kind.into()))]);
        if kind == 110 {
            stream.insert("streamConnectionID".into(), plist::Value::Integer(1.into()));
        } else {
            for (key, value) in [("ct", 8), ("sr", 44100), ("spf", 480)] {
                stream.insert(key.into(), plist::Value::Integer(value.into()));
            }
        }
        let body = body(vec![plist::Value::Dictionary(stream)]);
        let (header, response) = self.request("SETUP", &body).await;
        assert!(header.contains("200 OK"), "{header}");
        let value: plist::Value = plist::from_bytes(&response).unwrap();
        let stream = value.as_dictionary().unwrap()["streams"]
            .as_array()
            .unwrap()[0]
            .as_dictionary()
            .unwrap();
        (
            stream["dataPort"].as_unsigned_integer().unwrap() as u16,
            stream
                .get("controlPort")
                .and_then(plist::Value::as_unsigned_integer)
                .unwrap_or(0) as u16,
        )
    }
    async fn shutdown(mut self) {
        self.http.stop().await;
        self.server.shared.tasks.stop().await;
    }
}
fn stream(kind: u64) -> plist::Value {
    plist::Value::Dictionary(plist::Dictionary::from_iter([(
        "type",
        plist::Value::Integer(kind.into()),
    )]))
}
fn body(streams: Vec<plist::Value>) -> Vec<u8> {
    let mut bytes = Vec::new();
    plist::to_writer_binary(
        &mut bytes,
        &plist::Dictionary::from_iter([("streams", plist::Value::Array(streams))]),
    )
    .unwrap();
    bytes
}
async fn marker(video: &mut TcpStream, rx: &mut UnboundedReceiver<MediaSession>) -> MediaSession {
    let mut packet = vec![0u8; 132];
    packet[..4].copy_from_slice(&4u32.to_le_bytes());
    packet[4] = 1;
    video.write_all(&packet).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap()
}
async fn send_audio(
    socket: &UdpSocket,
    port: u16,
    seq: u16,
    timestamp: u32,
    rx: &mut UnboundedReceiver<AudioTiming>,
) -> AudioTiming {
    let mut packet = vec![0u8; 16];
    packet[0] = 0x80;
    packet[1] = 0x60;
    packet[2..4].copy_from_slice(&seq.to_be_bytes());
    packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
    packet[12..].fill(0xab);
    socket.send_to(&packet, ("127.0.0.1", port)).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap()
}
async fn sync(socket: &UdpSocket, port: u16, timestamp: u32, seconds: u64) {
    let mut packet = [0u8; 20];
    packet[0] = 0x80;
    packet[1] = 0xd4;
    packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
    packet[8..16].copy_from_slice(&((2_208_988_800 + seconds) << 32).to_be_bytes());
    socket.send_to(&packet, ("127.0.0.1", port)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
}
async fn freed_udp(port: u16) {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if UdpSocket::bind(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn typed_audio_teardown_preserves_video_and_restarts_audio_clock() {
    let mut h = Harness::start().await;
    let (vport, _) = h.setup(110).await;
    let mut video = TcpStream::connect(("127.0.0.1", vport)).await.unwrap();
    let original = marker(&mut video, &mut h.video).await;
    let (aport, cport) = h.setup(96).await;
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sync(&sender, cport, 0, 100).await;
    let first = send_audio(&sender, aport, 0, 0, &mut h.audio).await;
    assert_eq!(first.presentation_time_ns, Some(100_000_000_000));
    let (header, _) = h.request("TEARDOWN", &body(vec![stream(96)])).await;
    assert!(header.contains("200 OK"));
    assert!(
        !header.contains("Connection: close"),
        "audio teardown must retain RTSP/video"
    );
    let (header, _) = h.request("POST", &[]).await;
    assert!(
        header.contains("404 Not Found"),
        "retained RTSP must respond"
    );
    assert_eq!(marker(&mut video, &mut h.video).await, original);
    freed_udp(aport).await;
    freed_udp(cport).await;
    assert_eq!(
        h.flushes.load(Ordering::SeqCst),
        1,
        "stopped audio callback must flush host buffers once"
    );
    assert_eq!(h.ended.load(Ordering::SeqCst), 0);
    let (aport, cport) = h.setup(96).await;
    let unanchored = send_audio(&sender, aport, 10, 9_000_000, &mut h.audio).await;
    assert_eq!(
        unanchored.presentation_time_ns, None,
        "new RTP origin must not inherit old audio anchor"
    );
    sync(&sender, cport, 9_000_000, 102).await;
    let resumed = send_audio(&sender, aport, 11, 9_000_480, &mut h.audio).await;
    assert_eq!(resumed.session, original);
    assert_eq!(
        resumed.presentation_time_ns,
        Some(102_000_000_000 + 480_000_000_000 / 44100)
    );
    assert_eq!(marker(&mut video, &mut h.video).await, original);
    let (header, _) = h.request("TEARDOWN", &[]).await;
    assert!(header.contains("Connection: close"));
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), h.rtsp.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), video.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    freed_udp(aport).await;
    freed_udp(cport).await;
    assert_eq!(h.ended.load(Ordering::SeqCst), 1);
    h.shutdown().await;
}
#[tokio::test]
async fn typed_video_teardown_releases_video_but_keeps_control_connection() {
    let mut h = Harness::start().await;
    let (port, _) = h.setup(110).await;
    let mut video = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    marker(&mut video, &mut h.video).await;
    let (header, _) = h.request("TEARDOWN", &body(vec![stream(110)])).await;
    assert!(header.contains("200 OK"));
    assert!(!header.contains("Connection: close"));
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), video.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let (header, _) = h.request("POST", &[]).await;
    assert!(header.contains("404 Not Found"));
    assert_eq!(h.ended.load(Ordering::SeqCst), 1);
    h.shutdown().await;
}
#[tokio::test]
async fn malformed_typed_teardown_is_rejected_without_stopping_media() {
    let mut h = Harness::start().await;
    let (port, _) = h.setup(110).await;
    let mut video = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let original = marker(&mut video, &mut h.video).await;
    for request in [
        body(vec![]),
        body(vec![stream(999)]),
        body(vec![stream(96), stream(999)]),
        body(vec![plist::Value::String("invalid".into())]),
        b"invalid plist".to_vec(),
    ] {
        let (header, _) = h.request("TEARDOWN", &request).await;
        assert!(header.contains("400 Bad Request"), "{header}");
        assert!(!header.contains("Connection: close"));
        assert_eq!(marker(&mut video, &mut h.video).await, original);
    }
    assert_eq!(h.ended.load(Ordering::SeqCst), 0);
    h.shutdown().await;
}

#[tokio::test]
async fn audio_takeover_fences_old_auxiliary_connection_and_late_teardown() {
    for teardown in [None, Some(false), Some(true)] {
        let mut h = Harness::start().await;
        let address = h.rtsp.peer_addr().unwrap();
        let (vport, _) = h.setup(110).await;
        let mut video = TcpStream::connect(("127.0.0.1", vport)).await.unwrap();
        let original = marker(&mut video, &mut h.video).await;
        let mut video_control = TcpStream::connect(address).await.unwrap();
        std::mem::swap(&mut h.rtsp, &mut video_control);
        let (old_port, old_control) = h.setup(96).await;
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sync(&sender, old_control, 0, 100).await;
        assert_eq!(
            send_audio(&sender, old_port, 0, 0, &mut h.audio)
                .await
                .session,
            original
        );

        let mut old_connection = TcpStream::connect(address).await.unwrap();
        std::mem::swap(&mut h.rtsp, &mut old_connection);
        let (new_port, new_control) = h.setup(96).await;
        assert_eq!(
            h.flushes.load(Ordering::SeqCst),
            1,
            "takeover must finish old audio before new factory"
        );
        sync(&sender, new_control, 9_000_000, 102).await;
        let fresh = send_audio(&sender, new_port, 10, 9_000_000, &mut h.audio).await;
        assert_eq!(fresh.session, original);
        assert_eq!(fresh.presentation_time_ns, Some(102_000_000_000));

        // Delayed UDP callbacks and sync from the displaced auxiliary connection cannot affect B.
        let mut stale = [0u8; 16];
        stale[0] = 0x80;
        stale[1] = 0x60;
        stale[3] = 1;
        stale[12..].fill(0xab);
        sender
            .send_to(&stale, ("127.0.0.1", old_port))
            .await
            .unwrap();
        sync(&sender, old_control, 0, 900).await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), h.audio.recv())
                .await
                .is_err()
        );
        std::mem::swap(&mut h.rtsp, &mut old_connection);
        assert!(h.request("FLUSH", &[]).await.0.contains("200 OK"));
        if let Some(full) = teardown {
            let payload = if full { vec![] } else { body(vec![stream(96)]) };
            assert!(h.request("TEARDOWN", &payload).await.0.contains("200 OK"));
        }
        std::mem::swap(&mut h.rtsp, &mut old_connection);
        drop(old_connection);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            h.flushes.load(Ordering::SeqCst),
            1,
            "old FLUSH/TEARDOWN/close must not flush replacement"
        );
        let resumed = send_audio(&sender, new_port, 11, 9_000_480, &mut h.audio).await;
        assert_eq!(
            resumed.presentation_time_ns,
            Some(102_000_000_000 + 480_000_000_000 / 44100)
        );
        assert_eq!(marker(&mut video, &mut h.video).await, original);
        assert_eq!(h.ended.load(Ordering::SeqCst), 0);
        h.shutdown().await;
        drop(video_control);
    }
}

#[tokio::test]
async fn volume_parameters_report_cached_value_and_reject_invalid_levels() {
    let mut h = Harness::start().await;
    assert_eq!(
        h.request("GET_PARAMETER", b"volume\r\n").await.1,
        b"volume: 0.000000\r\n"
    );
    for (wire, expected) in [
        ("-144", "-144.000000"),
        ("-12.5", "-12.500000"),
        ("0", "0.000000"),
    ] {
        assert!(
            h.request("SET_PARAMETER", format!("volume: {wire}\r\n").as_bytes())
                .await
                .0
                .contains("200 OK")
        );
        assert_eq!(
            h.request("GET_PARAMETER", b"volume\r\n").await.1,
            format!("volume: {expected}\r\n").as_bytes()
        );
    }
    for value in ["NaN", "inf", "-inf", "1", "-145", "bad"] {
        assert!(
            h.request("SET_PARAMETER", format!("volume: {value}\r\n").as_bytes())
                .await
                .0
                .contains("400 Bad Request"),
            "{value}"
        );
        assert_eq!(
            h.request("GET_PARAMETER", b"volume\r\n").await.1,
            b"volume: 0.000000\r\n"
        );
    }
    h.shutdown().await;
}

#[tokio::test]
async fn volume_preinit_takeover_and_retired_control_identity() {
    let mut h = Harness::start().await;
    let address = h.rtsp.peer_addr().unwrap();
    assert_eq!(
        h.request("GET_PARAMETER", b"volume\r\n").await.1,
        b"volume: 0.000000\r\n"
    );
    assert!(
        h.volumes.lock().unwrap().is_empty(),
        "default GET must not emit unsolicited volume"
    );
    h.request("SET_PARAMETER", b"volume: -144\r\n").await;
    let (vport, _) = h.setup(110).await;
    let mut video = TcpStream::connect(("127.0.0.1", vport)).await.unwrap();
    let identity = marker(&mut video, &mut h.video).await;
    h.setup(96).await;
    assert!(
        h.volumes
            .lock()
            .unwrap()
            .ends_with(&[(identity, None), (identity, Some(-144.0))])
    );
    let mut control = TcpStream::connect(address).await.unwrap();
    std::mem::swap(&mut h.rtsp, &mut control);
    h.setup(96).await;
    assert!(
        h.volumes
            .lock()
            .unwrap()
            .ends_with(&[(identity, None), (identity, Some(-144.0))]),
        "replacement factory must retain explicit mute"
    );
    std::mem::swap(&mut h.rtsp, &mut control);
    assert!(
        h.request("SET_PARAMETER", b"volume: -12\r\n")
            .await
            .0
            .contains("200 OK"),
        "control remains valid after its audio ownership is retired"
    );
    std::mem::swap(&mut h.rtsp, &mut control);
    assert_eq!(
        h.request("GET_PARAMETER", b"volume\r\n").await.1,
        b"volume: -12.000000\r\n"
    );
    std::mem::swap(&mut h.rtsp, &mut control);
    h.request("TEARDOWN", &body(vec![stream(110)])).await;
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), video.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let events = h.volumes.lock().unwrap().len();
    assert!(
        h.request("SET_PARAMETER", b"volume: 0\r\n")
            .await
            .0
            .contains("454 Session Not Found")
    );
    let mut old = TcpStream::connect(address).await.unwrap();
    std::mem::swap(&mut h.rtsp, &mut old);
    assert_eq!(
        h.request("GET_PARAMETER", b"volume\r\n").await.1,
        b"volume: 0.000000\r\n"
    );
    std::mem::swap(&mut h.rtsp, &mut old);
    assert!(
        h.request("SET_PARAMETER", b"volume: -144\r\n")
            .await
            .0
            .contains("454 Session Not Found")
    );
    std::mem::swap(&mut h.rtsp, &mut old);
    assert_eq!(
        h.volumes.lock().unwrap().len(),
        events,
        "retired context must not emit callback into replacement"
    );
    h.setup(96).await;
    let recorded = h.volumes.lock().unwrap().clone();
    assert_eq!(
        recorded.len(),
        events + 1,
        "new context without SET emits only factory, no implicit volume0"
    );
    assert_eq!(recorded.last().unwrap().1, None);
    assert_ne!(recorded.last().unwrap().0, identity);
    h.shutdown().await;
    drop((control, old));
}

#[tokio::test]
async fn volume_admission_racing_retirement_keeps_original_context() {
    use crate::raop::handlers_ap1::volume_context_admit;
    let h = Harness::start().await;
    let endpoint = "127.0.0.1:1".parse().unwrap();
    let mut conn =
        crate::raop::connection::new_raop_connection(h.server.shared.clone(), endpoint, endpoint);
    conn.authenticated_peer = Some([1; 32]);
    assert!(conn.admit_media());
    let original = conn.media.clone();
    let video = original.video_lease().unwrap();
    // EOF retires the original after the first liveness check, just before
    // registry admission acquires its mutex. No timing/sleep assumption.
    assert!(!volume_context_admit(&mut conn, |conn| {
        drop(video);
        assert!(conn.admit_media());
        assert!(!Arc::ptr_eq(&original, &conn.media));
        true
    }));
    assert!(Arc::ptr_eq(&original, &conn.media));
    assert!(
        !volume_context_admit(&mut conn, |conn| conn.admit_media()),
        "rejected admission must not persist"
    );
    let mut fresh =
        crate::raop::connection::new_raop_connection(h.server.shared.clone(), endpoint, endpoint);
    fresh.authenticated_peer = Some([1; 32]);
    assert!(volume_context_admit(&mut fresh, |conn| conn.admit_media()));
    assert_ne!(original.session(), fresh.media.session());
    assert_eq!(fresh.media.volume(), 0.0);
    h.shutdown().await;
}
