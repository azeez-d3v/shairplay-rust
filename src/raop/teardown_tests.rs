use super::*;
use crate::net::server::{ConnectionHandler, HttpdCallbacks};
use crate::proto::http::{HttpRequest, HttpResponse};
use crate::raop::{AudioTiming, EncodedAudioFormat, EncodedAudioSession};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

struct Handler {
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
        _: MediaSession,
    ) -> Option<Box<dyn EncodedAudioSession>> {
        Some(Box::new(Audio(self.audio.clone(), self.flushes.clone())))
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
        let handler = Arc::new(Handler {
            audio: atx,
            video: vtx,
            flushes: flushes.clone(),
            ended: ended.clone(),
        });
        let server = RaopServer::builder()
            .video_handler(handler.clone())
            .build(handler)
            .unwrap();
        let mut http = HttpServer::new(Arc::new(Callbacks(server.shared.clone())), 2);
        http.set_bind_config(
            BindConfig::new()
                .addrs(["127.0.0.1".parse().unwrap()])
                .port(0),
        );
        let port = http.start(0).await.unwrap();
        let rtsp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        Self {
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
        let wire = format!(
            "{method} / RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: {}\r\n\r\n",
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
