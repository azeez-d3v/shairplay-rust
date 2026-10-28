//! Public compatibility and display validation.
#![cfg(feature = "video")]
use shairplay::*;
use std::sync::Arc;
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
#[test]
fn display_accepts_both_orientations_and_rejects_out_of_range() {
    for (w, h) in [(1920, 1080), (1080, 1920), (720, 1280)] {
        assert!(
            RaopServer::builder()
                .video_display(w, h, 60)
                .build(Arc::new(Handler))
                .is_ok()
        );
    }
    for (w, h, fps) in [
        (0, 1080, 60),
        (1920, 1080, 0),
        (1920, 1080, 61),
        (3840, 2160, 60),
    ] {
        assert!(
            RaopServer::builder()
                .video_display(w, h, fps)
                .build(Arc::new(Handler))
                .is_err()
        );
    }
}
