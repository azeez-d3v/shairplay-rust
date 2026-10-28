//! Shared media clock, authenticated-phone fencing, and owned child tasks.
use super::{MediaSession, ntp::SenderClock};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};

const RETIRING: u8 = 2;
const RETIRED: u8 = 3;

#[derive(Default)]
struct VolumeState {
    value: Option<f32>,
    dirty: bool,
    delivering: bool,
}

pub(crate) struct MediaContext {
    volume: Mutex<VolumeState>,
    audio_setup: AtomicBool,
    audio_owner: Mutex<Weak<super::rtp::AudioOwner>>,
    handler: Mutex<Option<Arc<dyn super::AudioHandler>>>,
    video_state: AtomicU8,
    transports: Mutex<Vec<tokio::task::AbortHandle>>,
    id: u64,
    generation: AtomicU64,
    pub(crate) clock: Mutex<SenderClock>,
    #[cfg_attr(not(feature = "video"), allow(dead_code))]
    pub(crate) keys: std::sync::RwLock<Option<([u8; 16], [u8; 16])>>,
}
#[allow(deprecated)] // fetch_update preserves the declared Rust 1.94 MSRV.
impl Default for MediaContext {
    fn default() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            volume: Mutex::default(),
            audio_setup: AtomicBool::new(false),
            audio_owner: Mutex::new(Weak::new()),
            handler: Mutex::new(None),
            video_state: AtomicU8::new(0),
            transports: Mutex::new(Vec::new()),
            id: NEXT
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .expect("media identity exhausted"),
            generation: AtomicU64::new(0),
            clock: Mutex::default(),
            keys: std::sync::RwLock::new(None),
        }
    }
}
impl MediaContext {
    pub(crate) fn accepts_control(&self) -> bool {
        self.video_state.load(Ordering::Acquire) < RETIRING
    }
    pub(crate) fn volume(&self) -> f32 {
        self.volume
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .value
            .unwrap_or(0.0)
    }
    pub(crate) fn set_volume(
        self: &Arc<Self>,
        value: f32,
        handler: &dyn super::AudioHandler,
    ) -> bool {
        if !value.is_finite() || !(-144.0..=0.0).contains(&value) {
            return false;
        }
        {
            let mut state = self.volume.lock().unwrap_or_else(|e| e.into_inner());
            if !self.accepts_control() {
                return false;
            }
            state.value = Some(value);
            state.dirty = true;
            if state.delivering {
                return true;
            }
            state.delivering = true;
        }
        VolumeDelivery {
            media: self.clone(),
            active: true,
        }
        .drain(handler);
        true
    }
    fn reserve_volume(self: &Arc<Self>) -> Option<VolumeDelivery> {
        let mut state = self.volume.lock().unwrap_or_else(|e| e.into_inner());
        if !self.accepts_control() || state.delivering {
            return None;
        }
        state.delivering = true;
        state.dirty = state.value.is_some();
        Some(VolumeDelivery {
            media: self.clone(),
            active: true,
        })
    }

    /// Only one auxiliary connection may replace this phone's audio at a time.
    /// Reject concurrent/reentrant setup rather than holding a mutex across host callbacks.
    pub(crate) fn begin_audio_setup(self: &Arc<Self>) -> Option<AudioSetup> {
        if self.video_state.load(Ordering::Acquire) >= RETIRING
            || self
                .audio_setup
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return None;
        }
        let mut reservation = AudioSetup {
            media: self.clone(),
            volume: None,
        };
        reservation.volume = Some(self.reserve_volume()?);
        let previous = self
            .audio_owner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade();
        if previous.is_some_and(|owner| !owner.stop()) {
            return None;
        }
        Some(reservation)
    }
    pub(crate) fn own_audio(&self, owner: &Arc<super::rtp::AudioOwner>) {
        *self.audio_owner.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(owner);
    }

    #[cfg(all(test, feature = "video"))]
    pub(crate) fn is_retired(&self) -> bool {
        self.video_state.load(Ordering::Acquire) == RETIRED
    }
    pub(crate) fn own_transport(&self, handle: tokio::task::AbortHandle) {
        let mut transports = self.transports.lock().unwrap_or_else(|e| e.into_inner());
        if self.video_state.load(Ordering::Acquire) >= RETIRING {
            handle.abort();
        } else {
            transports.retain(|task| !task.is_finished());
            transports.push(handle);
        }
    }
    #[cfg(feature = "video")]
    pub(crate) fn video_lease(self: &Arc<Self>) -> Option<VideoLease> {
        self.video_state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(VideoLease(self.clone()))
    }
    #[cfg(feature = "video")]
    fn retire(&self) {
        self.video_state.store(RETIRING, Ordering::Release);
        for transport in self
            .transports
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
        {
            transport.abort();
        }
        self.notify_ended("video_lease");
        // A replacement's factory must not run before the host finishes resetting the old session.
        self.video_state.store(RETIRED, Ordering::Release);
    }
    fn notify_ended(&self, source: &'static str) {
        let handler = self
            .handler
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(handler) = handler {
            super::diagnostics::emit(format_args!("stage=media_end source={source}"));
            handler.on_media_session_ended(self.session());
        }
    }

    pub(crate) fn attach_handler(&self, handler: Arc<dyn super::AudioHandler>) {
        *self.handler.lock().unwrap_or_else(|e| e.into_inner()) = Some(handler);
    }
    pub(crate) fn session(&self) -> MediaSession {
        MediaSession {
            id: self.id,
            generation: self.generation.load(Ordering::Acquire),
        }
    }
    #[allow(deprecated, dead_code)] // Reserved for a full common-clock discontinuity, not audio FLUSH.
    pub(crate) fn reset(&self) {
        self.clock.lock().unwrap_or_else(|e| e.into_inner()).reset();
        self.generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .expect("media generation exhausted");
    }
}
/// One pending value, not an event queue; callbacks run outside the cache mutex.
struct VolumeDelivery {
    media: Arc<MediaContext>,
    active: bool,
}
impl VolumeDelivery {
    fn drain(mut self, handler: &dyn super::AudioHandler) {
        loop {
            let value = {
                let mut state = self.media.volume.lock().unwrap_or_else(|e| e.into_inner());
                if !state.dirty || !self.media.accepts_control() {
                    state.delivering = false;
                    self.active = false;
                    return;
                }
                state.dirty = false;
                state.value
            };
            if let Some(value) = value {
                handler.on_volume_timed(value, self.media.session());
            }
        }
    }
}
impl Drop for VolumeDelivery {
    fn drop(&mut self) {
        if self.active {
            self.media
                .volume
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .delivering = false;
        }
    }
}
pub(crate) struct AudioSetup {
    media: Arc<MediaContext>,
    volume: Option<VolumeDelivery>,
}
impl AudioSetup {
    pub(crate) fn replay_volume(&mut self, handler: &dyn super::AudioHandler) {
        if let Some(volume) = self.volume.take() {
            volume.drain(handler);
        }
    }
}
impl Drop for AudioSetup {
    fn drop(&mut self) {
        self.volume.take();
        self.media.audio_setup.store(false, Ordering::Release);
    }
}
#[derive(Default)]
#[cfg_attr(not(feature = "ap2"), allow(dead_code))]
pub(crate) struct MediaRegistry {
    active: Option<([u8; 32], Weak<MediaContext>)>,
}
#[cfg_attr(not(feature = "ap2"), allow(dead_code))]
impl MediaRegistry {
    pub(crate) fn acquire(&mut self, authenticated_peer: [u8; 32]) -> Option<Arc<MediaContext>> {
        if let Some((peer, weak)) = &self.active
            && let Some(context) = weak.upgrade()
        {
            if *peer != authenticated_peer {
                return None;
            }
            match context.video_state.load(Ordering::Acquire) {
                RETIRING => return None,
                RETIRED => {}
                _ => return Some(context),
            }
        }
        let context = Arc::new(MediaContext::default());
        self.active = Some((authenticated_peer, Arc::downgrade(&context)));
        Some(context)
    }
}
#[derive(Default)]
pub(crate) struct Tasks(Mutex<Vec<tokio::task::JoinHandle<()>>>);
impl Tasks {
    pub(crate) fn abort_all(&self) {
        for task in self.0.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            task.abort();
        }
    }
    pub(crate) fn track(&self, task: tokio::task::JoinHandle<()>) -> tokio::task::AbortHandle {
        let abort = task.abort_handle();
        let mut tasks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        tasks.retain(|task| !task.is_finished());
        tasks.push(task);
        abort
    }
    pub(crate) async fn stop(&self) {
        let tasks = std::mem::take(&mut *self.0.lock().unwrap_or_else(|e| e.into_inner()));
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in self.0.get_mut().unwrap_or_else(|e| e.into_inner()) {
            task.abort();
        }
    }
}

#[cfg(feature = "video")]
pub(crate) struct VideoLease(Arc<MediaContext>);
#[cfg(feature = "video")]
impl Drop for VideoLease {
    fn drop(&mut self) {
        self.0.retire();
    }
}
impl Drop for MediaContext {
    fn drop(&mut self) {
        self.notify_ended("last_owner");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_authenticated_phone_shares_context_second_phone_cannot_replace_it() {
        let mut registry = MediaRegistry::default();
        let a = registry.acquire([1; 32]).unwrap();
        let b = registry.acquire([1; 32]).unwrap();
        assert_eq!(a.session(), b.session());
        assert!(registry.acquire([2; 32]).is_none());
        let old = a.session();
        a.reset();
        assert_ne!(old, b.session());
        drop(a);
        drop(b);
        assert!(registry.acquire([2; 32]).is_some());
    }

    #[derive(Default)]
    struct VolumeRecorder(Mutex<Vec<f32>>);
    impl super::super::AudioHandler for VolumeRecorder {
        fn audio_init(&self, _: super::super::AudioFormat) -> Box<dyn super::super::AudioSession> {
            unreachable!()
        }
        fn on_volume_timed(&self, value: f32, _: MediaSession) {
            self.0.lock().unwrap().push(value);
        }
    }
    #[test]
    fn volume_setup_reservation_replays_latest_before_release_and_survives_failure() {
        let media = Arc::new(MediaContext::default());
        let handler = VolumeRecorder::default();
        // No SET means default GET=0, but must not trigger a legacy callback.
        let mut setup = media.begin_audio_setup().unwrap();
        setup.replay_volume(&handler);
        drop(setup);
        assert!(handler.0.lock().unwrap().is_empty());
        assert!(media.set_volume(-12.0, &handler));
        handler.0.lock().unwrap().clear();
        let failed = media.begin_audio_setup().unwrap();
        // Models SET while a factory is running, then an unsuccessful factory.
        assert!(media.set_volume(-144.0, &handler));
        assert!(handler.0.lock().unwrap().is_empty());
        drop(failed);
        let mut retry = media.begin_audio_setup().unwrap();
        assert!(media.set_volume(-6.0, &handler));
        assert!(media.set_volume(-144.0, &handler));
        assert!(handler.0.lock().unwrap().is_empty());
        // Production calls this after the successful factory, before task spawn.
        retry.replay_volume(&handler);
        assert_eq!(*handler.0.lock().unwrap(), [-144.0]);
        assert!(
            media.begin_audio_setup().is_none(),
            "factory reservation is still held"
        );
        drop(retry);
        assert!(media.begin_audio_setup().is_some());
    }
    #[test]
    fn volume_concurrent_updates_coalesce_and_setup_cannot_overtake_callback() {
        use std::sync::mpsc;
        struct Blocking {
            events: Mutex<Vec<f32>>,
            entered: mpsc::Sender<()>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl super::super::AudioHandler for Blocking {
            fn audio_init(
                &self,
                _: super::super::AudioFormat,
            ) -> Box<dyn super::super::AudioSession> {
                unreachable!()
            }
            fn on_volume_timed(&self, value: f32, _: MediaSession) {
                self.events.lock().unwrap().push(value);
                if value == -12.0 {
                    self.entered.send(()).unwrap();
                    self.release.lock().unwrap().recv().unwrap();
                }
            }
        }
        let media = Arc::new(MediaContext::default());
        let (entered, arrived) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let handler = Arc::new(Blocking {
            events: Mutex::default(),
            entered,
            release: Mutex::new(gate),
        });
        let worker = {
            let media = media.clone();
            let handler = handler.clone();
            std::thread::spawn(move || media.set_volume(-12.0, &*handler))
        };
        arrived
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let cached = media.set_volume(-9.0, &*handler) && media.set_volume(-144.0, &*handler);
        let before_release = handler.events.lock().unwrap().clone();
        let rejected_setup = media.begin_audio_setup().is_none();
        release.send(()).unwrap();
        assert!(worker.join().unwrap());
        assert!(cached && rejected_setup);
        assert_eq!(before_release, [-12.0]);
        assert_eq!(*handler.events.lock().unwrap(), [-12.0, -144.0]);
        assert_eq!(media.volume(), -144.0);
        let mut setup = media.begin_audio_setup().unwrap();
        setup.replay_volume(&*handler);
        assert_eq!(*handler.events.lock().unwrap(), [-12.0, -144.0, -144.0]);
    }
    #[test]
    fn volume_reentrant_set_is_drained_after_current_callback_without_locking_host() {
        struct Reentrant {
            media: Arc<MediaContext>,
            values: Mutex<Vec<f32>>,
        }
        impl super::super::AudioHandler for Reentrant {
            fn audio_init(
                &self,
                _: super::super::AudioFormat,
            ) -> Box<dyn super::super::AudioSession> {
                unreachable!()
            }
            fn on_volume_timed(&self, value: f32, _: MediaSession) {
                self.values.lock().unwrap().push(value);
                if value == -12.0 {
                    assert!(self.media.set_volume(-144.0, self));
                    assert!(self.media.begin_audio_setup().is_none());
                }
            }
        }
        let media = Arc::new(MediaContext::default());
        let handler = Reentrant {
            media: media.clone(),
            values: Mutex::default(),
        };
        assert!(media.set_volume(-12.0, &handler));
        assert_eq!(*handler.values.lock().unwrap(), [-12.0, -144.0]);
        assert_eq!(media.volume(), -144.0);
        assert!(media.begin_audio_setup().is_some());
    }
    #[tokio::test]
    async fn tracked_tasks_are_joined_and_drop_resources() {
        let tasks = Tasks::default();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tasks.track(tokio::spawn(async move {
            let _socket = socket;
            std::future::pending::<()>().await;
        }));
        tasks.stop().await;
        assert!(tokio::net::UdpSocket::bind(addr).await.is_ok());
    }
    #[cfg(feature = "video")]
    #[test]
    fn retiring_context_cannot_be_reused_before_ended_callback_completes() {
        use std::sync::mpsc;
        struct BlockingEnd {
            entered: mpsc::Sender<()>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl super::super::AudioHandler for BlockingEnd {
            fn audio_init(
                &self,
                _: super::super::AudioFormat,
            ) -> Box<dyn super::super::AudioSession> {
                unreachable!()
            }
            fn on_media_session_ended(&self, _: MediaSession) {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
            }
        }
        let mut registry = MediaRegistry::default();
        let context = registry.acquire([1; 32]).unwrap();
        let original = context.session();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        context.attach_handler(Arc::new(BlockingEnd {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }));
        let lease = context.video_lease().unwrap();
        let ending = std::thread::spawn(move || drop(lease));
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let reusable_during_callback = context.is_retired();
        let admitted_during_callback = registry.acquire([1; 32]);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let transport = runtime.spawn(std::future::pending::<()>());
        context.own_transport(transport.abort_handle());
        runtime.block_on(tokio::task::yield_now());
        let transport_aborted = transport.is_finished();
        release_tx.send(()).unwrap();
        ending.join().unwrap();
        assert!(!reusable_during_callback, "Ended must finish before reuse");
        assert!(
            admitted_during_callback.is_none(),
            "a retiring context must reject new media admission"
        );
        assert!(
            transport_aborted,
            "a retiring context must reject newly registered transports"
        );
        assert!(context.is_retired());
        assert!(registry.acquire([1; 32]).unwrap().session().id > original.id);
    }
}
