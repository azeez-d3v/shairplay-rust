//! Shared media clock, authenticated-phone fencing, and owned child tasks.
use super::{MediaSession, ntp::SenderClock};
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU8, AtomicU64, Ordering},
};

const RETIRING: u8 = 2;
const RETIRED: u8 = 3;

pub(crate) struct MediaContext {
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
