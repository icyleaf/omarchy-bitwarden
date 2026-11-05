//! One-shot pause points for deterministic publication interleavings.
use std::sync::{mpsc, Mutex};
use std::time::Duration;

#[derive(Default)]
pub(crate) struct PausePoint(Mutex<Option<Box<dyn FnOnce() + Send>>>);

impl PausePoint {
    pub(crate) fn arm(&self) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let mut hook = self.0.lock().unwrap();
        assert!(hook.is_none(), "pause point already armed");
        *hook = Some(Box::new(move || {
            entered_tx.send(()).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(30))
                .expect("publication pause was not released");
        }));
        (entered_rx, release_tx)
    }

    pub(crate) fn reach(&self) {
        let hook = self.0.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
}
