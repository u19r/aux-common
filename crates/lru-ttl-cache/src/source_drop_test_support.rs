use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::Notify;

pub(super) struct SourceDropGate {
    pub(super) dropping: Arc<Notify>,
    pub(super) release: Arc<(StdMutex<bool>, std::sync::Condvar)>,
}

pub(super) struct SourceDropRelease(pub(super) Arc<(StdMutex<bool>, std::sync::Condvar)>);

impl Drop for SourceDropRelease {
    fn drop(&mut self) {
        let (mutex, condition) = self.0.as_ref();
        *mutex.lock().expect("release gate") = true;
        condition.notify_all();
    }
}

impl Drop for SourceDropGate {
    fn drop(&mut self) {
        self.dropping.notify_one();
        let (mutex, condition) = self.release.as_ref();
        let mut released = mutex.lock().expect("drop gate");
        while !*released {
            released = condition.wait(released).expect("drop gate release");
        }
    }
}
