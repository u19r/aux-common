use std::{
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
};

use wasmtime::Engine;

use crate::{JsError, constants::TICK_INTERVAL};

pub(super) struct EpochTicker {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}
impl EpochTicker {
    pub(super) fn try_new(engine: Engine) -> Result<Self, JsError> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let signal = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("javascript-epoch".into())
            .spawn(move || tick_epochs(engine, signal))
            .map_err(|_| JsError::Unavailable)?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
fn tick_epochs(engine: Engine, stop: Arc<(Mutex<bool>, Condvar)>) {
    let (lock, wake) = &*stop;
    let Ok(mut stopped) = lock.lock() else {
        return;
    };
    while !*stopped {
        let Ok((next, _)) = wake.wait_timeout(stopped, TICK_INTERVAL) else {
            return;
        };
        stopped = next;
        if !*stopped {
            engine.increment_epoch();
        }
    }
}
impl Drop for EpochTicker {
    fn drop(&mut self) {
        let (lock, wake) = &*self.stop;
        if let Ok(mut stopped) = lock.lock() {
            *stopped = true;
            wake.notify_one();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
