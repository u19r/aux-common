use std::sync::{Arc, Mutex, Weak};

use futures_util::task::AtomicWaker;

#[derive(Default)]
pub(super) struct WakeSet(Mutex<Vec<Weak<AtomicWaker>>>);

impl WakeSet {
    pub(super) fn subscribe(&self) -> Arc<AtomicWaker> {
        let waiter = Arc::new(AtomicWaker::new());
        let mut waiters = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        waiters.retain(|waiter| waiter.strong_count() > 0);
        waiters.push(Arc::downgrade(&waiter));
        waiter
    }

    pub(super) fn wake_all(&self) {
        let waiters = {
            let mut waiters = self
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            waiters.retain(|waiter| waiter.strong_count() > 0);
            waiters.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}
