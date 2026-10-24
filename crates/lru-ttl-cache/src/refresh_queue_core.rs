use std::{
    borrow::Borrow,
    hash::Hash,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use tokio::sync::Notify;

use crate::{
    RefreshAdmission, RefreshBatch, RefreshQueueLimits, RefreshQueueStats, RefreshTicket,
    refresh_queue_state::QueueState,
};

pub(super) enum QueuePoll<K: Eq + Hash> {
    Ready(RefreshBatch<K>),
    Wait(Option<Instant>),
    Closed,
}

pub(super) struct RefreshQueueCore<K: Eq + Hash> {
    state: Mutex<QueueState<K>>,
    limits: RefreshQueueLimits,
    pub(super) changed: Notify,
}

impl<K: Eq + Hash> RefreshQueueCore<K> {
    pub(super) fn new(limits: RefreshQueueLimits) -> Self {
        Self {
            state: Mutex::new(QueueState::new()),
            limits,
            changed: Notify::new(),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, QueueState<K>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn stats(&self) -> RefreshQueueStats {
        self.lock_state().stats()
    }

    pub(super) fn cancel(&self, key: &K, generation: u64) -> bool {
        let cancelled = self.lock_state().cancel_key(key, generation);
        if cancelled {
            self.changed.notify_waiters();
        }
        cancelled
    }

    pub(super) fn promote_cold<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let promoted = self.lock_state().promote_cold(key);
        if promoted {
            self.changed.notify_waiters();
        }
        promoted
    }

    pub(super) fn close(&self) {
        self.lock_state().close();
        self.changed.notify_waiters();
    }

    pub(super) fn release_batch(&self, id: u64) {
        self.lock_state().release_batch(id);
        self.changed.notify_waiters();
    }
}

impl<K: Eq + Hash + Clone> RefreshQueueCore<K> {
    pub(super) fn try_schedule(&self, ticket: RefreshTicket<K>) -> RefreshAdmission {
        let now = Instant::now();
        let mut state = self.lock_state();
        state.expire_tickets(now);
        let outcome = state.admit_ticket(ticket, &self.limits, now);
        drop(state);
        self.changed.notify_waiters();
        outcome
    }

    pub(super) fn poll_batch(self: &Arc<Self>, collection: Duration) -> QueuePoll<K> {
        self.lock_state()
            .poll_batch(&self.limits, collection, Arc::clone(self))
    }
}
