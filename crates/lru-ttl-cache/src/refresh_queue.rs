use std::{borrow::Borrow, hash::Hash, sync::Arc, time::Duration};

use crate::{
    RefreshAdmission, RefreshBatch, RefreshQueueLimits, RefreshTicket,
    refresh_queue_core::{QueuePoll, RefreshQueueCore},
};

/// Bounded scheduling with caller-owned execution. No task or provider call is
/// created by submission. Use a bounded result/cohort owner for subscribers.
/// All cold jobs are selected before background jobs; background work cannot
/// spend the reserved cold key/byte capacity or the final active batch slot.
pub struct RefreshQueue<K: Eq + Hash> {
    core: Arc<RefreshQueueCore<K>>,
}

impl<K: Eq + Hash> Clone for RefreshQueue<K> {
    fn clone(&self) -> Self {
        Self {
            core: Arc::clone(&self.core),
        }
    }
}

impl<K: Eq + Hash> RefreshQueue<K> {
    pub fn new(limits: RefreshQueueLimits) -> Self {
        Self {
            core: Arc::new(RefreshQueueCore::new(limits)),
        }
    }

    pub fn stats(&self) -> RefreshQueueStats {
        self.core.stats()
    }

    /// Cancel pending work immediately. Active work keeps its budget until the
    /// executor drops the batch after destroying its provider futures.
    pub fn cancel(&self, key: &K, generation: u64) -> bool {
        self.core.cancel(key, generation)
    }

    /// Promote already queued background work without creating another ticket.
    /// Active physical reads already serve both demand classes.
    pub fn promote_cold<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.core.promote_cold(key)
    }

    pub fn close(&self) {
        self.core.close();
    }
}

impl<K: Eq + Hash + Clone> RefreshQueue<K> {
    /// Queued joins merge the earliest deadline and largest byte declaration.
    /// Active jobs are immutable: earlier deadlines or larger charges return
    /// Full.
    pub fn try_schedule(&self, ticket: RefreshTicket<K>) -> RefreshAdmission {
        self.core.try_schedule(ticket)
    }

    /// Background collection is caller-configured. Arrival of cold demand wakes
    /// collection immediately. Run only the caller's fixed worker population.
    pub async fn next_batch(&self, collection: Duration) -> Option<RefreshBatch<K>> {
        loop {
            let changed = self.core.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.core.poll_batch(collection) {
                QueuePoll::Ready(batch) => return Some(batch),
                QueuePoll::Closed => return None,
                QueuePoll::Wait(Some(deadline)) => tokio::select! {
                    _ = &mut changed => {},
                    _ = tokio::time::sleep_until(deadline.into()) => {},
                },
                QueuePoll::Wait(None) => changed.await,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefreshQueueStats {
    pub queued_keys: usize,
    pub active_keys: usize,
    pub charged_bytes: usize,
    pub background_keys: usize,
    pub active_batches: usize,
    pub closed: bool,
}
