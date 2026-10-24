use std::{hash::Hash, sync::Arc, time::Instant};

use crate::{RefreshTicket, load_lease::LoadLease, refresh_queue_core::RefreshQueueCore};

pub struct RefreshJob<K> {
    pub(super) ticket: RefreshTicket<K>,
    pub(super) lease: LoadLease,
}

impl<K> RefreshJob<K> {
    pub fn ticket(&self) -> &RefreshTicket<K> {
        &self.ticket
    }

    /// Advisory eligibility; the publication owner still checks generation and
    /// authority atomically when applying the result.
    pub fn is_current(&self) -> bool {
        !self.lease.is_cancelled() && Instant::now() < self.ticket.work.deadline
    }
}

/// Keep this lease alive until all provider futures have been destroyed, even
/// after cancellation. Results may be published per key before batch
/// completion; their key/byte reservations conservatively remain until this
/// guard drops.
pub struct RefreshBatch<K: Eq + Hash> {
    pub(super) core: Arc<RefreshQueueCore<K>>,
    pub(super) id: u64,
    pub(super) jobs: Vec<RefreshJob<K>>,
    pub(super) cancellation: LoadLease,
    pub(super) deadline: Instant,
}

impl<K: Eq + Hash> RefreshBatch<K> {
    pub fn jobs(&self) -> &[RefreshJob<K>] {
        &self.jobs
    }

    /// Ends when all jobs are cancelled, the queue closes, or the earliest
    /// admitted deadline expires. Callers select this alongside provider work.
    pub async fn cancelled(&self) {
        tokio::select! {
            _ = self.cancellation.cancelled() => {},
            _ = tokio::time::sleep_until(self.deadline.into()) => {},
        }
    }
}

impl<K: Eq + Hash> Drop for RefreshBatch<K> {
    fn drop(&mut self) {
        // Retain admission while the batch's owned key/payload copies drop too.
        drop(std::mem::take(&mut self.jobs));
        self.core.release_batch(self.id);
    }
}
