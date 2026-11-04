//! Native acknowledgement loss after durable admission, with no producer retry.

use std::{
    future::{Future, pending},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bg_jobs::store::{
    CommitOutcome, JobStore, RangePage, RangeRequest, StoreCapabilities, StoreKey, StoreTransaction,
};
use bytes::Bytes;

#[derive(Clone)]
pub(crate) struct RecoveryStore<S> {
    inner: S,
    armed: Arc<AtomicBool>,
    pub(crate) accepted: Arc<AtomicBool>,
}

impl<S> RecoveryStore<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            armed: Arc::new(AtomicBool::new(false)),
            accepted: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn arm(&self) {
        self.accepted.store(false, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }
}

impl<S: JobStore> JobStore for RecoveryStore<S> {
    type Error = S::Error;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    fn get(
        &self,
        key: StoreKey,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_ {
        self.inner.get(key)
    }

    fn get_many<'a>(
        &'a self,
        keys: &'a [StoreKey],
    ) -> impl Future<Output = Result<Vec<Option<Bytes>>, Self::Error>> + Send + 'a {
        self.inner.get_many(keys)
    }

    fn read_range(
        &self,
        request: RangeRequest,
    ) -> impl Future<Output = Result<RangePage, Self::Error>> + Send + '_ {
        self.inner.read_range(request)
    }

    async fn transact(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        let outcome = self.inner.transact(transaction).await?;
        if outcome == CommitOutcome::Committed && self.armed.swap(false, Ordering::AcqRel) {
            self.accepted.store(true, Ordering::Release);
            return pending().await;
        }
        Ok(outcome)
    }
}
