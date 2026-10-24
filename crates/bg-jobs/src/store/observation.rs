use std::sync::Arc;

use bytes::Bytes;

use super::{
    CommitOutcome, JobStore, RangePage, RangeRequest, StoreCapabilities, StoreKey, StoreTransaction,
};
use crate::observer::{JobEvent, JobObserver, StoreOperation};

/// Instruments the engine-owned store boundary without changing backend
/// semantics.
pub(crate) struct ObservedStore<S> {
    pub(crate) inner: S,
    pub(crate) observer: Arc<dyn JobObserver>,
}

impl<S> ObservedStore<S> {
    fn observe_call(&self, operation: StoreOperation) {
        self.observer
            .observe(JobEvent::StoreOperation { operation });
    }
}

impl<S: JobStore> JobStore for ObservedStore<S> {
    type Error = S::Error;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.observe_call(StoreOperation::Get);
        self.inner.get(key).await
    }

    async fn get_many<'a>(
        &'a self,
        keys: &'a [StoreKey],
    ) -> Result<Vec<Option<Bytes>>, Self::Error> {
        if !keys.is_empty() {
            self.observe_call(StoreOperation::GetMany);
        }
        self.inner.get_many(keys).await
    }

    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.observe_call(StoreOperation::ReadRange);
        self.inner.read_range(request).await
    }

    async fn commit<'a>(
        &'a self,
        transaction: &'a StoreTransaction,
    ) -> Result<CommitOutcome, Self::Error> {
        self.observe_call(StoreOperation::Commit);
        self.inner.commit(transaction).await
    }
}
