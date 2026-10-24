use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use futures_util::future::BoxFuture;

use crate::{
    buffer::{
        BufferAppendRequest, BufferAppendResult, BufferClaimRequest, BufferInspectRequest,
        BufferRenewRequest, BufferSealRequest, BufferSettleRequest, BufferSnapshot, ClaimedWork,
        LeasedSealedBatch, WriteBuffer,
    },
    configuration::{DurabilityClass, Namespace},
    error::BufferError,
    retention::RetentionState,
};
/// Bounded in-memory retention provider (`DurabilityClass::Volatile`).
#[derive(Clone)]
pub struct MemoryBuffer {
    namespace: Namespace,
    state: Arc<Mutex<RetentionState>>,
}

impl std::fmt::Debug for MemoryBuffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemoryBuffer")
    }
}

impl MemoryBuffer {
    #[must_use]
    pub fn new(namespace: Namespace) -> Self {
        Self {
            namespace,
            state: Arc::new(Mutex::new(RetentionState::default())),
        }
    }

    fn with_lock<R>(
        &self,
        f: impl FnOnce(&mut RetentionState) -> Result<R, BufferError>,
    ) -> Result<R, BufferError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| BufferError::StorageUnavailable {
                reason: "memory buffer mutex poisoned",
            })?;
        f(&mut guard)
    }
}

impl WriteBuffer for MemoryBuffer {
    fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    fn durability_class(&self) -> DurabilityClass {
        DurabilityClass::Volatile
    }

    fn append(
        &self,
        request: BufferAppendRequest,
    ) -> BoxFuture<'static, Result<BufferAppendResult, BufferError>> {
        let res = self.with_lock(|s| s.append_record(request, DurabilityClass::Volatile));
        Box::pin(async move { res })
    }

    fn claim(
        &self,
        request: BufferClaimRequest,
    ) -> BoxFuture<'static, Result<ClaimedWork, BufferError>> {
        let res = self.with_lock(|s| Ok(s.claim_work(request)));
        Box::pin(async move { res })
    }

    fn seal(
        &self,
        request: BufferSealRequest,
    ) -> BoxFuture<'static, Result<Option<LeasedSealedBatch>, BufferError>> {
        let res =
            self.with_lock(|s| s.seal_candidate(request, Some(Instant::now()), &self.namespace));
        Box::pin(async move { res })
    }

    fn renew(&self, request: BufferRenewRequest) -> BoxFuture<'static, Result<(), BufferError>> {
        let res = self.with_lock(|s| s.renew_lease(request));
        Box::pin(async move { res })
    }

    fn settle(&self, request: BufferSettleRequest) -> BoxFuture<'static, Result<(), BufferError>> {
        let res = self.with_lock(|s| s.settle_batch(request));
        Box::pin(async move { res })
    }

    fn inspect(
        &self,
        request: BufferInspectRequest,
    ) -> BoxFuture<'static, Result<BufferSnapshot, BufferError>> {
        let res = self.with_lock(|s| Ok(s.inspect_state(request, DurabilityClass::Volatile)));
        Box::pin(async move { res })
    }
}
