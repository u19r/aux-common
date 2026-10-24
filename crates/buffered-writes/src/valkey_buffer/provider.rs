use std::time::Instant;

use futures_util::future::BoxFuture;

use super::connection::ValkeyBuffer;
use crate::{
    BufferAppendRequest, BufferAppendResult, BufferClaimRequest, BufferError, BufferInspectRequest,
    BufferRenewRequest, BufferSealRequest, BufferSettleRequest, BufferSnapshot, ClaimedWork,
    DurabilityClass, LeasedSealedBatch, WriteBuffer,
};

impl WriteBuffer for ValkeyBuffer {
    fn namespace(&self) -> &crate::Namespace {
        &self.namespace
    }

    fn durability_class(&self) -> DurabilityClass {
        DurabilityClass::RemoteValkey
    }

    fn append(
        &self,
        request: BufferAppendRequest,
    ) -> BoxFuture<'static, Result<BufferAppendResult, BufferError>> {
        let provider = self.clone();
        Box::pin(async move {
            let identity = request.record.operation_id.clone();
            let result = provider
                .mutate(request.deadline, |state, now| {
                    let mut request = request.clone();
                    request.record.admitted_at_utc_ms = now;
                    state.append_record(request, DurabilityClass::RemoteValkey)
                })
                .await;
            match result {
                Err(BufferError::StorageUnavailable { .. } | BufferError::DeadlineExceeded) => {
                    Err(BufferError::AmbiguousAdmission {
                        operation_id: identity,
                    })
                }
                result => result,
            }
        })
    }

    fn claim(
        &self,
        request: BufferClaimRequest,
    ) -> BoxFuture<'static, Result<ClaimedWork, BufferError>> {
        let provider = self.clone();
        Box::pin(async move {
            provider
                .mutate(request.deadline, |state, now| {
                    Ok(state.claim_work(BufferClaimRequest {
                        now_utc_ms: now,
                        now_instant: Instant::now(),
                        ..request
                    }))
                })
                .await
        })
    }

    fn seal(
        &self,
        request: BufferSealRequest,
    ) -> BoxFuture<'static, Result<Option<LeasedSealedBatch>, BufferError>> {
        let provider = self.clone();
        Box::pin(async move {
            provider
                .mutate(request.deadline, |state, now| {
                    state.seal_candidate(
                        BufferSealRequest {
                            now_utc_ms: now,
                            ..request.clone()
                        },
                        None,
                        &provider.namespace,
                    )
                })
                .await
        })
    }

    fn renew(&self, request: BufferRenewRequest) -> BoxFuture<'static, Result<(), BufferError>> {
        let provider = self.clone();
        Box::pin(async move {
            provider
                .mutate(request.deadline, |state, now| {
                    state.renew_lease(BufferRenewRequest {
                        now_utc_ms: now,
                        ..request
                    })
                })
                .await
        })
    }

    fn settle(&self, request: BufferSettleRequest) -> BoxFuture<'static, Result<(), BufferError>> {
        let provider = self.clone();
        Box::pin(async move {
            provider
                .mutate(request.deadline, |state, now| {
                    state.settle_batch(BufferSettleRequest {
                        now_utc_ms: now,
                        ..request.clone()
                    })
                })
                .await
        })
    }

    fn inspect(
        &self,
        request: BufferInspectRequest,
    ) -> BoxFuture<'static, Result<BufferSnapshot, BufferError>> {
        let provider = self.clone();
        Box::pin(async move {
            tokio::time::timeout(
                request.deadline.remaining_at(Instant::now()),
                provider.fetch_snapshot(request),
            )
            .await
            .map_err(|_| BufferError::DeadlineExceeded)?
        })
    }
}
