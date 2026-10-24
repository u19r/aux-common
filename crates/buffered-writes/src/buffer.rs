use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;

use crate::{
    batch::{AdmissionFingerprint, AdmittedRecord, SealedBatch},
    configuration::{
        BatchId, BufferCapacity, BufferStats, Deadline, DurabilityClass, FencingToken, Namespace,
        OperationId,
    },
    error::BufferError,
};

/// Request to append one admitted record to a [`WriteBuffer`].
#[derive(Clone, Debug)]
pub struct BufferAppendRequest {
    pub record: AdmittedRecord,
    /// Retained-byte reservation for this record's sealing and quarantine.
    /// Providers charge at least the canonical open and quarantine forms.
    pub reserved_bytes: usize,
    pub capacity: BufferCapacity,
    pub deadline: Deadline,
}

/// Successful append result from a [`WriteBuffer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferAppendResult {
    pub durability: DurabilityClass,
    pub duplicate: bool,
    pub watermark: u64,
}

/// Request to claim either a retryable sealed batch or an open candidate group.
#[derive(Clone, Copy, Debug)]
pub struct BufferClaimRequest {
    pub max_watermark: Option<u64>,
    pub allow_open_claim: bool,
    pub force_all_ages: bool,
    pub max_items: usize,
    pub max_bytes: usize,
    pub lease_duration: Duration,
    pub now_utc_ms: i64,
    pub now_instant: Instant,
    pub deadline: Deadline,
}

/// Claimed open candidate group ready for [`crate::WriteBatch::prepare`].
#[derive(Clone, Debug)]
pub struct OpenBatchCandidate {
    pub records: Vec<AdmittedRecord>,
    /// Per-record retained-byte reservations in the same order as `records`.
    pub reserved_bytes: Vec<usize>,
    pub fencing_token: FencingToken,
}

/// Claimed sealed batch with its current pending operation IDs and fencing
/// token.
#[derive(Clone, Debug)]
pub struct LeasedSealedBatch {
    pub batch: SealedBatch,
    pub pending_operation_ids: Vec<OperationId>,
    pub fencing_token: FencingToken,
    pub unsettled_record_count: usize,
}

/// Result of [`WriteBuffer::claim`].
#[derive(Clone, Debug)]
pub enum ClaimedWork {
    None,
    OpenCandidate(OpenBatchCandidate),
    ExistingSealed(LeasedSealedBatch),
}

/// Action performed by [`WriteBuffer::seal`].
#[derive(Clone, Debug)]
pub enum BufferSealAction {
    InstallBatch(SealedBatch),
    ReleaseCandidate,
    QuarantineSingleton {
        operation_id: OperationId,
        reason: &'static str,
    },
}

/// Request to atomically seal or release a claimed open candidate.
#[derive(Clone, Debug)]
pub struct BufferSealRequest {
    pub fencing_token: FencingToken,
    pub action: BufferSealAction,
    pub capacity: BufferCapacity,
    pub lease_duration: Duration,
    pub now_utc_ms: i64,
    pub deadline: Deadline,
}

/// Request to renew an active sealed-batch claim lease.
#[derive(Clone, Copy, Debug)]
pub struct BufferRenewRequest {
    pub batch_id: BatchId,
    pub fencing_token: FencingToken,
    pub lease_duration: Duration,
    pub now_utc_ms: i64,
    pub deadline: Deadline,
}

/// Settlement disposition for a leased sealed batch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SettleDisposition {
    Delivered,
    HandedOffToQueue,
    /// Checkpoints progress while retaining the current lease. The owner must
    /// release it explicitly when ending a turn; retry time applies after
    /// expiry.
    PartialProgress {
        completed_ids: Vec<OperationId>,
        retry_delay: Duration,
    },
    /// Relative delay starts at the provider's settlement time, never a client
    /// wall-clock deadline. Provider time also owns persisted rollback facts.
    ReleaseForRetry {
        retry_delay: Duration,
    },
    Quarantine {
        reason: crate::observer::QuarantineReason,
        completed_ids: Vec<OperationId>,
    },
}

/// Request to settle a leased sealed batch under its fencing token.
#[derive(Clone, Debug)]
pub struct BufferSettleRequest {
    pub batch_id: BatchId,
    pub fencing_token: FencingToken,
    pub disposition: SettleDisposition,
    pub now_utc_ms: i64,
    pub deadline: Deadline,
}

/// Request to inspect buffer statistics and ownership state without loading
/// payloads.
#[derive(Clone, Debug)]
pub struct BufferInspectRequest {
    pub operation_id: Option<OperationId>,
    pub now_utc_ms: i64,
    pub now_instant: Instant,
    pub deadline: Deadline,
}

/// Acknowledged identity and delivery status for one inspected operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdmissionReceipt {
    pub status: crate::configuration::AdmissionStatus,
    pub fingerprint: AdmissionFingerprint,
}

/// Snapshot of buffer metrics and unresolved ownership state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BufferSnapshot {
    /// Charged completed-receipt bytes that admission may reclaim atomically.
    pub reclaimable_bytes: usize,
    pub admission: Option<AdmissionReceipt>,
    pub stats: BufferStats,
    pub claimable_open_items: usize,
    pub claimable_sealed_batches: usize,
    pub in_flight_batches: usize,
    pub unsettled_items: usize,
    pub quarantined_items: usize,
    pub unresolved_batch_ids: Vec<BatchId>,
    pub watermark: u64,
    pub durability: DurabilityClass,
}

/// Retention provider contract owning persistence, discovery, admission
/// deduplication, and fencing.
/// Seal, renew, and settlement require an unexpired active lease, including
/// when no other claimant has replaced its fence. Releasing a lease ends its
/// authority. Persist each submitted record's `admission_fingerprint()` with
/// its receipt. An operation-specific inspection returns both that fingerprint
/// and its current status; a matching ID alone cannot reconcile an ambiguous
/// append.
pub trait WriteBuffer: Send + Sync + 'static {
    /// Immutable ownership domain, checked before a writer can use this
    /// provider.
    fn namespace(&self) -> &Namespace;

    fn durability_class(&self) -> DurabilityClass;

    fn append(
        &self,
        request: BufferAppendRequest,
    ) -> BoxFuture<'static, Result<BufferAppendResult, BufferError>>;

    fn claim(
        &self,
        request: BufferClaimRequest,
    ) -> BoxFuture<'static, Result<ClaimedWork, BufferError>>;

    fn seal(
        &self,
        request: BufferSealRequest,
    ) -> BoxFuture<'static, Result<Option<LeasedSealedBatch>, BufferError>>;

    fn renew(&self, request: BufferRenewRequest) -> BoxFuture<'static, Result<(), BufferError>>;

    fn settle(&self, request: BufferSettleRequest) -> BoxFuture<'static, Result<(), BufferError>>;

    fn inspect(
        &self,
        request: BufferInspectRequest,
    ) -> BoxFuture<'static, Result<BufferSnapshot, BufferError>>;
}
