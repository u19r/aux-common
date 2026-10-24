use std::future::Future;

use bytes::Bytes;

use crate::store::{RangePage, RangeRequest, StoreCapabilities, StoreKey, StoreTransaction};

/// The minimum ordered key/value contract for a consumer-provided backend.
///
/// This library defines the contract but does not provide production
/// persistence. The optional `test-support` feature provides a fake reference
/// store for tests and conformance only; each library consumer must implement
/// this trait for its production backend and run the reusable
/// `bg-jobs-conformance` suite against that adapter before claiming a store
/// level.
///
/// Every returned future must be cancellation-safe and bounded by the
/// adapter's backend/runtime deadline. Engine operation and deadline budgets
/// cannot make progress while a backend future remains pending indefinitely.
pub trait JobStore: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Reports truthful backend limits and sharing semantics.
    ///
    /// The limits are hard bounds for the corresponding operations. `Local`
    /// is only a single-process guarantee; `Distributed` requires the same
    /// atomic conditional semantics across every process and node that can
    /// use the adapter. A consumer must not advertise a stronger level than
    /// its conformance evidence supports.
    fn capabilities(&self) -> StoreCapabilities;

    /// Reads one arbitrary byte key without mutating the store.
    ///
    /// A missing key is `Ok(None)` and a present value is `Ok(Some(value))`.
    /// The adapter must enforce its declared key/value limits and return its
    /// typed error for unavailable or invalid operations. Point-read freshness
    /// is an adapter property; callers revalidate mutable state in `commit`.
    fn get(
        &self,
        key: StoreKey,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_;

    /// Reads the supplied keys with one native batch/read-plan operation.
    ///
    /// The result must contain exactly one item for every input key, in the
    /// same order, including duplicate keys and missing values. The operation
    /// has no cross-key snapshot guarantee: each result may reflect an
    /// independent read. Backends may provide a stronger snapshot while
    /// retaining this ordered cardinality contract. Implementers must map
    /// this method to their backend's native batching/read-plan facility (for
    /// example, a consumer-owned `ReadSequence`); this trait intentionally has
    /// no serial compatibility implementation. An empty input must return an
    /// empty result without backend I/O. The adapter must reject requests over
    /// `max_get_many_keys` or `max_get_many_key_bytes`; the latter is the sum
    /// of input key bytes, while returned values are individually bounded by
    /// `max_value_bytes`.
    fn get_many<'a>(
        &'a self,
        keys: &'a [StoreKey],
    ) -> impl Future<Output = Result<Vec<Option<Bytes>>, Self::Error>> + Send + 'a;

    /// Reads one bounded, ordered range page.
    ///
    /// `start` is inclusive and `end` is exclusive. Results must follow the
    /// requested direction, obey both item and byte limits, and use an
    /// exclusive continuation cursor so unchanged keys are neither repeated
    /// nor skipped across pages. Discovery may be stale, but the adapter must
    /// enforce its declared range/key limits and return a typed error when it
    /// cannot satisfy the request.
    fn read_range(
        &self,
        request: RangeRequest,
    ) -> impl Future<Output = Result<RangePage, Self::Error>> + Send + '_;

    /// Atomically evaluates all checks and applies all mutations.
    ///
    /// Every check and mutation is one all-or-nothing operation. A failed
    /// check returns `CommitOutcome::Conflict` and applies no mutation;
    /// incompatible concurrent checked commits cannot both return committed.
    /// `CommitOutcome::Unknown` is reserved for an ambiguous acknowledgement
    /// where the adapter cannot say whether the atomic operation applied; it
    /// must never be used as a substitute for a known conflict or success.
    /// An adapter error means the operation is known not to have applied; a
    /// post-dispatch timeout or transport loss whose outcome cannot be proven
    /// must return `Ok(CommitOutcome::Unknown)` instead.
    ///
    /// [`StoreTransaction::operation_id`] identifies one logical commit across
    /// transport and caller retries. The first accepted use binds that ID to
    /// the exact checks and mutations. Reusing it with the same transaction
    /// must return the already established `Committed` or `Conflict` outcome
    /// without applying mutations again. Reusing it with different transaction
    /// content must return a typed adapter error and apply nothing. If the
    /// adapter still cannot establish the original outcome, it returns
    /// `Unknown`; callers must reconcile rather than invent a new ID and retry
    /// blindly.
    /// The adapter enforces transaction limits and preserves the complete
    /// check/mutation set for conformance and reconciliation.
    fn commit<'a>(
        &'a self,
        transaction: &'a StoreTransaction,
    ) -> impl Future<Output = Result<CommitOutcome, Self::Error>> + Send + 'a;
}

/// Result of an atomic commit. `Unknown` requires reconciliation with the
/// transaction's stable commit operation ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommitOutcome {
    Committed,
    Conflict,
    Unknown,
}
