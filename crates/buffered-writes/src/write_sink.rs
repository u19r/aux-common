use futures_util::future::BoxFuture;

use crate::{Deadline, SinkError, SinkLimits, WriteAttempt, WriteOutcome};

/// Declared replay safety contract for a [`WriteSink`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayGuarantee {
    AtomicBatch,
    IndependentlyIdempotent,
    Unsupported,
}

/// Destination write contract. Implementations acknowledge committed effects
/// under their declared replay guarantee. Independently idempotent destinations
/// can report partial results; omitted operation outcomes remain unknown.
///
/// The engine can cancel a pending future at its deadline. The destination may
/// still have committed, so retries must recognize the same immutable
/// identities.
pub trait WriteSink<T>: Send + Sync + 'static {
    fn limits(&self) -> &SinkLimits;
    fn replay_guarantee(&self) -> ReplayGuarantee;
    fn flush_writes(
        &self,
        attempt: WriteAttempt<T>,
    ) -> BoxFuture<'static, Result<WriteOutcome, SinkError>>;

    /// Optional side-effect-free health check. Success permits real canary
    /// writes; it cannot restore buffered mode by itself. No probe is required.
    fn probe(&self, _deadline: Deadline) -> Option<BoxFuture<'static, Result<(), SinkError>>> {
        None
    }
}
