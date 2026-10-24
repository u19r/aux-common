//! Public job values grouped by persistence record, handler, and observation
//! concerns.

mod constants;
mod definition;
mod effect_authority;
#[cfg(test)]
mod effect_authority_tests;
mod execution;
mod handler;
#[cfg(test)]
mod handler_tests;
mod observation;
mod polling;
pub use polling::poll_checkpoint_payload;
mod panic_boundary;
#[cfg(test)]
mod polling_tests;
mod record;
mod remote_claim;
#[cfg(test)]
mod remote_claim_tests;
mod spec;
#[cfg(test)]
mod spec_tests;
mod terminal_authority;
#[cfg(test)]
mod terminal_authority_tests;

#[cfg(test)]
pub(crate) use constants::PAYLOAD_DIGEST_BYTES;
pub use constants::{MAX_CHECKPOINT_BYTES, MAX_COST_UNITS, MAX_INLINE_PAYLOAD_BYTES};
pub(crate) use definition::JobDefinition;
pub use effect_authority::JobEffectAuthority;
pub(crate) use execution::InvocationCheckpoint;
pub use execution::JobExecution;
pub(crate) use handler::ExecutionContextInput;
pub use handler::{
    ClaimLeasePolicy, ClaimPublicationFuture, ExecutionContext, HandlerFuture, JobHandler,
    WakeFuture, WakeScheduler, WakeSchedulerError,
};
pub use observation::{
    LifecycleObservation, LifecyclePayload, LifecycleRecord, LifecycleRecordStatus, LifecycleRoutes,
};
pub(crate) use panic_boundary::{HandlerPanic, PanicSafeFuture};
pub use record::{
    AttemptHistory, CancellationToken, EnqueueDisposition, EnqueueResult, HandlerDefinition,
    JobOutcome, JobPolicySnapshot, JobRecordV1, JobState, Lease, NewJob, OperationReceipt,
    PayloadManifest, TerminalDisposition,
};
pub use remote_claim::RemoteJobClaim;
pub use spec::{EnqueueOptions, JobHandle, JobSeed, JobSpec};
pub use terminal_authority::JobTerminalAuthority;
