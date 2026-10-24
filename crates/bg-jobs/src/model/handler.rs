use std::{
    future::Future,
    num::{NonZeroU32, NonZeroU64},
    pin::Pin,
    time::Duration,
};

use super::JobExecution;
use crate::{
    ids::{AttemptId, ExecutionId, JobId, LeaseToken, Namespace, OperationId, OwnerId, QueueName},
    model::{CancellationToken, JobOutcome},
    time::{MonotonicDeadline, Timestamp},
};

/// Safe immutable execution view passed to a handler.
#[derive(Clone)]
pub struct ExecutionContext<'a> {
    job_id: JobId,
    namespace: &'a Namespace,
    execution_id: ExecutionId,
    attempt_id: AttemptId,
    attempt: NonZeroU32,
    generation: u32,
    fence: NonZeroU64,
    token: &'a LeaseToken,
    owner: OwnerId,
    queue: &'a QueueName,
    wall_now: Timestamp,
    deadline: MonotonicDeadline,
    cancelled: bool,
    cancellation: CancellationToken,
    operation_id: OperationId,
    checkpoint: Option<&'a [u8]>,
    pub(super) poll_work_found: &'a std::sync::atomic::AtomicBool,
    payload: &'a [u8],
}

/// Crate-owned inputs for constructing an immutable execution context.
#[derive(Clone)]
pub(crate) struct ExecutionContextInput<'a> {
    pub(crate) job_id: JobId,
    pub(crate) namespace: &'a Namespace,
    pub(crate) execution_id: ExecutionId,
    pub(crate) attempt_id: AttemptId,
    pub(crate) attempt: NonZeroU32,
    pub(crate) generation: u32,
    pub(crate) fence: NonZeroU64,
    pub(crate) token: &'a LeaseToken,
    pub(crate) owner: OwnerId,
    pub(crate) queue: &'a QueueName,
    pub(crate) wall_now: Timestamp,
    pub(crate) deadline: MonotonicDeadline,
    pub(crate) cancelled: bool,
    pub(crate) operation_id: OperationId,
    pub(crate) checkpoint: Option<&'a [u8]>,
    pub(crate) poll_work_found: &'a std::sync::atomic::AtomicBool,
    pub(crate) payload: &'a [u8],
}

impl<'a> ExecutionContext<'a> {
    pub(crate) fn with_cancellation(
        input: ExecutionContextInput<'a>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            job_id: input.job_id,
            namespace: input.namespace,
            execution_id: input.execution_id,
            attempt_id: input.attempt_id,
            attempt: input.attempt,
            generation: input.generation,
            fence: input.fence,
            token: input.token,
            owner: input.owner,
            queue: input.queue,
            wall_now: input.wall_now,
            deadline: input.deadline,
            cancelled: input.cancelled,
            cancellation,
            operation_id: input.operation_id,
            checkpoint: input.checkpoint,
            poll_work_found: input.poll_work_found,
            payload: input.payload,
        }
    }

    /// Durable job identity whose lease supplies this context's authority.
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Validated scheduler namespace that scopes this job identity and its
    /// fence.
    pub const fn namespace(&self) -> &Namespace {
        self.namespace
    }

    /// Stable logical execution identity across retry and lease reclaim.
    ///
    /// An explicit redrive policy may rotate this identity. External effect
    /// adapters should combine it with [`Self::fence`] for idempotency and
    /// destination-side stale-writer rejection.
    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    pub const fn attempt(&self) -> NonZeroU32 {
        self.attempt
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Monotonic authority epoch within [`Self::namespace`] and
    /// [`Self::job_id`].
    ///
    /// The job store validates this fence for local lifecycle transitions. A
    /// destination that commits external effects must independently enforce
    /// the fence atomically with its effect and receipt; checking it before or
    /// after the destination transaction is not sufficient.
    pub const fn fence(&self) -> NonZeroU64 {
        self.fence
    }

    pub const fn token(&self) -> &LeaseToken {
        self.token
    }

    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    /// Issues authority that storage must validate atomically with the
    /// destination effect; this alone is not a commit acknowledgement.
    pub fn effect_authority(
        &self,
    ) -> Result<super::JobEffectAuthority, crate::store::StoreDataError> {
        super::JobEffectAuthority::try_from(self)
    }

    pub const fn queue(&self) -> &QueueName {
        self.queue
    }

    /// Immutable wall-clock snapshot supplied to the drive that claimed this
    /// attempt.
    ///
    /// A handler can use this as `not_before` for an immediate
    /// [`JobOutcome::Continue`]. The value does not advance during handler
    /// execution.
    pub const fn wall_now(&self) -> Timestamp {
        self.wall_now
    }

    pub const fn deadline(&self) -> MonotonicDeadline {
        self.deadline
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled || self.cancellation.is_cancelled()
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Identity of the current local lifecycle operation.
    ///
    /// This value can change across claims and transitions. It is useful for
    /// correlating local reconciliation, but is not the stable idempotency key
    /// for an external effect; use [`Self::execution_id`] for that role.
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Bounded continuation state persisted by the preceding
    /// [`JobOutcome::Continue`].
    ///
    /// The first invocation receives `None`. A resumed invocation receives
    /// the exact checkpoint bytes committed by the previous continuation.
    pub const fn checkpoint(&self) -> Option<&[u8]> {
        self.checkpoint
    }

    /// Immutable payload loaded with this accepted claim. Checkpointing does
    /// not replace it; destinations can bind work to the registered task.
    pub const fn payload(&self) -> &[u8] {
        self.payload
    }
}

impl std::fmt::Debug for ExecutionContext<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionContext")
            .field("job_id", &self.job_id)
            .field("execution_id", &self.execution_id)
            .field("fence", &self.fence)
            .finish_non_exhaustive()
    }
}

/// Type-erased handler future used by the runtime-neutral core boundary.
pub type HandlerFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<JobOutcome, Box<dyn std::error::Error + Send + Sync>>>
            + Send
            + 'a,
    >,
>;

/// Durable remote claim publication acknowledgement. Core owns the timeout
/// and never spawns the returned caller-owned future.
pub type ClaimPublicationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + 'a>>;

/// A caller-owned wakeable future used for handler deadlines and shutdown
/// grace periods. The future must arrange to wake the caller's task when the
/// requested delay elapses; the core never creates a timer or spawns a task.
/// It is `Send` so the enclosing drive future can run on a multi-thread
/// executor.
pub type WakeFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Infrastructure failures reported by a caller-owned wake scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeSchedulerError {
    /// The caller cannot provide a wake source for the requested delay.
    Unavailable,
}

impl std::fmt::Display for WakeSchedulerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("wake scheduler unavailable"),
        }
    }
}

impl std::error::Error for WakeSchedulerError {}

/// Caller-owned scheduling boundary for runtime-neutral, `Send` drive futures.
pub trait WakeScheduler: Send + Sync + 'static {
    /// Returns a future that wakes its caller after `delay`, or a typed
    /// infrastructure error when no wake source can be installed.
    fn sleep(&self, delay: Duration) -> Result<WakeFuture, WakeSchedulerError>;
}

/// Selects the authority lifetime for claims made by a bounded drive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClaimLeasePolicy {
    /// Preserve the registered lifetime, including remote claim publication.
    #[default]
    RegisteredTimeout,
    /// End new claims with the drive. Every effect must use native conditional
    /// fencing; a remote descriptor alone cannot authorize this shorter lease.
    DriveBoundedNative,
}

/// Runtime-neutral handler contract. The core does not spawn the returned
/// future; the caller-polled `drive` future polls it.
pub trait JobHandler: Send + Sync + 'static {
    /// Native fenced handlers may opt into bounded recovery without changing
    /// their saved seed policy. Existing and remote handlers retain their
    /// lease.
    fn claim_lease_policy(&self) -> ClaimLeasePolicy {
        ClaimLeasePolicy::RegisteredTimeout
    }

    /// Optionally register whole-job authority at a remote destination.
    ///
    /// Publication runs after the source claim commits and before `claim` or
    /// `drive` exposes that claim to execution. Return success only after a
    /// durable destination acknowledgement. An error, panic, timeout, or
    /// dropped future leaves the source lease for ordinary expiry/reclaim;
    /// it never rolls back a potentially acknowledged remote publication.
    /// Registration must accept exact replay and reject older claims.
    fn publish_claim<'a>(
        &'a self,
        _context: &ExecutionContext<'_>,
    ) -> Option<ClaimPublicationFuture<'a>> {
        None
    }

    fn execute<'a>(&'a self, context: ExecutionContext<'a>, payload: &'a [u8])
    -> HandlerFuture<'a>;

    /// The scheduler's drive supplies checkpoint access for the same claim.
    /// Existing handlers retain their context-only execution. A handler that
    /// needs durable acknowledgement before an external effect overrides this
    /// method and must reject context-only invocation in `execute`.
    fn execute_checkpointed<'a>(
        &'a self,
        execution: JobExecution<'a>,
        payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        match execution.into_context() {
            Ok(context) => self.execute(context, payload),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}
