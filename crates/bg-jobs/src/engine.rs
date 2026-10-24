use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;

use crate::{
    budget::{CompletionDetails, DriveReport, DriveRequest},
    catalog::JobCatalog,
    error::{JobResult, JobSystemError},
    ids::{AttemptId, JobId, Namespace, OperationId, OwnerId},
    model::{
        CancellationToken, EnqueueOptions, JobHandle, JobOutcome, JobSeed, LifecycleObservation,
        NewJob, WakeFuture, WakeScheduler,
    },
    observer::{JobEvent, JobObserver, NoopObserver, SafeJobErrorEvent},
    registry::HandlerRegistry,
    store::{JobStore, StoreKey},
    time::Timestamp,
};

/// The runtime-neutral durable job engine over a caller-owned `JobStore`.
pub struct JobSystem<S: JobStore> {
    store: crate::store::ObservedStore<S>,
    registry: HandlerRegistry,
    seeds: Vec<NewJob>,
    namespace: Namespace,
    owner: OwnerId,
    observer: Arc<dyn JobObserver>,
    scheduler: Arc<dyn WakeScheduler>,
    shutdown: Arc<AtomicBool>,
    active_attempts: Arc<Mutex<BTreeMap<AttemptAuthority, CancellationToken>>>,
}

/// Durable and local identity for one in-flight handler attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub(crate) struct AttemptAuthority {
    job_id: JobId,
    operation_id: OperationId,
    fence_high_water: u64,
    attempt_id: AttemptId,
}

impl AttemptAuthority {
    pub(crate) const fn new(
        job_id: JobId,
        operation_id: OperationId,
        fence_high_water: u64,
        attempt_id: AttemptId,
    ) -> Self {
        Self {
            job_id,
            operation_id,
            fence_high_water,
            attempt_id,
        }
    }
}

/// RAII registration for one in-flight attempt.
pub(crate) struct AttemptRegistration<'a, S: JobStore> {
    system: &'a JobSystem<S>,
    authority: AttemptAuthority,
}

impl<S: JobStore> Drop for AttemptRegistration<'_, S> {
    fn drop(&mut self) {
        self.system.unregister_attempt(self.authority);
    }
}

impl<S: JobStore> JobSystem<S> {
    /// Creates a job system with caller-owned wake scheduling. The scheduler
    /// supplies deadline and shutdown-grace wakeups; this crate never starts
    /// timer threads or selects an async runtime.
    pub(crate) fn new(
        store: S,
        catalog: JobCatalog,
        namespace: Namespace,
        owner: OwnerId,
        scheduler: Arc<dyn WakeScheduler>,
    ) -> Self {
        let (registry, seeds) = catalog.into_parts();
        Self {
            store: crate::store::ObservedStore {
                inner: store,
                observer: Arc::new(NoopObserver),
            },
            registry,
            seeds,
            namespace,
            owner,
            observer: Arc::new(NoopObserver),
            scheduler,
            shutdown: Arc::new(AtomicBool::new(false)),
            active_attempts: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Installs a safe, non-blocking observer for subsequent lifecycle events.
    pub(crate) fn with_observer(mut self, observer: Arc<dyn JobObserver>) -> Self {
        self.store.observer = Arc::clone(&observer);
        self.observer = observer;
        self
    }

    /// Requests that future drives stop claiming work while active attempts
    /// finish cooperatively.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.signal_active_attempts();
    }

    /// Clears a prior shutdown request.
    pub fn clear_shutdown(&self) {
        self.shutdown.store(false, Ordering::Release);
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    pub(crate) fn register_attempt_guard(
        &self,
        authority: AttemptAuthority,
        cancellation: CancellationToken,
    ) -> AttemptRegistration<'_, S> {
        if let Ok(mut active) = self.active_attempts.lock() {
            active.insert(authority, cancellation);
        }
        AttemptRegistration {
            system: self,
            authority,
        }
    }

    pub(crate) async fn register_execution(
        &self,
        claim: &crate::lifecycle::ClaimedJob,
    ) -> JobResult<AttemptRegistration<'_, S>, S::Error> {
        let authority = AttemptAuthority::new(
            claim.record().job_id,
            claim.operation_id(),
            claim.fence_high_water(),
            claim.attempt_id(),
        );
        let attempt = self.register_attempt_guard(authority, claim.cancellation());
        self.refresh_attempt_cancellation(authority).await?;
        if self.is_shutdown() {
            self.signal_active_attempts();
        }
        Ok(attempt)
    }

    pub(crate) fn unregister_attempt(&self, authority: AttemptAuthority) {
        if let Ok(mut active) = self.active_attempts.lock() {
            active.remove(&authority);
        }
    }

    pub(crate) fn signal_active_attempts(&self) {
        let cancellations = self
            .active_attempts
            .lock()
            .ok()
            .map(|active| active.values().cloned().collect::<Vec<_>>());
        if let Some(cancellations) = cancellations {
            for cancellation in cancellations {
                cancellation.cancel();
            }
        }
    }

    pub(crate) fn signal_matching_attempt(
        &self,
        job_id: JobId,
        fence_high_water: u64,
        fallback: Option<&CancellationToken>,
    ) {
        // Renewal rotates the operation ID without changing this lease
        // generation, so cancellation signals by the stable fence.
        let cancellations = self
            .active_attempts
            .lock()
            .ok()
            .map(|active| {
                active
                    .iter()
                    .filter(|(authority, _)| {
                        authority.job_id == job_id && authority.fence_high_water == fence_high_water
                    })
                    .map(|(_, cancellation)| cancellation.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if cancellations.is_empty() {
            if let Some(fallback) = fallback {
                fallback.cancel();
            }
            return;
        }
        for cancellation in cancellations {
            cancellation.cancel();
        }
    }

    pub(crate) fn signal_registered_attempt(&self, authority: AttemptAuthority) {
        let cancellation = self
            .active_attempts
            .lock()
            .ok()
            .and_then(|active| active.get(&authority).cloned());
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
    }

    pub(crate) async fn refresh_attempt_cancellation(
        &self,
        authority: AttemptAuthority,
    ) -> JobResult<(), S::Error> {
        let key = crate::keys::cancellation_key(self.namespace(), &authority.job_id)?;
        let Some(value) = self
            .store
            .get(key)
            .await
            .map_err(crate::error::JobSystemError::Store)?
        else {
            return Ok(());
        };
        crate::keys::validate_empty_marker(&value, crate::codec::ValueTag::Cancellation)
            .map_err(|_| crate::error::JobSystemError::PayloadCorrupt)?;
        self.signal_registered_attempt(authority);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn active_attempt_count(&self) -> usize {
        self.active_attempts
            .lock()
            .map(|active| active.len())
            .unwrap_or_default()
    }

    pub(crate) fn sleep(
        &self,
        delay: Duration,
    ) -> Result<WakeFuture, crate::model::WakeSchedulerError> {
        self.scheduler.sleep(delay)
    }

    pub(crate) fn clone_observer(&self) -> Arc<dyn JobObserver> {
        Arc::clone(&self.observer)
    }

    pub(crate) fn observe(&self, event: JobEvent) {
        self.observer.observe(event);
    }

    pub(crate) fn observe_error(&self, event: SafeJobErrorEvent) {
        self.observer.observe_error(event);
    }

    pub(crate) fn try_new_distributed(
        store: S,
        catalog: JobCatalog,
        namespace: Namespace,
        owner: OwnerId,
        scheduler: Arc<dyn WakeScheduler>,
    ) -> Result<Self, crate::error::StoreContractError> {
        if !store.capabilities().is_distributed() {
            return Err(crate::error::StoreContractError::FalseDistributedClaim);
        }
        Ok(Self::new(store, catalog, namespace, owner, scheduler))
    }

    pub(crate) fn store(&self) -> &crate::store::ObservedStore<S> {
        &self.store
    }

    pub(crate) async fn read_many(
        &self,
        keys: &[StoreKey],
    ) -> JobResult<Vec<Option<Bytes>>, S::Error> {
        self.store.capabilities().validate_get_many(keys)?;
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.store
            .get_many(keys)
            .await
            .map_err(JobSystemError::Store)
    }

    pub(crate) fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    pub(crate) fn owner(&self) -> &OwnerId {
        &self.owner
    }

    pub(crate) fn registry(&self) -> &HandlerRegistry {
        &self.registry
    }

    /// Enqueues a fully encoded record inside the crate's low-level paths.
    pub(crate) async fn enqueue_impl(
        &self,
        job: NewJob,
        now: Timestamp,
    ) -> JobResult<crate::model::EnqueueResult, S::Error> {
        crate::enqueue::enqueue(self, job, now).await
    }

    /// Enqueues a fully encoded record for conformance and test profiles.
    ///
    /// Routine callers should use [`Self::enqueue_typed`] or
    /// [`Self::enqueue_seed`], which keep encoding and record construction
    /// behind the typed facade.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn enqueue_raw(
        &self,
        job: NewJob,
        now: Timestamp,
    ) -> JobResult<crate::model::EnqueueResult, S::Error> {
        self.enqueue_impl(job, now).await
    }

    /// Enqueues a pre-encoded seed through the explicit value boundary.
    ///
    /// Routine callers should prefer [`Self::enqueue_typed`]. This method is
    /// useful to adapters and tests whose payload factory already produced a
    /// validated [`JobSeed`].
    pub async fn enqueue_seed(
        &self,
        seed: JobSeed,
        now: Timestamp,
    ) -> JobResult<crate::model::EnqueueResult, S::Error> {
        self.enqueue_impl(seed.into_new_job(), now).await
    }

    /// Encodes and enqueues a payload through a registered typed handle.
    pub async fn enqueue_typed<T: 'static>(
        &self,
        handle: &JobHandle<T>,
        payload: T,
        options: EnqueueOptions,
        now: Timestamp,
    ) -> JobResult<crate::model::EnqueueResult, S::Error> {
        let job_id = match options.job_id_value() {
            Some(job_id) => job_id,
            None => JobId::generate().map_err(|_| JobSystemError::EntropyUnavailable)?,
        };
        let job = handle.new_job(payload, options, job_id, now)?;
        self.enqueue_impl(job, now).await
    }

    /// Ensures that a stable controller seed exists without replacing durable
    /// progress.
    ///
    /// When the job already exists, its immutable definition must match while
    /// its persisted schedule, state, attempts, and checkpoint are preserved.
    /// The input `scheduled_at` is used only when the job is absent. Use
    /// the low-level enqueue path when replay must match the original schedule
    /// exactly.
    pub(crate) async fn ensure_seed_impl(
        &self,
        job: NewJob,
        now: Timestamp,
    ) -> JobResult<crate::model::EnqueueResult, S::Error> {
        crate::enqueue::ensure_seed(self, job, now).await
    }

    /// Ensures a raw stable seed for conformance and test profiles.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn ensure_seed_raw(
        &self,
        job: NewJob,
        now: Timestamp,
    ) -> JobResult<crate::model::EnqueueResult, S::Error> {
        self.ensure_seed_impl(job, now).await
    }

    /// Ensures a stable seed produced by the routine seed constructor.
    ///
    /// An ambiguous commit is reconciled against the complete persisted seed
    /// identity. If the seed is still absent, this operation makes at most one
    /// exact replay of the original store transaction and commit operation ID.
    /// A second unresolved acknowledgement returns
    /// [`JobSystemError::UnknownCommit`].
    pub async fn ensure_seed(
        &self,
        seed: JobSeed,
        now: Timestamp,
    ) -> JobResult<crate::model::EnqueueResult, S::Error> {
        self.ensure_seed_impl(seed.into_new_job(), now).await
    }

    /// Encodes and ensures a stable seed through a registered typed handle,
    /// using the bounded exact-replay semantics of [`Self::ensure_seed`].
    pub async fn ensure_seed_typed<T: 'static>(
        &self,
        handle: &JobHandle<T>,
        payload: T,
        options: EnqueueOptions,
        now: Timestamp,
    ) -> JobResult<crate::model::EnqueueResult, S::Error> {
        let job_id = options.job_id_value().ok_or(JobSystemError::Validation(
            crate::error::ValidationError::InvalidValue {
                field: "seed job id",
            },
        ))?;
        let job = handle.new_job(payload, options, job_id, now)?;
        self.ensure_seed_impl(job, now).await
    }

    /// Ensures every catalog seed exists without replacing durable progress.
    ///
    /// The builder owns the catalog after construction, so callers do not need
    /// to unpack handler registrations or seed values to initialize a system.
    /// Seeds are confirmed sequentially and the first unresolved or failed
    /// seed stops initialization. Callers must wait for success before driving
    /// work from this system.
    pub async fn ensure_seeds(
        &self,
        now: Timestamp,
    ) -> JobResult<Vec<crate::model::EnqueueResult>, S::Error> {
        let mut results = Vec::with_capacity(self.seeds.len());
        for seed in &self.seeds {
            results.push(self.ensure_seed_impl(seed.clone(), now).await?);
        }
        Ok(results)
    }

    /// Evaluates and durably enqueues a bounded set of occurrences visible at
    /// `now`.  The caller persists the returned cursor with its schedule
    /// record using the same revision/generation checks used for pause and
    /// resume.  Catch-up work is capped by the default materialisation budget
    /// and can be resumed from the returned cursor.
    pub async fn materialize_schedule(
        &self,
        schedule: &crate::schedule::RecurringSchedule,
        cursor: &crate::schedule::ScheduleCursor,
        now: Timestamp,
    ) -> JobResult<crate::schedule::ScheduleMaterialization, S::Error> {
        self.materialize_schedule_with_budget(
            schedule,
            cursor,
            now,
            crate::schedule::ScheduleMaterializationBudget::default(),
            || crate::time::MonotonicDeadline::ZERO,
        )
        .await
    }

    /// Evaluates and durably enqueues occurrences under explicit item, store
    /// operation, and monotonic deadline bounds.  If the deadline or item
    /// bound stops a CatchUp call, the returned cursor remains at the last
    /// materialised occurrence and `complete` is false.
    pub async fn materialize_schedule_with_budget<C>(
        &self,
        schedule: &crate::schedule::RecurringSchedule,
        cursor: &crate::schedule::ScheduleCursor,
        now: Timestamp,
        budget: crate::schedule::ScheduleMaterializationBudget,
        monotonic_now: C,
    ) -> JobResult<crate::schedule::ScheduleMaterialization, S::Error>
    where
        C: FnMut() -> crate::time::MonotonicDeadline,
    {
        crate::schedule::materialize(self, schedule, cursor, now, budget, monotonic_now).await
    }

    pub async fn claim(
        &self,
        job_id: JobId,
        now: Timestamp,
    ) -> JobResult<crate::lifecycle::ClaimedJob, S::Error> {
        crate::lifecycle::claim(self, job_id, now).await
    }

    /// Runs the registered handler for an existing claim without exposing the
    /// handler registry or its registration metadata.
    ///
    /// The handler's validated registration timeout is applied against the
    /// caller-owned monotonic clock. `now` must be the current wall time; an
    /// expired claim is rejected before invoking its handler. The returned
    /// outcome is not persisted; pass it to [`Self::complete`] or
    /// [`Self::apply_outcome`] with the same claim when the application has
    /// finished its domain work.
    pub async fn execute_claimed<C>(
        &self,
        claim: &crate::lifecycle::ClaimedJob,
        now: Timestamp,
        monotonic_now: C,
    ) -> JobResult<JobOutcome, S::Error>
    where
        C: Fn() -> crate::time::MonotonicDeadline + Send + Sync,
    {
        let registration = self
            .registry
            .get_ref(&claim.record().kind, claim.record().schema_version)
            .ok_or(JobSystemError::UnregisteredHandler)?;
        let lease = crate::transition::current_lease(self, claim, now)?;
        let clock = crate::drive::DriveClock::new(monotonic_now, now);
        let finish_by = clock
            .deadline_after(registration.default_timeout())?
            .min(clock.deadline_at(lease.expires_at)?);
        let context = claim
            .context_with_deadline(finish_by)
            .ok_or(JobSystemError::LeaseLost)?;
        let _attempt = self.register_execution(claim).await?;
        crate::transition::current_lease(self, claim, clock.wall_now()?)?;

        match crate::drive::execute_handler(crate::drive::HandlerInvocation {
            system: self,
            finish_by,
            clock,
            handler: registration.handler().as_ref(),
            context: crate::drive::HandlerContext::Standard(context),
            payload: claim.payload(),
        })
        .await?
        {
            crate::drive::HandlerExecution::Outcome(outcome) => Ok(outcome),
            crate::drive::HandlerExecution::Deadline => Ok(JobOutcome::Retry {
                class: crate::policy::RetryClass::Transient,
                not_before: None,
                code: crate::policy::OutcomeCode::try_new("handler_deadline")?,
            }),
        }
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) async fn claim_with_capacity(
        &self,
        job_id: JobId,
        now: Timestamp,
        capacity: std::num::NonZeroU16,
    ) -> JobResult<crate::lifecycle::ClaimedJob, S::Error> {
        crate::lifecycle::claim_with_capacity(self, job_id, now, capacity).await
    }

    pub async fn complete(
        &self,
        claim: crate::lifecycle::ClaimedJob,
        outcome: JobOutcome,
        completed_at: Timestamp,
    ) -> JobResult<CompletionDetails, S::Error> {
        crate::lifecycle::complete(self, claim, outcome, completed_at).await
    }

    pub async fn apply_outcome(
        &self,
        claim: crate::lifecycle::ClaimedJob,
        outcome: JobOutcome,
        now: Timestamp,
    ) -> JobResult<crate::failure::OutcomeResult, S::Error> {
        crate::failure::apply_outcome(self, claim, outcome, now).await
    }

    pub async fn renew(
        &self,
        claim: &mut crate::lifecycle::ClaimedJob,
        now: Timestamp,
    ) -> JobResult<crate::failure::RenewalResult, S::Error> {
        crate::failure::renew(self, claim, now).await
    }

    pub async fn heartbeat(
        &self,
        claim: &mut crate::lifecycle::ClaimedJob,
        now: Timestamp,
    ) -> JobResult<crate::failure::RenewalResult, S::Error> {
        self.renew(claim, now).await
    }

    pub async fn checkpoint(
        &self,
        claim: &mut crate::lifecycle::ClaimedJob,
        checkpoint: Bytes,
        now: Timestamp,
    ) -> JobResult<crate::failure::CheckpointResult, S::Error> {
        crate::failure::checkpoint(self, claim, checkpoint, now).await
    }

    pub async fn request_job_cancellation(
        &self,
        claim: &crate::lifecycle::ClaimedJob,
        now: Timestamp,
    ) -> JobResult<crate::failure::CancellationResult, S::Error> {
        crate::admin::request_job_cancellation(self, claim, now).await
    }

    pub async fn cancel_claim(
        &self,
        claim: crate::lifecycle::ClaimedJob,
        now: Timestamp,
    ) -> JobResult<crate::failure::CancellationResult, S::Error> {
        crate::failure::cancel_claim(self, claim, now).await
    }

    pub async fn cancel_job(
        &self,
        job_id: JobId,
        now: Timestamp,
    ) -> JobResult<crate::failure::CancellationResult, S::Error> {
        crate::admin::cancel_job(self, job_id, now).await
    }

    /// Suspends scheduled work without changing its identity, schedule or
    /// checkpoint. Leased work must finish or be cancelled before it can be
    /// suspended.
    pub async fn suspend_job(&self, job_id: JobId) -> JobResult<(), S::Error> {
        crate::admin::suspend_job(self, job_id).await
    }

    /// Restores a suspended job's original schedule without creating a new
    /// execution.
    pub async fn resume_job(&self, job_id: JobId) -> JobResult<(), S::Error> {
        crate::admin::resume_job(self, job_id).await
    }

    pub async fn redrive_job(
        &self,
        job_id: JobId,
        request: crate::failure::RedriveRequest,
    ) -> JobResult<crate::failure::RedriveResult, S::Error> {
        crate::admin::redrive_job(self, job_id, request).await
    }

    pub async fn reconcile(
        &self,
        job_id: JobId,
        operation: crate::ids::OperationId,
    ) -> JobResult<crate::transition::ReconciliationOutcome, S::Error> {
        crate::transition::reconcile(self, job_id, operation).await
    }

    /// Reads the authoritative job or its persisted terminal receipt.
    pub async fn observe_lifecycle(
        &self,
        job_id: JobId,
    ) -> JobResult<LifecycleObservation, S::Error> {
        crate::lifecycle::observe(self, job_id).await
    }

    pub async fn expire_job(
        &self,
        job_id: JobId,
        now: Timestamp,
    ) -> JobResult<crate::failure::ExpiryResult, S::Error> {
        crate::admin::expire_job(self, job_id, now).await
    }

    pub async fn repair_job(
        &self,
        job_id: JobId,
        expected_revision: u64,
        expected_operation: crate::ids::OperationId,
    ) -> JobResult<(), S::Error> {
        crate::admin::repair_job(self, job_id, expected_revision, expected_operation).await
    }

    /// Drives bounded work with a caller-owned monotonic clock so claim and
    /// handler deadlines remain independent from persisted wall time.
    ///
    /// The returned future is `Send` when borrowed values remain valid, so it
    /// can be spawned by a multi-thread executor. Store operation budgets are
    /// bounded, but wall-clock completion also requires the consumer's
    /// [`JobStore`] adapter and [`crate::runtime::WakeScheduler`] to honour
    /// their own deadlines.
    /// Competing claim or fairness reservations are counted in the report;
    /// unclaimed work remains visible for a subsequent drive. Store errors
    /// and unresolved commit outcomes remain errors.
    pub async fn drive<C>(
        &self,
        request: DriveRequest,
        wall_now: Timestamp,
        monotonic_now: C,
    ) -> JobResult<DriveReport, S::Error>
    where
        C: Fn() -> crate::time::MonotonicDeadline + Send + Sync,
    {
        crate::drive::drive(self, request, wall_now, monotonic_now).await
    }
}

impl<S: JobStore> std::fmt::Debug for JobSystem<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JobSystem")
            .field("namespace", &self.namespace)
            .field("owner", &self.owner)
            .field("registered_handlers", &self.registry.len())
            .finish_non_exhaustive()
    }
}
