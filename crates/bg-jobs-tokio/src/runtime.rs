use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bg_jobs::{
    DriveBudget, DriveReport, DriveStopReason, EnqueueOptions, EnqueueResult, JobCatalog,
    JobHandle, JobResult, JobSeed, Namespace, OwnerId, Timestamp, ValidationError, WakeHint,
    runtime::{JobSystem, JobSystemBuilder, WakeScheduler},
    store::{JobStore, StoreContractError},
};

use crate::scheduler::TokioWakeScheduler;

/// Errors found while composing a runtime and its store contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobRuntimeBuildError {
    Validation(ValidationError),
    StoreContract(StoreContractError),
}

impl std::fmt::Display for JobRuntimeBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => error.fmt(formatter),
            Self::StoreContract(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for JobRuntimeBuildError {}

impl From<ValidationError> for JobRuntimeBuildError {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}

impl From<StoreContractError> for JobRuntimeBuildError {
    fn from(error: StoreContractError) -> Self {
        Self::StoreContract(error)
    }
}

impl From<JobRuntimeBuildError> for StoreContractError {
    fn from(error: JobRuntimeBuildError) -> Self {
        match error {
            JobRuntimeBuildError::Validation(error) => Self::from(error),
            JobRuntimeBuildError::StoreContract(error) => error,
        }
    }
}

/// Result of waiting for either a scheduled wake or cooperative shutdown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The scheduler delay elapsed and the caller may drive again.
    Woken,
    /// Shutdown was requested while waiting (or before the wait began).
    Shutdown,
}

/// Tokio-owned facade for routine background-job registration, enqueueing, and
/// bounded driving.
pub struct JobRuntime<S: JobStore> {
    system: Arc<JobSystem<S>>,
    budget: DriveBudget,
    scheduler: Arc<dyn WakeScheduler>,
    clock: Arc<dyn crate::clock::JobClock>,
    safety_wake: Duration,
    shutdown_requested: Arc<AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
}

impl<S: JobStore> JobRuntime<S> {
    /// Builds a runtime for a store whose claims are local to this worker.
    pub fn local(
        store: S,
        catalog: JobCatalog,
        budget: DriveBudget,
        namespace: Namespace,
        owner: OwnerId,
    ) -> Result<Self, JobRuntimeBuildError> {
        Self::builder(store, catalog, budget)
            .namespace(namespace)
            .owner(owner)
            .build()
    }

    /// Builds a local runtime with an application-owned observer.
    pub fn local_with_observer(
        store: S,
        catalog: JobCatalog,
        budget: DriveBudget,
        namespace: Namespace,
        owner: OwnerId,
        observer: Arc<dyn bg_jobs::observer::JobObserver>,
    ) -> Result<Self, JobRuntimeBuildError> {
        Self::builder(store, catalog, budget)
            .namespace(namespace)
            .owner(owner)
            .observer(observer)
            .build()
    }

    /// Builds a runtime for a store that supports distributed claim fencing.
    pub fn distributed(
        store: S,
        catalog: JobCatalog,
        budget: DriveBudget,
        namespace: Namespace,
        owner: OwnerId,
    ) -> Result<Self, JobRuntimeBuildError> {
        Self::builder(store, catalog, budget)
            .namespace(namespace)
            .owner(owner)
            .distributed()
            .build()
    }

    /// Builds a distributed runtime with an application-owned observer.
    pub fn distributed_with_observer(
        store: S,
        catalog: JobCatalog,
        budget: DriveBudget,
        namespace: Namespace,
        owner: OwnerId,
        observer: Arc<dyn bg_jobs::observer::JobObserver>,
    ) -> Result<Self, JobRuntimeBuildError> {
        Self::builder(store, catalog, budget)
            .namespace(namespace)
            .owner(owner)
            .distributed()
            .observer(observer)
            .build()
    }

    /// Starts composition using the shared lifecycle and runtime defaults.
    pub fn builder(store: S, catalog: JobCatalog, budget: DriveBudget) -> JobRuntimeBuilder<S> {
        JobRuntimeBuilder {
            store,
            catalog,
            budget,
            namespace: None,
            owner: None,
            distributed: false,
            scheduler: Arc::new(TokioWakeScheduler),
            observer: Arc::new(bg_jobs::observer::NoopObserver),
            clock: crate::clock::system_clock(),
            safety_wake: Duration::from_millis(500),
        }
    }

    /// Returns the wall-clock value used by the next lifecycle operation.
    pub fn wall_now(&self) -> Timestamp {
        self.clock.wall_now()
    }

    /// Encodes and enqueues a payload through a registered handle.
    pub async fn enqueue<T: 'static>(
        &self,
        handle: &JobHandle<T>,
        payload: T,
        options: EnqueueOptions,
    ) -> JobResult<EnqueueResult, S::Error> {
        self.system
            .enqueue_typed(handle, payload, options, self.clock.wall_now())
            .await
    }

    /// Encodes and ensures one stable seed through a registered handle.
    pub async fn ensure_seed_typed<T: 'static>(
        &self,
        handle: &JobHandle<T>,
        payload: T,
        options: EnqueueOptions,
    ) -> JobResult<EnqueueResult, S::Error> {
        self.system
            .ensure_seed_typed(handle, payload, options, self.clock.wall_now())
            .await
    }

    /// Ensures a pre-encoded stable seed produced by a product-owned payload
    /// factory. The seed carries its immutable identity and schedule, while
    /// this facade supplies only the current wall clock for the store call.
    pub async fn ensure_seed(&self, seed: JobSeed) -> JobResult<EnqueueResult, S::Error> {
        self.system.ensure_seed(seed, self.clock.wall_now()).await
    }

    /// Issues authority for an atomic terminal application status projection.
    pub async fn terminal_authority(
        &self,
        job_id: bg_jobs::JobId,
    ) -> JobResult<Option<bg_jobs::JobTerminalAuthority>, S::Error> {
        self.system.terminal_authority(job_id).await
    }

    /// Observes durable completion, including recovery after a lost response.
    pub async fn observe_lifecycle(
        &self,
        job_id: bg_jobs::JobId,
    ) -> JobResult<bg_jobs::LifecycleObservation, S::Error> {
        self.system.observe_lifecycle(job_id).await
    }

    /// Settles an existing queue delivery from this job's durable lifecycle.
    /// Unfinished work always retains its delivery, including an occupied lease
    /// and suspended recovery. Missing or invalid state cannot acknowledge
    /// work. Publish any product-owned terminal status before settling
    /// closed jobs.
    pub async fn observe_queue_outcome(
        &self,
        job_id: bg_jobs::JobId,
    ) -> JobResult<crate::QueueOutcome, S::Error> {
        use bg_jobs::{JobState, JobSystemError, LifecycleObservation};
        let deadline = match self.observe_lifecycle(job_id).await? {
            LifecycleObservation::Terminal(_) => return Ok(crate::QueueOutcome::Complete),
            LifecycleObservation::Current { record, .. } => match record.state {
                JobState::Scheduled => record.scheduled_at,
                JobState::Leased(lease) => lease.expires_at,
                JobState::Cancelled | JobState::DeadLettered => {
                    return Ok(crate::QueueOutcome::Complete);
                }
                JobState::Suspended => {
                    return Ok(crate::QueueOutcome::RetryAfter(
                        crate::constants::DRIVE_RECOVERY_WAKE,
                    ));
                }
            },
            LifecycleObservation::Missing => return Err(JobSystemError::NotFound),
            LifecycleObservation::Invalid { .. } => return Err(JobSystemError::PayloadCorrupt),
        };
        let remaining = deadline
            .as_millis()
            .saturating_sub(self.wall_now().as_millis());
        Ok(crate::QueueOutcome::RetryAfter(Duration::from_millis(
            u64::try_from(remaining).unwrap_or_default().max(1),
        )))
    }

    /// Ensures every seed declared in the catalog.
    pub async fn ensure_seeds(&self) -> JobResult<Vec<EnqueueResult>, S::Error> {
        self.system.ensure_seeds(self.clock.wall_now()).await
    }

    /// Builds one bounded request from the injected monotonic clock and drives
    /// the engine with the matching wall-clock value.
    pub async fn drive_once(&self) -> JobResult<DriveReport, S::Error> {
        let monotonic = Arc::clone(&self.clock);
        let request = self.budget.request_at(monotonic.monotonic_now())?;
        self.system
            .drive(request, self.clock.wall_now(), move || {
                monotonic.monotonic_now()
            })
            .await
    }

    /// Requests cooperative shutdown. The current drive finishes its active
    /// handlers and the resident loop returns after observing the shutdown
    /// stop reason.
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
        self.system.request_shutdown();
        // `notify_one` latches a permit when the waiter has not registered
        // yet. That closes the race where shutdown arrives between the
        // atomic check and polling the select branch.
        self.shutdown_notify.notify_one();
    }

    /// Reports whether cooperative shutdown has been requested.
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }

    /// Calculates a bounded scheduler delay from a drive report and an
    /// optional application-owned wake hint.
    pub(crate) fn wake_delay(&self, report: &DriveReport, extra: WakeHint) -> Duration {
        let hint = report.next_wake.earliest(extra);
        let delay = match hint {
            WakeHint::Now => Duration::ZERO,
            WakeHint::At(at) => at
                .duration_since(self.clock.wall_now())
                .unwrap_or(Duration::ZERO),
            WakeHint::None => self.safety_wake,
        };
        // A durable wake is an advisory lower bound, not permission to park
        // past the safety poll. Consumers can enqueue new work while this
        // task is asleep, so recheck at least once per safety interval. The
        // fixed floor also bounds repeated due scans when an application
        // keeps returning immediate work without making progress.
        delay.min(self.safety_wake).max(Duration::from_millis(1))
    }

    /// Sleeps until the next common or application-owned wake point.
    pub async fn wait_for(
        &self,
        report: &DriveReport,
        extra: WakeHint,
    ) -> JobResult<WaitOutcome, S::Error> {
        self.wait_for_delay(self.wake_delay(report, extra)).await
    }

    /// Sleeps for an application-owned delay using the runtime scheduler.
    ///
    /// This is intentionally separate from [`Self::wait_for`]: callers may
    /// have a durable wake report but also need to retry a product-specific
    /// scheduling operation after a bounded error delay.
    async fn wait_for_delay(&self, delay: Duration) -> JobResult<WaitOutcome, S::Error> {
        let shutdown = self.shutdown_notify.notified();
        tokio::pin!(shutdown);
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Ok(WaitOutcome::Shutdown);
        }
        let wake = self
            .scheduler
            .sleep(delay.max(Duration::from_millis(1)))
            .map_err(bg_jobs::JobSystemError::WakeScheduler)?;
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Ok(WaitOutcome::Shutdown);
        }
        let outcome = tokio::select! {
            _ = wake => {
                if self.shutdown_requested.load(Ordering::Acquire) {
                    WaitOutcome::Shutdown
                } else {
                    WaitOutcome::Woken
                }
            }
            _ = &mut shutdown => WaitOutcome::Shutdown,
        };
        Ok(outcome)
    }

    /// Waits for a bounded error retry delay without duplicating scheduler
    /// plumbing in the consuming application.
    pub async fn wait_after_error(&self, delay: Duration) -> JobResult<WaitOutcome, S::Error> {
        self.wait_for_delay(delay).await
    }

    /// Runs bounded drives until a cooperative shutdown request is observed.
    /// Lost claims, unacknowledged commits or remote claim publications, and
    /// transient store failures resume durable discovery after a bounded delay.
    /// Permanent errors retain their original classification. Losing one
    /// claim must not stop unrelated queued work.
    ///
    /// The loop owns only generic drive and wake mechanics. Product callers
    /// can use [`Self::drive_once`] and [`Self::wait_for`] when they need to
    /// merge an application-specific wake hint.
    pub async fn run_until_shutdown(&self) -> JobResult<(), S::Error> {
        loop {
            let report = match self.drive_once().await {
                Ok(report) => report,
                Err(error) if Self::is_recoverable_drive_error(&error) => {
                    if self
                        .wait_for_delay(crate::constants::DRIVE_RECOVERY_WAKE)
                        .await?
                        == WaitOutcome::Shutdown
                    {
                        return Ok(());
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            if report.stop_reason == DriveStopReason::Shutdown {
                return Ok(());
            }
            if self.wait_for(&report, WakeHint::None).await? == WaitOutcome::Shutdown {
                return Ok(());
            }
        }
    }

    fn is_recoverable_drive_error(error: &bg_jobs::JobSystemError<S::Error>) -> bool {
        match error {
            bg_jobs::JobSystemError::UnknownCommit
            | bg_jobs::JobSystemError::LeaseLost
            | bg_jobs::JobSystemError::ClaimPublicationUnacknowledged => true,
            bg_jobs::JobSystemError::Store(error) => {
                std::iter::successors(Some(error as &(dyn std::error::Error + 'static)), |cause| {
                    cause.source()
                })
                .any(|cause| {
                    matches!(
                        cause.downcast_ref::<bg_jobs::store::StoreFailure>(),
                        Some(
                            bg_jobs::store::StoreFailure::Unavailable
                                | bg_jobs::store::StoreFailure::Timeout
                        )
                    )
                })
            }
            _ => false,
        }
    }

    /// Clones the raw engine handle for a deterministic test-profile probe.
    /// Production callers should stay on this facade's typed operations.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_system(&self) -> Arc<JobSystem<S>> {
        Arc::clone(&self.system)
    }
}

/// Runtime builder retaining only the composition choices that belong to the
/// infrastructure boundary. Production defaults hide Tokio, clock, and wake
/// plumbing; tests may inject deterministic replacements.
pub struct JobRuntimeBuilder<S: JobStore> {
    store: S,
    catalog: JobCatalog,
    budget: DriveBudget,
    namespace: Option<Namespace>,
    owner: Option<OwnerId>,
    distributed: bool,
    scheduler: Arc<dyn WakeScheduler>,
    observer: Arc<dyn bg_jobs::observer::JobObserver>,
    clock: Arc<dyn crate::clock::JobClock>,
    safety_wake: Duration,
}

impl<S: JobStore> JobRuntimeBuilder<S> {
    pub fn namespace(mut self, namespace: Namespace) -> Self {
        self.namespace = Some(namespace);
        self
    }

    pub fn owner(mut self, owner: OwnerId) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Requires the store to prove distributed atomic claim semantics.
    pub fn distributed(mut self) -> Self {
        self.distributed = true;
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn scheduler(mut self, scheduler: Arc<dyn WakeScheduler>) -> Self {
        self.scheduler = scheduler;
        self
    }

    pub fn observer(mut self, observer: Arc<dyn bg_jobs::observer::JobObserver>) -> Self {
        self.observer = observer;
        self
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn clock(mut self, clock: Arc<dyn crate::test_support::JobClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Changes the fallback delay used when no durable wake is known.
    #[cfg(any(test, feature = "test-support"))]
    pub fn safety_wake(mut self, safety_wake: Duration) -> Self {
        self.safety_wake = safety_wake;
        self
    }

    pub fn build(self) -> Result<JobRuntime<S>, JobRuntimeBuildError> {
        let namespace = self.namespace.ok_or(ValidationError::InvalidValue {
            field: "job runtime namespace",
        })?;
        let owner = self.owner.ok_or(ValidationError::InvalidValue {
            field: "job runtime owner",
        })?;
        if self.safety_wake.is_zero() {
            return Err(ValidationError::InvalidValue {
                field: "job runtime safety wake",
            }
            .into());
        }
        let builder = JobSystemBuilder::new(self.store)
            .catalog(self.catalog)
            .namespace(namespace)
            .owner(owner)
            .scheduler(Arc::clone(&self.scheduler))
            .with_observer(self.observer);
        let system = if self.distributed {
            builder.build_distributed()?
        } else {
            builder.build()?
        };
        Ok(JobRuntime {
            system: Arc::new(system),
            budget: self.budget,
            scheduler: self.scheduler,
            clock: self.clock,
            safety_wake: self.safety_wake,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        })
    }
}

impl<S: JobStore> std::fmt::Debug for JobRuntime<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JobRuntime")
            .field("budget", &self.budget)
            .field("safety_wake", &self.safety_wake)
            .finish_non_exhaustive()
    }
}
