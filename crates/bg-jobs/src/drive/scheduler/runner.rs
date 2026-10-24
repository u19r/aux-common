//! Bounded candidate scheduling, shutdown, and completion ordering.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::{Future, poll_fn},
    pin::Pin,
};

use super::{
    clock::DriveClock,
    completion,
    completion::{CompletionBookkeeping, finish_report},
    owner::prepare_owner,
    reservation,
    reservation::{CandidateStartStatus, CandidateStarter},
    shutdown::ShutdownController,
};
use crate::{
    budget::{DriveReport, DriveRequest, DriveStopReason},
    drive::{
        candidate::{Candidate, CandidateResult, process_candidate},
        constants::OperationBudget,
        discovery::{Discovery, discover},
    },
    engine::JobSystem,
    error::JobResult,
    fairness::FairPermit,
    ids::JobId,
    store::JobStore,
    time::{MonotonicDeadline, Timestamp, WakeHint},
};

pub(in crate::drive::scheduler) struct InFlightCandidate<'a, S: JobStore> {
    pub(in crate::drive::scheduler) order: usize,
    pub(in crate::drive::scheduler) payload_bytes: usize,
    pub(in crate::drive::scheduler) permit: FairPermit,
    pub(in crate::drive::scheduler) future:
        Pin<Box<dyn Future<Output = JobResult<CandidateResult, S::Error>> + Send + 'a>>,
}

pub(in crate::drive::scheduler) struct CompletedCandidate<E> {
    pub(in crate::drive::scheduler) order: usize,
    pub(in crate::drive::scheduler) payload_bytes: usize,
    pub(in crate::drive::scheduler) result: JobResult<CandidateResult, E>,
}

pub(in crate::drive) async fn run<S, C>(
    system: &JobSystem<S>,
    request: DriveRequest,
    now: Timestamp,
    clock: C,
) -> JobResult<DriveReport, S::Error>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
    let clock = DriveClock::new(clock, now);
    let mut monotonic_now = || clock.now();
    let mut operation_budget = OperationBudget::new(
        request.max_store_operations().get(),
        system.clone_observer(),
    );
    let discovery = discover(
        system,
        &request,
        now,
        &mut monotonic_now,
        &mut operation_budget,
    )
    .await?;
    drive_scheduler(
        system,
        DiscoveredDrive {
            request,
            discovery,
            operation_budget,
        },
        clock,
    )
    .await
}

struct DiscoveredDrive {
    request: DriveRequest,
    discovery: Discovery,
    operation_budget: OperationBudget,
}

async fn drive_scheduler<S, C>(
    system: &JobSystem<S>,
    drive: DiscoveredDrive,
    clock: DriveClock<C>,
) -> JobResult<DriveReport, S::Error>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
    let DiscoveredDrive {
        request,
        discovery,
        mut operation_budget,
    } = drive;
    let setup = SchedulerSetup::new(&request, &discovery);
    let Some((owner, candidates)) =
        prepare_owner(system, &request, discovery, &mut operation_budget).await?
    else {
        return setup.finish(system, &request, clock.wall_now()?).await;
    };
    let mut scheduler = SchedulerLoop::new(
        system,
        SchedulerInit {
            request,
            owner,
            candidates,
            operation_budget,
            setup,
        },
        clock,
    );
    scheduler.run().await?;
    scheduler.finish().await
}

struct SchedulerSetup {
    report: DriveReport,
    stop_reason: Option<DriveStopReason>,
    future_wake: Option<Timestamp>,
    immediate_candidates: u32,
}

impl SchedulerSetup {
    fn new(request: &DriveRequest, discovery: &Discovery) -> Self {
        let mut report = completion::empty_report(request.max_completion_details());
        if let Some(stop_reason) = discovery.stop_reason {
            report.stop_reason = stop_reason;
        }
        Self {
            report,
            stop_reason: discovery.stop_reason,
            future_wake: discovery.future_wake,
            immediate_candidates: discovery.immediate_candidates,
        }
    }

    async fn finish<S: JobStore>(
        self,
        system: &JobSystem<S>,
        request: &DriveRequest,
        now: Timestamp,
    ) -> JobResult<DriveReport, S::Error> {
        let next_wake = if self.immediate_candidates > 0 {
            WakeHint::Now
        } else {
            self.future_wake
                .map_or(WakeHint::None, |at| WakeHint::from_timestamp(at, now))
        };
        finish_report(system, request, self.report, next_wake).await
    }
}

struct SchedulerLoop<'system, S, C>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
    system: &'system JobSystem<S>,
    request: DriveRequest,
    owner: crate::fairness::FairDispatchOwner,
    candidates: BTreeMap<JobId, Candidate>,
    eligible_ids: BTreeSet<JobId>,
    operation_budget: OperationBudget,
    clock: DriveClock<C>,
    report: DriveReport,
    completion: CompletionBookkeeping<S::Error>,
    active: Vec<InFlightCandidate<'system, S>>,
    active_payload_bytes: usize,
    shutdown: ShutdownController,
}

struct SchedulerInit {
    request: DriveRequest,
    owner: crate::fairness::FairDispatchOwner,
    candidates: BTreeMap<JobId, Candidate>,
    operation_budget: OperationBudget,
    setup: SchedulerSetup,
}

impl<'system, S, C> SchedulerLoop<'system, S, C>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync + 'system,
{
    fn new(system: &'system JobSystem<S>, init: SchedulerInit, clock: DriveClock<C>) -> Self {
        let SchedulerInit {
            request,
            owner,
            candidates,
            operation_budget,
            setup,
        } = init;
        let eligible_ids = candidates.keys().copied().collect();
        let active_capacity = request.max_concurrency().get() as usize;
        let stop_starting = setup.stop_reason == Some(DriveStopReason::Deadline);
        let SchedulerSetup {
            report,
            stop_reason: _,
            future_wake: _,
            immediate_candidates: _,
        } = setup;
        Self {
            system,
            request,
            owner,
            candidates,
            eligible_ids,
            operation_budget,
            clock,
            report,
            completion: CompletionBookkeeping::new(stop_starting),
            active: Vec::with_capacity(active_capacity),
            active_payload_bytes: 0,
            shutdown: ShutdownController::new(),
        }
    }

    async fn run(&mut self) -> JobResult<(), S::Error> {
        let mut error = None;
        loop {
            let selection_idle = self.advance_candidates().await.unwrap_or_else(|cause| {
                error.get_or_insert(cause);
                self.completion.stop_starting = true;
                true
            });
            if self.active.is_empty() {
                if selection_idle
                    || self.completion.stop_starting
                    || self.report.counts.claimed >= self.request.max_claims().get()
                {
                    break;
                }
                continue;
            }
            let Some((completed, permit)) = self.poll_active().await? else {
                self.finish_shutdown();
                break;
            };
            if self.shutdown.requested() {
                self.report.stop_reason = DriveStopReason::Shutdown;
                self.completion.stop_starting = true;
            }
            self.completion.settle(
                &mut self.owner,
                &mut self.active_payload_bytes,
                completed,
                permit,
            );
        }
        error.map_or(Ok(()), Err)
    }

    async fn advance_candidates(&mut self) -> JobResult<bool, S::Error> {
        let selection_idle = self.start_available().await?;
        self.completion.apply(
            &mut self.report,
            self.clock.wall_now()?,
            self.request.max_completion_details(),
        )?;
        Ok(selection_idle)
    }

    async fn finish(self) -> JobResult<DriveReport, S::Error> {
        let now = self.clock.wall_now()?;
        let pending_at = self
            .candidates
            .values()
            .map(|candidate| candidate.when)
            .chain(self.completion.future_wake)
            .min();
        let next_wake = if self.shutdown.requested() {
            WakeHint::None
        } else {
            pending_at.map_or(WakeHint::None, |at| WakeHint::from_timestamp(at, now))
        };
        finish_report(self.system, &self.request, self.report, next_wake).await
    }

    async fn start_available(&mut self) -> JobResult<bool, S::Error> {
        let mut selection_idle = false;
        while !self.completion.stop_starting
            && self.active.len() < self.request.max_concurrency().get() as usize
        {
            if self.should_stop_starting() {
                break;
            }
            let start = {
                let mut starter = CandidateStarter {
                    system: self.system,
                    request: &self.request,
                    now: self.clock.wall_now()?,
                    owner: &mut self.owner,
                    candidates: &mut self.candidates,
                    eligible_ids: &self.eligible_ids,
                    operation_budget: &mut self.operation_budget,
                    active_payload_bytes: self.active_payload_bytes,
                    has_active: !self.active.is_empty(),
                };
                starter.reserve_next().await?
            };
            match start {
                Ok(reservation) => self.start_candidate(reservation),
                Err(status) => {
                    self.record_start_status(status);
                    selection_idle = true;
                    break;
                }
            }
        }
        Ok(selection_idle)
    }

    fn record_start_status(&mut self, status: CandidateStartStatus) {
        match status {
            CandidateStartStatus::Idle => {}
            CandidateStartStatus::LeaseConflict => {
                self.report.counts.lease_conflicts += 1;
                self.completion.stop_starting = true;
            }
            CandidateStartStatus::Stop(reason) => {
                self.report.stop_reason = reason;
                self.completion.stop_starting = true;
            }
        }
    }

    fn should_stop_starting(&mut self) -> bool {
        if self.system.is_shutdown() {
            self.report.stop_reason = DriveStopReason::Shutdown;
            self.completion.stop_starting = true;
            self.shutdown.request(self.system);
            return true;
        }
        self.report
            .counts
            .claimed
            .saturating_add(self.completion.reserved_claims)
            >= self.request.max_claims().get()
    }

    fn start_candidate(&mut self, reservation: reservation::ReservedCandidate) {
        let job_id = reservation.candidate.record.job_id;
        self.candidates.remove(&job_id);
        self.eligible_ids.remove(&job_id);
        let order = self.completion.reserve_claim();
        self.active_payload_bytes = self
            .active_payload_bytes
            .saturating_add(reservation.payload_bytes);
        let request = self.request.clone();
        let system = self.system;
        let clock = self.clock.clone();
        let future = Box::pin(async move {
            process_candidate(system, &request, reservation.candidate, clock).await
        });
        self.active.push(InFlightCandidate {
            order,
            payload_bytes: reservation.payload_bytes,
            permit: reservation.permit,
            future,
        });
    }

    async fn poll_active(
        &mut self,
    ) -> JobResult<Option<(CompletedCandidate<S::Error>, FairPermit)>, S::Error> {
        let polled =
            poll_fn(|context| self.shutdown.poll(self.system, &mut self.active, context)).await;
        match polled {
            Ok(result) => Ok(result),
            Err(error) => {
                let drained = self.shutdown.drain(&mut self.owner, &mut self.active);
                self.completion.reserved_claims =
                    self.completion.reserved_claims.saturating_sub(drained);
                Err(error)
            }
        }
    }

    fn finish_shutdown(&mut self) {
        self.report.stop_reason = DriveStopReason::Shutdown;
        let drained = self.shutdown.drain(&mut self.owner, &mut self.active);
        self.completion.reserved_claims = self.completion.reserved_claims.saturating_sub(drained);
        self.completion.future_wake = None;
    }
}
