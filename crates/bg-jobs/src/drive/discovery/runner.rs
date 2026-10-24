//! Bounded due/lease discovery and item-local route decoding.

use super::{
    budget::DiscoveryBudget,
    records,
    records::{DiscoveryRoute, RecordCandidateContext, collect_due_entries, collect_lease_entries},
    scan::QueueDiscoveryContext,
};
use crate::{
    budget::{DriveRequest, DriveStopReason},
    drive::{
        candidate::Candidate,
        constants::{self, OperationBudget},
    },
    engine::JobSystem,
    error::JobResult,
    keys,
    store::JobStore,
    time::{MonotonicDeadline, Timestamp},
};

pub(in crate::drive) struct Discovery {
    pub(in crate::drive) candidates: Vec<Candidate>,
    pub(in crate::drive) future_wake: Option<Timestamp>,
    pub(in crate::drive) immediate_candidates: u32,
    pub(in crate::drive) stop_reason: Option<DriveStopReason>,
}

struct RouteEntries {
    due_entries: Vec<records::DueDiscoveryEntry>,
    lease_entries: Vec<records::LeaseDiscoveryEntry>,
    stop_reason: Option<DriveStopReason>,
}

impl RouteEntries {
    fn new() -> Self {
        Self {
            due_entries: Vec::new(),
            lease_entries: Vec::new(),
            stop_reason: None,
        }
    }
}

impl Discovery {
    fn new(request: &DriveRequest) -> Self {
        Self {
            candidates: Vec::with_capacity(
                (request.max_claims().get() as usize).min(constants::MAX_DISCOVERY_ITEMS),
            ),
            future_wake: None,
            immediate_candidates: 0,
            stop_reason: None,
        }
    }

    pub(in crate::drive) fn record(&mut self, candidate: Candidate, now: Timestamp) {
        if candidate.when <= now {
            self.immediate_candidates = self.immediate_candidates.saturating_add(1);
        } else {
            self.future_wake = Some(
                self.future_wake
                    .map_or(candidate.when, |current| current.min(candidate.when)),
            );
        }
        self.candidates.push(candidate);
    }
}

pub(in crate::drive) async fn discover<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    now: Timestamp,
    clock: &mut impl FnMut() -> MonotonicDeadline,
    operation_budget: &mut OperationBudget,
) -> JobResult<Discovery, S::Error> {
    let mut discovery = Discovery::new(request);
    let mut discovery_budget = DiscoveryBudget::new(system.clone_observer());
    let routes = discover_routes(
        system,
        request,
        clock,
        operation_budget,
        &mut discovery_budget,
    )
    .await?;
    discovery.stop_reason = routes.stop_reason;
    let record_entries = routes
        .due_entries
        .into_iter()
        .map(DiscoveryRoute::Due)
        .chain(routes.lease_entries.into_iter().map(DiscoveryRoute::Lease))
        .collect::<Vec<_>>();
    let record_keys: Vec<_> = record_entries
        .iter()
        .map(|route| keys::job_key(system.namespace(), &route.job_id()))
        .collect::<Result<_, _>>()?;
    RecordCandidateContext {
        system,
        request,
        now,
        discovery: &mut discovery,
        record_entries: &record_entries,
        record_keys: &record_keys,
        discovery_budget: &mut discovery_budget,
        operation_budget,
    }
    .load()
    .await?;
    Ok(discovery)
}

async fn discover_routes<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    clock: &mut impl FnMut() -> MonotonicDeadline,
    operation_budget: &mut OperationBudget,
    discovery_budget: &mut DiscoveryBudget,
) -> JobResult<RouteEntries, S::Error> {
    let mut routes = RouteEntries::new();
    let queues = std::iter::once(None)
        .take(if request.queues().is_all() { 1 } else { 0 })
        .chain(request.queues().iter().map(Some));
    for queue in queues {
        let queue_discovery = QueueDiscoveryContext {
            system,
            request,
            clock,
            operation_budget,
            budget: discovery_budget,
        }
        .discover(queue)
        .await?;
        collect_due_entries(
            system,
            queue,
            queue_discovery.due_entries,
            &mut routes.due_entries,
        )?;
        collect_lease_entries(
            system,
            request,
            queue_discovery.lease_entries,
            &mut routes.lease_entries,
        )?;
        if queue_discovery.stop_now {
            routes.stop_reason = queue_discovery.stop_reason;
            break;
        }
        if routes.stop_reason.is_none() {
            routes.stop_reason = queue_discovery.stop_reason;
        }
    }
    Ok(routes)
}

pub(in crate::drive) fn queue_selected(request: &DriveRequest, queue: &str) -> bool {
    request.queues().is_all() || request.queues().iter().any(|item| item.as_str() == queue)
}
