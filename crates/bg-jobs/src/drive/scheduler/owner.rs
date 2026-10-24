use std::collections::{BTreeMap, BTreeSet};

use super::super::{
    candidate::Candidate,
    constants::{
        CANDIDATE_WORST_CASE_STORE_OPERATIONS, OWNER_LOAD_STORE_OPERATIONS, OperationBudget,
    },
    discovery::Discovery,
};
use crate::{
    budget::DriveRequest,
    engine::JobSystem,
    error::JobResult,
    fairness::{
        FairCandidateInput, FairCandidateMetadata, FairDispatchOwner, FairScope, FairnessBudget,
        FairnessBudgetInput,
    },
    ids::JobId,
    policy::FairnessPolicy,
    store::JobStore,
};

pub(super) async fn prepare_owner<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    discovery: Discovery,
    operation_budget: &mut OperationBudget,
) -> JobResult<Option<(FairDispatchOwner, BTreeMap<JobId, Candidate>)>, S::Error> {
    if !operation_budget.reserve(OWNER_LOAD_STORE_OPERATIONS)
        || (!discovery.candidates.is_empty()
            && CANDIDATE_WORST_CASE_STORE_OPERATIONS > operation_budget.remaining)
    {
        if CANDIDATE_WORST_CASE_STORE_OPERATIONS > operation_budget.remaining {
            system.observe(crate::observer::JobEvent::CapacityLimited {
                resource: crate::observer::CapacityResource::StoreOperations,
            });
        }
        return Ok(None);
    }
    let stop_reason = discovery.stop_reason;
    let mut candidates = BTreeMap::new();
    let mut owner = build_owner(system, request, discovery.candidates, &mut candidates).await?;
    if stop_reason.is_none() {
        remove_undiscovered_candidates(system, request, &mut owner, &candidates);
    }
    let conflicts = apply_registration_weights(system, &mut owner);
    candidates.retain(|_, candidate| {
        let scope = FairScope::from(&candidate.record.fairness).primary_scope();
        !conflicts.contains(&scope)
    });
    Ok(Some((owner, candidates)))
}

fn remove_undiscovered_candidates<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    owner: &mut FairDispatchOwner,
    candidates: &BTreeMap<JobId, Candidate>,
) {
    let discovered_ids: BTreeSet<_> = candidates.keys().copied().collect();
    let stale_ids: Vec<_> = owner
        .candidate_ids()
        .filter(|job_id| {
            !discovered_ids.contains(job_id)
                && owner_candidate_is_selected(system, request, owner, *job_id)
        })
        .collect();
    for job_id in stale_ids {
        owner.remove_candidate(job_id);
    }
}

fn owner_candidate_is_selected<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    owner: &FairDispatchOwner,
    job_id: JobId,
) -> bool {
    let Some(metadata) = owner.metadata(job_id) else {
        return false;
    };
    let Some(registration) = system
        .registry()
        .get_ref(&metadata.handler_kind, metadata.schema_version)
    else {
        return false;
    };
    super::super::discovery::queue_selected(request, registration.queue().as_str())
}

async fn build_owner<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    discovered: Vec<Candidate>,
    candidates: &mut BTreeMap<JobId, Candidate>,
) -> JobResult<FairDispatchOwner, S::Error> {
    insert_discovered(discovered, candidates);
    let mut owner = load_owner(system, request).await?;
    let ordered = ordered_candidates(candidates);
    owner.ensure_discovered_candidates(ordered.iter().map(|candidate| {
        (
            candidate_input(candidate),
            FairCandidateMetadata::for_record(&candidate.record),
        )
    }))?;
    Ok(owner)
}

fn insert_discovered(discovered: Vec<Candidate>, candidates: &mut BTreeMap<JobId, Candidate>) {
    for candidate in discovered {
        candidates
            .entry(candidate.record.job_id)
            .or_insert(candidate);
    }
}

fn ordered_candidates(candidates: &BTreeMap<JobId, Candidate>) -> Vec<&Candidate> {
    let mut ordered: Vec<_> = candidates.values().collect();
    ordered.sort_by(|left, right| {
        left.record
            .ordering_key
            .cmp(&right.record.ordering_key)
            // A lease already owns its ordering permit, including after expiry.
            // Waiting work cannot become its reconstructed ordering head.
            .then_with(|| left.route_is_due.cmp(&right.route_is_due))
            .then_with(|| left.when.cmp(&right.when))
            .then_with(|| left.record.job_id.cmp(&right.record.job_id))
    });
    ordered
}

async fn load_owner<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
) -> JobResult<FairDispatchOwner, S::Error> {
    let budget = FairnessBudget::try_new(FairnessBudgetInput {
        candidate_window: request.max_claims(),
        max_concurrency_per_scope: nonzero_u32(u32::from(request.max_concurrency().get())),
        max_rate_per_scope: request.max_claims(),
        // Low-volume is one aggregate class, independent of the caller's
        // claim window. Conflicts restore capacity without consuming service,
        // so no extra allowance is needed to fill a later claim.
        max_low_volume_service: nonzero_u32(1),
        max_payload_bytes: request.max_payload_bytes_in_flight(),
        max_cost_units: nonzero_u16(crate::model::MAX_COST_UNITS),
    })?;
    match FairDispatchOwner::load(system).await? {
        Some(owner) => Ok(owner),
        None => Ok(FairDispatchOwner::try_new(budget)?),
    }
}

fn candidate_input(candidate: &Candidate) -> FairCandidateInput {
    FairCandidateInput {
        job_id: candidate.record.job_id,
        fairness: candidate.record.fairness.clone(),
        priority: candidate.record.priority,
        cost_units: candidate.record.policy.cost_units,
        scheduled_at: candidate.when,
        payload_bytes: candidate.record.payload.total_length as usize,
        ordering_key: candidate.record.ordering_key.clone(),
        ordering_position: 0,
        block: None,
    }
}

fn apply_registration_weights<S: JobStore>(
    system: &JobSystem<S>,
    owner: &mut FairDispatchOwner,
) -> BTreeSet<FairScope> {
    let mut weights = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for (scope, metadata) in owner.active_registrations() {
        let Some(registration) = system
            .registry()
            .get_ref(&metadata.handler_kind, metadata.schema_version)
        else {
            continue;
        };
        let FairnessPolicy::Scoped { weight } = registration.fairness_policy() else {
            continue;
        };
        for key in [scope.clone(), scope.primary_scope()] {
            if let Some(previous) = weights.insert(key, weight)
                && previous != weight
            {
                conflicts.insert(scope.primary_scope());
            }
        }
    }
    for (scope, weight) in weights {
        if !conflicts.contains(&scope.primary_scope()) {
            owner.set_scope_weight(&scope, weight);
        }
    }
    for _ in &conflicts {
        system.observe_error(crate::observer::SafeJobErrorEvent {
            kind: crate::observer::SafeJobErrorKind::InvariantViolation,
            queue: None,
            effect_mode: None,
        });
    }
    conflicts
}

fn nonzero_u16(value: u16) -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(value).unwrap_or(std::num::NonZeroU16::MIN)
}

fn nonzero_u32(value: u32) -> std::num::NonZeroU32 {
    std::num::NonZeroU32::new(value).unwrap_or(std::num::NonZeroU32::MIN)
}
