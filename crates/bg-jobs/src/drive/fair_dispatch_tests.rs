use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;

use crate::{
    batch::{
        AuthConfigId, BatchBuilder, BatchCompatibility, BatchItem, BatchKey, BatchLimits,
        BatchLimitsInput, BatchResult, ScratchStorage,
    },
    budget::{DriveRequest, DriveRequestInput, QueueSelection},
    fairness::{
        CandidateBlock, FairCandidateInput, FairCandidateMetadata, FairDispatchOwner, FairRelease,
        FairScope, FairnessBudget, FairnessBudgetInput, FairnessLedger, FairnessRejection,
    },
    ids::{AttemptId, ExecutionId, FairnessKey, JobId, JobKind, Namespace, OrderingKey, OwnerId},
    model::{ExecutionContext, HandlerDefinition, HandlerFuture, JobHandler, JobOutcome},
    policy::{
        BackoffMultiplier, EffectMode, FairnessClass, FairnessPath, FairnessPolicy, OutcomeCode,
        Priority, RetryPolicy, RetryPolicyInput, RetryPreset, RetrySelection,
    },
    store::JobStore,
    test_helper::block_on,
    time::{MonotonicDeadline, Timestamp},
};

fn budget() -> FairnessBudget {
    FairnessBudget::try_new(FairnessBudgetInput {
        candidate_window: nz32(3),
        max_concurrency_per_scope: nz32(2),
        max_rate_per_scope: nz32(3),
        max_low_volume_service: nz32(1),
        max_payload_bytes: nz_usize(32),
        max_cost_units: nz16(2),
    })
    .expect("bounded fairness budget")
}

fn scope(primary: u8, secondary: Option<u8>) -> FairnessClass {
    let primary = FairnessKey::try_new([primary]).expect("primary key");
    let secondary = secondary.map(|value| FairnessKey::try_new([value]).expect("secondary key"));
    FairnessClass::from(FairnessPath::new(primary, secondary))
}

fn candidate(
    byte: u8,
    fairness: FairnessClass,
    priority: Priority,
    cost: u16,
    position: u64,
) -> FairCandidateInput {
    FairCandidateInput {
        job_id: JobId::from([byte; 16]),
        fairness,
        priority,
        cost_units: nz16(cost),
        scheduled_at: Timestamp::ZERO,
        payload_bytes: 1,
        ordering_key: Some(
            OrderingKey::try_new([byte]).expect("ordering key is non-empty and bounded"),
        ),
        ordering_position: position,
        block: None,
    }
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy::try_from(RetryPolicyInput {
        maximum_attempts: nz16(3),
        maximum_age: Duration::from_secs(60),
        minimum_backoff: Duration::from_millis(1),
        maximum_backoff: Duration::from_secs(1),
        multiplier: BackoffMultiplier::try_from(2).expect("valid retry multiplier"),
    })
    .expect("valid retry policy")
}

fn batch_item(byte: u8, ordering: u8, payload: &'static [u8]) -> BatchItem {
    let kind = JobKind::try_new("handler").expect("valid handler kind");
    BatchItem {
        job_id: JobId::from([byte; 16]),
        execution_id: ExecutionId::from([byte; 16]),
        attempt_id: AttemptId::from([byte; 16]),
        payload: Bytes::from_static(payload),
        compatibility: BatchCompatibility {
            handler_kind: kind,
            schema_version: nz16(1),
            batch_key: BatchKey::new(1),
            auth_config: AuthConfigId::new(1),
            effect_mode: EffectMode::Idempotent,
            retry_policy: retry_policy(),
            timeout: Duration::from_secs(1),
            priority: Priority::Default,
            fairness: scope(1, None),
        },
        ordering_key: Some(OrderingKey::try_new([ordering]).expect("ordering key")),
        ordering_position: 1,
        enqueued_at: Timestamp::ZERO,
        batch_deadline: Timestamp::from_millis(10),
    }
}

struct RecordingHandler {
    executions: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl JobHandler for RecordingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        self.executions
            .lock()
            .expect("recording handler lock is available")
            .push(payload.to_vec());
        Box::pin(async {
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("completed").expect("test outcome is valid"),
            ))
        })
    }
}

fn recording_scoped_system(
    executions: Arc<Mutex<Vec<Vec<u8>>>>,
) -> crate::JobSystem<crate::FakeStore> {
    recording_scoped_system_with_store(crate::FakeStore::new(), OwnerId::from([41; 16]), executions)
}

fn recording_scoped_system_with_store(
    store: crate::FakeStore,
    owner: OwnerId,
    executions: Arc<Mutex<Vec<Vec<u8>>>>,
) -> crate::JobSystem<crate::FakeStore> {
    let mut registry = crate::HandlerRegistry::new();
    registry
        .register(HandlerDefinition {
            kind: JobKind::try_new("email").expect("test kind is valid"),
            schema_version: nz16(1),
            queue: crate::QueueName::try_new("default").expect("test queue is valid"),
            effect_mode: EffectMode::Idempotent,
            cost_units: nz16(1),
            fairness_policy: FairnessPolicy::from(nz16(1)),
            default_retry: RetrySelection::Preset(RetryPreset::Interactive),
            default_timeout: Duration::from_secs(1),
            handler: RecordingHandler { executions },
        })
        .expect("test registration is valid");
    crate::JobSystem::new(
        store,
        crate::JobCatalog::from_registry(registry),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        owner,
        crate::test_helper::wake_scheduler(),
    )
}

fn claim_with_capacity(
    system: &crate::JobSystem<crate::FakeStore>,
    id: u8,
    capacity: NonZeroU16,
) -> crate::JobResult<crate::lifecycle::ClaimedJob, crate::test_helper::FakeStoreError> {
    let job_id = JobId::from([id; 16]);
    let job_key = crate::keys::job_key(system.namespace(), &job_id).expect("job key");
    let encoded = block_on(system.store().get(job_key))
        .expect("job read")
        .expect("job exists");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    let due_key = crate::keys::due_key(
        system.namespace(),
        &record.queue,
        record.scheduled_at,
        &job_id,
    )
    .expect("due key");
    let due_value = block_on(system.store().get(due_key.clone()))
        .expect("due read")
        .expect("due exists");
    block_on(crate::lifecycle::claim_record_with_capacity(
        system,
        crate::lifecycle::ClaimRecordInput {
            record,
            encoded,
            route: crate::lifecycle::ClaimRoute::Due {
                key: due_key,
                value: due_value,
            },
            now: Timestamp::ZERO,
            capacity,
            deadline: None,
        },
    ))
}

fn one_claim_drive_request() -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nz32(1),
        max_concurrency: nz16(1),
        max_payload_bytes_in_flight: nz_usize(1024),
        max_completion_details: 1,
        max_store_operations: nz32(64),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("one-claim drive request is valid")
}

#[test]
fn given_noisy_primary_backlog_and_quiet_due_work_when_one_claim_is_driven_then_quiet_primary_runs()
{
    let executions = Arc::new(Mutex::new(Vec::new()));
    let system = recording_scoped_system(Arc::clone(&executions));
    for (id, payload) in [(1, b"noisy-a".as_slice()), (2, b"noisy-b"), (3, b"noisy-c")] {
        let job = crate::test_helper::job(
            id,
            Bytes::copy_from_slice(payload),
            scope(1, None),
            Timestamp::ZERO,
            None,
            None,
        );
        block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("noisy enqueue commits");
    }
    let quiet = crate::test_helper::job(
        200,
        Bytes::from_static(b"quiet"),
        scope(2, None),
        Timestamp::ZERO,
        None,
        None,
    );
    block_on(system.enqueue_raw(quiet, Timestamp::ZERO)).expect("quiet enqueue commits");

    let report = block_on(
        system.drive(one_claim_drive_request(), Timestamp::ZERO, || {
            MonotonicDeadline::ZERO
        }),
    )
    .expect("public drive reports");

    assert_eq!(report.counts.claimed, 1);
    assert_eq!(
        executions
            .lock()
            .expect("recording handler lock is available")
            .as_slice(),
        [b"quiet".to_vec()]
    );
}

#[test]
fn given_capacity_two_when_two_nodes_claim_same_scope_then_distinct_durable_slots_are_used() {
    let store = crate::FakeStore::distributed();
    let executions = Arc::new(Mutex::new(Vec::new()));
    let first = recording_scoped_system_with_store(
        store.clone(),
        OwnerId::from([41; 16]),
        Arc::clone(&executions),
    );
    let second =
        recording_scoped_system_with_store(store.clone(), OwnerId::from([42; 16]), executions);
    for id in [1, 2] {
        block_on(first.enqueue_raw(
            crate::test_helper::job(
                id,
                Bytes::from_static(b"payload"),
                scope(7, None),
                Timestamp::ZERO,
                None,
                None,
            ),
            Timestamp::ZERO,
        ))
        .expect("enqueue commits");
    }

    let capacity = NonZeroU16::new(2).expect("capacity is non-zero");
    let first_claim = claim_with_capacity(&first, 1, capacity).expect("first claim");
    let second_claim = claim_with_capacity(&second, 2, capacity).expect("second claim");
    assert_eq!(first_claim.permit_keys().len(), 1);
    assert_eq!(second_claim.permit_keys().len(), 1);
    assert_ne!(first_claim.permit_keys()[0], second_claim.permit_keys()[0]);
    assert!(
        block_on(store.get(first_claim.permit_keys()[0].clone()))
            .expect("first permit read")
            .is_some()
    );
    assert!(
        block_on(store.get(second_claim.permit_keys()[0].clone()))
            .expect("second permit read")
            .is_some()
    );

    block_on(first.complete(
        first_claim,
        crate::test_helper::completion(),
        Timestamp::ZERO,
    ))
    .expect("first completion releases its slot");
    block_on(second.complete(
        second_claim,
        crate::test_helper::completion(),
        Timestamp::ZERO,
    ))
    .expect("second completion releases its slot");
}

#[test]
fn given_one_scope_slot_when_two_nodes_claim_same_scope_then_second_claim_is_deferred() {
    let store = crate::FakeStore::distributed();
    let executions = Arc::new(Mutex::new(Vec::new()));
    let first = recording_scoped_system_with_store(
        store.clone(),
        OwnerId::from([51; 16]),
        Arc::clone(&executions),
    );
    let second = recording_scoped_system_with_store(store, OwnerId::from([52; 16]), executions);
    for id in [11, 12] {
        block_on(first.enqueue_raw(
            crate::test_helper::job(
                id,
                Bytes::from_static(b"payload"),
                scope(8, None),
                Timestamp::ZERO,
                None,
                None,
            ),
            Timestamp::ZERO,
        ))
        .expect("enqueue commits");
    }

    let capacity = NonZeroU16::new(1).expect("capacity is non-zero");
    let first_claim = claim_with_capacity(&first, 11, capacity).expect("first claim");
    assert!(matches!(
        claim_with_capacity(&second, 12, capacity),
        Err(crate::JobSystemError::LeaseConflict)
    ));

    block_on(first.complete(
        first_claim,
        crate::test_helper::completion(),
        Timestamp::ZERO,
    ))
    .expect("completion releases the durable slot");
}

#[test]
fn given_capacity_two_when_ordering_group_is_held_then_its_successor_is_excluded() {
    let store = crate::FakeStore::distributed();
    let executions = Arc::new(Mutex::new(Vec::new()));
    let system = recording_scoped_system_with_store(store, OwnerId::from([61; 16]), executions);
    for id in [21, 22] {
        let mut job = crate::test_helper::job(
            id,
            Bytes::from_static(b"payload"),
            scope(9, None),
            Timestamp::ZERO,
            None,
            None,
        );
        job.ordering_key = Some(OrderingKey::try_new([3]).expect("ordering key"));
        block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue commits");
    }

    let capacity = NonZeroU16::new(2).expect("capacity is non-zero");
    let first_claim = claim_with_capacity(&system, 21, capacity).expect("first claim");
    assert!(matches!(
        claim_with_capacity(&system, 22, capacity),
        Err(crate::JobSystemError::LeaseConflict)
    ));

    block_on(system.complete(
        first_claim,
        crate::test_helper::completion(),
        Timestamp::ZERO,
    ))
    .expect("completion releases ordering exclusion");
    claim_with_capacity(&system, 22, capacity).expect("successor claims after release");
}

#[test]
fn unit_020_primary_service_bound_and_conflict_is_credit_neutral() {
    let mut ledger = FairnessLedger::new(budget());
    assert_eq!(ledger.budget().normalized_error_bound(), 10);

    ledger
        .add_candidate(candidate(1, scope(1, None), Priority::Critical, 2, 1))
        .unwrap();
    ledger
        .add_candidate(candidate(2, scope(2, None), Priority::Default, 2, 1))
        .unwrap();
    let first = ledger
        .select(JobId::from([1; 16]))
        .expect("first candidate");
    assert_eq!(first.cost_units().get(), 2);
    ledger
        .release(first, FairRelease::Complete)
        .expect("release does not spend additional service");
    let quiet_before = ledger
        .scope_snapshot(&FairScope::Scoped {
            primary: FairnessKey::try_new([2]).unwrap(),
            secondary: None,
        })
        .expect("quiet primary");
    assert!(quiet_before.served_cost <= 2);

    let retry_job = JobId::from([3; 16]);
    ledger
        .add_candidate(candidate(3, scope(1, None), Priority::Critical, 2, 1))
        .expect("retry candidate");
    let primary_before = ledger
        .scope_snapshot(&FairScope::Scoped {
            primary: FairnessKey::try_new([1]).unwrap(),
            secondary: None,
        })
        .unwrap();
    let permit = ledger.select(retry_job).expect("retry candidate selected");
    ledger
        .release(permit, FairRelease::Conflict)
        .expect("conflict releases capacity");
    let primary_after = ledger
        .scope_snapshot(&FairScope::Scoped {
            primary: FairnessKey::try_new([1]).unwrap(),
            secondary: None,
        })
        .unwrap();
    assert_eq!(primary_after.served_cost, primary_before.served_cost);
    assert_eq!(
        ledger.candidate_state(retry_job),
        Some(crate::FairCandidateState::RetryWaiting)
    );
}

#[test]
fn primary_service_bound_applies_between_top_level_scopes() {
    let budget = FairnessBudget::try_new(FairnessBudgetInput {
        candidate_window: nz32(2),
        max_concurrency_per_scope: nz32(1),
        max_rate_per_scope: nz32(16),
        max_low_volume_service: nz32(1),
        max_payload_bytes: nz_usize(32),
        max_cost_units: nz16(1),
    })
    .expect("bounded fairness budget");
    let mut ledger = FairnessLedger::new(budget);
    let busy = JobId::from([1; 16]);
    let quiet = JobId::from([2; 16]);
    ledger
        .add_candidate(candidate(1, scope(1, None), Priority::Default, 1, 1))
        .expect("busy candidate");
    ledger
        .add_candidate(candidate(2, scope(2, None), Priority::Default, 1, 1))
        .expect("quiet candidate");

    for _ in 0..ledger.budget().normalized_error_bound() {
        ledger
            .service_transition(busy, true)
            .expect("busy service remains within the bound");
    }
    assert_eq!(
        ledger.service_transition(busy, true),
        Err(FairnessRejection::NormalizedServiceBound)
    );
    ledger
        .service_transition(quiet, true)
        .expect("quiet primary remains eligible");
}

#[test]
fn unit_021_secondary_service_subdivides_without_aggregate_multiplication() {
    let mut ledger = FairnessLedger::new(budget());
    ledger
        .add_candidate(candidate(1, scope(1, Some(1)), Priority::Default, 1, 1))
        .unwrap();
    ledger
        .add_candidate(candidate(2, scope(1, Some(2)), Priority::Default, 1, 1))
        .unwrap();
    let first = ledger.select(JobId::from([1; 16])).unwrap();
    let second = ledger.select(JobId::from([2; 16])).unwrap();
    assert_eq!(
        first.scope().primary_scope(),
        second.scope().primary_scope()
    );
    let primary = ledger
        .scope_snapshot(&FairScope::Scoped {
            primary: FairnessKey::try_new([1]).unwrap(),
            secondary: None,
        })
        .unwrap();
    assert_eq!(primary.served_cost, 2);
    assert_eq!(primary.permits, 0);
}

#[test]
fn unit_022_priority_deficit_preserves_8_to_4_to_1_and_bulk_progress() {
    let mut ledger = FairnessLedger::new(budget());
    ledger
        .add_candidate(candidate(1, scope(1, None), Priority::Critical, 1, 1))
        .unwrap();
    ledger
        .add_candidate(candidate(2, scope(2, None), Priority::Default, 1, 1))
        .unwrap();
    ledger
        .add_candidate(candidate(3, scope(3, None), Priority::Bulk, 1, 1))
        .unwrap();
    let first = ledger.select(JobId::from([1; 16])).unwrap();
    ledger.release(first, FairRelease::Complete).unwrap();
    let second = ledger.select(JobId::from([2; 16])).unwrap();
    ledger.release(second, FairRelease::Complete).unwrap();
    let third = ledger.select(JobId::from([3; 16])).unwrap();
    assert_eq!(third.priority(), Priority::Bulk);
    let deficit = ledger.priority_deficit();
    assert_eq!(deficit.critical_window(), 1);
    assert_eq!(deficit.default_window(), 1);
    assert_eq!(deficit.bulk_window(), 1);
}

#[test]
fn given_only_default_candidates_when_priority_window_is_full_then_dispatch_continues() {
    let mut ledger = FairnessLedger::new(budget());
    for id in 1..=5 {
        ledger
            .add_candidate(candidate(id, scope(id, None), Priority::Default, 1, 1))
            .expect("default candidate is valid");
    }

    for _ in 0..5 {
        let permit = ledger
            .select_next_due(Timestamp::ZERO)
            .expect("default-only selection remains available")
            .expect("a default candidate is due");
        ledger
            .release(permit, FairRelease::Complete)
            .expect("default completion releases capacity");
    }
}

#[test]
fn unit_023_permits_and_rates_recover_without_shard_overshoot() {
    let mut ledger = FairnessLedger::new(budget());
    ledger
        .add_candidate(candidate(1, scope(1, Some(1)), Priority::Default, 1, 1))
        .unwrap();
    let permit = ledger.select(JobId::from([1; 16])).unwrap();
    let child = ledger.scope_snapshot(permit.scope()).unwrap();
    assert_eq!(child.in_flight, 1);
    assert_eq!(child.permits, 1);
    let permit_scope = permit.scope().clone();
    ledger.release(permit, FairRelease::Retry).unwrap();
    let child = ledger.scope_snapshot(&permit_scope).unwrap();
    assert_eq!(child.in_flight, 0);
    assert_eq!(child.permits, 2);
    assert_eq!(child.rate, 3);

    let second_permit = ledger
        .select(JobId::from([1; 16]))
        .expect("candidate can be claimed again");
    let child_scope = scope(1, Some(1));
    assert!(ledger.refill(&FairScope::from(&child_scope)));
    let refilled = ledger
        .scope_snapshot(&FairScope::from(&child_scope))
        .unwrap();
    assert_eq!(refilled.in_flight, 1);
    assert_eq!(refilled.permits, 1);
    assert_eq!(refilled.rate, 3);
    ledger
        .release(second_permit, FairRelease::Retry)
        .expect("second permit releases");
}

#[test]
fn given_a_reacquired_candidate_when_a_retained_permit_releases_then_current_authority_is_unchanged()
 {
    let mut ledger = FairnessLedger::new(budget());
    let ordering = OrderingKey::try_new([9]).unwrap();
    let mut first_input = candidate(1, scope(1, None), Priority::Default, 1, 1);
    first_input.ordering_key = Some(ordering.clone());
    let mut successor_input = candidate(2, scope(1, None), Priority::Default, 1, 2);
    successor_input.ordering_key = Some(ordering.clone());
    ledger.add_candidate(first_input).unwrap();
    ledger.add_candidate(successor_input).unwrap();

    let first = ledger.select(JobId::from([1; 16])).unwrap();
    ledger.settle_service(&first, true).unwrap();
    let current = ledger.select(JobId::from([1; 16])).unwrap();
    let current_scope = current.scope().clone();
    let scope_before = ledger.scope_snapshot(&current_scope).unwrap();

    assert_eq!(
        ledger.release(first, FairRelease::Complete),
        Err(FairnessRejection::OrderingHead)
    );
    assert_eq!(
        ledger.candidate_state(JobId::from([1; 16])),
        Some(crate::FairCandidateState::Leased)
    );
    assert_eq!(ledger.scope_snapshot(&current_scope).unwrap(), scope_before);
    assert_eq!(
        ledger.select(JobId::from([2; 16])),
        Err(FairnessRejection::OrderingHead)
    );

    ledger.release(current, FairRelease::Retry).unwrap();
}

#[test]
fn given_a_candidate_when_a_retained_permit_settles_twice_then_current_authority_is_unchanged() {
    let mut ledger = FairnessLedger::new(budget());
    let job_id = JobId::from([3; 16]);
    ledger
        .add_candidate(candidate(3, scope(3, None), Priority::Default, 1, 1))
        .unwrap();

    let first = ledger.select(job_id).unwrap();
    ledger.settle_service(&first, true).unwrap();
    let current_scope = first.scope().clone();
    let scope_before = ledger.scope_snapshot(&current_scope).unwrap();

    assert_eq!(
        ledger.settle_service(&first, true),
        Err(FairnessRejection::OrderingHead)
    );
    assert_eq!(
        ledger.candidate_state(job_id),
        Some(crate::FairCandidateState::RetryWaiting)
    );
    assert_eq!(ledger.scope_snapshot(&current_scope).unwrap(), scope_before);
}

#[test]
fn unit_024_candidate_isolation_rejects_each_head_class_without_mutating_independent_work() {
    let mut ledger = FairnessLedger::new(budget());
    for (byte, reason) in [
        (1, CandidateBlock::Leased),
        (2, CandidateBlock::Missing),
        (3, CandidateBlock::Corrupt),
        (4, CandidateBlock::Oversized),
        (5, CandidateBlock::Poison),
        (6, CandidateBlock::RateLimited),
        (7, CandidateBlock::Capacity),
    ] {
        ledger
            .add_candidate(FairCandidateInput {
                block: Some(reason),
                ..candidate(byte, scope(byte, None), Priority::Default, 1, 1)
            })
            .unwrap();
    }
    ledger
        .add_candidate(candidate(8, scope(8, None), Priority::Default, 1, 1))
        .unwrap();
    for (byte, reason) in [
        (1, CandidateBlock::Leased),
        (2, CandidateBlock::Missing),
        (3, CandidateBlock::Corrupt),
        (4, CandidateBlock::Oversized),
        (5, CandidateBlock::Poison),
        (6, CandidateBlock::RateLimited),
        (7, CandidateBlock::Capacity),
    ] {
        assert!(matches!(
            ledger.select(JobId::from([byte; 16])),
            Err(FairnessRejection::Blocked(actual)) if actual == reason
        ));
    }
    let independent = ledger
        .select(JobId::from([8; 16]))
        .expect("independent candidate remains selectable");
    let snapshot = ledger.scope_snapshot(independent.scope()).unwrap();
    assert_eq!(snapshot.in_flight, 1);
    assert_eq!(snapshot.served_cost, 1);

    let oversized = FairCandidateInput {
        payload_bytes: 33,
        ..candidate(9, scope(9, None), Priority::Default, 1, 1)
    };
    ledger.add_candidate(oversized).unwrap();
    assert_eq!(
        ledger.select(JobId::from([9; 16])),
        Err(FairnessRejection::PayloadCapacity)
    );
}

#[test]
fn given_a_blocked_candidate_when_a_sibling_shares_its_scope_then_only_the_candidate_is_blocked() {
    let mut ledger = FairnessLedger::new(budget());
    let shared_scope = scope(1, None);
    let blocked_job = JobId::from([1; 16]);
    let ready_job = JobId::from([2; 16]);

    ledger
        .add_candidate(FairCandidateInput {
            block: Some(CandidateBlock::Poison),
            ..candidate(1, shared_scope.clone(), Priority::Default, 1, 1)
        })
        .unwrap();
    ledger
        .add_candidate(candidate(2, shared_scope, Priority::Default, 1, 1))
        .unwrap();

    assert_eq!(
        ledger.select(blocked_job),
        Err(FairnessRejection::Blocked(CandidateBlock::Poison))
    );
    ledger
        .select(ready_job)
        .expect("a candidate-local block must not poison its sibling");
}

#[test]
fn given_more_than_the_owner_entry_limit_when_candidates_finish_then_terminal_state_is_compacted() {
    let store = crate::FakeStore::new();
    let system = crate::test_helper::system(store, FairnessPolicy::low_volume(), 91);
    let mut owner = FairDispatchOwner::try_new(budget()).expect("owner is valid");
    let fairness = scope(91, None);
    let metadata = FairCandidateMetadata {
        handler_kind: JobKind::try_new("handler").expect("handler kind is valid"),
        schema_version: nz16(1),
        batch_key: BatchKey::new(1),
        auth_config: AuthConfigId::new(1),
        effect_mode: EffectMode::Idempotent,
        retry_policy: retry_policy(),
        timeout: Duration::from_secs(1),
        enqueued_at: Timestamp::ZERO,
        batch_deadline: Timestamp::ZERO,
    };

    for value in 0_u64..4_097 {
        let job_id = JobId::from(<[u8; 16]>::try_from(value.to_be_bytes().repeat(2)).unwrap());
        owner
            .ensure_candidate(
                FairCandidateInput {
                    job_id,
                    fairness: fairness.clone(),
                    priority: Priority::Default,
                    cost_units: nz16(1),
                    scheduled_at: Timestamp::ZERO,
                    payload_bytes: 1,
                    ordering_key: None,
                    ordering_position: value,
                    block: None,
                },
                metadata.clone(),
            )
            .expect("candidate is valid");
        owner.remove_candidate(job_id);
    }

    assert!(block_on(owner.save(&system)).is_ok());
}

#[test]
fn given_a_blocked_candidate_when_it_is_upserted_without_a_block_then_only_an_explicit_scope_block_remains()
 {
    let mut ledger = FairnessLedger::new(budget());
    let shared_scope = scope(1, None);
    let blocked_job = JobId::from([1; 16]);
    ledger
        .add_candidate(FairCandidateInput {
            block: Some(CandidateBlock::Poison),
            ..candidate(1, shared_scope.clone(), Priority::Default, 1, 1)
        })
        .unwrap();
    ledger
        .upsert_candidate(candidate(1, shared_scope.clone(), Priority::Default, 1, 1))
        .unwrap();

    ledger
        .select(blocked_job)
        .expect("an unblocked upsert clears the candidate-local restriction");

    let mut ledger = FairnessLedger::new(budget());
    ledger
        .add_candidate(candidate(2, shared_scope.clone(), Priority::Default, 1, 1))
        .unwrap();
    assert!(ledger.block(&FairScope::from(&shared_scope), CandidateBlock::Capacity));
    ledger
        .upsert_candidate(candidate(2, shared_scope, Priority::Default, 1, 1))
        .unwrap();

    assert_eq!(
        ledger.select(JobId::from([2; 16])),
        Err(FairnessRejection::Blocked(CandidateBlock::Capacity))
    );
}

#[test]
fn given_retry_waiting_candidate_when_fair_configuration_refreshes_then_lifecycle_state_is_preserved()
 {
    let mut ledger = FairnessLedger::new(budget());
    let job_id = JobId::from([3; 16]);
    ledger
        .add_candidate(candidate(3, scope(3, None), Priority::Default, 1, 1))
        .unwrap();

    let permit = ledger.select(job_id).expect("candidate is selectable");
    ledger
        .release(permit, FairRelease::Retry)
        .expect("retry transition commits");
    assert_eq!(
        ledger.candidate_state(job_id),
        Some(crate::FairCandidateState::RetryWaiting)
    );

    let refreshed = FairCandidateInput {
        priority: Priority::Critical,
        scheduled_at: Timestamp::from_millis(1_000_000),
        payload_bytes: 2,
        ..candidate(3, scope(3, None), Priority::Critical, 1, 1)
    };
    ledger
        .upsert_candidate(refreshed)
        .expect("fair configuration refresh commits");

    assert_eq!(
        ledger.candidate_state(job_id),
        Some(crate::FairCandidateState::RetryWaiting)
    );
}

#[test]
fn unit_025_batch_formation_enforces_item_bytes_time_deadline_and_compatibility_bounds() {
    let limits = BatchLimits::try_new(BatchLimitsInput {
        max_items: nz16(3),
        max_payload_bytes: nz_usize(4),
        max_formation_delay: Duration::from_millis(2),
    })
    .unwrap();
    let first = batch_item(1, 1, b"aa");
    let mut builder = BatchBuilder::try_new(first.clone(), limits, Timestamp::ZERO).unwrap();

    let incompatible = BatchItem {
        compatibility: BatchCompatibility {
            auth_config: AuthConfigId::new(2),
            ..batch_item(2, 2, b"b").compatibility
        },
        ..batch_item(2, 2, b"b")
    };
    assert!(matches!(
        builder.try_add(incompatible, Timestamp::ZERO),
        Err(crate::batch::BatchRejection::Incompatible)
    ));

    assert!(matches!(
        builder.try_add(batch_item(2, 1, b"b"), Timestamp::ZERO),
        Err(crate::batch::BatchRejection::DuplicateOrderingGroup)
    ));
    assert!(matches!(
        builder.try_add(batch_item(2, 2, b"ccc"), Timestamp::ZERO),
        Err(crate::batch::BatchRejection::PayloadCapacity)
    ));
    assert!(matches!(
        builder.try_add(batch_item(2, 2, b"b"), Timestamp::from_millis(3)),
        Err(crate::batch::BatchRejection::FormationWindow)
    ));

    let mut deadline_builder =
        BatchBuilder::try_new(first.clone(), limits, Timestamp::ZERO).unwrap();
    let deadline_item = BatchItem {
        batch_deadline: Timestamp::from_millis(1),
        ..batch_item(2, 2, b"b")
    };
    assert!(matches!(
        deadline_builder.try_add(deadline_item, Timestamp::from_millis(2)),
        Err(crate::batch::BatchRejection::FormationDeadline)
    ));

    let mut clock_builder = BatchBuilder::try_new(first.clone(), limits, Timestamp::ZERO).unwrap();
    let clock_item = BatchItem {
        enqueued_at: Timestamp::from_millis(5),
        ..batch_item(2, 2, b"b")
    };
    assert!(matches!(
        clock_builder.try_add(clock_item, Timestamp::ZERO),
        Err(crate::batch::BatchRejection::FormationClock)
    ));

    let one_item = BatchLimits::try_new(BatchLimitsInput {
        max_items: nz16(1),
        max_payload_bytes: nz_usize(4),
        max_formation_delay: Duration::from_millis(2),
    })
    .unwrap();
    let mut full_builder = BatchBuilder::try_new(first, one_item, Timestamp::ZERO).unwrap();
    assert!(matches!(
        full_builder.try_add(batch_item(2, 2, b"b"), Timestamp::ZERO),
        Err(crate::batch::BatchRejection::Full)
    ));

    assert!(
        BatchLimits::try_new(BatchLimitsInput {
            max_items: nz16(1),
            max_payload_bytes: nz_usize(1),
            max_formation_delay: Duration::ZERO,
        })
        .is_err()
    );
}

#[test]
fn unit_026_batch_results_preserve_partial_retry_duplicate_and_missing_item_outcomes() {
    let limits = BatchLimits::try_new(BatchLimitsInput {
        max_items: nz16(2),
        max_payload_bytes: nz_usize(8),
        max_formation_delay: Duration::from_millis(2),
    })
    .unwrap();
    let first = batch_item(1, 1, b"a");
    let second = batch_item(2, 2, b"b");
    let mut builder = BatchBuilder::try_new(first.clone(), limits, Timestamp::ZERO).unwrap();
    builder.try_add(second.clone(), Timestamp::ZERO).unwrap();
    let batch = builder.finish();
    let result = BatchResult {
        attempt_id: first.attempt_id,
        outcome: JobOutcome::Complete(OutcomeCode::try_new("ok").unwrap()),
    };
    let duplicate = BatchResult {
        attempt_id: first.attempt_id,
        outcome: JobOutcome::Retry {
            class: crate::policy::RetryClass::Transient,
            not_before: None,
            code: OutcomeCode::try_new("duplicate").unwrap(),
        },
    };
    let applied = batch.apply_results(&[result, duplicate]).unwrap();
    assert!(matches!(
        applied.resolutions[0].outcome,
        crate::batch::BatchOutcome::RetryInvariant
    ));
    assert!(matches!(
        applied.resolutions[1].outcome,
        crate::batch::BatchOutcome::MissingResult
    ));
    assert!(matches!(
        batch.apply_results(&[BatchResult {
            attempt_id: AttemptId::from([9; 16]),
            outcome: JobOutcome::Cancelled,
        }]),
        Err(crate::batch::BatchResultError::UnknownAttempt)
    ));
}

#[test]
fn unit_027_scratch_storage_drops_payloads_reuses_capacity_and_shrinks_retained_memory() {
    use std::rc::Rc;

    #[derive(Clone)]
    struct DropProbe(Rc<std::cell::Cell<usize>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let mut scratch = ScratchStorage::<Bytes>::new(2);
    scratch.push(Bytes::from_static(b"payload-a"));
    scratch.push(Bytes::from_static(b"payload-b"));
    let retained = scratch.capacity();
    scratch.clear();
    assert!(scratch.is_empty());
    scratch.push(Bytes::from_static(b"reused"));
    assert_eq!(scratch.capacity(), retained);
    scratch.clear();
    scratch.shrink_to_retained_cap();
    assert!(scratch.capacity() <= 2);

    let drops = Rc::new(std::cell::Cell::new(0));
    let mut probes = ScratchStorage::new(1);
    for _ in 0..8 {
        probes.push(DropProbe(drops.clone()));
    }
    let expanded = probes.capacity();
    probes.clear();
    assert_eq!(drops.get(), 8);
    assert!(expanded > probes.capacity() || expanded > 1);
    probes.shrink_to_retained_cap();
    assert!(probes.capacity() <= 1);
}

#[test]
fn given_mixed_due_candidates_when_selecting_next_then_future_and_blocked_work_is_skipped() {
    let mut ledger = FairnessLedger::new(budget());
    let mut future = candidate(2, scope(2, None), Priority::Critical, 1, 1);
    future.scheduled_at = Timestamp::from_millis(1);
    let mut blocked = candidate(3, scope(3, None), Priority::Critical, 1, 1);
    blocked.block = Some(CandidateBlock::Poison);
    ledger
        .add_candidate(candidate(1, scope(1, None), Priority::Default, 1, 1))
        .expect("default candidate is valid");
    ledger
        .add_candidate(future)
        .expect("future candidate is valid");
    ledger
        .add_candidate(blocked)
        .expect("blocked candidate is valid");
    ledger
        .add_candidate(candidate(4, scope(4, None), Priority::Critical, 1, 1))
        .expect("critical candidate is valid");

    let permit = ledger
        .select_next_due(Timestamp::ZERO)
        .expect("selection succeeds")
        .expect("a due candidate exists");

    assert_eq!(permit.job_id(), JobId::from([4; 16]));
}

#[test]
fn given_many_primary_scopes_when_selecting_next_then_candidate_scans_are_linear() {
    const CANDIDATE_COUNT: u8 = 24;
    let mut ledger = scaling_ledger(CANDIDATE_COUNT, Priority::Default);

    FairnessLedger::reset_selection_scan_visits();
    let permit = ledger
        .select_next_due(Timestamp::ZERO)
        .expect("selection succeeds")
        .expect("a candidate exists");

    assert_eq!(permit.job_id(), JobId::from([1; 16]));
    assert_eq!(
        FairnessLedger::selection_scan_visits(),
        usize::from(CANDIDATE_COUNT) * 3,
        "selection visits each candidate once during preparation, bulk probing, and scoring"
    );
    assert_eq!(
        FairnessLedger::selection_scope_visits(),
        usize::from(CANDIDATE_COUNT) * 2,
        "selection visits each primary once for indexing and once for extrema"
    );
}

#[test]
fn given_twice_as_many_primary_scopes_when_selecting_next_then_preparation_scales_linearly() {
    const SMALL_COUNT: u8 = 12;
    let small = measure_selection_pass(SMALL_COUNT);
    let large = measure_selection_pass(SMALL_COUNT * 2);

    assert_eq!(
        small.candidate_visits,
        usize::from(SMALL_COUNT) * 3,
        "small pass candidate visits"
    );
    assert_eq!(
        large.candidate_visits,
        usize::from(SMALL_COUNT) * 6,
        "doubling primaries doubles candidate visits"
    );
    assert_eq!(
        small.scope_visits,
        usize::from(SMALL_COUNT) * 2,
        "small pass scope visits"
    );
    assert_eq!(
        large.scope_visits,
        usize::from(SMALL_COUNT) * 4,
        "doubling primaries doubles scope visits"
    );
    println!(
        "fair_selection_single_pass_perf small_count={} elapsed_nanos={} allocations={} \
         allocated_bytes={} candidate_visits={} scope_visits={} large_count={} elapsed_nanos={} \
         allocations={} allocated_bytes={} candidate_visits={} scope_visits={}",
        SMALL_COUNT,
        small.elapsed_nanos,
        small.allocation_count,
        small.allocated_bytes,
        small.candidate_visits,
        small.scope_visits,
        SMALL_COUNT * 2,
        large.elapsed_nanos,
        large.allocation_count,
        large.allocated_bytes,
        large.candidate_visits,
        large.scope_visits,
    );
}

#[test]
fn given_repeated_drains_when_selecting_each_due_candidate_then_visits_and_allocations_are_quadratic()
 {
    const SMALL_COUNT: u8 = 12;
    let small = measure_repeated_drain(SMALL_COUNT);
    let large = measure_repeated_drain(SMALL_COUNT * 2);

    let small_count = usize::from(SMALL_COUNT);
    let large_count = small_count * 2;
    assert_eq!(
        small.candidate_visits,
        small_count * small_count * 3,
        "each repeated drain scans the bounded candidate window once"
    );
    assert_eq!(
        large.candidate_visits,
        large_count * large_count * 3,
        "doubling the drain window remains quadratic in candidate visits"
    );
    assert_eq!(
        small.scope_visits,
        small_count * small_count * 2,
        "each pass visits the primary index and extrema set once"
    );
    assert_eq!(
        large.scope_visits,
        large_count * large_count * 2,
        "doubling the drain window remains quadratic in scope visits"
    );
    assert!(
        large.allocation_count <= small.allocation_count.saturating_mul(8),
        "allocation count should stay within a quadratic envelope"
    );
    assert!(
        large.allocated_bytes <= small.allocated_bytes.saturating_mul(8),
        "allocated bytes should stay within a quadratic envelope"
    );

    println!(
        "fair_selection_perf small_count={} elapsed_nanos={} allocations={} allocated_bytes={} \
         candidate_visits={} scope_visits={} large_count={} elapsed_nanos={} allocations={} \
         allocated_bytes={} candidate_visits={} scope_visits={}",
        SMALL_COUNT,
        small.elapsed_nanos,
        small.allocation_count,
        small.allocated_bytes,
        small.candidate_visits,
        small.scope_visits,
        SMALL_COUNT * 2,
        large.elapsed_nanos,
        large.allocation_count,
        large.allocated_bytes,
        large.candidate_visits,
        large.scope_visits,
    );

    // Elapsed time is diagnostic because scheduler noise varies across test
    // hosts; the visit counters and allocation envelope are deterministic
    // complexity evidence.
}

#[derive(Clone, Copy)]
struct SelectionMetrics {
    candidate_visits: usize,
    scope_visits: usize,
    elapsed_nanos: u128,
    allocation_count: u64,
    allocated_bytes: u64,
}

fn scaling_ledger(candidate_count: u8, priority: Priority) -> FairnessLedger {
    let fairness_budget = FairnessBudget::try_new(FairnessBudgetInput {
        candidate_window: nz32(u32::from(candidate_count)),
        max_concurrency_per_scope: nz32(1),
        max_rate_per_scope: nz32(u32::from(candidate_count)),
        max_low_volume_service: nz32(1),
        max_payload_bytes: nz_usize(32),
        max_cost_units: nz16(1),
    })
    .expect("scaling budget is valid");
    let mut ledger = FairnessLedger::new(fairness_budget);
    for id in 1..=candidate_count {
        ledger
            .add_candidate(candidate(id, scope(id, None), priority, 1, 1))
            .expect("candidate is valid");
    }
    ledger
}

fn measure_selection_pass(candidate_count: u8) -> SelectionMetrics {
    let mut ledger = scaling_ledger(candidate_count, Priority::Default);
    FairnessLedger::reset_selection_scan_visits();
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "given_twice_as_many_primary_scopes_when_selecting_next_then_preparation_scales_linearly",
        file!(),
        line!(),
        Some("fair-selection-final"),
    );
    let started = Instant::now();
    let permit = ledger
        .select_next_due(Timestamp::ZERO)
        .expect("selection succeeds")
        .expect("a candidate exists");
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    assert_eq!(permit.job_id(), JobId::from([1; 16]));
    SelectionMetrics {
        candidate_visits: FairnessLedger::selection_scan_visits(),
        scope_visits: FairnessLedger::selection_scope_visits(),
        elapsed_nanos,
        allocation_count: allocations.allocation_count,
        allocated_bytes: allocations.allocated_bytes,
    }
}

fn measure_repeated_drain(candidate_count: u8) -> SelectionMetrics {
    let mut ledger = scaling_ledger(candidate_count, Priority::Default);
    FairnessLedger::reset_selection_scan_visits();
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "given_repeated_drains_when_selecting_each_due_candidate_then_visits_and_allocations_are_quadratic",
        file!(),
        line!(),
        Some("fair-selection"),
    );
    let started = Instant::now();
    for _ in 0..candidate_count {
        let permit = ledger
            .select_next_due(Timestamp::ZERO)
            .expect("selection succeeds")
            .expect("a candidate remains");
        ledger
            .release(permit, FairRelease::Complete)
            .expect("terminal release succeeds");
        ledger.reset_priority_window();
    }
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    SelectionMetrics {
        candidate_visits: FairnessLedger::selection_scan_visits(),
        scope_visits: FairnessLedger::selection_scope_visits(),
        elapsed_nanos,
        allocation_count: allocations.allocation_count,
        allocated_bytes: allocations.allocated_bytes,
    }
}

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).expect("non-zero test value")
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("non-zero test value")
}

fn nz_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("non-zero test value")
}

#[test]
fn given_expired_scope_capacity_and_older_backlog_when_driving_then_recovery_frees_capacity() {
    for ordering in [
        None,
        Some(OrderingKey::try_new("document-jobs").expect("ordering key")),
    ] {
        let executions = Arc::new(Mutex::new(Vec::new()));
        let system = recording_scoped_system_with_store(
            crate::FakeStore::distributed(),
            OwnerId::from([71; 16]),
            Arc::clone(&executions),
        );
        for id in 1..=18 {
            let mut job = crate::test_helper::job(
                id,
                Bytes::from(vec![id]),
                scope(8, None),
                Timestamp::ZERO,
                None,
                None,
            );
            job.ordering_key = ordering.clone();
            block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue commits");
        }
        let held = claim_with_capacity(&system, 1, nz16(1)).expect("initial claim holds sole slot");
        let crate::JobState::Leased(lease) = &held.record().state else {
            panic!("claim must lease");
        };
        let expiry = lease.expires_at;
        let before = Timestamp::from_millis(expiry.as_millis() - 1);
        let live = block_on(system.drive(one_claim_drive_request(), before, || {
            MonotonicDeadline::ZERO
        }))
        .expect("live capacity defers new work");
        assert_eq!(live.counts.claimed, 0);
        assert!(executions.lock().expect("executions").is_empty());
        let recovered = block_on(system.drive(one_claim_drive_request(), expiry, || {
            MonotonicDeadline::ZERO
        }))
        .expect("expired claim is recovered");
        assert_eq!(
            recovered.counts.succeeded, 1,
            "older waiting jobs must not starve lease recovery: {recovered:?}"
        );
        assert_eq!(*executions.lock().expect("executions"), vec![vec![1]]);
        assert!(matches!(
            block_on(system.complete(held, crate::test_helper::completion(), expiry,)),
            Err(crate::JobSystemError::LeaseLost)
        ));
        for expected in 2..=18 {
            let resumed = block_on(system.drive(one_claim_drive_request(), expiry, || {
                MonotonicDeadline::ZERO
            }))
            .expect("released capacity serves backlog");
            assert_eq!(resumed.counts.succeeded, 1);
            assert_eq!(
                executions.lock().expect("executions").last(),
                Some(&vec![expected])
            );
        }
        let mut appended = crate::test_helper::job(
            19,
            Bytes::from_static(&[19]),
            scope(8, None),
            expiry,
            None,
            None,
        );
        appended.ordering_key = ordering;
        block_on(system.enqueue_raw(appended, expiry)).expect("append after draining");
        let final_run = block_on(system.drive(one_claim_drive_request(), expiry, || {
            MonotonicDeadline::ZERO
        }))
        .expect("new tail runs");
        assert_eq!(final_run.counts.succeeded, 1);
        assert_eq!(
            *executions.lock().expect("executions"),
            (1..=19).map(|id| vec![id]).collect::<Vec<_>>()
        );
    }
}

fn weighted_recording_system(
    weights: [u16; 3],
    executions: Arc<Mutex<Vec<Vec<u8>>>>,
) -> crate::JobSystem<crate::FakeStore> {
    let mut registry = crate::HandlerRegistry::new();
    for (kind, weight) in ["direct", "first-child", "second-child"]
        .into_iter()
        .zip(weights)
    {
        registry
            .register(HandlerDefinition {
                kind: JobKind::try_new(kind).unwrap(),
                schema_version: nz16(1),
                queue: crate::QueueName::try_new("default").unwrap(),
                effect_mode: EffectMode::Idempotent,
                cost_units: nz16(1),
                fairness_policy: FairnessPolicy::from(nz16(weight)),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: RecordingHandler {
                    executions: Arc::clone(&executions),
                },
            })
            .unwrap();
    }
    crate::JobSystem::new(
        crate::FakeStore::new(),
        crate::JobCatalog::from_registry(registry),
        Namespace::try_new(b"jobs").unwrap(),
        OwnerId::from([41; 16]),
        crate::test_helper::wake_scheduler(),
    )
}

fn enqueue_weighted_family(system: &crate::JobSystem<crate::FakeStore>, reverse: bool) {
    for (position, (kind, child)) in [
        ("direct", None),
        ("first-child", Some(2)),
        ("second-child", Some(3)),
    ]
    .into_iter()
    .enumerate()
    {
        let id = if reverse {
            3 - position as u8
        } else {
            position as u8 + 1
        };
        let mut job = crate::test_helper::job(
            id,
            Bytes::copy_from_slice(kind.as_bytes()),
            scope(1, child),
            Timestamp::ZERO,
            None,
            None,
        );
        job.kind = JobKind::try_new(kind).unwrap();
        block_on(system.enqueue_raw(job, Timestamp::ZERO)).unwrap();
    }
}

#[derive(Default)]
struct FairnessErrorObserver {
    errors: Mutex<Vec<crate::observer::SafeJobErrorEvent>>,
}

impl crate::observer::JobObserver for FairnessErrorObserver {
    fn observe(&self, _event: crate::observer::JobEvent) {}

    fn observe_error(&self, event: crate::observer::SafeJobErrorEvent) {
        self.errors.lock().unwrap().push(event);
    }
}

#[test]
fn given_conflicting_family_weights_when_driving_in_either_order_then_unrelated_work_completes() {
    for weights in [[1, 1, 16], [16, 1, 1]] {
        for reverse in [false, true] {
            let executions = Arc::new(Mutex::new(Vec::new()));
            let observer = Arc::new(FairnessErrorObserver::default());
            let system = weighted_recording_system(weights, Arc::clone(&executions))
                .with_observer(observer.clone());
            enqueue_weighted_family(&system, reverse);
            let mut independent = crate::test_helper::job(
                90,
                Bytes::from_static(b"unrelated"),
                scope(9, None),
                Timestamp::ZERO,
                None,
                None,
            );
            independent.kind = JobKind::try_new("direct").unwrap();
            block_on(system.enqueue_raw(independent, Timestamp::ZERO)).unwrap();
            let report = block_on(
                system.drive(one_claim_drive_request(), Timestamp::ZERO, || {
                    MonotonicDeadline::ZERO
                }),
            )
            .unwrap();
            assert_eq!(report.counts.succeeded, 1);
            assert_eq!(
                observer.errors.lock().unwrap().as_slice(),
                [crate::observer::SafeJobErrorEvent {
                    kind: crate::observer::SafeJobErrorKind::InvariantViolation,
                    queue: None,
                    effect_mode: None,
                }]
            );
            assert_eq!(
                executions.lock().unwrap().as_slice(),
                [b"unrelated".to_vec()]
            );
            let owner = block_on(FairDispatchOwner::load(&system)).unwrap().unwrap();
            let family = FairScope::from(scope(1, None));
            assert_eq!(
                owner.ledger().scope_snapshot(&family).unwrap().served_cost,
                0
            );
        }
    }
}

#[test]
fn given_consistent_family_weights_when_driving_then_direct_and_child_work_complete() {
    let executions = Arc::new(Mutex::new(Vec::new()));
    let system = weighted_recording_system([2, 2, 2], Arc::clone(&executions));
    enqueue_weighted_family(&system, false);
    for _ in 0..3 {
        let report = block_on(
            system.drive(one_claim_drive_request(), Timestamp::ZERO, || {
                MonotonicDeadline::ZERO
            }),
        )
        .unwrap();
        assert_eq!(report.counts.succeeded, 1);
    }
    let mut completed = executions.lock().unwrap().clone();
    completed.sort();
    assert_eq!(
        completed,
        [
            b"direct".to_vec(),
            b"first-child".to_vec(),
            b"second-child".to_vec()
        ]
    );
}
