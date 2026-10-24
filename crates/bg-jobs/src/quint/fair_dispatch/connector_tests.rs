use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::Duration,
};

use bytes::Bytes;

use super::driver::FairDispatchDriver;
use crate::{
    DriveRequest, DriveRequestInput, EffectMode, FairnessClass, FairnessPolicy, FakeStore, JobId,
    JobKind, MonotonicDeadline, QueueSelection, RetryPolicy, RetryPreset, Timestamp,
    drive::{FairDispatchCandidateSpec, fair_dispatch_batch_start, fair_dispatch_configure},
    fairness::{FairCandidateMetadata, FairVolumeMode},
    keys,
    model::JobState,
    store::{CommitOutcome, JobStore},
    test_helper::{block_on, job, system},
};

fn request() -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: NonZeroU32::MIN,
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::new(1024).expect("bytes are non-zero"),
        max_completion_details: 1,
        max_store_operations: NonZeroU32::new(64).expect("operations are non-zero"),
        stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid")
}

#[test]
fn public_drive_reuses_one_fair_owner_across_calls() {
    let store = FakeStore::distributed();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 91);
    let job_id = JobId::from([91; 16]);
    block_on(system.enqueue_raw(
        job(
            job_id.as_bytes()[0],
            Bytes::from_static(b"real"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");

    let first = block_on(system.drive(request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("first drive commits");
    let second = block_on(system.drive(request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("second drive commits");

    assert_eq!(first.counts.claimed, 1);
    assert_eq!(second.counts.claimed, 0);
    let owner_key = keys::fair_state_key(system.namespace()).expect("owner key is valid");
    assert!(
        block_on(store.get(owner_key))
            .expect("owner state read")
            .is_some()
    );
    let job_key = keys::job_key(system.namespace(), &job_id).expect("job key is valid");
    assert!(
        block_on(store.get(job_key))
            .expect("job state read")
            .is_none()
    );
}

#[test]
fn given_a_batch_failure_when_rollback_is_reentered_then_all_claims_are_released() {
    let store = FakeStore::distributed();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 92);
    for id in [1, 2] {
        block_on(fair_dispatch_configure(
            &system,
            candidate_spec(id),
            Timestamp::ZERO,
        ))
        .expect("candidate configuration commits");
    }

    // Both claims and the batch formation attempt reach the owner.  The
    // failed formation is followed by independent rollback attempts; the
    // second rollback must still run if the first rollback path is
    // re-entered after a conflict.
    for outcome in [
        CommitOutcome::Committed,
        CommitOutcome::Committed,
        CommitOutcome::Committed,
        CommitOutcome::Committed,
        CommitOutcome::Conflict,
        CommitOutcome::Conflict,
        CommitOutcome::Committed,
        CommitOutcome::Committed,
        CommitOutcome::Committed,
    ] {
        store
            .queue_commit_outcome(outcome)
            .expect("queued commit outcome");
    }
    assert!(
        block_on(fair_dispatch_batch_start(
            &system,
            JobId::from([1; 16]),
            JobId::from([2; 16]),
            3,
            Timestamp::ZERO,
        ))
        .is_err()
    );

    for id in [1, 2] {
        let key =
            keys::job_key(system.namespace(), &JobId::from([id; 16])).expect("job key is valid");
        let encoded = block_on(store.get(key))
            .expect("job state read")
            .expect("job record remains after rollback");
        let record = crate::codec::decode_job_record(&encoded).expect("job record decodes");
        assert!(
            matches!(record.state, JobState::Scheduled),
            "job {id} was not rolled back: {:?}",
            record.state
        );
    }
}

fn candidate_spec(id: u8) -> FairDispatchCandidateSpec {
    FairDispatchCandidateSpec {
        job_id: JobId::from([id; 16]),
        payload: Bytes::from_static(b"payload"),
        fairness: FairnessClass::low_volume(),
        volume_mode: FairVolumeMode::LowVolume,
        priority: crate::Priority::Default,
        cost_units: NonZeroU16::MIN,
        scheduled_at: Timestamp::ZERO,
        ordering_key: None,
        ordering_position: u64::from(id),
        metadata: FairCandidateMetadata {
            handler_kind: JobKind::try_new("email").expect("handler kind is valid"),
            schema_version: NonZeroU16::MIN,
            batch_key: crate::BatchKey::new(1),
            auth_config: crate::AuthConfigId::new(1),
            effect_mode: EffectMode::Idempotent,
            retry_policy: RetryPolicy::preset(RetryPreset::Network),
            timeout: Duration::from_secs(1),
            enqueued_at: Timestamp::ZERO,
            batch_deadline: Timestamp::from_millis(4),
        },
    }
}

#[test]
fn fixed_bulk_seed_uses_real_enqueue_and_owner_projection() {
    let mut driver = FairDispatchDriver::default();
    driver
        .apply_action_for_test("fixedBulkSeedTrace")
        .expect("bulk seed crosses real boundaries");
    let projection = driver.projection_for_test();
    assert_eq!(
        projection.jobs[&super::types::JobId::JobC].state,
        super::types::JobState::Scheduled
    );
    assert!(projection.scopes[&super::types::Scope::ScopeA1].ready);
    assert_eq!(
        projection.scopes[&super::types::Scope::ScopeA1].mode,
        super::types::VolumeMode::LowVolume
    );
    assert_eq!(projection.meta.batch_scope, super::types::Scope::ScopeA);
}

#[test]
fn fixed_primary_batch_resolves_real_claims_and_clears_scratch() {
    let mut driver = FairDispatchDriver::default();
    for _ in 0..5 {
        driver
            .apply_action_for_test("fixedPrimaryBatchTrace")
            .expect("primary batch action crosses real boundaries");
    }
    let projection = driver.projection_for_test();
    assert!(!projection.meta.batch_active);
    assert_eq!(
        projection.jobs[&super::types::JobId::JobA].state,
        super::types::JobState::Absent
    );
    assert_eq!(
        projection.jobs[&super::types::JobId::JobB].state,
        super::types::JobState::DeadLettered
    );
}

#[test]
fn fixed_secondary_batch_claims_both_child_and_primary_permits() {
    let mut driver = FairDispatchDriver::default();
    for _ in 0..3 {
        driver
            .apply_action_for_test("fixedSecondaryBatchTrace")
            .expect("secondary batch action crosses real boundaries");
    }
    let projection = driver.projection_for_test();
    assert!(projection.meta.batch_active);
    assert_eq!(projection.meta.batch_members.len(), 2);
    assert_eq!(projection.meta.batch_scope, super::types::Scope::ScopeA);
    assert_eq!(
        projection.scopes[&super::types::Scope::ScopeA2].mode,
        super::types::VolumeMode::ScopedVolume
    );
    assert_eq!(
        projection.scopes[&super::types::Scope::ScopeA2].in_flight,
        2
    );
    assert_eq!(projection.scopes[&super::types::Scope::ScopeA].in_flight, 2);
}

#[test]
fn fixed_batch_rejection_rolls_back_real_claims() {
    let mut driver = FairDispatchDriver::default();
    for _ in 0..3 {
        driver
            .apply_action_for_test("fixedBatchRejectionTrace")
            .expect("batch rejection action crosses real boundaries");
    }
    let projection = driver.projection_for_test();
    assert!(!projection.meta.batch_active);
    assert_eq!(
        projection.jobs[&super::types::JobId::JobA].state,
        super::types::JobState::Scheduled
    );
    assert_eq!(
        projection.jobs[&super::types::JobId::JobB].state,
        super::types::JobState::Scheduled
    );
    assert_eq!(projection.scopes[&super::types::Scope::ScopeA].in_flight, 0);
    assert_eq!(projection.meta.service_transitions, 0);
    assert_eq!(
        projection.result,
        super::types::CommandResult::FairRejected(projection.transition.clone())
    );
}

#[test]
fn real_scratch_rejects_clear_until_batch_items_are_terminal() {
    let mut driver = FairDispatchDriver::default();
    for _ in 0..3 {
        driver
            .apply_action_for_test("fixedPrimaryBatchTrace")
            .expect("primary batch action crosses real boundaries");
    }
    driver
        .apply_action_for_test("FairScratch")
        .expect("scratch rejection crosses the real boundary");
    let projection = driver.projection_for_test();
    assert!(projection.meta.batch_active);
    assert_eq!(projection.meta.batch_results.len(), 2);
    assert_eq!(
        projection.result,
        super::types::CommandResult::FairRejected(projection.transition.clone())
    );
}

#[test]
fn service_unit_uses_real_claim_and_retry_route() {
    let mut driver = FairDispatchDriver::default();
    driver
        .apply_action_for_test("FairService")
        .expect("service unit crosses real claim and outcome boundaries");
    let projection = driver.projection_for_test();
    assert_eq!(
        projection.jobs[&super::types::JobId::JobA].state,
        super::types::JobState::RetryWaiting
    );
    assert_eq!(
        projection.jobs[&super::types::JobId::JobA].service_transitions,
        2
    );
    assert_eq!(projection.scopes[&super::types::Scope::ScopeA].in_flight, 0);
    assert_eq!(projection.meta.selected_job, super::types::JobId::JobA);
    assert_eq!(projection.meta.selected_scope, super::types::Scope::ScopeA);
    assert_eq!(projection.meta.selected_cost, 2);
    assert_eq!(
        projection.meta.last_outcome,
        super::types::FairOutcome::SelectionServed
    );
}

#[test]
fn ordinary_select_does_not_record_hol_escape() {
    let mut driver = FairDispatchDriver::default();
    driver
        .apply_action_for_test("FairSelect")
        .expect("ordinary selection crosses real claim boundary");
    let projection = driver.projection_for_test();
    assert_eq!(projection.meta.hol_escapes, 0);
    assert_eq!(
        projection.jobs[&super::types::JobId::JobA].state,
        super::types::JobState::Leased
    );
    let scope = &projection.scopes[&super::types::Scope::ScopeA];
    assert_eq!(scope.permits, 1);
    assert_eq!(scope.rate, 2);
    assert_eq!(scope.in_flight, 1);
}

#[test]
fn live_authority_candidate_is_rejected_by_the_real_owner() {
    let mut driver = FairDispatchDriver::default();
    driver
        .apply_action_for_test("fixedLiveAuthorityCandidateTrace")
        .expect("live select crosses real boundaries");
    driver
        .apply_action_for_test("fixedLiveAuthorityCandidateTrace")
        .expect("leased replacement is rejected by real owner");
    let projection = driver.projection_for_test();
    assert_eq!(
        projection.jobs[&super::types::JobId::JobA].state,
        super::types::JobState::Leased
    );
    assert_eq!(
        projection.result,
        super::types::CommandResult::FairRejected(projection.transition.clone())
    );
}
