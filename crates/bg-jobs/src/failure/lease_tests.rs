use std::num::NonZeroU64;

use crate::{
    codec::encode_job_record,
    test_helper::{block_on, low_volume_job, system},
    *,
};

fn successor_record(claim: &ClaimedJob) -> JobRecordV1 {
    let mut successor = claim.record().clone();
    successor.revision += 1;
    successor.state = JobState::Leased(
        Lease::try_new(
            OwnerId::from([2; 16]),
            LeaseToken::from([4; 16]),
            NonZeroU64::new(2).expect("fence is non-zero"),
            Timestamp::from_millis(5_000),
        )
        .expect("lease is valid"),
    );
    successor
}

fn replace_authority(store: &FakeStore, system: &JobSystem<FakeStore>, claim: &ClaimedJob) {
    let id = claim.record().job_id;
    store
        .put_raw(
            crate::keys::job_key(system.namespace(), &id).expect("job key is valid"),
            encode_job_record(&successor_record(claim)).expect("successor encodes"),
        )
        .expect("successor write succeeds");
    store
        .put_raw(
            crate::keys::lease_key(system.namespace(), &claim.record().queue, &id)
                .expect("lease key is valid"),
            crate::keys::lease_value(&id).expect("lease value is valid"),
        )
        .expect("successor lease route succeeds");
}

#[test]
fn given_a_claim_when_heartbeats_arrive_within_the_margin_then_renewal_is_coalesced() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");

    let first = block_on(system.renew(&mut claim, Timestamp::ZERO)).expect("renew commits");
    assert!(matches!(first, RenewalResult::Renewed { .. }));
    let coalesced = block_on(system.renew(&mut claim, Timestamp::from_millis(50)))
        .expect("coalesced heartbeat succeeds");
    assert!(matches!(coalesced, RenewalResult::Coalesced { .. }));
    let second = block_on(system.renew(&mut claim, Timestamp::from_millis(100)))
        .expect("renew after margin commits");
    assert!(matches!(second, RenewalResult::Renewed { .. }));
}

#[test]
fn given_a_clock_rollback_when_renewing_then_expiry_never_moves_backwards() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([2; 16]);
    block_on(system.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let renewed =
        block_on(system.renew(&mut claim, Timestamp::from_millis(500))).expect("renew commits");
    let before = match renewed {
        RenewalResult::Renewed { expires_at } => expires_at,
        RenewalResult::Coalesced { .. } => panic!("first heartbeat must renew"),
    };
    let after = block_on(system.renew(&mut claim, Timestamp::from_millis(50)))
        .expect("rollback heartbeat is coalesced");
    let after = match after {
        RenewalResult::Renewed { expires_at } | RenewalResult::Coalesced { expires_at } => {
            expires_at
        }
    };
    assert!(after >= before);
}

#[test]
fn given_a_live_lease_when_renewing_before_its_expiry_then_extension_is_from_now() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([11; 16]);
    block_on(system.enqueue_raw(low_volume_job(11, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");

    let first = block_on(system.renew(&mut claim, Timestamp::ZERO)).expect("first renew commits");
    assert_eq!(
        first,
        RenewalResult::Renewed {
            expires_at: Timestamp::from_millis(1_000)
        }
    );
    let second = block_on(system.renew(&mut claim, Timestamp::from_millis(200)))
        .expect("second renew commits");
    assert_eq!(
        second,
        RenewalResult::Renewed {
            expires_at: Timestamp::from_millis(1_200)
        }
    );
}

#[test]
fn given_a_running_attempt_when_renewal_rotates_operation_then_public_cancel_wakes_it() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 12);
    let id = JobId::from([12; 16]);
    block_on(system.enqueue_raw(low_volume_job(12, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let cancellation = claim.cancellation();
    let initial_authority = crate::engine::AttemptAuthority::new(
        id,
        claim.operation_id(),
        claim.fence_high_water(),
        claim.attempt_id(),
    );
    let initial_operation = claim.operation_id();
    let registration = system.register_attempt_guard(initial_authority, cancellation.clone());

    assert!(matches!(
        block_on(system.renew(&mut claim, Timestamp::from_millis(200))).expect("renew commits"),
        RenewalResult::Renewed { .. }
    ));
    assert_ne!(claim.operation_id(), initial_operation);
    assert!(!cancellation.is_cancelled());

    assert_eq!(
        block_on(system.cancel_job(id, Timestamp::from_millis(201))).expect("cancel commits"),
        CancellationResult::Requested
    );
    assert!(
        cancellation.is_cancelled(),
        "public cancellation must wake the renewed running attempt"
    );

    drop(registration);
}

#[test]
fn given_a_lost_token_or_fence_when_renewing_then_the_claim_is_cancelled() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([3; 16]);
    block_on(system.enqueue_raw(low_volume_job(3, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    replace_authority(&store, &system, &claim);

    assert!(matches!(
        block_on(system.renew(&mut claim, Timestamp::from_millis(1))),
        Err(JobSystemError::LeaseLost)
    ));
    assert!(claim.cancellation().is_cancelled());
}
