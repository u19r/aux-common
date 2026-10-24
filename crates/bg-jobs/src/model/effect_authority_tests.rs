use crate::{
    FairnessPolicy, FakeStore, JobId, JobStore, Timestamp,
    codec::encode_job_record,
    test_helper::{block_on, low_volume_job, system},
};

#[test]
fn given_renewed_claim_when_validating_destination_authority_then_witness_remains_valid() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let mut claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    let authority = claim.context().unwrap().effect_authority().unwrap();
    block_on(system.heartbeat(&mut claim, Timestamp::from_millis(500))).unwrap();
    let bytes = block_on(store.get_many(authority.observation_keys())).unwrap();
    assert!(
        authority
            .matches_observations(&bytes, Timestamp::from_millis(1000))
            .unwrap()
    );
    assert!(
        !authority
            .matches_observations(&bytes, Timestamp::from_millis(1500))
            .unwrap()
    );
    assert_eq!(format!("{authority:?}"), "JobEffectAuthority(<redacted>)");
}

#[test]
fn given_replacement_claim_when_validating_old_effect_authority_then_stale_owner_is_rejected() {
    let store = FakeStore::new();
    let first = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let second = system(store.clone(), FairnessPolicy::low_volume(), 2);
    let id = JobId::from([2; 16]);
    block_on(first.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let old = block_on(first.claim(id, Timestamp::ZERO)).unwrap();
    let authority = old.context().unwrap().effect_authority().unwrap();
    let current = block_on(second.claim(id, Timestamp::from_millis(1000))).unwrap();
    let new_authority = current.context().unwrap().effect_authority().unwrap();
    let bytes = block_on(store.get_many(authority.observation_keys())).unwrap();
    assert!(
        !authority
            .matches_observations(&bytes, Timestamp::from_millis(1000))
            .unwrap()
    );
    assert!(
        new_authority
            .matches_observations(&bytes, Timestamp::from_millis(1000))
            .unwrap()
    );
    let mut old_identity = b"destination-request".to_vec();
    let mut new_identity = old_identity.clone();
    authority.bind_request_identity(&mut old_identity);
    new_authority.bind_request_identity(&mut new_identity);
    assert_eq!(
        old_identity, new_identity,
        "replay follows the logical execution"
    );
}

#[test]
fn given_foreign_or_inactive_records_when_validating_effect_authority_then_they_are_rejected() {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([3; 16]);
    block_on(system.enqueue_raw(low_volume_job(3, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(id, Timestamp::ZERO)).unwrap();
    let authority = claim.context().unwrap().effect_authority().unwrap();
    let mut foreign = claim.record().clone();
    foreign.namespace = crate::Namespace::try_new(b"foreign").unwrap();
    assert!(
        !authority
            .matches_observations(
                &[Some(encode_job_record(&foreign).unwrap()), None],
                Timestamp::ZERO
            )
            .unwrap()
    );
    foreign = claim.record().clone();
    foreign.job_id = JobId::from([4; 16]);
    assert!(
        !authority
            .matches_observations(
                &[Some(encode_job_record(&foreign).unwrap()), None],
                Timestamp::ZERO
            )
            .unwrap()
    );
    assert!(
        authority
            .matches_observations(
                &[Some(bytes::Bytes::from_static(b"corrupt")), None],
                Timestamp::ZERO
            )
            .is_err()
    );
    block_on(system.request_job_cancellation(&claim, Timestamp::ZERO)).unwrap();
    let requested = block_on(store.get_many(authority.observation_keys())).unwrap();
    assert!(
        !authority
            .matches_observations(&requested, Timestamp::ZERO)
            .unwrap()
    );
    block_on(system.cancel_claim(claim, Timestamp::ZERO)).unwrap();
    let bytes = block_on(store.get_many(authority.observation_keys())).unwrap();
    assert!(
        !authority
            .matches_observations(&bytes, Timestamp::ZERO)
            .unwrap()
    );
}
