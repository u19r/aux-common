use crate::{
    FairnessPolicy, FakeStore, JobId, RemoteJobClaim, Timestamp,
    test_helper::{block_on, low_volume_job, system},
};

#[test]
fn given_real_replacement_claims_when_registering_remote_authority_then_only_newer_same_job_claims_replace()
 {
    let store = FakeStore::new();
    let first = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let second = system(store, FairnessPolicy::low_volume(), 2);
    let id = JobId::from([1; 16]);
    block_on(first.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let old = block_on(first.claim(id, Timestamp::ZERO)).unwrap();
    let old = RemoteJobClaim::from(&old.context().unwrap());
    let new = block_on(second.claim(id, Timestamp::from_millis(1000))).unwrap();
    let new = RemoteJobClaim::from(&new.context().unwrap());
    assert!(new.is_replacement_of(&old));
    assert!(!old.is_replacement_of(&new));
    assert!(!new.is_replacement_of(&new));
    assert_eq!(old.job_key().unwrap(), new.job_key().unwrap());
    let mut old_identity = b"chunk".to_vec();
    let mut new_identity = old_identity.clone();
    old.bind_request_identity(&mut old_identity);
    new.bind_request_identity(&mut new_identity);
    assert_eq!(old_identity, new_identity);

    let encoded = serde_json::to_value(&new).unwrap();
    let decoded: RemoteJobClaim = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(decoded, new);
    assert_eq!(format!("{new:?}"), "RemoteJobClaim(<redacted>)");
    let mut foreign = encoded;
    foreign["namespace"] = serde_json::json!([102, 111, 114, 101, 105, 103, 110]);
    let foreign: RemoteJobClaim = serde_json::from_value(foreign).unwrap();
    assert!(!foreign.is_replacement_of(&old));
    assert_ne!(foreign.job_key().unwrap(), old.job_key().unwrap());
}

#[test]
fn given_untrusted_remote_claims_when_decoding_then_invalid_authority_and_versions_are_rejected() {
    let engine = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    block_on(engine.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(JobId::from([2; 16]), Timestamp::ZERO)).unwrap();
    let encoded = serde_json::to_value(RemoteJobClaim::from(&claim.context().unwrap())).unwrap();
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("generation", serde_json::json!(0)),
        ("fence", serde_json::json!(0)),
        ("namespace", serde_json::json!([])),
        ("token", serde_json::json!([1])),
        ("unknown", serde_json::json!(true)),
    ] {
        let mut invalid = encoded.clone();
        invalid[field] = value;
        assert!(
            serde_json::from_value::<RemoteJobClaim>(invalid).is_err(),
            "{field}"
        );
    }
    let mut changed = encoded.clone();
    changed["owner"] = serde_json::to_value([3u8; 16]).unwrap();
    let current: RemoteJobClaim = serde_json::from_value(encoded).unwrap();
    let changed: RemoteJobClaim = serde_json::from_value(changed).unwrap();
    assert_ne!(changed, current);
    assert!(!changed.is_replacement_of(&current));
}
