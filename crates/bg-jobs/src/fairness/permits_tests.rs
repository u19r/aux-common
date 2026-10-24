use std::num::{NonZeroU16, NonZeroU32};

use bytes::Bytes;

use super::{find_available_permit_keys, find_owned_permit_keys, find_reclaimable_permit_keys};
use crate::{
    FairnessPolicy, Timestamp, keys,
    store::{StoreCapabilities, StoreCapabilitiesInput},
    test_helper::{FakeStore, block_on, job, scoped_fairness, system},
};

#[test]
fn given_a_small_get_many_limit_when_recovering_a_distant_permit_then_the_complete_set_is_found() {
    let store = store_with_get_many_limit(100);
    let system = system(store.clone(), FairnessPolicy::from(NonZeroU16::MIN), 91);
    let new_job = job(
        91,
        Bytes::from_static(b"payload"),
        scoped_fairness(),
        Timestamp::ZERO,
        None,
        None,
    );
    let job_id = new_job.job_id;
    block_on(system.enqueue_raw(new_job, Timestamp::ZERO)).expect("job enqueues");
    let claim = block_on(system.claim(job_id, Timestamp::ZERO)).expect("job claims");
    let record = claim.record().clone();
    let first_permit = claim
        .permit_keys()
        .first()
        .expect("scoped claim owns a permit")
        .clone();
    store
        .delete_raw(&first_permit)
        .expect("initial permit is removed");

    let capacity = NonZeroU16::new(keys::MAX_DURABLE_PERMIT_SLOTS)
        .expect("durable permit capacity is non-zero");
    let distant_permit = keys::permit_key_sets(system.namespace(), &record, capacity)
        .expect("permit key-space encodes")
        .into_iter()
        .nth(1_000)
        .and_then(|set| set.into_iter().next())
        .expect("distant permit exists");
    store
        .put_raw(
            distant_permit.clone(),
            keys::permit_value_for_record(&record).expect("permit value encodes"),
        )
        .expect("distant permit is stored");

    let owned = block_on(find_owned_permit_keys(&system, &record))
        .expect("owned permit discovery succeeds");
    let reclaimable = block_on(find_reclaimable_permit_keys(&system, &record))
        .expect("reclaimable permit discovery succeeds");

    assert_eq!(owned, vec![distant_permit.clone()]);
    assert_eq!(reclaimable, Some(vec![distant_permit]));
}

#[test]
fn given_a_small_get_many_limit_when_selecting_a_distant_slot_then_the_complete_set_is_found() {
    let store = store_with_get_many_limit(100);
    let system = system(store.clone(), FairnessPolicy::from(NonZeroU16::MIN), 92);
    let new_job = job(
        92,
        Bytes::from_static(b"payload"),
        scoped_fairness(),
        Timestamp::ZERO,
        None,
        None,
    );
    let job_id = new_job.job_id;
    block_on(system.enqueue_raw(new_job, Timestamp::ZERO)).expect("job enqueues");
    let claim = block_on(system.claim(job_id, Timestamp::ZERO)).expect("job claims");
    let record = claim.record().clone();
    let capacity = NonZeroU16::new(keys::MAX_DURABLE_PERMIT_SLOTS)
        .expect("durable permit capacity is non-zero");
    let sets = keys::permit_key_sets(system.namespace(), &record, capacity)
        .expect("permit key-space encodes");
    let occupied_value = keys::permit_value_for_record(&record).expect("permit value encodes");
    for set in sets.iter().take(1_000) {
        for key in set {
            store
                .put_raw(key.clone(), occupied_value.clone())
                .expect("occupied permit is stored");
        }
    }

    let available = block_on(find_available_permit_keys(&system, &record, capacity))
        .expect("available permit discovery succeeds");

    assert_eq!(available, sets.get(1_000).cloned());
}

fn store_with_get_many_limit(limit: u32) -> FakeStore {
    let defaults = FakeStore::local().capabilities();
    let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
        level: defaults.level(),
        max_key_bytes: defaults.max_key_bytes(),
        max_value_bytes: defaults.max_value_bytes(),
        max_get_many_keys: NonZeroU32::new(limit).expect("test limit is non-zero"),
        max_get_many_key_bytes: defaults.max_get_many_key_bytes(),
        max_transaction_bytes: defaults.max_transaction_bytes(),
        max_transaction_keys: defaults.max_transaction_keys(),
        max_range_items: defaults.max_range_items(),
        max_range_bytes: defaults.max_range_bytes(),
        max_transaction_duration: defaults.max_transaction_duration(),
    })
    .expect("test capabilities are valid");
    FakeStore::with_capabilities(capabilities)
}
