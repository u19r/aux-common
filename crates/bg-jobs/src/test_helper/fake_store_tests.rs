use std::num::{NonZeroU32, NonZeroUsize};

use bytes::Bytes;

use super::{
    block_on,
    fake_store::{FakeStore, FakeStoreError},
};
use crate::{
    CommitOperationId, JobSystem, Namespace, OwnerId,
    store::{
        Check, CommitOutcome, JobStore, Mutation, RangeDirection, RangeRequest, RangeRequestInput,
        StoreKey, StoreTransaction, StoreTransactionInput, TransactionLimits,
    },
};

fn request(direction: RangeDirection, continuation: Option<StoreKey>) -> RangeRequest {
    RangeRequest::try_from(RangeRequestInput {
        start: Some(StoreKey::try_from(&b"a"[..]).expect("start key is valid")),
        end: Some(StoreKey::try_from(&b"z"[..]).expect("end key is valid")),
        direction,
        item_limit: NonZeroU32::new(2).expect("item limit is non-zero"),
        byte_limit: NonZeroUsize::new(16).expect("byte limit is non-zero"),
        continuation,
    })
    .expect("range request is valid")
}

fn seed(store: &FakeStore) {
    for (key, value) in [
        (b"b".as_slice(), b"1".as_slice()),
        (b"c", b"2"),
        (b"d", b"3"),
    ] {
        let key = StoreKey::try_from(key).expect("seed key is valid");
        store
            .put_raw(key, Bytes::copy_from_slice(value))
            .expect("seed value is valid");
    }
}

#[test]
fn given_ordered_entries_when_reading_forward_pages_then_continuation_is_exclusive() {
    let store = FakeStore::new();
    seed(&store);
    let first = block_on(store.read_range(request(RangeDirection::Forward, None)))
        .expect("first page succeeds");
    let first_keys: Vec<_> = first
        .entries
        .iter()
        .map(|entry| entry.key.as_bytes().to_vec())
        .collect();
    assert_eq!(first_keys, vec![b"b".to_vec(), b"c".to_vec()]);
    let second = block_on(store.read_range(request(RangeDirection::Forward, first.continuation)))
        .expect("second page succeeds");
    assert_eq!(second.entries[0].key.as_bytes(), b"d");
    assert!(second.continuation.is_none());
}

#[test]
fn given_ordered_entries_when_reading_reverse_pages_then_continuation_is_exclusive() {
    let store = FakeStore::new();
    seed(&store);
    let first = block_on(store.read_range(request(RangeDirection::Reverse, None)))
        .expect("first page succeeds");
    assert_eq!(first.entries[0].key.as_bytes(), b"d");
    assert_eq!(first.entries[1].key.as_bytes(), b"c");
    let second = block_on(store.read_range(request(RangeDirection::Reverse, first.continuation)))
        .expect("second page succeeds");
    assert_eq!(second.entries[0].key.as_bytes(), b"b");
    assert!(second.continuation.is_none());
}

#[test]
fn given_a_checked_multi_key_commit_when_one_check_conflicts_then_no_mutation_is_visible() {
    let store = FakeStore::new();
    let existing = StoreKey::try_from(&b"existing"[..]).expect("key is valid");
    let new_key = StoreKey::try_from(&b"new"[..]).expect("key is valid");
    store
        .put_raw(existing.clone(), Bytes::from_static(b"current"))
        .expect("seed succeeds");
    let transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([1; 16]),
        checks: vec![Check::Value(existing, Bytes::from_static(b"stale"))],
        mutations: vec![Mutation::Put(new_key.clone(), Bytes::from_static(b"value"))],
        limits: TransactionLimits {
            max_checks: NonZeroU32::new(1).expect("check limit is non-zero"),
            max_mutations: NonZeroU32::new(1).expect("mutation limit is non-zero"),
            max_bytes: NonZeroUsize::new(64).expect("byte limit is non-zero"),
        },
    })
    .expect("transaction is valid");

    assert_eq!(
        block_on(store.commit(&transaction)).expect("commit succeeds"),
        CommitOutcome::Conflict
    );
    assert!(!store.contains(&new_key).expect("contains succeeds"));
}

#[test]
fn given_an_atomic_unknown_before_commit_when_reading_state_then_no_mutation_is_visible() {
    let store = FakeStore::new();
    let key = StoreKey::try_from(&b"new"[..]).expect("key is valid");
    store
        .queue_unknown_before_commit()
        .expect("queue unknown-before outcome");
    let transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([2; 16]),
        checks: vec![Check::Absent(key.clone())],
        mutations: vec![Mutation::Put(key.clone(), Bytes::from_static(b"value"))],
        limits: TransactionLimits {
            max_checks: NonZeroU32::new(1).expect("check limit is non-zero"),
            max_mutations: NonZeroU32::new(1).expect("mutation limit is non-zero"),
            max_bytes: NonZeroUsize::new(64).expect("byte limit is non-zero"),
        },
    })
    .expect("transaction is valid");

    assert_eq!(
        block_on(store.commit(&transaction)).expect("commit succeeds"),
        CommitOutcome::Unknown
    );
    assert!(!store.contains(&key).expect("contains succeeds"));
}

#[test]
fn given_the_same_commit_when_retried_then_the_established_outcome_is_replayed() {
    let store = FakeStore::new();
    let key = StoreKey::try_from(&b"retry"[..]).expect("key is valid");
    let transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([3; 16]),
        checks: vec![Check::Absent(key.clone())],
        mutations: vec![Mutation::Put(key, Bytes::from_static(b"value"))],
        limits: TransactionLimits {
            max_checks: NonZeroU32::MIN,
            max_mutations: NonZeroU32::MIN,
            max_bytes: NonZeroUsize::new(64).expect("byte limit is non-zero"),
        },
    })
    .expect("transaction is valid");

    let first = block_on(store.commit(&transaction)).expect("first commit succeeds");
    let retry = block_on(store.commit(&transaction)).expect("retry succeeds");

    assert_eq!(first, CommitOutcome::Committed);
    assert_eq!(retry, CommitOutcome::Committed);
}

#[test]
fn given_an_unknown_after_commit_when_retried_then_committed_is_reconciled_by_operation_id() {
    let store = FakeStore::new();
    let key = StoreKey::try_from(&b"unknown-retry"[..]).expect("key is valid");
    store
        .queue_unknown_after_commit()
        .expect("unknown-after outcome queues");
    let transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([4; 16]),
        checks: vec![Check::Absent(key.clone())],
        mutations: vec![Mutation::Put(key.clone(), Bytes::from_static(b"value"))],
        limits: TransactionLimits {
            max_checks: NonZeroU32::MIN,
            max_mutations: NonZeroU32::MIN,
            max_bytes: NonZeroUsize::new(64).expect("byte limit is non-zero"),
        },
    })
    .expect("transaction is valid");

    let first = block_on(store.commit(&transaction)).expect("first commit responds");
    let retry = block_on(store.commit(&transaction)).expect("retry reconciles");

    assert_eq!(first, CommitOutcome::Unknown);
    assert_eq!(retry, CommitOutcome::Committed);
    assert_eq!(
        block_on(store.get(key)).expect("value read succeeds"),
        Some(Bytes::from_static(b"value"))
    );
}

#[test]
fn given_a_commit_operation_id_when_reused_with_different_content_then_it_is_rejected() {
    let store = FakeStore::new();
    let operation_id = CommitOperationId::from([5; 16]);
    let first_key = StoreKey::try_from(&b"first"[..]).expect("first key is valid");
    let second_key = StoreKey::try_from(&b"second"[..]).expect("second key is valid");
    let transaction = |key: StoreKey| {
        StoreTransaction::try_from(StoreTransactionInput {
            operation_id,
            checks: vec![Check::Absent(key.clone())],
            mutations: vec![Mutation::Put(key, Bytes::from_static(b"value"))],
            limits: TransactionLimits {
                max_checks: NonZeroU32::MIN,
                max_mutations: NonZeroU32::MIN,
                max_bytes: NonZeroUsize::new(64).expect("byte limit is non-zero"),
            },
        })
        .expect("transaction is valid")
    };

    let first = block_on(store.commit(&transaction(first_key))).expect("first commit succeeds");
    let reused = block_on(store.commit(&transaction(second_key.clone())));

    assert_eq!(first, CommitOutcome::Committed);
    assert!(matches!(reused, Err(FakeStoreError::CommitOperationReused)));
    assert!(!store.contains(&second_key).expect("contains succeeds"));
}

#[test]
fn given_local_and_distributed_fake_stores_when_constructing_systems_then_mode_is_explicit() {
    let local = FakeStore::local();
    let distributed = FakeStore::distributed();
    assert!(!local.capabilities().is_distributed());
    assert!(distributed.capabilities().is_distributed());
    assert!(
        JobSystem::try_new_distributed(
            local,
            crate::JobCatalog::new(),
            Namespace::try_new(b"jobs").expect("namespace is valid"),
            OwnerId::from([1; 16]),
            crate::test_helper::wake_scheduler(),
        )
        .is_err()
    );
    assert!(
        JobSystem::try_new_distributed(
            distributed,
            crate::JobCatalog::new(),
            Namespace::try_new(b"jobs").expect("namespace is valid"),
            OwnerId::from([1; 16]),
            crate::test_helper::wake_scheduler(),
        )
        .is_ok()
    );
}
