use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use bytes::Bytes;

use super::{
    codec::slot_key,
    state::{ActiveHead, Head, Phase},
};
use crate::{
    ids::{CommitOperationId, LeaseToken},
    policy::FairnessPolicy,
    store::{
        CommitOutcome, JobStore, Mutation, RangePage, RangeRequest, StoreCapabilities, StoreKey,
        StoreTransaction,
    },
    test_helper::{FakeStore, FakeStoreError, block_on, system},
};

#[derive(Clone)]
struct DelayedAtomicStore {
    inner: FakeStore,
    armed: Arc<AtomicBool>,
    delayed: Arc<Mutex<Option<StoreTransaction>>>,
    applies_before_unknown: bool,
}

impl JobStore for DelayedAtomicStore {
    type Error = FakeStoreError;
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.inner.get(key).await
    }
    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.inner.get_many(keys).await
    }
    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.inner.read_range(request).await
    }
    async fn transact(&self, input: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        if self.armed.swap(false, Ordering::SeqCst) {
            *self.delayed.lock().unwrap() = Some(input.clone());
            if self.applies_before_unknown {
                assert_eq!(self.inner.transact(input).await?, CommitOutcome::Committed);
            }
            return Ok(CommitOutcome::Unknown);
        }
        self.inner.transact(input).await
    }
}

fn command<S: JobStore>(engine: &crate::JobSystem<S>, value: &'static [u8]) -> StoreTransaction {
    engine
        .build_transaction(
            CommitOperationId::from([7; 16]),
            Vec::new(),
            vec![Mutation::Put(
                StoreKey::try_from(b"business".as_slice()).unwrap(),
                Bytes::from_static(value),
            )],
        )
        .unwrap()
}

#[test]
fn given_ambiguous_atomic_dispatch_when_input_is_accepted_or_result_observed_then_late_dispatch_is_fenced()
 {
    for applies_before_unknown in [false, true] {
        let inner = FakeStore::new();
        let delayed = Arc::new(Mutex::new(None));
        let store = DelayedAtomicStore {
            inner: inner.clone(),
            armed: Arc::new(AtomicBool::new(true)),
            delayed: delayed.clone(),
            applies_before_unknown,
        };
        let engine = crate::JobSystem::new(
            store,
            crate::JobCatalog::new(),
            crate::Namespace::try_new(b"jobs").unwrap(),
            crate::OwnerId::from([1; 16]),
            crate::test_helper::wake_scheduler(),
        );
        assert_eq!(
            block_on(engine.commit_durable(command(&engine, b"first"))).unwrap(),
            CommitOutcome::Committed
        );
        let old = delayed.lock().unwrap().take().unwrap();
        let slot = old.mutations().last().unwrap().key();
        if applies_before_unknown {
            let witness = block_on(inner.get(slot.clone())).unwrap().unwrap();
            let head = Head::decode(&witness).unwrap();
            assert!(matches!(
                head,
                Head::Active(ActiveHead {
                    chunks: 0,
                    phase: Phase::Committed,
                    ..
                })
            ));
            let changed = command(&engine, b"changed");
            let Head::Active(active) = head else {
                unreachable!()
            };
            let previous = super::state::Slot {
                index: 7,
                key: slot.clone(),
                encoded: None,
                head: Head::Vacant(0),
            };
            assert!(
                block_on(engine.reserve_commit_input(
                    &previous,
                    &changed,
                    active.token,
                    Phase::Prepared
                ))
                .is_err()
            );
        }
        let second = command(&engine, b"second");
        let second = engine
            .build_transaction(
                CommitOperationId::from([8; 16]),
                second.checks().to_vec(),
                second.mutations().to_vec(),
            )
            .unwrap();
        assert_eq!(
            block_on(engine.commit_durable(second)).unwrap(),
            CommitOutcome::Committed
        );
        assert_eq!(
            block_on(inner.transact(&old)).unwrap(),
            CommitOutcome::Conflict,
            "the slot guard must reject late dispatch even without business checks"
        );
        assert_eq!(
            block_on(inner.get(StoreKey::try_from(b"business".as_slice()).unwrap())).unwrap(),
            Some(Bytes::from_static(b"second"))
        );
        assert!(inner.snapshot().unwrap().iter().all(|(key, _)| {
            crate::codec::KeyCodec::decode_borrowed(engine.namespace(), key)
                .map_or(true, |key| key.tag != crate::codec::KeyTag::CommitInput)
        }));
    }
}

#[test]
fn given_an_unacknowledged_completed_pool_when_replacement_recovers_then_only_reconciled_witnesses_can_be_reused()
 {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    for index in 0..=u8::MAX {
        let head = Head::Active(ActiveHead {
            generation: 1,
            command_id: CommitOperationId::from([index; 16]),
            token: LeaseToken::from([index; 16]),
            chunks: 0,
            input_bytes: 0,
            binding: [index; 32],
            phase: Phase::Committed,
        });
        store
            .put_raw(slot_key(engine.namespace(), index).unwrap(), head.encode())
            .unwrap();
    }
    let before = store.snapshot().unwrap();
    assert!(matches!(
        block_on(engine.commit_durable(command(&engine, b"unaccepted"))),
        Err(crate::JobSystemError::StoreContract(
            crate::StoreContractError::CommitCapacity
        ))
    ));
    assert_eq!(store.snapshot().unwrap(), before);
    assert_eq!(block_on(engine.recover_commits()).unwrap(), 256);
    assert_eq!(
        store.snapshot().unwrap(),
        before,
        "reconciliation makes no native writes"
    );
    assert_eq!(block_on(engine.recover_commits()).unwrap(), 0);
    assert_eq!(
        block_on(engine.commit_durable(command(&engine, b"accepted"))).unwrap(),
        CommitOutcome::Committed
    );
    assert_eq!(store.snapshot().unwrap().len(), 257);
}

fn limited_capabilities(max_value_bytes: usize) -> StoreCapabilities {
    use std::num::{NonZeroU32, NonZeroUsize};

    use crate::store::{StoreCapabilitiesInput, StoreLevel};
    StoreCapabilities::try_from(StoreCapabilitiesInput {
        level: StoreLevel::Local,
        max_key_bytes: NonZeroUsize::new(128).unwrap(),
        max_value_bytes: NonZeroUsize::new(max_value_bytes).unwrap(),
        max_get_many_keys: NonZeroU32::new(8).unwrap(),
        max_get_many_key_bytes: NonZeroUsize::new(1024).unwrap(),
        max_transaction_bytes: NonZeroUsize::new(4096).unwrap(),
        max_transaction_keys: NonZeroU32::new(8).unwrap(),
        max_range_items: NonZeroU32::new(256).unwrap(),
        max_range_bytes: NonZeroUsize::new(65536).unwrap(),
        max_transaction_duration: std::time::Duration::from_secs(1),
    })
    .unwrap()
}

#[test]
fn given_a_native_key_limit_when_applying_and_recovering_then_witness_reuse_never_exceeds_it() {
    let capabilities = limited_capabilities(512);
    let store = FakeStore::with_capabilities(capabilities);
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let mutations = (0..6)
        .map(|index| {
            Mutation::Put(
                StoreKey::try_from(vec![index]).unwrap(),
                Bytes::from(vec![1; 200]),
            )
        })
        .collect::<Vec<_>>();
    for index in 0..3 {
        if index == 1 {
            store.queue_unknown_before_commit().unwrap();
        }
        let input = engine
            .build_transaction(
                CommitOperationId::from([index; 16]),
                Vec::new(),
                mutations.clone(),
            )
            .unwrap();
        assert_eq!(
            block_on(engine.commit_durable(input)).unwrap(),
            CommitOutcome::Committed
        );
    }
    let before = store.snapshot().unwrap();
    let mut oversized = mutations;
    oversized.push(Mutation::Delete(
        StoreKey::try_from(b"extra".as_slice()).unwrap(),
    ));
    let input = engine
        .build_transaction(CommitOperationId::from([9; 16]), Vec::new(), oversized)
        .unwrap();
    assert!(matches!(
        block_on(engine.commit_durable(input)),
        Err(crate::JobSystemError::StoreContract(_))
    ));
    assert_eq!(
        store.snapshot().unwrap(),
        before,
        "reject before atomic application"
    );
}

#[test]
fn given_a_native_valid_command_without_fallback_capacity_when_dispatching_then_it_is_rejected_before_any_native_attempt()
 {
    let inner = FakeStore::with_capabilities(limited_capabilities(83));
    let delayed = Arc::new(Mutex::new(None));
    let store = DelayedAtomicStore {
        inner: inner.clone(),
        armed: Arc::new(AtomicBool::new(true)),
        delayed: delayed.clone(),
        applies_before_unknown: false,
    };
    let engine = crate::JobSystem::new(
        store,
        crate::JobCatalog::new(),
        crate::Namespace::try_new(b"jobs").unwrap(),
        crate::OwnerId::from([1; 16]),
        crate::test_helper::wake_scheduler(),
    );
    let mutations = (0..6)
        .map(|index| {
            Mutation::Put(
                StoreKey::try_from(vec![index]).unwrap(),
                Bytes::from(vec![1; 83]),
            )
        })
        .collect();
    let input = engine
        .build_transaction(CommitOperationId::from([1; 16]), Vec::new(), mutations)
        .unwrap();
    let previous = block_on(engine.load_commit_slot(1)).unwrap();
    let completed = previous.replace(Head::Active(ActiveHead {
        generation: 1,
        command_id: input.operation_id(),
        token: LeaseToken::from([1; 16]),
        chunks: 0,
        input_bytes: 0,
        binding: input.binding(),
        phase: Phase::Committed,
    }));
    engine
        .build_slot_application(&previous, completed, &input)
        .unwrap();
    assert!(matches!(
        block_on(engine.commit_durable(input)),
        Err(crate::JobSystemError::StoreData(_))
    ));
    assert!(
        delayed.lock().unwrap().is_none(),
        "no ambiguous native attempt may escape the capacity check"
    );
    assert!(inner.snapshot().unwrap().is_empty());
}
