use std::sync::{Arc, Mutex};

use bytes::Bytes;

use super::constants;
use crate::{
    store::{
        Check, CommitOutcome, JobStore, Mutation, RangePage, RangeRequest, StoreCapabilities,
        StoreKey, StoreTransaction,
    },
    test_helper::{block_on, low_volume_job, registry, system, wake_scheduler},
    *,
};

#[derive(Clone, Debug)]
enum SettlementCall {
    Get(StoreKey),
    Commit(StoreTransaction),
}

#[derive(Clone)]
struct UnknownWakeStore {
    inner: FakeStore,
    calls: Arc<Mutex<Vec<SettlementCall>>>,
}

impl JobStore for UnknownWakeStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.calls
            .lock()
            .unwrap()
            .push(SettlementCall::Get(key.clone()));
        self.inner.get(key).await
    }

    async fn get_many(&self, _keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        panic!("settlement reconciliation uses individual probes")
    }

    async fn read_range(&self, _request: RangeRequest) -> Result<RangePage, Self::Error> {
        panic!("conservative wake refresh must not rescan due routes")
    }

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        let commit_number = {
            let mut calls = self.calls.lock().unwrap();
            calls.push(SettlementCall::Commit(transaction.clone()));
            calls
                .iter()
                .filter(|call| matches!(call, SettlementCall::Commit(_)))
                .count()
        };
        match commit_number {
            1 | 3 | 4 => Ok(CommitOutcome::Unknown),
            2 => {
                let result = self.inner.commit(transaction).await;
                assert_eq!(
                    result,
                    Ok(CommitOutcome::Conflict),
                    "changed canonical wake causes a known abort"
                );
                result
            }
            _ => panic!("only exact Unknown replay and one known-abort rebase are permitted"),
        }
    }
}

fn settlement_system(store: UnknownWakeStore) -> JobSystem<UnknownWakeStore> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(registry(FairnessPolicy::low_volume())),
        Namespace::try_new(b"jobs").unwrap(),
        OwnerId::from([1; 16]),
        wake_scheduler(),
    )
}

fn prepare_changed_wake(inner: &FakeStore) -> (StoreKey, Bytes, StoreKey, Bytes) {
    let engine = system(inner.clone(), FairnessPolicy::low_volume(), 1);
    block_on(engine.enqueue_raw(
        low_volume_job(1, Timestamp::from_millis(100)),
        Timestamp::ZERO,
    ))
    .unwrap();
    let job_key = crate::keys::job_key(engine.namespace(), &JobId::from([1; 16])).unwrap();
    let job = block_on(inner.get(job_key.clone())).unwrap().unwrap();
    let wake_key =
        crate::keys::wake_key(engine.namespace(), &QueueName::try_new("default").unwrap()).unwrap();
    let wake = block_on(inner.get(wake_key.clone())).unwrap().unwrap();
    block_on(engine.enqueue_raw(
        low_volume_job(2, Timestamp::from_millis(50)),
        Timestamp::ZERO,
    ))
    .unwrap();
    (job_key, job, wake_key, wake)
}

fn assert_exact_unknown_replays(calls: &[SettlementCall], job: &StoreKey, wake: &StoreKey) {
    assert_eq!(calls.len(), 8, "observed full settlement store-call bound");
    for index in [1, 5, 7] {
        assert!(matches!(&calls[index], SettlementCall::Get(key) if key == job));
    }
    assert!(matches!(&calls[3], SettlementCall::Get(key) if key == wake));
    let transactions: Vec<_> = calls
        .iter()
        .filter_map(|call| match call {
            SettlementCall::Commit(transaction) => Some(transaction),
            SettlementCall::Get(_) => None,
        })
        .collect();
    assert_eq!(transactions.len(), 4);
    assert_eq!(
        transactions[0], transactions[1],
        "original Unknown retries exact transaction"
    );
    assert_eq!(
        transactions[2], transactions[3],
        "rebased Unknown retries exact transaction"
    );
    assert_ne!(
        transactions[0].operation_id(),
        transactions[2].operation_id()
    );
    assert_eq!(
        transactions[0]
            .checks()
            .iter()
            .filter(|check| check.key() != wake)
            .collect::<Vec<_>>(),
        transactions[2]
            .checks()
            .iter()
            .filter(|check| check.key() != wake)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        transactions[0]
            .mutations()
            .iter()
            .filter(|mutation| mutation.key() != wake)
            .collect::<Vec<_>>(),
        transactions[2]
            .mutations()
            .iter()
            .filter(|mutation| mutation.key() != wake)
            .collect::<Vec<_>>()
    );
}

#[test]
fn given_unknown_then_wake_conflict_when_rebased_settlement_remains_unknown_then_candidate_reserves_all_observed_calls()
 {
    let inner = FakeStore::new();
    let (job_key, old_job, wake_key, old_wake) = prepare_changed_wake(&inner);
    let before = inner.snapshot().unwrap();
    let store = UnknownWakeStore {
        inner: inner.clone(),
        calls: Arc::new(Mutex::new(Vec::new())),
    };
    let engine = settlement_system(store.clone());
    let mut next_record = crate::codec::decode_job_record(&old_job).unwrap();
    next_record.revision += 1;
    let next_job = crate::codec::encode_job_record(&next_record).unwrap();
    let transaction = crate::transition::checked_transaction(
        &engine,
        vec![
            Check::Value(job_key.clone(), old_job.clone()),
            Check::Value(wake_key.clone(), old_wake),
        ],
        vec![
            Mutation::Put(job_key.clone(), next_job.clone()),
            Mutation::Put(
                wake_key.clone(),
                crate::keys::wake_value(Timestamp::from_millis(200)).unwrap(),
            ),
        ],
    )
    .unwrap();
    let result = block_on(crate::transition::commit_transition(
        &engine,
        transaction,
        job_key.clone(),
        Some(&old_job),
        Some(&next_job),
        crate::transition::TransitionConflict::LeaseLost,
    ));
    assert!(
        matches!(result, Err(JobSystemError::UnknownCommit)),
        "two unresolved rebased acknowledgements remain unknown: {result:?}"
    );
    let calls = store.calls.lock().unwrap();
    assert_exact_unknown_replays(&calls, &job_key, &wake_key);
    assert_eq!(
        inner.snapshot().unwrap(),
        before,
        "unknown-before writes change no authority or business state"
    );
    let reserved_outcome = constants::CANDIDATE_WORST_CASE_STORE_OPERATIONS
        - constants::CLAIM_INPUT_STORE_OPERATIONS
        - constants::UNKNOWN_TRANSITION_STORE_OPERATIONS
        - constants::PAYLOAD_READ_STORE_OPERATIONS
        - constants::CANCELLATION_READ_STORE_OPERATIONS
        - constants::WAKE_RECONCILIATION_STORE_OPERATIONS;
    assert!(
        reserved_outcome as usize >= calls.len(),
        "candidate reserves {reserved_outcome} outcome calls but observed {}",
        calls.len()
    );
}
