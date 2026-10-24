use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::{Poll, Waker},
};

use bytes::Bytes;

use crate::{
    store::{
        Check, CommitOutcome, JobStore, RangePage, RangeRequest, StoreCapabilities, StoreKey,
        StoreTransaction,
    },
    test_helper::{block_on, completion, dedupe, job, low_volume_job, system},
    *,
};

#[derive(Default)]
struct SettlementInterleaving {
    transactions: Vec<StoreTransaction>,
    first_result: Option<Result<CommitOutcome, FakeStoreError>>,
    first_waker: Option<Waker>,
    before_loser: Vec<(StoreKey, Bytes)>,
    after_loser: Vec<(StoreKey, Bytes)>,
    interference: SettlementInterference,
}

#[derive(Clone, Copy, Default)]
enum SettlementInterference {
    #[default]
    None,
    EarlierEnqueue,
    ReplacementClaim,
}

#[derive(Clone)]
struct SettlementRaceStore {
    inner: FakeStore,
    interleaving: Arc<Mutex<Option<SettlementInterleaving>>>,
    fail_next_commit: Arc<std::sync::atomic::AtomicBool>,
}

impl SettlementRaceStore {
    fn new() -> Self {
        Self {
            inner: FakeStore::new(),
            interleaving: Arc::new(Mutex::new(None)),
            fail_next_commit: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn arm(&self, interference: SettlementInterference) {
        *self.interleaving.lock().unwrap() = Some(SettlementInterleaving {
            interference,
            ..SettlementInterleaving::default()
        });
    }

    async fn await_first_commit(&self) -> Result<CommitOutcome, FakeStoreError> {
        std::future::poll_fn(|context| {
            let mut guard = self.interleaving.lock().unwrap();
            let state = guard.as_mut().unwrap();
            if let Some(result) = state.first_result.take() {
                return Poll::Ready(result);
            }
            state.first_waker = Some(context.waker().clone());
            Poll::Pending
        })
        .await
    }

    async fn commit_preceding(&self) {
        let preceding = self
            .interleaving
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .transactions[0]
            .clone();
        let result = self.inner.commit(&preceding).await;
        let interference = self
            .interleaving
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .interference;
        let engine = settlement_system(self.inner.clone());
        match interference {
            SettlementInterference::None => {}
            SettlementInterference::EarlierEnqueue => {
                engine
                    .enqueue_raw(
                        settlement_job(3, Timestamp::from_millis(5)),
                        Timestamp::ZERO,
                    )
                    .await
                    .unwrap();
            }
            SettlementInterference::ReplacementClaim => {
                engine
                    .claim(JobId::from([2; 16]), Timestamp::from_millis(1000))
                    .await
                    .unwrap();
            }
        }
        let snapshot = self.inner.snapshot().unwrap();
        let mut guard = self.interleaving.lock().unwrap();
        let state = guard.as_mut().unwrap();
        state.first_result = Some(result);
        state.before_loser = snapshot;
        if let Some(waker) = state.first_waker.take() {
            waker.wake();
        }
    }
}

impl JobStore for SettlementRaceStore {
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

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        if self
            .fail_next_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(FakeStoreError::Poisoned);
        }
        let position = {
            let mut guard = self.interleaving.lock().unwrap();
            guard.as_mut().map(|state| {
                state.transactions.push(transaction.clone());
                state.transactions.len()
            })
        };
        match position {
            Some(1) => return self.await_first_commit().await,
            Some(2) => self.commit_preceding().await,
            Some(3) | None => {}
            Some(_) => panic!("settlement permits at most one fresh rebased commit"),
        }
        let result = self.inner.commit(transaction).await;
        if position == Some(2) {
            assert_eq!(result, Ok(CommitOutcome::Conflict));
            self.interleaving
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .after_loser = self.inner.snapshot().unwrap();
        }
        result
    }
}

fn settlement_system<S: JobStore>(store: S) -> JobSystem<S> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(crate::test_helper::registry(FairnessPolicy::from(
            std::num::NonZeroU16::MIN,
        ))),
        Namespace::try_new(b"jobs").unwrap(),
        OwnerId::from([1; 16]),
        crate::test_helper::wake_scheduler(),
    )
}

fn prepare_settlement_claims(engine: &JobSystem<SettlementRaceStore>) -> [ClaimedJob; 2] {
    [1u8, 2].map(|id| {
        block_on(engine.enqueue_raw(settlement_job(id, Timestamp::ZERO), Timestamp::ZERO)).unwrap();
        block_on(engine.claim(JobId::from([id; 16]), Timestamp::ZERO)).unwrap()
    })
}

fn settlement_job(id: u8, scheduled_at: Timestamp) -> NewJob {
    let fairness =
        FairnessClass::from(FairnessPath::new(FairnessKey::try_new([id]).unwrap(), None));
    job(
        id,
        Bytes::from_static(b"payload"),
        fairness,
        scheduled_at,
        None,
        None,
    )
}

async fn join_settlements<T>(
    left: impl Future<Output = T>,
    right: impl Future<Output = T>,
) -> (T, T) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut results = (None, None);
    std::future::poll_fn(|context| {
        if results.0.is_none()
            && let Poll::Ready(result) = left.as_mut().poll(context)
        {
            results.0 = Some(result);
        }
        if results.1.is_none()
            && let Poll::Ready(result) = right.as_mut().poll(context)
        {
            results.1 = Some(result);
        }
        if results.0.is_some() && results.1.is_some() {
            return Poll::Ready((results.0.take().unwrap(), results.1.take().unwrap()));
        }
        Poll::Pending
    })
    .await
}

fn assert_only_settlement_wake_conflicts(store: &SettlementRaceStore, namespace: &Namespace) {
    let guard = store.interleaving.lock().unwrap();
    let state = guard.as_ref().unwrap();
    assert_rebased_settlement(&state.transactions, namespace);
    let conflicts: Vec<_> = state.transactions[1]
        .checks()
        .iter()
        .filter(|check| {
            let actual = state
                .before_loser
                .iter()
                .find(|(key, _)| key == check.key())
                .map(|(_, value)| value);
            match check {
                Check::Absent(_) => actual.is_some(),
                Check::Value(_, expected) => actual != Some(expected),
            }
        })
        .collect();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        crate::codec::KeyCodec::decode(namespace, conflicts[0].key())
            .unwrap()
            .tag,
        crate::codec::KeyTag::Wake
    );
    assert_eq!(
        state.after_loser, state.before_loser,
        "losing settlement applies no mutation"
    );
    for tag in [
        crate::codec::KeyTag::Job,
        crate::codec::KeyTag::Lease,
        crate::codec::KeyTag::Operation,
    ] {
        assert!(
            state.transactions[1]
                .checks()
                .iter()
                .any(|check| matches!(check, Check::Value(_, _))
                    && crate::codec::KeyCodec::decode(namespace, check.key())
                        .unwrap()
                        .tag
                        == tag),
            "loser retains checked authority {tag:?}"
        );
    }
}

fn assert_rebased_settlement(transactions: &[StoreTransaction], namespace: &Namespace) {
    assert_eq!(transactions.len(), 3);
    let original = &transactions[1];
    let rebased = &transactions[2];
    assert_ne!(original.operation_id(), rebased.operation_id());
    let is_wake = |key: &StoreKey| {
        crate::codec::KeyCodec::decode(namespace, key).unwrap().tag == crate::codec::KeyTag::Wake
    };
    assert_eq!(
        original
            .checks()
            .iter()
            .filter(|check| !is_wake(check.key()))
            .collect::<Vec<_>>(),
        rebased
            .checks()
            .iter()
            .filter(|check| !is_wake(check.key()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        original
            .mutations()
            .iter()
            .filter(|mutation| !is_wake(mutation.key()))
            .collect::<Vec<_>>(),
        rebased
            .mutations()
            .iter()
            .filter(|mutation| !is_wake(mutation.key()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn given_distinct_claims_when_same_queue_settlements_overlap_then_both_settle_with_live_authority()
{
    for other_outcome in [
        completion(),
        JobOutcome::Retry {
            code: OutcomeCode::try_new("retry").unwrap(),
            class: RetryClass::Transient,
            not_before: Some(Timestamp::from_millis(30_000)),
        },
    ] {
        let store = SettlementRaceStore::new();
        let engine = settlement_system(store.clone());
        let [first, second] = prepare_settlement_claims(&engine);
        store.arm(SettlementInterference::None);
        let (first, second) = block_on(join_settlements(
            engine.apply_outcome(first, completion(), Timestamp::ZERO),
            engine.apply_outcome(second, other_outcome, Timestamp::ZERO),
        ));
        assert!(first.is_ok(), "first settlement commits: {first:?}");
        assert!(
            second.is_ok(),
            "wake contention must not discard valid settlement: {second:?}"
        );
        assert_only_settlement_wake_conflicts(&store, engine.namespace());
    }
}

#[test]
fn given_valid_settlement_authority_when_store_fails_then_error_is_not_reported_as_lease_loss() {
    let store = SettlementRaceStore::new();
    let engine = settlement_system(store.clone());
    let [first, _second] = prepare_settlement_claims(&engine);
    let before = store.inner.snapshot().unwrap();
    store
        .fail_next_commit
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        block_on(engine.apply_outcome(first, completion(), Timestamp::ZERO)),
        Err(JobSystemError::Store(FakeStoreError::Poisoned))
    ));
    assert_eq!(store.inner.snapshot().unwrap(), before);
}

#[test]
fn given_an_earlier_enqueue_when_same_queue_settlements_rebase_then_due_work_remains_discoverable()
{
    for other_outcome in [
        completion(),
        JobOutcome::Retry {
            code: OutcomeCode::try_new("retry").unwrap(),
            class: RetryClass::Transient,
            not_before: Some(Timestamp::from_millis(30_000)),
        },
    ] {
        let store = SettlementRaceStore::new();
        let engine = settlement_system(store.clone());
        let [first, second] = prepare_settlement_claims(&engine);
        store.arm(SettlementInterference::EarlierEnqueue);
        let (first, second) = block_on(join_settlements(
            engine.apply_outcome(first, completion(), Timestamp::ZERO),
            engine.apply_outcome(second, other_outcome, Timestamp::ZERO),
        ));
        assert!(
            first.is_ok() && second.is_ok(),
            "both settlements commit: {first:?}, {second:?}"
        );
        assert_only_settlement_wake_conflicts(&store, engine.namespace());
        assert_earlier_enqueue_is_claimable(&store, engine.namespace());
    }
}

fn assert_earlier_enqueue_is_claimable(store: &SettlementRaceStore, namespace: &Namespace) {
    let queue = QueueName::try_new("default").unwrap();
    let id = JobId::from([3; 16]);
    let at = Timestamp::from_millis(5);
    let wake = block_on(
        store
            .inner
            .get(crate::keys::wake_key(namespace, &queue).unwrap()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        crate::keys::decode_timestamp_value(&wake, crate::codec::ValueTag::Wake).unwrap(),
        at
    );
    assert!(
        block_on(
            store
                .inner
                .get(crate::keys::due_key(namespace, &queue, at, &id).unwrap())
        )
        .unwrap()
        .is_some()
    );
    block_on(settlement_system(store.inner.clone()).claim(id, at))
        .expect("earlier enqueued work remains claimable");
}

#[test]
fn given_replaced_authority_and_wake_when_settlement_rebases_then_the_stale_claim_still_fails() {
    let store = SettlementRaceStore::new();
    let engine = settlement_system(store.clone());
    let [first, second] = prepare_settlement_claims(&engine);
    store.arm(SettlementInterference::ReplacementClaim);
    let (first, second) = block_on(join_settlements(
        engine.apply_outcome(first, completion(), Timestamp::ZERO),
        engine.apply_outcome(second, completion(), Timestamp::ZERO),
    ));
    assert!(first.is_ok(), "first settlement commits: {first:?}");
    assert!(
        matches!(second, Err(JobSystemError::LeaseLost)),
        "replacement authority rejects stale settlement: {second:?}"
    );
    let guard = store.interleaving.lock().unwrap();
    let state = guard.as_ref().unwrap();
    assert_rebased_settlement(&state.transactions, engine.namespace());
    assert_eq!(state.before_loser, state.after_loser);
    assert_eq!(store.inner.snapshot().unwrap(), state.after_loser);
    for tag in [crate::codec::KeyTag::Wake, crate::codec::KeyTag::Job] {
        assert!(
            state.transactions[1].checks().iter().any(|check| {
                let actual = state
                    .before_loser
                    .iter()
                    .find(|(key, _)| key == check.key())
                    .map(|(_, value)| value);
                let changed = match check {
                    Check::Absent(_) => actual.is_some(),
                    Check::Value(_, expected) => actual != Some(expected),
                };
                changed
                    && crate::codec::KeyCodec::decode(engine.namespace(), check.key())
                        .unwrap()
                        .tag
                        == tag
            }),
            "interposition changes both advisory wake and authoritative job: {tag:?}"
        );
    }
    let key = crate::keys::job_key(engine.namespace(), &JobId::from([2; 16])).unwrap();
    let encoded = state
        .after_loser
        .iter()
        .find(|(stored, _)| stored == &key)
        .unwrap()
        .1
        .clone();
    let record = crate::codec::decode_job_record(&encoded).unwrap();
    assert_eq!(record.generation, 2);
    assert!(matches!(record.state, JobState::Leased(lease) if lease.fence.get() == 2));
}

fn successor_record(claim: &ClaimedJob) -> JobRecordV1 {
    let mut successor = claim.record().clone();
    successor.revision += 1;
    successor.state = JobState::Leased(
        Lease::try_new(
            OwnerId::from([2; 16]),
            LeaseToken::from([4; 16]),
            std::num::NonZeroU64::new(2).expect("fence is non-zero"),
            Timestamp::from_millis(100),
        )
        .expect("lease is valid"),
    );
    successor
}

fn write_successor(
    store: &FakeStore,
    engine: &JobSystem<FakeStore>,
    id: JobId,
    record: &JobRecordV1,
) {
    store
        .put_raw(
            crate::keys::job_key(engine.namespace(), &id).expect("job key is valid"),
            crate::codec::encode_job_record(record).expect("successor encodes"),
        )
        .expect("successor write succeeds");
    store
        .put_raw(
            crate::keys::lease_key(engine.namespace(), &record.queue, &id)
                .expect("lease key is valid"),
            crate::keys::lease_value(&id).expect("lease value is valid"),
        )
        .expect("successor lease route succeeds");
}

#[test]
fn given_a_stale_claim_when_a_successor_changed_authority_then_completion_is_rejected() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(engine.claim(id, Timestamp::ZERO)).expect("claim commits");
    write_successor(&store, &engine, id, &successor_record(&claim));

    assert!(matches!(
        block_on(engine.complete(claim, completion(), Timestamp::from_millis(2))),
        Err(JobSystemError::LeaseLost)
    ));
    assert!(
        block_on(
            engine
                .store()
                .get(crate::keys::job_key(engine.namespace(), &id).expect("job key is valid"))
        )
        .expect("job read succeeds")
        .is_some()
    );
}

#[test]
fn given_a_claimed_job_when_completion_commits_then_all_live_keys_are_deleted() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    let dedupe = dedupe(b"producer-1", Timestamp::from_millis(10_000));
    block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            Some(dedupe.clone()),
        ),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");
    let claim = block_on(engine.claim(id, Timestamp::ZERO)).expect("claim commits");
    block_on(engine.complete(claim, completion(), Timestamp::from_millis(1)))
        .expect("completion commits");

    let live_tags: Vec<_> = store
        .snapshot()
        .expect("snapshot succeeds")
        .iter()
        .map(|(key, _)| {
            crate::codec::KeyCodec::decode(engine.namespace(), key)
                .expect("key decodes")
                .tag
        })
        .collect();
    assert!(!live_tags.contains(&crate::codec::KeyTag::Job));
    assert!(!live_tags.contains(&crate::codec::KeyTag::PayloadChunk));
    assert!(!live_tags.contains(&crate::codec::KeyTag::Due));
    assert!(!live_tags.contains(&crate::codec::KeyTag::FairReady));
    assert!(!live_tags.contains(&crate::codec::KeyTag::Lease));
    assert!(live_tags.contains(&crate::codec::KeyTag::Dedupe));
    assert!(!live_tags.contains(&crate::codec::KeyTag::Wake));
}

#[test]
fn given_a_successor_due_job_when_earliest_completes_then_wake_moves_forward() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    block_on(engine.enqueue_raw(
        low_volume_job(1, Timestamp::from_millis(10)),
        Timestamp::ZERO,
    ))
    .expect("first enqueue commits");
    block_on(engine.enqueue_raw(
        low_volume_job(2, Timestamp::from_millis(20)),
        Timestamp::ZERO,
    ))
    .expect("second enqueue commits");
    let claim = block_on(engine.claim(JobId::from([1; 16]), Timestamp::from_millis(10)))
        .expect("claim commits");
    block_on(engine.complete(claim, completion(), Timestamp::from_millis(11)))
        .expect("completion commits");

    let wake = block_on(
        engine.store().get(
            crate::keys::wake_key(
                engine.namespace(),
                &QueueName::try_new("default").expect("queue is valid"),
            )
            .expect("wake key is valid"),
        ),
    )
    .expect("wake read succeeds")
    .expect("successor wake remains");
    assert_eq!(
        crate::keys::decode_timestamp_value(&wake, crate::codec::ValueTag::Wake)
            .expect("wake decodes"),
        Timestamp::from_millis(20)
    );
}

#[test]
fn given_completion_unknown_before_commit_when_reconciling_then_the_job_and_receipt_are_not_lost() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([1; 16]);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(engine.claim(id, Timestamp::ZERO)).expect("claim commits");
    store
        .queue_unknown_before_commit()
        .expect("queue unknown-before outcome");
    store
        .queue_unknown_before_commit()
        .expect("queue repeated unknown-before outcome");

    assert!(matches!(
        block_on(engine.complete(claim, completion(), Timestamp::from_millis(1))),
        Err(JobSystemError::UnknownCommit)
    ));
    assert!(
        block_on(
            engine
                .store()
                .get(crate::keys::job_key(engine.namespace(), &id).expect("job key is valid"))
        )
        .expect("job read succeeds")
        .is_some()
    );
}

#[test]
fn given_an_expired_claim_without_successor_when_completing_then_lease_is_lost() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([91; 16]);
    block_on(engine.enqueue_raw(low_volume_job(91, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(engine.claim(id, Timestamp::ZERO)).expect("claim commits");
    let before = store.snapshot().expect("snapshot succeeds");
    assert!(matches!(
        block_on(engine.complete(claim, completion(), Timestamp::from_millis(2000))),
        Err(JobSystemError::LeaseLost)
    ));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
}

#[test]
fn given_renewal_loss_when_completing_with_old_time_then_authority_cannot_be_reused() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([96; 16]);
    block_on(engine.enqueue_raw(low_volume_job(96, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut claim = block_on(engine.claim(id, Timestamp::ZERO)).expect("claim commits");
    assert!(matches!(
        block_on(engine.renew(&mut claim, Timestamp::from_millis(2000))),
        Err(JobSystemError::LeaseLost)
    ));
    let before = store.snapshot().expect("snapshot succeeds");
    assert!(matches!(
        block_on(engine.complete(claim, completion(), Timestamp::ZERO)),
        Err(JobSystemError::LeaseLost)
    ));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
}
