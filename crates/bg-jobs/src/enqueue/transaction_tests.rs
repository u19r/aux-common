use std::sync::{Arc, Mutex};

use bytes::Bytes;

use crate::{
    codec::{DecodedOperation, KeyCodec, KeyTag, ValueTag, decode_operation},
    store::Check,
    test_helper::{block_on, completion, dedupe, job, low_volume_job, system},
    *,
};

fn tags(store: &FakeStore, namespace: &Namespace) -> Vec<KeyTag> {
    store
        .snapshot()
        .expect("snapshot succeeds")
        .iter()
        .map(|(key, _)| KeyCodec::decode(namespace, key).expect("key decodes").tag)
        .collect()
}

#[derive(Clone)]
struct CommitRecordingStore {
    inner: FakeStore,
    transactions: Arc<Mutex<Vec<StoreTransaction>>>,
    failing_commit: Option<usize>,
    preceding_commit: Option<StoreTransaction>,
}

impl CommitRecordingStore {
    fn new(inner: FakeStore) -> Self {
        Self {
            inner,
            transactions: Arc::new(Mutex::new(Vec::new())),
            failing_commit: None,
            preceding_commit: None,
        }
    }

    fn with_failing_commit(inner: FakeStore, failing_commit: usize) -> Self {
        Self {
            inner,
            transactions: Arc::new(Mutex::new(Vec::new())),
            failing_commit: Some(failing_commit),
            preceding_commit: None,
        }
    }

    fn transactions(&self) -> Vec<StoreTransaction> {
        self.transactions
            .lock()
            .expect("commit transaction record lock")
            .clone()
    }
}

impl JobStore for CommitRecordingStore {
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
        let commit_number = {
            let mut transactions = self
                .transactions
                .lock()
                .expect("commit transaction record lock");
            transactions.push(transaction.clone());
            transactions.len()
        };
        if commit_number == 1
            && let Some(preceding) = &self.preceding_commit
        {
            assert_eq!(
                self.inner.commit(preceding).await?,
                CommitOutcome::Committed
            );
        }
        if self.failing_commit == Some(commit_number) {
            return Err(FakeStoreError::Poisoned);
        }
        self.inner.commit(transaction).await
    }
}

fn recording_system(store: CommitRecordingStore) -> JobSystem<CommitRecordingStore> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(crate::test_helper::registry(FairnessPolicy::low_volume())),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([1; OwnerId::BYTE_LENGTH]),
        crate::test_helper::wake_scheduler(),
    )
}

#[test]
fn given_a_new_payload_with_dedupe_when_enqueue_commits_then_chunks_indexes_and_wake_are_atomic() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let dedupe = dedupe(b"producer-1", Timestamp::from_millis(10_000));

    let result = block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            Some(Timestamp::from_millis(100)),
            Some(dedupe),
        ),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");

    assert_eq!(result.disposition, EnqueueDisposition::Enqueued);
    let tags = tags(&store, engine.namespace());
    assert_eq!(tags.len(), 6);
    for expected in [
        KeyTag::PayloadChunk,
        KeyTag::Job,
        KeyTag::Due,
        KeyTag::FairReady,
        KeyTag::Dedupe,
        KeyTag::Wake,
    ] {
        assert!(tags.contains(&expected), "missing {expected:?}");
    }
}

#[test]
fn given_a_terminal_job_with_active_dedupe_when_reenqueuing_then_retained_identity_is_returned() {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let deduplication = dedupe(b"producer-2", Timestamp::from_millis(10));
    block_on(engine.enqueue_raw(
        job(
            2,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            Some(deduplication.clone()),
        ),
        Timestamp::ZERO,
    ))
    .expect("first enqueue commits");
    let claim =
        block_on(engine.claim(JobId::from([2; 16]), Timestamp::ZERO)).expect("claim commits");
    block_on(engine.complete(claim, completion(), Timestamp::from_millis(1)))
        .expect("completion commits");

    let duplicate = block_on(engine.enqueue_raw(
        job(
            3,
            Bytes::from_static(b"different payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            Some(deduplication.clone()),
        ),
        Timestamp::from_millis(2),
    ))
    .expect("active dedupe is returned");
    assert_eq!(duplicate.job_id, JobId::from([2; 16]));
    assert_eq!(duplicate.disposition, EnqueueDisposition::Deduplicated);

    let replacement = block_on(engine.enqueue_raw(
        job(
            4,
            Bytes::from_static(b"replacement"),
            FairnessClass::low_volume(),
            Timestamp::from_millis(11),
            None,
            Some(deduplication),
        ),
        Timestamp::from_millis(11),
    ))
    .expect("expired dedupe can be replaced");
    assert_eq!(replacement.job_id, JobId::from([4; 16]));
    assert_eq!(replacement.disposition, EnqueueDisposition::Enqueued);
}

#[test]
fn given_a_completed_job_with_a_nonzero_fence_when_reusing_its_id_then_the_next_claim_advances_the_fence()
 {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([5; 16]);
    block_on(engine.enqueue_raw(low_volume_job(5, Timestamp::ZERO), Timestamp::ZERO))
        .expect("first enqueue commits");
    let first = block_on(engine.claim(id, Timestamp::ZERO)).expect("first claim commits");
    let retried = block_on(engine.apply_outcome(
        first,
        JobOutcome::Retry {
            class: RetryClass::Transient,
            not_before: None,
            code: OutcomeCode::try_new("transient").expect("retry code is valid"),
        },
        Timestamp::ZERO,
    ))
    .expect("retry commits");
    let not_before = match retried {
        OutcomeResult::Retried { not_before, .. } => not_before,
        other => panic!("expected retry, got {other:?}"),
    };
    let second = block_on(engine.claim(id, not_before)).expect("second claim commits");
    let completed_operation = second.operation_id();
    let fence_before = match &second.record().state {
        JobState::Leased(lease) => lease.fence.get(),
        _ => panic!("second claim must be leased"),
    };
    assert_eq!(fence_before, 2);
    block_on(engine.complete(second, completion(), not_before)).expect("completion commits");
    block_on(engine.enqueue_raw(low_volume_job(5, not_before), not_before))
        .expect("same ID enqueue commits");
    let observation = block_on(engine.observe_lifecycle(id)).expect("reuse is observable");
    assert!(matches!(
        observation,
        LifecycleObservation::Current {
            operation_id: None,
            record,
            ..
        } if record.state == JobState::Scheduled
    ));
    assert_eq!(
        block_on(engine.reconcile(id, completed_operation)).expect("reconcile reads state"),
        ReconciliationOutcome::LeaseLost
    );
    let successor = block_on(engine.claim(id, not_before)).expect("successor claim commits");
    let fence_after = match &successor.record().state {
        JobState::Leased(lease) => lease.fence.get(),
        _ => panic!("successor claim must be leased"),
    };
    assert_eq!(fence_after, fence_before + 1);
}

#[test]
fn given_an_expired_dedupe_with_a_retained_receipt_when_reusing_its_id_then_the_fence_advances() {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let id = JobId::from([6; 16]);
    let deduplication = dedupe(b"expired-reuse", Timestamp::from_millis(1));
    let input = job(
        6,
        Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        None,
        Some(deduplication.clone()),
    );
    block_on(engine.enqueue_raw(input.clone(), Timestamp::ZERO)).expect("first enqueue commits");
    let claim = block_on(engine.claim(id, Timestamp::ZERO)).expect("claim commits");
    block_on(engine.complete(claim, completion(), Timestamp::from_millis(2)))
        .expect("completion commits");

    let replacement = block_on(engine.enqueue_raw(input, Timestamp::from_millis(2)))
        .expect("expired dedupe permits reuse");
    assert_eq!(replacement.disposition, EnqueueDisposition::Enqueued);
    let observation = block_on(engine.observe_lifecycle(id)).expect("reuse is observable");
    assert!(matches!(
        observation,
        LifecycleObservation::Current {
            operation_id: None,
            record,
            ..
        } if record.state == JobState::Scheduled
    ));
    let successor =
        block_on(engine.claim(id, Timestamp::from_millis(2))).expect("successor claim commits");
    assert!(matches!(
        successor.record().state,
        JobState::Leased(ref lease) if lease.fence.get() == 2
    ));
}

#[test]
fn given_a_retained_maximum_fence_receipt_when_reusing_its_id_then_state_is_unchanged() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([7; 16]);
    block_on(engine.enqueue_raw(low_volume_job(7, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(engine.claim(id, Timestamp::ZERO)).expect("claim commits");
    block_on(engine.complete(claim, completion(), Timestamp::ZERO)).expect("completion commits");

    let operation_key = crate::keys::operation_key(engine.namespace(), &id).expect("operation key");
    let encoded = store
        .snapshot()
        .expect("snapshot succeeds")
        .into_iter()
        .find(|(key, _)| key == &operation_key)
        .map(|(_, value)| value)
        .expect("completion receipt is retained");
    let mut receipt = match decode_operation(&encoded).expect("receipt decodes") {
        DecodedOperation::Receipt(receipt) => receipt,
        DecodedOperation::Live(_) => panic!("completion must retain a receipt"),
    };
    receipt.fence = std::num::NonZeroU64::new(u64::MAX).expect("maximum fence is non-zero");
    store
        .put_raw(
            operation_key,
            crate::keys::operation_receipt_value(&receipt).expect("maximum receipt encodes"),
        )
        .expect("receipt fixture writes");
    let before = store.snapshot().expect("snapshot succeeds");

    let result = block_on(engine.enqueue_raw(low_volume_job(7, Timestamp::ZERO), Timestamp::ZERO));
    assert!(matches!(result, Err(JobSystemError::LeaseConflict)));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
}

#[test]
fn given_an_orphan_maximum_fence_watermark_when_reusing_its_id_then_state_is_unchanged() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let id = JobId::from([8; 16]);
    let operation_key = crate::keys::operation_key(engine.namespace(), &id).expect("operation key");
    let watermark =
        crate::keys::operation_watermark_value(&id, u64::MAX).expect("maximum watermark encodes");
    store
        .put_raw(operation_key, watermark)
        .expect("watermark fixture writes");
    let before = store.snapshot().expect("snapshot succeeds");

    let result = block_on(engine.enqueue_raw(low_volume_job(8, Timestamp::ZERO), Timestamp::ZERO));
    assert!(matches!(result, Err(JobSystemError::LeaseConflict)));
    assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
}

#[test]
fn given_a_conflicting_enqueue_commit_when_reconciling_then_no_partial_state_is_visible() {
    let store = FakeStore::new();
    store
        .queue_commit_outcome(CommitOutcome::Conflict)
        .expect("queue outcome");
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);

    let result = block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ));

    assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
    assert!(store.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_an_unknown_before_enqueue_commit_when_reconciling_then_no_partial_state_is_visible() {
    let inner = FakeStore::new();
    inner
        .queue_unknown_before_commit()
        .expect("queue unknown-before outcome");
    let store = CommitRecordingStore::new(inner.clone());
    let engine = recording_system(store.clone());

    let result = block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ));

    assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
    assert_eq!(store.transactions().len(), 1);
    assert!(inner.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_a_seed_commit_unknown_before_apply_when_ensuring_then_the_exact_transaction_is_retried() {
    let inner = FakeStore::new();
    inner
        .queue_unknown_before_commit()
        .expect("queue unknown-before outcome");
    let store = CommitRecordingStore::new(inner.clone());
    let engine = recording_system(store.clone());

    let result =
        block_on(engine.ensure_seed_raw(low_volume_job(9, Timestamp::ZERO), Timestamp::ZERO))
            .expect("the exact seed transaction is reconciled");

    assert_eq!(result.disposition, EnqueueDisposition::Enqueued);
    let transactions = store.transactions();
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0], transactions[1]);
    assert!(!inner.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_a_seed_commit_unknown_after_apply_when_ensuring_then_reconciliation_does_not_replay() {
    let inner = FakeStore::new();
    inner
        .queue_unknown_after_commit()
        .expect("queue unknown-after outcome");
    let store = CommitRecordingStore::new(inner.clone());
    let engine = recording_system(store.clone());

    let result =
        block_on(engine.ensure_seed_raw(low_volume_job(10, Timestamp::ZERO), Timestamp::ZERO))
            .expect("the applied seed is reconciled");

    assert_eq!(result.disposition, EnqueueDisposition::Enqueued);
    assert_eq!(store.transactions().len(), 1);
    assert!(!inner.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_a_seed_with_mismatched_persisted_identity_when_ensuring_then_the_mismatch_is_preserved() {
    let inner = FakeStore::new();
    let initial_system = system(inner.clone(), FairnessPolicy::low_volume(), 1);
    let initial = low_volume_job(11, Timestamp::ZERO);
    block_on(initial_system.enqueue_raw(initial.clone(), Timestamp::ZERO))
        .expect("initial job commits");
    let store = CommitRecordingStore::new(inner);
    let engine = recording_system(store.clone());
    let mut changed = initial;
    changed.payload = Bytes::from_static(b"changed payload");

    let result = block_on(engine.ensure_seed_raw(changed, Timestamp::ZERO));

    assert!(matches!(result, Err(JobSystemError::JobIdConflict)));
    assert!(store.transactions().is_empty());
}

#[test]
fn given_a_seed_commit_conflict_without_state_when_ensuring_then_the_conflict_is_not_replayed() {
    let inner = FakeStore::new();
    inner
        .queue_commit_outcome(CommitOutcome::Conflict)
        .expect("queue conflict outcome");
    let store = CommitRecordingStore::new(inner.clone());
    let engine = recording_system(store.clone());

    let result =
        block_on(engine.ensure_seed_raw(low_volume_job(12, Timestamp::ZERO), Timestamp::ZERO));

    assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
    assert_eq!(store.transactions().len(), 1);
    assert!(inner.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_a_seed_exact_retry_store_error_when_ensuring_then_the_typed_error_is_preserved() {
    let inner = FakeStore::new();
    inner
        .queue_unknown_before_commit()
        .expect("queue unknown-before outcome");
    let store = CommitRecordingStore::with_failing_commit(inner.clone(), 2);
    let engine = recording_system(store.clone());

    let result =
        block_on(engine.ensure_seed_raw(low_volume_job(13, Timestamp::ZERO), Timestamp::ZERO));

    assert!(matches!(
        result,
        Err(JobSystemError::Store(FakeStoreError::Poisoned))
    ));
    let transactions = store.transactions();
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0], transactions[1]);
    assert!(inner.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_two_unresolved_seed_commits_when_ensuring_then_unknown_is_returned_after_one_exact_retry()
{
    let inner = FakeStore::new();
    inner
        .queue_unknown_before_commit()
        .expect("queue first unknown-before outcome");
    inner
        .queue_unknown_before_commit()
        .expect("queue second unknown-before outcome");
    let store = CommitRecordingStore::new(inner.clone());
    let engine = recording_system(store.clone());

    let result =
        block_on(engine.ensure_seed_raw(low_volume_job(14, Timestamp::ZERO), Timestamp::ZERO));

    assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
    let transactions = store.transactions();
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0], transactions[1]);
    assert!(inner.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_an_identical_replay_when_enqueue_reconciles_then_it_is_already_present_with_the_same_wake()
{
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let first = job(
        1,
        Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        None,
        None,
    );
    let first_result = block_on(engine.enqueue_raw(first.clone(), Timestamp::ZERO))
        .expect("first enqueue commits");

    let replay = block_on(engine.enqueue_raw(first, Timestamp::ZERO)).expect("replay reconciles");
    assert_eq!(replay.disposition, EnqueueDisposition::AlreadyPresent);
    assert_eq!(replay.wake, first_result.wake);
}

#[test]
fn given_a_changed_payload_when_enqueue_reconciles_then_it_returns_job_id_conflict() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("first enqueue commits");

    let changed = job(
        1,
        Bytes::from_static(b"changed"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        None,
        None,
    );
    assert!(matches!(
        block_on(engine.enqueue_raw(changed, Timestamp::ZERO)),
        Err(JobSystemError::JobIdConflict)
    ));
}

#[test]
fn given_a_changed_retry_override_when_enqueue_reconciles_then_it_returns_job_id_conflict() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("first enqueue commits");

    let mut changed = job(
        1,
        Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        None,
        None,
    );
    changed.retry_override = Some(RetrySelection::Preset(RetryPreset::Network));

    assert!(matches!(
        block_on(engine.enqueue_raw(changed, Timestamp::ZERO)),
        Err(JobSystemError::JobIdConflict)
    ));
}

#[test]
fn given_a_replayed_job_with_a_foreign_namespace_when_reconciling_then_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let replay = job(
        7,
        Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        None,
        None,
    );
    block_on(engine.enqueue_raw(replay.clone(), Timestamp::ZERO)).expect("enqueue commits");

    let job_key = crate::keys::job_key(engine.namespace(), &replay.job_id).expect("job key");
    let encoded = block_on(store.get(job_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    record.namespace = Namespace::try_new(b"foreign").expect("foreign namespace is valid");
    store
        .put_raw(
            job_key,
            crate::codec::encode_job_record(&record).expect("tampered record encodes"),
        )
        .expect("tampered record write succeeds");
    let before_rejection = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(engine.enqueue_raw(replay, Timestamp::ZERO)),
        Err(JobSystemError::JobIdConflict)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "identity rejection must not rewrite persisted bytes or indexes"
    );
}

#[test]
fn given_an_unknown_after_commit_when_enqueue_reconciles_then_it_returns_enqueued_with_all_state() {
    let store = FakeStore::new();
    store
        .queue_commit_outcome(CommitOutcome::Unknown)
        .expect("queue unknown outcome");
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);

    let result = block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("unknown commit reconciles");

    assert_eq!(result.disposition, EnqueueDisposition::Enqueued);
    assert_eq!(tags(&store, engine.namespace()).len(), 5);
}

#[test]
fn given_a_later_enqueue_when_the_wake_exists_then_the_earliest_wake_is_retained() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::new(),
            FairnessClass::low_volume(),
            Timestamp::from_millis(50),
            None,
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("first enqueue commits");
    block_on(engine.enqueue_raw(
        job(
            2,
            Bytes::new(),
            FairnessClass::low_volume(),
            Timestamp::from_millis(100),
            None,
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("second enqueue commits");

    let queue = QueueName::try_new("default").expect("test queue is valid");
    let wake = block_on(
        engine
            .store()
            .get(crate::keys::wake_key(engine.namespace(), &queue).expect("wake key is valid")),
    )
    .expect("wake read succeeds")
    .expect("wake exists");
    assert_eq!(
        crate::keys::decode_timestamp_value(&wake, ValueTag::Wake).expect("wake decodes"),
        Timestamp::from_millis(50)
    );
}

#[test]
fn given_independent_seeds_when_queue_wake_initialization_races_then_only_the_wake_check_conflicts()
{
    let competitor = CommitRecordingStore::new(FakeStore::new());
    block_on(
        recording_system(competitor.clone())
            .ensure_seed_raw(low_volume_job(21, Timestamp::ZERO), Timestamp::ZERO),
    )
    .expect("prepare a real competing enqueue transaction");
    let inner = FakeStore::new();
    let mut store = CommitRecordingStore::new(inner.clone());
    store.preceding_commit = Some(competitor.transactions().remove(0));
    let engine = recording_system(store.clone());
    let result = block_on(engine.ensure_seed_raw(
        low_volume_job(22, Timestamp::from_millis(1)),
        Timestamp::from_millis(1),
    ));
    assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
    let transactions = store.transactions();
    assert_eq!(
        transactions.len(),
        1,
        "a conflict must not be blindly retried"
    );
    assert_only_queue_wake_check_conflicts(&inner, engine.namespace(), &transactions[0]);
    let retry = block_on(engine.ensure_seed_raw(
        low_volume_job(22, Timestamp::from_millis(1)),
        Timestamp::from_millis(1),
    ))
    .expect("a new operation observes the already initialized queue wake");
    assert_eq!(retry.disposition, EnqueueDisposition::Enqueued);
}

fn assert_only_queue_wake_check_conflicts(
    store: &FakeStore,
    namespace: &Namespace,
    transaction: &StoreTransaction,
) {
    let snapshot = store.snapshot().expect("snapshot succeeds");
    let conflicting: Vec<_> = transaction
        .checks()
        .iter()
        .filter(|check| {
            let actual = snapshot
                .iter()
                .find(|(key, _)| key == check.key())
                .map(|(_, value)| value);
            match check {
                Check::Absent(_) => actual.is_some(),
                Check::Value(_, expected) => actual != Some(expected),
            }
        })
        .collect();
    assert_eq!(conflicting.len(), 1);
    assert_eq!(
        KeyCodec::decode(namespace, conflicting[0].key())
            .unwrap()
            .tag,
        KeyTag::Wake
    );
    for tag in [KeyTag::Job, KeyTag::Operation] {
        let checks: Vec<_> = transaction
            .checks()
            .iter()
            .filter(|check| KeyCodec::decode(namespace, check.key()).unwrap().tag == tag)
            .collect();
        assert_eq!(
            checks.len(),
            1,
            "each seed must guard its job and operation"
        );
        assert!(!snapshot.iter().any(|(key, _)| key == checks[0].key()));
    }
}
