use bytes::Bytes;

use crate::{
    test_helper::{block_on, job, system},
    *,
};

#[test]
fn given_a_950_kib_payload_when_enqueuing_then_the_boundary_is_accepted() {
    assert_eq!(MAX_INLINE_PAYLOAD_BYTES, 972_800);
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let payload = Bytes::from(vec![0x41; MAX_INLINE_PAYLOAD_BYTES]);

    let result = block_on(engine.enqueue_raw(
        job(
            1,
            payload,
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ));

    assert!(result.is_ok());
    assert!(!store.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_a_payload_over_950_kib_when_enqueuing_then_validation_rejects_before_write() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let payload = Bytes::from(vec![0x41; MAX_INLINE_PAYLOAD_BYTES + 1]);

    let result = block_on(engine.enqueue_raw(
        job(
            1,
            payload,
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ));

    assert!(matches!(
        result,
        Err(JobSystemError::Validation(ValidationError::TooLong {
            field: "payload",
            maximum: MAX_INLINE_PAYLOAD_BYTES,
            ..
        }))
    ));
    assert!(store.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_expiry_before_schedule_when_enqueuing_then_ordering_is_rejected() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);

    let result = block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            FairnessClass::low_volume(),
            Timestamp::from_millis(20),
            Some(Timestamp::from_millis(19)),
            None,
        ),
        Timestamp::ZERO,
    ));

    assert!(matches!(
        result,
        Err(JobSystemError::Validation(ValidationError::Ordering {
            field: "job expiry"
        }))
    ));
    assert!(store.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_an_unregistered_kind_when_enqueuing_then_the_request_is_rejected_without_io() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let mut unknown = job(
        1,
        Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        None,
        None,
    );
    unknown.kind = JobKind::try_new("missing").expect("test kind is valid");

    let result = block_on(engine.enqueue_raw(unknown, Timestamp::ZERO));

    assert!(matches!(result, Err(JobSystemError::UnregisteredHandler)));
    assert!(store.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_a_low_volume_enqueue_for_a_scoped_registration_when_enqueuing_then_fairness_is_rejected() {
    let store = FakeStore::new();
    let engine = system(
        store.clone(),
        FairnessPolicy::from(std::num::NonZeroU16::new(2).expect("weight is non-zero")),
        1,
    );

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

    assert!(matches!(
        result,
        Err(JobSystemError::Validation(ValidationError::InvalidValue {
            field: "fairness policy"
        }))
    ));
    assert!(store.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_a_scoped_enqueue_for_a_low_volume_registration_when_enqueuing_then_fairness_is_rejected() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);

    let result = block_on(engine.enqueue_raw(
        job(
            1,
            Bytes::from_static(b"payload"),
            crate::test_helper::scoped_fairness(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ));

    assert!(matches!(
        result,
        Err(JobSystemError::Validation(ValidationError::InvalidValue {
            field: "fairness policy"
        }))
    ));
    assert!(store.snapshot().expect("snapshot succeeds").is_empty());
}

#[test]
fn given_a_continued_controller_when_restart_ensures_its_seed_then_progress_is_preserved() {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let seed = job(
        1,
        Bytes::from_static(b"controller"),
        FairnessClass::low_volume(),
        Timestamp::ZERO,
        None,
        None,
    );
    let job_id = seed.job_id;
    let initial = block_on(engine.ensure_seed_raw(seed.clone(), Timestamp::ZERO))
        .expect("missing controller seed is created");
    assert_eq!(initial.disposition, EnqueueDisposition::Enqueued);
    let claim = block_on(engine.claim(job_id, Timestamp::ZERO)).expect("seed claim commits");
    block_on(engine.apply_outcome(
        claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(10),
            checkpoint: Bytes::from_static(b"page-1"),
        },
        Timestamp::ZERO,
    ))
    .expect("continuation commits");

    let mut restart_seed = seed;
    restart_seed.scheduled_at = Timestamp::from_millis(100);
    assert!(matches!(
        block_on(engine.enqueue_raw(restart_seed.clone(), Timestamp::from_millis(1))),
        Err(JobSystemError::JobIdConflict)
    ));

    let result = block_on(engine.ensure_seed_raw(restart_seed.clone(), Timestamp::from_millis(1)))
        .expect("matching controller seed is already present");
    assert_eq!(result.disposition, EnqueueDisposition::AlreadyPresent);
    assert_eq!(result.wake, WakeHint::At(Timestamp::from_millis(10)));

    restart_seed.payload = Bytes::from_static(b"different controller");
    assert!(matches!(
        block_on(engine.ensure_seed_raw(restart_seed, Timestamp::from_millis(1))),
        Err(JobSystemError::JobIdConflict)
    ));

    let resumed = block_on(engine.claim(job_id, Timestamp::from_millis(10)))
        .expect("continued controller remains claimable");
    assert_eq!(
        resumed.context().expect("resumed context").checkpoint(),
        Some(b"page-1".as_slice())
    );
}

#[test]
fn given_a_completed_seed_when_startup_reseeds_then_the_terminal_receipt_is_preserved() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let seed = crate::test_helper::low_volume_job(11, Timestamp::ZERO);
    block_on(engine.ensure_seed_raw(seed.clone(), Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(seed.job_id, Timestamp::ZERO)).unwrap();
    block_on(engine.complete(claim, crate::test_helper::completion(), Timestamp::ZERO)).unwrap();
    let before = store.snapshot().unwrap();
    let result = block_on(engine.ensure_seed_raw(seed, Timestamp::from_millis(1))).unwrap();
    assert_eq!(result.disposition, EnqueueDisposition::AlreadyPresent);
    assert_eq!(result.wake, WakeHint::None);
    assert_eq!(store.snapshot().unwrap(), before);
}

#[test]
fn given_a_foreign_terminal_receipt_when_startup_reseeds_then_identity_conflicts_without_writes() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let seed = crate::test_helper::low_volume_job(12, Timestamp::ZERO);
    block_on(engine.ensure_seed_raw(seed.clone(), Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(seed.job_id, Timestamp::ZERO)).unwrap();
    block_on(engine.complete(claim, crate::test_helper::completion(), Timestamp::ZERO)).unwrap();
    let key = crate::keys::operation_key(engine.namespace(), &seed.job_id).unwrap();
    let mut receipt =
        match crate::codec::decode_operation(&block_on(store.get(key.clone())).unwrap().unwrap())
            .unwrap()
        {
            crate::codec::DecodedOperation::Receipt(receipt) => receipt,
            crate::codec::DecodedOperation::Live(_) => panic!("terminal receipt"),
        };
    receipt.kind = JobKind::try_new("different").unwrap();
    store
        .put_raw(key, crate::keys::operation_receipt_value(&receipt).unwrap())
        .unwrap();
    let before = store.snapshot().unwrap();
    assert!(matches!(
        block_on(engine.ensure_seed_raw(seed, Timestamp::ZERO)),
        Err(JobSystemError::JobIdConflict)
    ));
    assert_eq!(store.snapshot().unwrap(), before);
}

#[test]
fn given_a_completed_seed_when_its_definition_changes_then_startup_conflicts_without_writes() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let seed = crate::test_helper::low_volume_job(13, Timestamp::ZERO);
    block_on(engine.ensure_seed_raw(seed.clone(), Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(seed.job_id, Timestamp::ZERO)).unwrap();
    block_on(engine.complete(claim, crate::test_helper::completion(), Timestamp::ZERO)).unwrap();
    let before = store.snapshot().unwrap();
    let mut changed_payload = seed.clone();
    changed_payload.payload = Bytes::from_static(b"different");
    let mut changed_policy = seed.clone();
    changed_policy.retry_override = Some(RetrySelection::Preset(RetryPreset::Network));
    let mut changed_priority = seed;
    changed_priority.priority = Priority::Bulk;
    for changed in [changed_payload, changed_policy, changed_priority] {
        assert!(matches!(
            block_on(engine.ensure_seed_raw(changed, Timestamp::ZERO)),
            Err(JobSystemError::JobIdConflict)
        ));
        assert_eq!(store.snapshot().unwrap(), before);
    }
}

#[test]
fn given_a_legacy_completed_seed_receipt_when_startup_reseeds_then_unproved_identity_fails_closed()
{
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let seed = crate::test_helper::low_volume_job(14, Timestamp::ZERO);
    block_on(engine.ensure_seed_raw(seed.clone(), Timestamp::ZERO)).unwrap();
    let claim = block_on(engine.claim(seed.job_id, Timestamp::ZERO)).unwrap();
    block_on(engine.complete(claim, crate::test_helper::completion(), Timestamp::ZERO)).unwrap();
    let key = crate::keys::operation_key(engine.namespace(), &seed.job_id).unwrap();
    let mut receipt =
        match crate::codec::decode_operation(&block_on(store.get(key.clone())).unwrap().unwrap())
            .unwrap()
        {
            crate::codec::DecodedOperation::Receipt(receipt) => receipt,
            crate::codec::DecodedOperation::Live(_) => panic!("terminal receipt"),
        };
    receipt.definition_digest = None;
    store
        .put_raw(key, crate::keys::operation_receipt_value(&receipt).unwrap())
        .unwrap();
    let before = store.snapshot().unwrap();
    assert!(matches!(
        block_on(engine.ensure_seed_raw(seed, Timestamp::ZERO)),
        Err(JobSystemError::JobIdConflict)
    ));
    assert_eq!(store.snapshot().unwrap(), before);
}

#[derive(Clone)]
struct CompleteBeforeAcknowledgement {
    inner: FakeStore,
    job_id: JobId,
    interrupt: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl JobStore for CompleteBeforeAcknowledgement {
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
        let outcome = self.inner.commit(transaction).await?;
        if outcome == CommitOutcome::Committed
            && self
                .interrupt
                .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let worker = system(self.inner.clone(), FairnessPolicy::low_volume(), 2);
            let claim = worker.claim(self.job_id, Timestamp::ZERO).await.unwrap();
            worker
                .complete(claim, crate::test_helper::completion(), Timestamp::ZERO)
                .await
                .unwrap();
            return Ok(CommitOutcome::Unknown);
        }
        Ok(outcome)
    }
}

#[test]
fn given_seed_completion_before_a_lost_enqueue_response_when_reconciled_then_applied_disposition_is_preserved()
 {
    let seed = crate::test_helper::low_volume_job(15, Timestamp::ZERO);
    let store = CompleteBeforeAcknowledgement {
        inner: FakeStore::new(),
        job_id: seed.job_id,
        interrupt: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let engine = JobSystem::new(
        store.clone(),
        JobCatalog::from_registry(crate::test_helper::registry(FairnessPolicy::low_volume())),
        Namespace::try_new(b"jobs").unwrap(),
        OwnerId::from([1; 16]),
        crate::test_helper::wake_scheduler(),
    );
    let result = block_on(engine.ensure_seed_raw(seed.clone(), Timestamp::ZERO)).unwrap();
    assert_eq!(result.disposition, EnqueueDisposition::Enqueued);
    assert_eq!(result.wake, WakeHint::None);
    let before = store.inner.snapshot().unwrap();
    let repeated = block_on(engine.ensure_seed_raw(seed, Timestamp::ZERO)).unwrap();
    assert_eq!(repeated.disposition, EnqueueDisposition::AlreadyPresent);
    assert_eq!(store.inner.snapshot().unwrap(), before);
}

#[test]
fn given_an_overdue_stable_seed_when_first_enqueued_then_it_can_be_claimed_at_enqueue_time() {
    let store = FakeStore::new();
    let engine = system(store, FairnessPolicy::low_volume(), 1);
    let seed = crate::test_helper::low_volume_job(16, Timestamp::ZERO);
    let now = Timestamp::from_millis(1_000_000_000_000);
    let id = seed.job_id;
    block_on(engine.ensure_seed_raw(seed, now)).unwrap();
    let claim = block_on(engine.claim(id, now)).expect("new overdue seed remains claimable");
    assert_eq!(claim.record().scheduled_at, Timestamp::ZERO);
    assert_eq!(claim.record().created_at, now);
    assert!(claim.record().retention_deadline > now);
}
