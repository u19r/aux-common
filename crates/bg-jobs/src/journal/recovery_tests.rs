use std::{
    num::{NonZeroU32, NonZeroUsize},
    sync::{Arc, Mutex},
};

use bytes::Bytes;

use super::state::{Head, Phase, Slot};
use crate::{
    codec::{KeyCodec, KeyTag},
    error::{JobSystemError, StoreContractError},
    ids::{CommitOperationId, LeaseToken},
    policy::FairnessPolicy,
    store::{
        Check, CommitOutcome, JobStore, Mutation, StoreKey, StoreTransaction,
        StoreTransactionInput, TransactionLimits,
    },
    test_helper::{FakeStore, block_on, system},
};

fn command(id: u128, key: &[u8], value: &'static [u8]) -> StoreTransaction {
    StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from(id.to_be_bytes()),
        checks: Vec::new(),
        mutations: vec![Mutation::Put(
            StoreKey::try_from(key).unwrap(),
            Bytes::from_static(value),
        )],
        limits: TransactionLimits {
            max_checks: NonZeroU32::new(128).unwrap(),
            max_mutations: NonZeroU32::new(128).unwrap(),
            max_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
        },
    })
    .unwrap()
}

fn reserve(engine: &crate::JobSystem<FakeStore>, index: u8, input: &StoreTransaction) -> Slot {
    let vacant = block_on(engine.load_commit_slot(index)).unwrap();
    block_on(engine.reserve_commit_input(
        &vacant,
        input,
        LeaseToken::from([3; 16]),
        Phase::Prepared,
    ))
    .unwrap()
    .unwrap()
}

#[test]
fn given_completed_witness_when_only_scan_budget_remains_then_recovery_acknowledges_without_writes()
{
    let store = FakeStore::new();
    let original = system(store.clone(), FairnessPolicy::low_volume(), 1);
    assert_eq!(
        block_on(original.commit_durable(command(1, b"completed", b"value"))).unwrap(),
        CommitOutcome::Committed
    );
    drop(original);
    let before = store.snapshot().unwrap();
    let replacement = system(store.clone(), FairnessPolicy::low_volume(), 2);
    let mut budget = crate::budget::OperationBudget::new(1, replacement.clone_observer());

    let progress = block_on(replacement.recover_pending_commits(&mut budget, || false)).unwrap();

    assert_eq!(progress.recovered, 1);
    assert!(!progress.pending);
    assert_eq!(budget.remaining, 0);
    assert_eq!(store.snapshot().unwrap(), before);
}

#[test]
fn given_an_accepted_command_when_its_producer_never_returns_then_a_replacement_finishes_it() {
    for applied in [false, true] {
        let store = FakeStore::new();
        let original = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let input = command(1, b"accepted-work", b"finished");
        let slot = reserve(&original, 7, &input);
        if applied {
            let (application, _) = original.build_commit_application(&slot, &input).unwrap();
            assert_eq!(
                block_on(store.transact(&application)).unwrap(),
                CommitOutcome::Committed
            );
        }
        drop(original);
        let replacement = system(store.clone(), FairnessPolicy::low_volume(), 2);
        assert_eq!(block_on(replacement.recover_commits()).unwrap(), 1);
        assert_eq!(
            block_on(store.get(StoreKey::try_from(b"accepted-work".as_slice()).unwrap())).unwrap(),
            Some(Bytes::from_static(b"finished"))
        );
        assert!(matches!(
            block_on(replacement.load_commit_slot(7)).unwrap().head,
            Head::Vacant(1)
        ));
        assert_eq!(
            store.snapshot().unwrap().len(),
            2,
            "only application data and the fixed frontier remain"
        );
    }
}

#[test]
fn given_a_takeover_when_a_stale_producer_dispatches_then_it_cannot_apply_or_retire_the_obligation()
{
    let store = FakeStore::new();
    let original = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let replacement = system(store.clone(), FairnessPolicy::low_volume(), 2);
    let input = command(2, b"fenced-work", b"finished");
    let previous = reserve(&original, 8, &input);
    let mut head = previous.active().unwrap();
    head.token = LeaseToken::from([4; 16]);
    let claimed = previous.replace(Head::Active(head));
    assert!(block_on(replacement.write_commit_control(&previous, &claimed, Vec::new())).unwrap());
    assert!(matches!(
        block_on(original.resume_commit(previous, Some(input))),
        Err(JobSystemError::StoreContract(
            StoreContractError::CommitOwnershipLost
        ))
    ));
    assert_eq!(
        block_on(store.get(StoreKey::try_from(b"fenced-work".as_slice()).unwrap())).unwrap(),
        None
    );
    assert_eq!(
        block_on(replacement.resume_commit(claimed, None)).unwrap(),
        CommitOutcome::Committed
    );
}

#[test]
fn given_a_bound_command_when_changed_content_is_submitted_then_no_mutation_or_evidence_changes() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let input = command(3, b"bound-work", b"first");
    let slot = reserve(&engine, 9, &input);
    let before = store.snapshot().unwrap();
    let changed = command(3, b"bound-work", b"different");
    assert!(matches!(
        block_on(engine.resume_commit(slot, Some(changed))),
        Err(JobSystemError::StoreContract(
            StoreContractError::CommitContentMismatch
        ))
    ));
    assert_eq!(store.snapshot().unwrap(), before);
}

#[test]
fn given_lost_atomic_pending_application_or_cleanup_acknowledgements_when_replayed_then_effects_apply_once()
 {
    for lost_step in 0..4 {
        let store = FakeStore::new();
        let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let input = command(4, b"once", b"first");
        let mut checks = input.checks().to_vec();
        checks.push(Check::Absent(
            StoreKey::try_from(b"once".as_slice()).unwrap(),
        ));
        let input = StoreTransaction::try_from(StoreTransactionInput {
            operation_id: input.operation_id(),
            checks,
            mutations: input.mutations().to_vec(),
            limits: input.limits(),
        })
        .unwrap();
        if lost_step > 0 {
            store.queue_unknown_before_commit().unwrap();
        }
        for step in (if lost_step == 0 { 0 } else { 1 })..=lost_step {
            store
                .queue_commit_outcome(if step == lost_step {
                    CommitOutcome::Unknown
                } else {
                    CommitOutcome::Committed
                })
                .unwrap();
        }
        assert_eq!(
            block_on(engine.commit_durable(input)).unwrap(),
            CommitOutcome::Committed
        );
        assert_eq!(store.snapshot().unwrap().len(), 2);
    }
}

#[test]
fn given_a_retired_command_when_its_old_ticket_reappears_then_it_cannot_reapply() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let input = command(5, b"old-ticket", b"first");
    let slot = reserve(&engine, 10, &input);
    let stale = Slot {
        index: slot.index,
        key: slot.key.clone(),
        encoded: slot.encoded.clone(),
        head: slot.head,
    };
    assert_eq!(
        block_on(engine.resume_commit(slot, Some(input.clone()))).unwrap(),
        CommitOutcome::Committed
    );
    assert!(matches!(
        block_on(engine.resume_commit(stale, Some(input))),
        Err(JobSystemError::StoreContract(
            StoreContractError::RetiredCommit
        ))
    ));
}

#[test]
fn given_two_equivalent_batches_when_twenty_thousand_commands_settle_then_rows_and_bytes_stop_growing()
 {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let mut sizes = Vec::new();
    for batch in 0..2 {
        for index in 0..10_000 {
            let input = command((batch * 10_000 + index + 1) as u128, b"current", b"value");
            assert_eq!(
                block_on(engine.commit_durable(input)).unwrap(),
                CommitOutcome::Committed
            );
        }
        let snapshot = store.snapshot().unwrap();
        assert!(snapshot.iter().all(|(key, _)| {
            KeyCodec::decode_borrowed(engine.namespace(), key)
                .map_or(true, |decoded| decoded.tag != KeyTag::CommitInput)
        }));
        sizes.push((
            snapshot.len(),
            snapshot
                .iter()
                .map(|(key, value)| key.as_bytes().len() + value.len())
                .sum::<usize>(),
        ));
    }
    assert_eq!(sizes[0], sizes[1]);
    assert_eq!(sizes[0].0, 2, "one reused witness and one business key");
}

#[test]
fn given_a_full_pool_with_abandoned_producers_when_recovered_then_every_accepted_command_finishes()
{
    let store = FakeStore::new();
    let original = system(store.clone(), FairnessPolicy::low_volume(), 1);
    for index in 0..256 {
        reserve(
            &original,
            index as u8,
            &command(
                index + 10,
                format!("accepted/{index}").as_bytes(),
                b"finished",
            ),
        );
    }
    assert!(matches!(
        block_on(original.commit_durable(command(999, b"not-accepted", b"value"))),
        Err(JobSystemError::StoreContract(
            StoreContractError::CommitCapacity
        ))
    ));
    drop(original);
    let replacement = system(store.clone(), FairnessPolicy::low_volume(), 2);
    assert_eq!(block_on(replacement.recover_commits()).unwrap(), 256);
    for index in 0..256 {
        assert_eq!(
            block_on(
                store.get(StoreKey::try_from(format!("accepted/{index}").as_bytes()).unwrap())
            )
            .unwrap(),
            Some(Bytes::from_static(b"finished"))
        );
    }
    assert_eq!(
        block_on(store.get(StoreKey::try_from(b"not-accepted".as_slice()).unwrap())).unwrap(),
        None
    );
}

#[test]
fn given_a_prepared_command_when_settlement_is_requested_then_the_accepted_input_is_preserved() {
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let slot = reserve(&engine, 11, &command(1000, b"pending", b"value"));
    assert_eq!(slot.active().unwrap().phase, Phase::Prepared);
    let before = store.snapshot().unwrap();
    assert!(block_on(engine.settle_commit(&slot, CommitOutcome::Committed)).is_err());
    assert_eq!(store.snapshot().unwrap(), before);
}

#[derive(Clone)]
struct RegressingReservationStore {
    inner: FakeStore,
    target: StoreKey,
    pending: Arc<Mutex<Option<StoreTransaction>>>,
}

impl JobStore for RegressingReservationStore {
    type Error = crate::FakeStoreError;

    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        if key == self.target && self.pending.lock().unwrap().is_some() {
            return Ok(None);
        }
        self.inner.get(key).await
    }
    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.inner.get_many(keys).await
    }
    async fn read_range(
        &self,
        request: crate::store::RangeRequest,
    ) -> Result<crate::store::RangePage, Self::Error> {
        self.inner.read_range(request).await
    }
    async fn transact(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        if transaction
            .mutations()
            .iter()
            .any(|mutation| mutation.key() == &self.target)
        {
            self.pending
                .lock()
                .unwrap()
                .get_or_insert_with(|| transaction.clone());
            return Ok(CommitOutcome::Unknown);
        }
        self.inner.transact(transaction).await
    }
}

#[test]
fn given_delayed_reservation_and_a_regressing_read_when_admitting_then_no_second_slot_accepts_it() {
    let inner = FakeStore::new();
    let namespace = crate::Namespace::try_new(b"jobs").unwrap();
    let target = super::codec::slot_key(&namespace, 0).unwrap();
    inner
        .put_raw(target.clone(), Head::Vacant(5).encode())
        .unwrap();
    let pending = Arc::new(Mutex::new(None));
    let store = RegressingReservationStore {
        inner: inner.clone(),
        target,
        pending: pending.clone(),
    };
    let engine = crate::JobSystem::new(
        store,
        crate::JobCatalog::new(),
        namespace,
        crate::OwnerId::from([1; 16]),
        crate::test_helper::wake_scheduler(),
    );
    assert!(matches!(
        block_on(engine.commit_durable(command(6, b"delayed", b"finished"))),
        Err(JobSystemError::UnknownCommit)
    ));
    assert_eq!(
        inner.snapshot().unwrap().len(),
        1,
        "no other slot accepted the unresolved command"
    );
    let delayed = pending.lock().unwrap().take().unwrap();
    assert_eq!(
        block_on(inner.transact(&delayed)).unwrap(),
        CommitOutcome::Committed
    );
    drop(engine);
    let replacement = system(inner.clone(), FairnessPolicy::low_volume(), 2);
    assert_eq!(block_on(replacement.recover_commits()).unwrap(), 1);
    assert_eq!(inner.snapshot().unwrap().len(), 2);
    assert_eq!(
        block_on(inner.get(StoreKey::try_from(b"delayed".as_slice()).unwrap())).unwrap(),
        Some(Bytes::from_static(b"finished"))
    );
}

#[test]
fn given_an_abandoned_conflicted_wake_transition_when_recovered_then_its_original_work_is_completed()
 {
    let store = FakeStore::new();
    let original = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let wake = crate::keys::wake_key(
        original.namespace(),
        &crate::QueueName::try_new("default").unwrap(),
    )
    .unwrap();
    store
        .put_raw(
            wake.clone(),
            crate::keys::wake_value(crate::Timestamp::from_millis(200)).unwrap(),
        )
        .unwrap();
    let input = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([7; 16]),
        checks: vec![Check::Value(
            wake.clone(),
            crate::keys::wake_value(crate::Timestamp::from_millis(100)).unwrap(),
        )],
        mutations: vec![
            Mutation::Put(
                wake.clone(),
                crate::keys::wake_value(crate::Timestamp::from_millis(300)).unwrap(),
            ),
            Mutation::Put(
                StoreKey::try_from(b"produced-outcome".as_slice()).unwrap(),
                Bytes::from_static(b"completed"),
            ),
        ],
        limits: command(7, b"fixture", b"value").limits(),
    })
    .unwrap();
    let empty = block_on(original.load_commit_slot(12)).unwrap();
    let slot = block_on(original.reserve_commit_input(
        &empty,
        &input,
        LeaseToken::from([7; 16]),
        Phase::Prepared,
    ))
    .unwrap()
    .unwrap();
    let (application, _) = original.build_commit_application(&slot, &input).unwrap();
    assert_eq!(
        block_on(store.transact(&application)).unwrap(),
        CommitOutcome::Conflict
    );
    let conflicted = slot.replace(Head::Active(super::state::ActiveHead {
        phase: Phase::Conflict,
        ..slot.active().unwrap()
    }));
    assert!(block_on(original.write_commit_control(&slot, &conflicted, Vec::new())).unwrap());
    drop(original);
    let replacement = system(store.clone(), FairnessPolicy::low_volume(), 2);
    assert_eq!(block_on(replacement.recover_commits()).unwrap(), 1);
    assert_eq!(
        block_on(store.get(StoreKey::try_from(b"produced-outcome".as_slice()).unwrap())).unwrap(),
        Some(Bytes::from_static(b"completed"))
    );
    assert_eq!(
        block_on(store.get(wake)).unwrap(),
        Some(crate::keys::wake_value(crate::Timestamp::from_millis(200)).unwrap())
    );
}

#[test]
fn given_recovery_input_exceeds_handler_payload_budget_when_driving_then_it_recovers_before_handlers_start()
 {
    let store = FakeStore::new();
    let original = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let input = command(99, b"memory-bounded-recovery", b"accepted");
    reserve(&original, 8, &input);
    drop(original);
    let replacement = system(store.clone(), FairnessPolicy::low_volume(), 2);
    let request = crate::DriveRequest::try_from(crate::DriveRequestInput {
        queues: crate::QueueSelection::all(),
        max_claims: NonZeroU32::MIN,
        max_concurrency: std::num::NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::MIN,
        max_completion_details: 1,
        max_store_operations: NonZeroU32::new(512).unwrap(),
        stop_claiming_at: crate::MonotonicDeadline::from_nanos(1),
        finish_by: crate::MonotonicDeadline::from_nanos(u64::MAX),
    })
    .unwrap();
    let report = block_on(replacement.drive(request, crate::Timestamp::ZERO, || {
        crate::MonotonicDeadline::ZERO
    }))
    .unwrap();
    assert_eq!(report.stop_reason, crate::DriveStopReason::NoVisibleWork);
    assert_eq!(report.next_wake, crate::WakeHint::None);
    assert_eq!(report.counts.claimed, 0);
    assert_eq!(
        block_on(replacement.recover_commits()).unwrap(),
        0,
        "drive already finished the accepted command"
    );
    assert_eq!(
        block_on(store.get(StoreKey::try_from(b"memory-bounded-recovery".as_slice()).unwrap()))
            .unwrap(),
        Some(Bytes::from_static(b"accepted"))
    );
}

#[derive(Clone)]
struct WakeChurnStore {
    inner: FakeStore,
    wake: StoreKey,
    job: StoreKey,
    applications: Arc<std::sync::atomic::AtomicUsize>,
    interferences: usize,
    read_mode: WakeRead,
}

#[derive(Clone, Copy)]
enum WakeRead {
    Fresh,
    StaleOriginal,
    Restored,
}

impl JobStore for WakeChurnStore {
    type Error = crate::test_helper::FakeStoreError;
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        if key == self.wake
            && matches!(self.read_mode, WakeRead::StaleOriginal)
            && self.applications.load(std::sync::atomic::Ordering::SeqCst) > 0
        {
            return Ok(Some(
                crate::keys::wake_value(crate::Timestamp::from_millis(1000)).unwrap(),
            ));
        }
        self.inner.get(key).await
    }
    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.inner.get_many(keys).await
    }
    async fn read_range(
        &self,
        request: crate::store::RangeRequest,
    ) -> Result<crate::store::RangePage, Self::Error> {
        self.inner.read_range(request).await
    }
    async fn transact(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        if transaction
            .mutations()
            .iter()
            .any(|mutation| mutation.key() == &self.job)
        {
            let attempt = self
                .applications
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt < self.interferences {
                self.inner.put_raw(
                    self.wake.clone(),
                    crate::keys::wake_value(crate::Timestamp::from_millis(
                        500 / (attempt as i64 + 1),
                    ))
                    .unwrap(),
                )?;
            }
            let outcome = self.inner.transact(transaction).await;
            if attempt < self.interferences && matches!(self.read_mode, WakeRead::Restored) {
                self.inner.put_raw(
                    self.wake.clone(),
                    crate::keys::wake_value(crate::Timestamp::from_millis(1000)).unwrap(),
                )?;
            }
            return outcome;
        }
        self.inner.transact(transaction).await
    }
}

#[test]
fn given_two_wake_conflicts_after_enqueue_acceptance_when_the_producer_never_returns_then_recovery_still_enqueues_the_job()
 {
    let inner = FakeStore::new();
    let namespace = crate::Namespace::try_new(b"jobs").unwrap();
    let wake =
        crate::keys::wake_key(&namespace, &crate::QueueName::try_new("default").unwrap()).unwrap();
    inner
        .put_raw(
            wake.clone(),
            crate::keys::wake_value(crate::Timestamp::from_millis(1000)).unwrap(),
        )
        .unwrap();
    let id = crate::JobId::from([24; 16]);
    let job = crate::keys::job_key(&namespace, &id).unwrap();
    let applications = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let store = WakeChurnStore {
        inner: inner.clone(),
        wake,
        job: job.clone(),
        applications: applications.clone(),
        interferences: 2,
        read_mode: WakeRead::Fresh,
    };
    let original = crate::JobSystem::new(
        store,
        crate::JobCatalog::from_registry(
            crate::test_helper::registry(FairnessPolicy::low_volume()),
        ),
        namespace,
        crate::OwnerId::from([1; 16]),
        crate::test_helper::wake_scheduler(),
    );
    let result = block_on(original.enqueue_raw(
        crate::test_helper::low_volume_job(24, crate::Timestamp::ZERO),
        crate::Timestamp::ZERO,
    ));
    assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
    assert_eq!(applications.load(std::sync::atomic::Ordering::SeqCst), 2);
    drop(original);
    assert_eq!(block_on(inner.get(job)).unwrap(), None);
    let replacement = system(inner, FairnessPolicy::low_volume(), 2);
    assert_eq!(
        block_on(replacement.recover_commits()).unwrap(),
        1,
        "known wake aborts must not retire an unfulfilled accepted enqueue"
    );
    let claim = block_on(replacement.claim(id, crate::Timestamp::ZERO)).unwrap();
    assert_eq!(claim.payload().as_ref(), b"payload");
}

#[test]
fn given_a_wake_conflict_and_stale_or_restored_observation_when_the_producer_is_dropped_then_accepted_work_is_not_discarded()
 {
    for read_mode in [WakeRead::StaleOriginal, WakeRead::Restored] {
        let inner = FakeStore::new();
        let namespace = crate::Namespace::try_new(b"jobs").unwrap();
        let wake =
            crate::keys::wake_key(&namespace, &crate::QueueName::try_new("default").unwrap())
                .unwrap();
        inner
            .put_raw(
                wake.clone(),
                crate::keys::wake_value(crate::Timestamp::from_millis(1000)).unwrap(),
            )
            .unwrap();
        let id = crate::JobId::from([25; 16]);
        let job = crate::keys::job_key(&namespace, &id).unwrap();
        let store = WakeChurnStore {
            inner: inner.clone(),
            wake,
            job,
            applications: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            interferences: 1,
            read_mode,
        };
        let original = crate::JobSystem::new(
            store,
            crate::JobCatalog::from_registry(crate::test_helper::registry(
                FairnessPolicy::low_volume(),
            )),
            namespace,
            crate::OwnerId::from([1; 16]),
            crate::test_helper::wake_scheduler(),
        );
        let result = block_on(original.enqueue_raw(
            crate::test_helper::low_volume_job(25, crate::Timestamp::ZERO),
            crate::Timestamp::ZERO,
        ));
        assert!(matches!(result, Ok(_) | Err(JobSystemError::UnknownCommit)));
        drop(original);
        let replacement = system(inner, FairnessPolicy::low_volume(), 2);
        block_on(replacement.recover_commits()).unwrap();
        let claim = block_on(replacement.claim(id, crate::Timestamp::ZERO))
            .expect("a wake observation cannot retire unfulfilled accepted work");
        assert_eq!(claim.payload().as_ref(), b"payload");
    }
}

#[test]
fn given_a_rejected_probe_that_lost_ownership_when_a_replacement_commits_then_stale_retirement_cannot_report_rejection()
 {
    let store = FakeStore::new();
    let original = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let replacement = system(store.clone(), FairnessPolicy::low_volume(), 2);
    let job = crate::keys::job_key(original.namespace(), &crate::JobId::from([26; 16])).unwrap();
    let wake = crate::keys::wake_key(
        original.namespace(),
        &crate::QueueName::try_new("default").unwrap(),
    )
    .unwrap();
    let old_wake = crate::keys::wake_value(crate::Timestamp::from_millis(1000)).unwrap();
    store
        .put_raw(
            wake.clone(),
            crate::keys::wake_value(crate::Timestamp::from_millis(500)).unwrap(),
        )
        .unwrap();
    let input = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([26; 16]),
        checks: vec![
            Check::Absent(job.clone()),
            Check::Value(wake.clone(), old_wake),
        ],
        mutations: vec![
            Mutation::Put(job.clone(), Bytes::from_static(b"applied")),
            Mutation::Put(
                wake,
                crate::keys::wake_value(crate::Timestamp::ZERO).unwrap(),
            ),
        ],
        limits: command(1, b"unused", b"unused").limits(),
    })
    .unwrap();
    let vacant = block_on(original.load_commit_slot(26)).unwrap();
    let prepared = block_on(original.reserve_commit_input(
        &vacant,
        &input,
        LeaseToken::from([1; 16]),
        Phase::Prepared,
    ))
    .unwrap()
    .unwrap();
    let (application, _) = original
        .build_commit_application(&prepared, &input)
        .unwrap();
    assert_eq!(
        block_on(store.transact(&application)).unwrap(),
        CommitOutcome::Conflict
    );
    let mut failed = prepared.active().unwrap();
    failed.phase = Phase::Conflict;
    let conflicted = prepared.replace(Head::Active(failed));
    assert!(block_on(original.write_commit_control(&prepared, &conflicted, Vec::new())).unwrap());
    assert_eq!(conflicted.active().unwrap().phase, Phase::Conflict);
    let mut next = conflicted.active().unwrap();
    next.token = LeaseToken::from([2; 16]);
    let claimed = conflicted.replace(Head::Active(next));
    assert!(block_on(replacement.write_commit_control(&conflicted, &claimed, Vec::new())).unwrap());
    let probe = block_on(
        original.store().transact(
            &original
                .build_transaction(
                    input.operation_id(),
                    vec![Check::Absent(job.clone()), conflicted.check()],
                    Vec::new(),
                )
                .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        probe,
        CommitOutcome::Conflict,
        "only the owner token changed"
    );
    assert_eq!(
        block_on(replacement.resume_commit(claimed, None)).unwrap(),
        CommitOutcome::Committed
    );
    assert!(matches!(
        block_on(original.settle_commit(&conflicted, CommitOutcome::Conflict)),
        Err(JobSystemError::StoreContract(
            StoreContractError::RetiredCommit | StoreContractError::CommitOwnershipLost
        ))
    ));
    assert_eq!(
        block_on(store.get(job)).unwrap(),
        Some(Bytes::from_static(b"applied"))
    );
}

#[test]
fn given_full_abandoned_journal_when_seed_worker_starts_then_recovery_precedes_admission_retry() {
    let store = FakeStore::new();
    let original = system(store.clone(), FairnessPolicy::low_volume(), 1);
    for index in 0..256 {
        reserve(
            &original,
            index as u8,
            &command(
                index + 10,
                format!("accepted/{index}").as_bytes(),
                b"finished",
            ),
        );
    }
    let seed = crate::test_helper::low_volume_job(1, crate::Timestamp::ZERO);
    let manifest = crate::CatalogManifest::try_new(
        crate::CatalogRevision::from(std::num::NonZeroU64::MIN),
        vec![seed.job_id],
        Vec::new(),
    )
    .unwrap();
    let mut catalog =
        crate::JobCatalog::from_registry(original.registry().clone()).with_manifest(manifest);
    catalog.add_seed_raw(seed.clone()).unwrap();
    let replacement = crate::JobSystem::new(
        store.clone(),
        catalog,
        original.namespace().clone(),
        *original.owner(),
        crate::test_helper::wake_scheduler(),
    );
    drop(original);
    block_on(replacement.ensure_seeds(crate::Timestamp::ZERO))
        .expect("configured startup recovers abandoned input");
    for index in 0..256 {
        assert_eq!(
            block_on(
                store.get(StoreKey::try_from(format!("accepted/{index}").as_bytes()).unwrap())
            )
            .unwrap(),
            Some(Bytes::from_static(b"finished"))
        );
    }
    assert!(matches!(
        block_on(replacement.observe_lifecycle(seed.job_id)).unwrap(),
        crate::LifecycleObservation::Current { .. }
    ));
}
