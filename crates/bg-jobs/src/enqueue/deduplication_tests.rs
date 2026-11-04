use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;

use crate::{
    store::{
        JobStore, Mutation, RangePage, RangeRequest, StoreCapabilities, StoreKey, StoreTransaction,
    },
    test_helper::{block_on, dedupe, low_volume_job, wake_scheduler},
    *,
};

fn engine<S: JobStore>(store: S, owner: u8) -> JobSystem<S> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(crate::test_helper::registry(FairnessPolicy::low_volume())),
        Namespace::try_new(b"jobs").unwrap(),
        OwnerId::from([owner; 16]),
        wake_scheduler(),
    )
}

fn retained_job(id: u8, until: Timestamp) -> NewJob {
    let mut job = low_volume_job(id, Timestamp::ZERO);
    job.deduplication = Some(dedupe(b"retained", until));
    job
}

fn complete_retained<S: JobStore>(system: &JobSystem<S>, id: u8, until: Timestamp) {
    block_on(system.enqueue_raw(retained_job(id, until), Timestamp::ZERO)).unwrap();
    let claim = block_on(system.claim(JobId::from([id; 16]), Timestamp::ZERO)).unwrap();
    block_on(system.complete(claim, crate::test_helper::completion(), Timestamp::ZERO)).unwrap();
}

fn drive<S: JobStore>(system: &JobSystem<S>, now: Timestamp) -> DriveReport {
    let request = DriveBudget::try_resident(QueueSelection::all())
        .unwrap()
        .request_at(MonotonicDeadline::ZERO)
        .unwrap();
    block_on(system.drive(request, now, || MonotonicDeadline::ZERO)).unwrap()
}

#[test]
fn given_retained_deduplication_when_idle_before_expiry_then_the_scheduler_requests_its_maintenance_deadline_without_writes()
 {
    let store = FakeStore::distributed();
    let system = engine(store.clone(), 1);
    complete_retained(&system, 1, Timestamp::from_millis(50));
    let before = store.snapshot().unwrap();
    let report = drive(&system, Timestamp::from_millis(2));
    assert_eq!(report.next_wake, WakeHint::At(Timestamp::from_millis(50)));
    assert_eq!(store.snapshot().unwrap(), before);
    drive(&system, Timestamp::from_millis(50));
    assert!(
        !store
            .contains(
                &crate::keys::dedupe_key(
                    system.namespace(),
                    &DeduplicationKey::try_new(b"retained").unwrap()
                )
                .unwrap()
            )
            .unwrap()
    );
}

#[test]
fn given_negative_and_positive_expiry_times_when_maintenance_runs_then_only_due_identities_retire_in_time_order()
 {
    let store = FakeStore::distributed();
    let system = engine(store.clone(), 1);
    for (id, due) in [(1, -2), (2, 2), (3, 5)] {
        let identity = DeduplicationKey::try_new([id]).unwrap();
        let until = Timestamp::from_millis(due);
        let value = crate::keys::dedupe_value(&JobId::from([id; 16]), until).unwrap();
        store
            .put_raw(
                crate::keys::dedupe_key(system.namespace(), &identity).unwrap(),
                value.clone(),
            )
            .unwrap();
        store
            .put_raw(
                crate::keys::dedupe_expiry_key(system.namespace(), &identity, until).unwrap(),
                value,
            )
            .unwrap();
    }
    let report = drive(&system, Timestamp::ZERO);
    assert_eq!(report.next_wake, WakeHint::At(Timestamp::from_millis(2)));
    for (id, remains) in [(1, false), (2, true), (3, true)] {
        assert_eq!(
            store
                .contains(
                    &crate::keys::dedupe_key(
                        system.namespace(),
                        &DeduplicationKey::try_new([id]).unwrap()
                    )
                    .unwrap()
                )
                .unwrap(),
            remains
        );
    }
}

enum Race {
    Replace,
    LoseAdmission,
    LoseCleanup,
    RegressRead,
    CleanupBeforeEnqueue,
    AcceptBeforeCleanup,
    RegressUnexpired,
    CompetingBeforeEnqueue,
    AcceptBeforeCompeting,
}

#[derive(Clone)]
struct ExpiryRaceStore {
    inner: FakeStore,
    action: Arc<Mutex<Option<Race>>>,
}

impl JobStore for ExpiryRaceStore {
    type Error = FakeStoreError;
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        let target = crate::keys::dedupe_key(
            &Namespace::try_new(b"jobs").unwrap(),
            &DeduplicationKey::try_new(b"retained").unwrap(),
        )
        .unwrap();
        if key == target {
            let mut action = self.action.lock().unwrap();
            if matches!(*action, Some(Race::RegressRead)) {
                action.take();
                return Ok(None);
            }
            if matches!(*action, Some(Race::RegressUnexpired)) {
                action.take();
                return Ok(Some(
                    crate::keys::dedupe_value(&JobId::from([99; 16]), Timestamp::from_millis(500))
                        .unwrap(),
                ));
            }
        }
        self.inner.get(key).await
    }
    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.inner.get_many(keys).await
    }
    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.inner.read_range(request).await
    }
    async fn transact(&self, input: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        let key = crate::keys::dedupe_key(
            &Namespace::try_new(b"jobs").unwrap(),
            &DeduplicationKey::try_new(b"retained").unwrap(),
        )
        .unwrap();
        let action = {
            let mut guard = self.action.lock().unwrap();
            let cleanup = input
                .mutations()
                .iter()
                .any(|mutation| matches!(mutation, Mutation::Delete(target) if target == &key));
            let enqueue = input
                .mutations()
                .iter()
                .any(|mutation| matches!(mutation, Mutation::Put(target, _) if target == &key));
            if (matches!(*guard, Some(Race::LoseCleanup)) && cleanup)
                || matches!(*guard, Some(Race::LoseAdmission))
                || (matches!(
                    *guard,
                    Some(
                        Race::CleanupBeforeEnqueue
                            | Race::CompetingBeforeEnqueue
                            | Race::AcceptBeforeCleanup
                            | Race::AcceptBeforeCompeting
                    )
                ) && enqueue)
                || (matches!(*guard, Some(Race::Replace)) && cleanup)
            {
                guard.take()
            } else {
                None
            }
        };
        match action {
            Some(Race::AcceptBeforeCleanup | Race::AcceptBeforeCompeting) => {
                // Leave the first atomic attempt unapplied and ambiguous.
                // The engine must accept durable input before the next
                // business dispatch reaches the requested interleaving.
                *self.action.lock().unwrap() =
                    Some(if matches!(action, Some(Race::AcceptBeforeCleanup)) {
                        Race::CleanupBeforeEnqueue
                    } else {
                        Race::CompetingBeforeEnqueue
                    });
                return Ok(CommitOutcome::Unknown);
            }
            Some(Race::Replace) => {
                block_on(engine(self.inner.clone(), 2).enqueue_raw(
                    retained_job(2, Timestamp::from_millis(50)),
                    Timestamp::from_millis(2),
                ))
                .unwrap();
            }
            Some(Race::CleanupBeforeEnqueue) => {
                // A second scheduler has already passed its recovery scan.
                // Its maintenance application wins before this enqueue.
                let competing = engine(self.inner.clone(), 2);
                let mut budget =
                    crate::budget::OperationBudget::new(256, competing.clone_observer());
                block_on(competing.retire_expired_deduplication(
                    Timestamp::from_millis(2),
                    &mut budget,
                    || false,
                ))
                .unwrap();
                return std::future::pending().await;
            }
            Some(Race::CompetingBeforeEnqueue) => {
                block_on(engine(self.inner.clone(), 3).enqueue_raw(
                    retained_job(3, Timestamp::from_millis(100)),
                    Timestamp::from_millis(2),
                ))
                .unwrap();
                return std::future::pending().await;
            }
            Some(Race::RegressRead | Race::RegressUnexpired) => {
                panic!("stale read must be consumed before dispatch")
            }
            Some(Race::LoseCleanup) => return std::future::pending().await,
            Some(Race::LoseAdmission) => {
                assert_eq!(self.inner.transact(input).await?, CommitOutcome::Committed);
                return std::future::pending().await;
            }
            None => {}
        }
        self.inner.transact(input).await
    }
}

#[test]
fn given_expired_identity_replaced_during_cleanup_when_the_stale_cleanup_dispatches_then_the_new_window_survives()
 {
    let store = ExpiryRaceStore {
        inner: FakeStore::distributed(),
        action: Arc::new(Mutex::new(None)),
    };
    let system = engine(store.clone(), 1);
    complete_retained(&system, 1, Timestamp::from_millis(1));
    *store.action.lock().unwrap() = Some(Race::Replace);
    drive(&system, Timestamp::from_millis(2));
    let identity = DeduplicationKey::try_new(b"retained").unwrap();
    let value =
        block_on(store.get(crate::keys::dedupe_key(system.namespace(), &identity).unwrap()))
            .unwrap()
            .unwrap();
    assert_eq!(
        crate::keys::decode_dedupe_value(&value).unwrap(),
        (JobId::from([2; 16]), Timestamp::from_millis(50))
    );
    assert!(
        store
            .inner
            .contains(
                &crate::keys::dedupe_expiry_key(
                    system.namespace(),
                    &identity,
                    Timestamp::from_millis(50)
                )
                .unwrap()
            )
            .unwrap()
    );
    let result = block_on(system.enqueue_raw(
        retained_job(3, Timestamp::from_millis(100)),
        Timestamp::from_millis(3),
    ))
    .unwrap();
    assert_eq!(result.disposition, EnqueueDisposition::Deduplicated);
}

#[test]
fn given_expiry_cleanup_producer_death_before_or_after_dispatch_when_replacement_runs_then_the_index_supplies_all_retry_input()
 {
    for applied in [false, true] {
        let store = ExpiryRaceStore {
            inner: FakeStore::distributed(),
            action: Arc::new(Mutex::new(None)),
        };
        let system = engine(store.clone(), 1);
        complete_retained(&system, 1, Timestamp::from_millis(1));
        *store.action.lock().unwrap() = Some(if applied {
            Race::LoseAdmission
        } else {
            Race::LoseCleanup
        });
        let request = DriveBudget::try_resident(QueueSelection::all())
            .unwrap()
            .request_at(MonotonicDeadline::ZERO)
            .unwrap();
        let mut future = Box::pin(system.drive(request, Timestamp::from_millis(2), || {
            MonotonicDeadline::ZERO
        }));
        assert!(matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        drop(future);
        drop(system);
        let replacement = engine(store.inner.clone(), 2);
        assert_eq!(
            block_on(replacement.recover_commits()).unwrap(),
            1,
            "the final completed witness is reconciled without writes"
        );
        drive(&replacement, Timestamp::from_millis(2));
        assert!(!store.inner.snapshot().unwrap().iter().any(|(key, _)| {
            matches!(
                crate::codec::KeyCodec::decode(replacement.namespace(), key)
                    .unwrap()
                    .tag,
                crate::codec::KeyTag::Dedupe | crate::codec::KeyTag::DedupeExpiry
            )
        }));
    }
}

#[test]
fn given_expired_identity_when_cleanup_budget_or_deadline_is_exhausted_then_no_unadmitted_mutations_start()
 {
    for expired_deadline in [false, true] {
        let store = FakeStore::distributed();
        let system = engine(store.clone(), 1);
        complete_retained(&system, 1, Timestamp::from_millis(1));
        let before = store.snapshot().unwrap();
        let mut budget = crate::budget::OperationBudget::new(2, system.clone_observer());
        let wake = block_on(system.retire_expired_deduplication(
            Timestamp::from_millis(2),
            &mut budget,
            || expired_deadline,
        ))
        .unwrap();
        assert_eq!(
            wake,
            if expired_deadline {
                WakeHint::None
            } else {
                WakeHint::Now
            }
        );
        assert_eq!(store.snapshot().unwrap(), before);
    }
}

#[test]
fn given_one_reused_expired_identity_when_many_jobs_finish_then_replacement_keeps_one_current_expiry_entry()
 {
    let store = FakeStore::distributed();
    let system = engine(store.clone(), 1);
    let prefix =
        crate::codec::KeyCodec::encode(system.namespace(), crate::codec::KeyTag::DedupeExpiry, &[])
            .unwrap();
    for id in 1..=100 {
        let now = Timestamp::from_millis(i64::from(id));
        block_on(system.enqueue_raw(
            retained_job(id, Timestamp::from_millis(i64::from(id) + 1)),
            now,
        ))
        .unwrap();
        let claim = block_on(system.claim(JobId::from([id; 16]), now)).unwrap();
        block_on(system.complete(claim, crate::test_helper::completion(), now)).unwrap();
        assert_eq!(
            store
                .snapshot()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.as_bytes().starts_with(prefix.as_bytes()))
                .count(),
            1
        );
    }
    drive(&system, Timestamp::from_millis(101));
    assert!(
        !store
            .snapshot()
            .unwrap()
            .iter()
            .any(|(key, _)| key.as_bytes().starts_with(prefix.as_bytes()))
    );
}

#[test]
fn given_stale_missing_identity_read_when_retiring_expiry_then_native_guard_preserves_the_expiry_index()
 {
    let store = ExpiryRaceStore {
        inner: FakeStore::distributed(),
        action: Arc::new(Mutex::new(None)),
    };
    let system = engine(store.clone(), 1);
    complete_retained(&system, 1, Timestamp::from_millis(1));
    *store.action.lock().unwrap() = Some(Race::RegressRead);
    let report = drive(&system, Timestamp::from_millis(2));
    assert_eq!(report.next_wake, WakeHint::Now);
    let identity = DeduplicationKey::try_new(b"retained").unwrap();
    assert!(
        store
            .inner
            .contains(&crate::keys::dedupe_key(system.namespace(), &identity).unwrap())
            .unwrap()
    );
    assert!(
        store
            .inner
            .contains(
                &crate::keys::dedupe_expiry_key(
                    system.namespace(),
                    &identity,
                    Timestamp::from_millis(1)
                )
                .unwrap()
            )
            .unwrap()
    );
    drive(&system, Timestamp::from_millis(2));
    assert!(
        !store
            .inner
            .contains(&crate::keys::dedupe_key(system.namespace(), &identity).unwrap())
            .unwrap()
    );
}

#[test]
fn given_accepted_replacement_enqueue_when_cleanup_removes_its_expired_marker_and_producer_is_lost_then_recovery_finishes_work()
 {
    let store = ExpiryRaceStore {
        inner: FakeStore::distributed(),
        action: Arc::new(Mutex::new(None)),
    };
    let system = engine(store.clone(), 1);
    complete_retained(&system, 1, Timestamp::from_millis(1));
    *store.action.lock().unwrap() = Some(Race::AcceptBeforeCleanup);
    let mut future = Box::pin(system.enqueue_raw(
        retained_job(2, Timestamp::from_millis(50)),
        Timestamp::from_millis(2),
    ));
    assert!(matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(future);
    drop(system);
    let replacement = engine(store.inner, 2);
    assert_eq!(block_on(replacement.recover_commits()).unwrap(), 1);
    let claim =
        block_on(replacement.claim(JobId::from([2; 16]), Timestamp::from_millis(2))).unwrap();
    assert_eq!(
        claim.payload().as_ref(),
        retained_job(2, Timestamp::from_millis(50)).payload.as_ref()
    );
}

#[test]
fn given_stale_unexpired_identity_read_when_recovering_accepted_work_then_native_rejection_proof_is_required()
 {
    let store = ExpiryRaceStore {
        inner: FakeStore::distributed(),
        action: Arc::new(Mutex::new(None)),
    };
    let system = engine(store.clone(), 1);
    complete_retained(&system, 1, Timestamp::from_millis(1));
    *store.action.lock().unwrap() = Some(Race::AcceptBeforeCleanup);
    let mut future = Box::pin(system.enqueue_raw(
        retained_job(2, Timestamp::from_millis(50)),
        Timestamp::from_millis(2),
    ));
    assert!(matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(future);
    drop(system);
    *store.action.lock().unwrap() = Some(Race::RegressUnexpired);
    let replacement = engine(store, 2);
    assert!(matches!(
        block_on(replacement.recover_commits()),
        Err(JobSystemError::UnknownCommit)
    ));
    assert_eq!(block_on(replacement.recover_commits()).unwrap(), 1);
    block_on(replacement.claim(JobId::from([2; 16]), Timestamp::from_millis(2))).unwrap();
}

#[test]
fn given_competing_unexpired_identity_when_recovering_accepted_enqueue_then_only_the_winning_job_executes()
 {
    let store = ExpiryRaceStore {
        inner: FakeStore::distributed(),
        action: Arc::new(Mutex::new(None)),
    };
    let system = engine(store.clone(), 1);
    complete_retained(&system, 1, Timestamp::from_millis(1));
    *store.action.lock().unwrap() = Some(Race::AcceptBeforeCompeting);
    let mut future = Box::pin(system.enqueue_raw(
        retained_job(2, Timestamp::from_millis(50)),
        Timestamp::from_millis(2),
    ));
    assert!(matches!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(future);
    drop(system);
    let replacement = engine(store.inner, 2);
    assert_eq!(
        block_on(replacement.recover_commits()).unwrap(),
        2,
        "recover pending input and reconcile the competing committed witness"
    );
    assert!(matches!(
        block_on(replacement.claim(JobId::from([2; 16]), Timestamp::from_millis(2))),
        Err(JobSystemError::NotFound)
    ));
    block_on(replacement.claim(JobId::from([3; 16]), Timestamp::from_millis(2))).unwrap();
}

#[derive(Default)]
struct CleanupWrites(std::sync::atomic::AtomicU32);

impl crate::observer::JobObserver for CleanupWrites {
    fn observe(&self, event: crate::observer::JobEvent) {
        if matches!(
            event,
            crate::observer::JobEvent::StoreOperation {
                operation: crate::observer::StoreOperation::Commit
            }
        ) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[test]
fn given_a_durable_expiry_entry_when_cleaning_then_one_native_cas_is_sufficient_without_a_second_recovery_record()
 {
    let store = FakeStore::distributed();
    let writes = Arc::new(CleanupWrites::default());
    let system = engine(store.clone(), 1).with_observer(writes.clone());
    complete_retained(&system, 1, Timestamp::from_millis(1));
    writes.0.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut budget = crate::budget::OperationBudget::new(256, system.clone_observer());
    block_on(system.retire_expired_deduplication(Timestamp::from_millis(2), &mut budget, || false))
        .unwrap();
    assert_eq!(writes.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(
        !store
            .contains(
                &crate::keys::dedupe_key(
                    system.namespace(),
                    &DeduplicationKey::try_new(b"retained").unwrap()
                )
                .unwrap()
            )
            .unwrap()
    );
}
