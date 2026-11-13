use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
};

use bg_jobs::{
    JobSystemError, Namespace,
    store::{
        CommitOutcome, JobStore, RangePage, RangeRequest, StoreCapabilities, StoreKey,
        StoreTransaction,
    },
    test_support::FakeStore,
};
use bytes::Bytes;

use crate::{
    CommitFaultKind, ConformanceError, FaultOperation, FaultStore, ReadFaultKind,
    run_lifecycle_growth,
};

#[derive(Clone)]
struct GrowthFaultStore {
    inner: FaultStore<FakeStore>,
    commits: Arc<AtomicUsize>,
    fault_at: usize,
    fault: CommitFaultKind,
}

impl GrowthFaultStore {
    fn new(fault_at: usize, fault: CommitFaultKind) -> Self {
        Self {
            inner: FaultStore::new(FakeStore::local()),
            commits: Arc::new(AtomicUsize::new(0)),
            fault_at,
            fault,
        }
    }
}

impl JobStore for GrowthFaultStore {
    type Error = <FaultStore<FakeStore> as JobStore>::Error;

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
    async fn transact(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        let index = self.commits.fetch_add(1, Ordering::SeqCst) + 1;
        if index == self.fault_at {
            // Exhaust the kernel's immediate two-attempt control retry so the
            // harness must resolve uncertainty through the public scheduler.
            self.inner.queue_commit_fault(self.fault)?;
            if self.fault == CommitFaultKind::UnknownBeforeCommit {
                self.inner.queue_commit_fault(self.fault)?;
            }
        }
        if self.fault_at == usize::MAX {
            return Ok(CommitOutcome::Unknown);
        }
        self.inner.transact(transaction).await
    }
}

#[test]
fn given_lost_acknowledgements_when_each_growth_transaction_is_interrupted_then_work_and_retention_invariants_hold()
 {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    runtime.block_on(async {
        for deduplicated in [false, true] {
            let baseline = GrowthFaultStore::new(0, CommitFaultKind::UnknownBeforeCommit);
            assert_growth(baseline.clone(), deduplicated).await;
            let commits = baseline.commits.load(Ordering::SeqCst);
            assert!(commits > 0);
            for fault in [
                CommitFaultKind::UnknownBeforeCommit,
                CommitFaultKind::UnknownAfterCommit,
            ] {
                for index in 1..=commits {
                    let store = GrowthFaultStore::new(index, fault);
                    assert_growth(store.clone(), deduplicated).await;
                    assert_eq!(
                        store.inner.pending_faults().unwrap(),
                        0,
                        "fault {fault:?} at {index}"
                    );
                }
            }
        }
    });
}

async fn assert_growth(store: GrowthFaultStore, deduplicated: bool) {
    use crate::lifecycle_growth::{GrowthExecution, GrowthWorkload, measure_retained_storage};

    let namespace = Namespace::try_new(b"faulted-growth").unwrap();
    let calls = Arc::new(AtomicU32::new(0));
    let system =
        crate::recovery_fixture::recovery_system(store.clone(), namespace.clone(), calls.clone())
            .unwrap();
    let execution = GrowthExecution {
        system: &system,
        calls: &calls,
        store: &store,
        namespace: &namespace,
    };
    let workload = if deduplicated {
        GrowthWorkload::ExpiringDeduplication
    } else {
        GrowthWorkload::Recurring
    };
    let result = async {
        execution.resolve(|| system.initialize_catalog()).await?;
        let settled_at = execution.execute_batch(0, 4, workload).await?;
        if !deduplicated {
            let schedule = crate::recovery_fixture::recovery_schedule().unwrap();
            let initial =
                bg_jobs::runtime::ScheduleCursor::new(Some(bg_jobs::Timestamp::ZERO), true);
            let report = system
                .materialize_schedule(&schedule, &initial, settled_at)
                .await
                .map_err(ConformanceError::Store)?;
            assert!(report.occurrences.is_empty());
            assert!(!report.cursor.is_active());
        }
        let before = store.commits.load(Ordering::SeqCst);
        execution.drive_one(settled_at, None).await?;
        assert_eq!(
            store.commits.load(Ordering::SeqCst),
            before,
            "resolved idle turn must not mutate"
        );
        // A lost acknowledgment can leave an additional bounded journal slot.
        // Validate that only namespace-owned rows remain; the unchanged 20,000
        // completion tests separately enforce the retained-storage plateau.
        measure_retained_storage(&store, &namespace).await
    }
    .await;
    result.unwrap_or_else(|error| {
        panic!(
            "deduplicated={deduplicated}, fault={:?}, at={}: {error:?}",
            store.fault, store.fault_at
        )
    });
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[test]
fn given_persistent_unknown_commits_when_running_growth_then_resolution_stops_with_an_error() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let store = GrowthFaultStore::new(usize::MAX, CommitFaultKind::UnknownBeforeCommit);
    let result = runtime.block_on(run_lifecycle_growth(
        store.clone(),
        Namespace::try_new(b"unresolved-growth").unwrap(),
        NonZeroU32::MIN,
    ));
    assert!(matches!(
        result,
        Err(ConformanceError::Store(JobSystemError::UnknownCommit))
    ));
    assert!(
        store.commits.load(Ordering::SeqCst) <= 32,
        "resolution must remain bounded"
    );
}

#[test]
fn given_an_unavailable_store_when_running_growth_then_the_error_is_not_retried_or_hidden() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let store = FaultStore::new(FakeStore::local());
    store
        .queue_read_fault(FaultOperation::Get, ReadFaultKind::Unavailable)
        .unwrap();
    let result = runtime.block_on(run_lifecycle_growth(
        store.clone(),
        Namespace::try_new(b"unavailable-growth").unwrap(),
        NonZeroU32::MIN,
    ));
    assert!(matches!(
        result,
        Err(ConformanceError::Store(JobSystemError::Store(
            crate::FaultStoreError::Unavailable
        )))
    ));
    assert_eq!(store.pending_faults().unwrap(), 0);
}
