use std::{
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use alloc_counter::AllocationGuard;
use bg_jobs::{
    Timestamp,
    runtime::MonotonicDeadline,
    store::{
        Check, CommitOperationId, CommitOutcome, JobStore, Mutation, RangeDirection, RangePage,
        RangeRequest, RangeRequestInput, StoreCapabilities, StoreCapabilitiesInput, StoreKey,
        StoreLevel, StoreTransaction, StoreTransactionInput, TransactionLimits,
    },
    test_support::{FakeStore, FakeStoreError},
};
use bg_jobs_conformance::{
    CommitFaultKind, ConformanceConfig, ConformanceConfigError, ConformanceError, FaultOperation,
    FaultStore, FaultStoreError, ReadFaultKind, RepairBudget, RepairEntry, RepairReason,
    StoreModel, run_basic, run_faults, run_operation_profile,
};
use bytes::Bytes;

const LABEL: &str = "bg-jobs-conformance-unit";

#[test]
fn given_empty_prefix_when_constructing_conformance_config_then_rejected_before_store_use() {
    let error = ConformanceConfig::try_new([], nonzero_u32(2), nonzero_usize(1_024))
        .expect_err("an empty prefix must not create an unnamespaced conformance run");
    assert_eq!(error, ConformanceConfigError::EmptyPrefix);

    let config =
        ConformanceConfig::try_new(b"custom-conformance/", nonzero_u32(2), nonzero_usize(1_024))
            .expect("a non-empty prefix creates a validated configuration");
    let store = FakeStore::local();
    block_on(run_basic(&store, &config)).expect("validated configuration should run");
}

#[test]
fn given_default_conformance_configs_when_created_then_each_uses_an_isolated_prefix() {
    let first = ConformanceConfig::default();
    let second = ConformanceConfig::default();
    assert_ne!(
        first, second,
        "default runs must not share a destructive prefix"
    );

    let store = FakeStore::local();
    let legacy_key = key(b"bg-jobs-conformance/basic/a");
    store
        .put_raw(legacy_key.clone(), Bytes::from_static(b"preserve"))
        .expect("legacy fixture is valid");
    block_on(run_basic(&store, &first)).expect("isolated run should pass");
    assert_eq!(
        block_on(store.get(legacy_key)).expect("legacy read succeeds"),
        Some(Bytes::from_static(b"preserve"))
    );
}

#[test]
fn given_distributed_fake_store_when_running_basic_then_get_range_commit_and_limits_hold() {
    let store = FakeStore::distributed();
    let config = ConformanceConfig::default();
    let report = block_on(run_basic(&store, &config)).expect("basic conformance should pass");

    assert!(store.capabilities().is_distributed());
    assert_eq!(report.reads, 3);
    assert_eq!(report.get_many, 4);
    assert_eq!(report.ranges, 4);
    assert_eq!(report.commits, 9);
    assert_eq!(report.conflicts, 4);
    assert!(report.assertions >= 22);

    let key = key(b"limits");
    let value = Bytes::from(vec![0; store.capabilities().max_value_bytes().get() + 1]);
    let transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: commit_operation_id(),
        checks: vec![],
        mutations: vec![Mutation::Put(key, value)],
        limits: transaction_limits(store.capabilities()),
    })
    .expect("transaction envelope is within its byte limit");
    assert!(
        block_on(store.commit(&transaction)).is_err(),
        "store value capability must be enforced at commit"
    );
}

#[test]
fn given_malformed_range_pages_when_generic_runner_runs_then_contract_violation_is_reported() {
    for shape in [
        RangeShape::Reordered,
        RangeShape::OversizedItems,
        RangeShape::OversizedBytes,
        RangeShape::WrongCursor,
    ] {
        let store = MalformedRangeStore::new(shape);
        let result = block_on(run_basic(&store, &ConformanceConfig::default()));
        assert!(matches!(result, Err(ConformanceError::Invalid(_))));
    }
}

#[test]
fn given_partial_multi_key_conflict_when_generic_runner_runs_then_no_partial_mutation_is_accepted()
{
    let store = PartialCommitStore::new();
    let result = block_on(run_basic(&store, &ConformanceConfig::default()));
    assert!(matches!(result, Err(ConformanceError::Invalid(_))));
}

#[test]
fn given_delete_ack_without_deletion_when_generic_runner_runs_then_readback_rejects_it() {
    let store = DeleteNoopStore::new();
    let result = block_on(run_basic(&store, &ConformanceConfig::default()));
    assert!(matches!(result, Err(ConformanceError::Invalid(_))));
}

#[test]
fn given_tiny_advertised_capabilities_when_limits_are_exceeded_then_operations_are_rejected() {
    let store = tiny_capability_store();
    let capabilities = store.capabilities();
    let long_key = key(&[0; 9]);
    assert!(block_on(store.get(long_key)).is_err());
    assert!(
        block_on(store.get_many(&[key(b"a"), key(b"b"), key(b"c")])).is_err(),
        "get_many key-count capability must be enforced"
    );
    assert!(
        block_on(store.get_many(&[key(b"12345678"), key(b"abcdefgh"), key(b"x")])).is_err(),
        "get_many key-byte capability must be enforced"
    );

    let value_transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: commit_operation_id(),
        checks: vec![],
        mutations: vec![Mutation::Put(key(b"value"), Bytes::from(vec![0; 9]))],
        limits: TransactionLimits {
            max_checks: nonzero_u32(4),
            max_mutations: nonzero_u32(4),
            max_bytes: nonzero_usize(32),
        },
    })
    .expect("value probe envelope is valid");
    assert!(block_on(store.commit(&value_transaction)).is_err());

    let key_transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: commit_operation_id(),
        checks: vec![],
        mutations: (0..5)
            .map(|index| Mutation::Delete(key(format!("k{index}").as_bytes())))
            .collect(),
        limits: TransactionLimits {
            max_checks: nonzero_u32(4),
            max_mutations: nonzero_u32(5),
            max_bytes: nonzero_usize(32),
        },
    })
    .expect("transaction-key probe envelope is valid");
    assert!(block_on(store.commit(&key_transaction)).is_err());

    let bytes_transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: commit_operation_id(),
        checks: vec![],
        mutations: vec![
            Mutation::Put(key(b"a"), Bytes::from(vec![0; 8])),
            Mutation::Put(key(b"b"), Bytes::from(vec![0; 8])),
        ],
        limits: TransactionLimits {
            max_checks: nonzero_u32(4),
            max_mutations: nonzero_u32(4),
            max_bytes: nonzero_usize(32),
        },
    })
    .expect("transaction-byte probe envelope is valid");
    assert!(block_on(store.commit(&bytes_transaction)).is_err());

    let item_request = RangeRequest::try_from(RangeRequestInput {
        start: None,
        end: None,
        direction: RangeDirection::Forward,
        item_limit: nonzero_u32(3),
        byte_limit: nonzero_usize(1),
        continuation: None,
    })
    .expect("range-item probe envelope is valid");
    assert!(block_on(store.read_range(item_request)).is_err());

    let byte_request = RangeRequest::try_from(RangeRequestInput {
        start: None,
        end: None,
        direction: RangeDirection::Forward,
        item_limit: nonzero_u32(1),
        byte_limit: nonzero_usize(17),
        continuation: None,
    })
    .expect("range-byte probe envelope is valid");
    assert!(block_on(store.read_range(byte_request)).is_err());
    assert_eq!(
        capabilities.max_transaction_duration(),
        Duration::from_millis(1)
    );

    let invalid_duration = StoreCapabilities::try_from(StoreCapabilitiesInput {
        level: StoreLevel::Local,
        max_key_bytes: nonzero_usize(8),
        max_value_bytes: nonzero_usize(8),
        max_get_many_keys: nonzero_u32(2),
        max_get_many_key_bytes: nonzero_usize(16),
        max_transaction_bytes: nonzero_usize(16),
        max_transaction_keys: nonzero_u32(4),
        max_range_items: nonzero_u32(2),
        max_range_bytes: nonzero_usize(16),
        max_transaction_duration: Duration::ZERO,
    });
    assert!(invalid_duration.is_err());
}

#[test]
fn given_many_claimants_when_committing_checked_writes_then_one_wins_and_stale_owners_conflict() {
    let store = FakeStore::distributed();
    let key = key(b"claimants");
    commit(
        &store,
        vec![],
        vec![Mutation::Put(key.clone(), Bytes::from_static(b"ready"))],
    );

    let outcomes = (0..16)
        .map(|claimant| {
            let owner = Bytes::from(format!("owner-{claimant}"));
            commit(
                &store,
                vec![Check::Value(key.clone(), Bytes::from_static(b"ready"))],
                vec![Mutation::Put(key.clone(), owner)],
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == CommitOutcome::Committed)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == CommitOutcome::Conflict)
            .count(),
        15
    );
    assert_eq!(
        commit(
            &store,
            vec![Check::Value(key.clone(), Bytes::from_static(b"owner-1"))],
            vec![Mutation::Put(key.clone(), Bytes::from_static(b"stale"))],
        ),
        CommitOutcome::Conflict
    );
}

#[test]
fn given_faults_at_each_store_operation_when_exercised_then_outcomes_are_explicit_and_atomic() {
    let inner = FakeStore::distributed();
    let store = FaultStore::new(inner);
    let config = ConformanceConfig::default();
    let report = block_on(run_faults(&store, &config)).expect("commit fault suite should pass");
    assert_eq!(report.conflicts, 1);
    assert_eq!(report.unknowns, 2);

    let read_key = key(b"read-fault");
    store
        .queue_read_fault(FaultOperation::Get, ReadFaultKind::Unavailable)
        .expect("queue get fault");
    let get = block_on(store.get(read_key.clone()));
    assert!(matches!(
        get,
        Err(bg_jobs_conformance::FaultStoreError::Unavailable)
    ));

    let range = range_request(b"range-fault");
    store
        .queue_read_fault(FaultOperation::Range, ReadFaultKind::Timeout)
        .expect("queue range fault");
    let result = block_on(store.read_range(range));
    assert!(matches!(
        result,
        Err(bg_jobs_conformance::FaultStoreError::Timeout)
    ));

    let key = key(b"atomic-fault");
    for kind in [ReadFaultKind::Unavailable, ReadFaultKind::Timeout] {
        store
            .queue_commit_fault(CommitFaultKind::Transient(kind))
            .expect("queue commit fault");
        let transaction = transaction(
            &store,
            vec![],
            vec![Mutation::Put(
                key.clone(),
                Bytes::from_static(b"not-applied"),
            )],
        );
        let result = block_on(store.commit(&transaction));
        assert!(result.is_err());
        assert!(
            block_on(store.get(key.clone()))
                .expect("read after transient fault")
                .is_none()
        );
    }
}

#[test]
fn given_interleaved_typed_faults_when_operations_match_then_each_one_shot_fault_is_consumed() {
    let store = FaultStore::new(FakeStore::distributed());
    let read_key = key(b"typed-read");
    store
        .queue_read_fault(FaultOperation::Get, ReadFaultKind::Unavailable)
        .expect("queue read fault");
    store
        .queue_commit_fault(CommitFaultKind::Conflict)
        .expect("queue commit fault");
    assert_eq!(store.pending_faults().expect("fault queue length"), 2);

    let transaction = transaction(
        &store,
        vec![],
        vec![Mutation::Put(
            key(b"typed-commit"),
            Bytes::from_static(b"value"),
        )],
    );
    assert!(matches!(
        block_on(store.commit(&transaction)),
        Ok(CommitOutcome::Conflict)
    ));
    assert_eq!(store.pending_faults().expect("fault queue length"), 1);
    assert!(matches!(
        block_on(store.commit(&transaction)),
        Ok(CommitOutcome::Conflict)
    ));
    assert_eq!(store.pending_faults().expect("fault queue length"), 1);
    assert!(matches!(
        block_on(store.get(read_key)),
        Err(FaultStoreError::Unavailable)
    ));
    assert_eq!(store.pending_faults().expect("fault queue length"), 0);
}

#[test]
fn given_corrupt_routes_and_unknown_versions_when_repair_is_planned_then_actions_are_bounded() {
    let store = FakeStore::distributed();
    let mut model = StoreModel::new(store.capabilities());
    let authoritative = key(b"job/authoritative");
    let present_route = key(b"route/present");
    let missing_route = key(b"route/missing");
    model
        .put(authoritative.clone(), Bytes::from_static(b"record"))
        .expect("authoritative fixture is valid");
    model
        .put(present_route.clone(), Bytes::from_static(b"route"))
        .expect("route fixture is valid");

    let entries = vec![
        RepairEntry {
            authoritative: authoritative.clone(),
            routes: vec![present_route.clone()],
            required_routes: vec![missing_route.clone()],
            unknown_version: false,
        },
        RepairEntry {
            authoritative: key(b"job/missing"),
            routes: vec![present_route.clone()],
            required_routes: vec![],
            unknown_version: false,
        },
        RepairEntry {
            authoritative: key(b"job/unknown"),
            routes: vec![present_route],
            required_routes: vec![],
            unknown_version: true,
        },
    ];
    let plan = model.repair_plan(
        &entries,
        RepairBudget {
            max_items: nonzero_u32(3),
            max_bytes: nonzero_usize(256),
        },
    );
    assert_eq!(plan.actions[0].reason, RepairReason::MissingIndex);
    assert_eq!(plan.actions[1].reason, RepairReason::DanglingIndex);
    assert_eq!(plan.actions[2].reason, RepairReason::UnknownVersion);
    assert_eq!(plan.inspected, 3);
    assert!(!plan.truncated);
    assert_eq!(
        model.get(&authoritative),
        Some(&Bytes::from_static(b"record"))
    );

    let many_routes = (0..8)
        .map(|index| key(format!("route/{index}").as_bytes()))
        .collect::<Vec<_>>();
    for route in &many_routes {
        model
            .put(route.clone(), Bytes::from_static(b"route"))
            .expect("bounded route fixture is valid");
    }
    let bounded = model.repair_plan(
        &[RepairEntry {
            authoritative: key(b"job/missing-many"),
            routes: many_routes,
            required_routes: vec![],
            unknown_version: false,
        }],
        RepairBudget {
            max_items: nonzero_u32(2),
            max_bytes: nonzero_usize(256),
        },
    );
    assert_eq!(bounded.actions.len(), 2);
    assert_eq!(bounded.inspected, 2);
    assert!(bounded.truncated);
}

#[test]
fn given_reference_fake_when_constructing_runtime_neutral_components_then_public_path_compiles() {
    let store = FakeStore::local();
    let model = StoreModel::new(store.capabilities());
    assert!(!model.capabilities().is_distributed());
    let timestamp = Timestamp::from_millis(42);
    let deadline = MonotonicDeadline::from_nanos(99);
    assert_eq!(timestamp.as_millis(), 42);
    assert_eq!(deadline.as_nanos(), 99);
}

#[test]
fn given_reference_model_commit_identity_when_retried_or_reused_then_exact_semantics_hold() {
    let store = FakeStore::local();
    let mut model = StoreModel::new(store.capabilities());
    let operation_id = CommitOperationId::from([0x41; 16]);
    let first_key = key(b"model/first");
    let second_key = key(b"model/second");
    let model_transaction = |key: StoreKey| {
        StoreTransaction::try_from(StoreTransactionInput {
            operation_id,
            checks: vec![Check::Absent(key.clone())],
            mutations: vec![Mutation::Put(key, Bytes::from_static(b"value"))],
            limits: transaction_limits(store.capabilities()),
        })
        .expect("model transaction is valid")
    };
    let committed = model_transaction(first_key);

    assert_eq!(
        model.commit(&committed).expect("first commit succeeds"),
        CommitOutcome::Committed
    );
    assert_eq!(
        model.commit(&committed).expect("commit replay succeeds"),
        CommitOutcome::Committed
    );
    assert!(matches!(
        model.commit(&model_transaction(second_key.clone())),
        Err(bg_jobs_conformance::StoreModelError::CommitOperationReused)
    ));
    assert!(model.get(&second_key).is_none());
}

#[test]
fn given_repeated_idle_enqueue_complete_retry_and_batch_workloads_when_profiled_then_allocations_are_bounded()
 {
    let idle = measure_allocations("idle", || {
        let store = FakeStore::local();
        for _ in 0..8 {
            let _ = block_on(store.get(key(b"idle")));
        }
    });
    let healthy = measure_allocations("enqueue-complete", || {
        let store = FakeStore::local();
        block_on(run_basic(&store, &ConformanceConfig::default())).expect("healthy workload");
    });
    let retry = measure_allocations("retry", || {
        let store = FaultStore::new(FakeStore::local());
        block_on(run_faults(&store, &ConformanceConfig::default())).expect("retry workload");
    });
    let batch = measure_allocations("batch", || {
        let store = FakeStore::local();
        let mutations = (0..8)
            .map(|index| {
                Mutation::Put(
                    key(format!("batch/{index}").as_bytes()),
                    Bytes::from_static(b"v"),
                )
            })
            .collect();
        assert_eq!(commit(&store, vec![], mutations), CommitOutcome::Committed);
    });

    for report in [&idle, &healthy, &retry, &batch] {
        assert!(report.allocation_count > 0);
        assert!(report.allocated_bytes >= report.allocation_count);
    }
    assert!(idle.allocation_count < healthy.allocation_count);
}

#[test]
fn given_healthy_empty_conflict_and_retry_runs_when_counted_then_store_operation_budgets_hold() {
    let config = ConformanceConfig::default();
    let counted = bg_jobs_conformance::CountingStore::new(FakeStore::distributed());
    let profile = block_on(run_operation_profile(&counted, &config)).expect("profile should pass");
    assert_eq!(profile.report.commits, 9);
    assert_eq!(profile.report.reads, 3);
    assert_eq!(profile.report.get_many, 4);
    assert_eq!(profile.report.ranges, 4);
    assert!(profile.counts.commits <= 12);
    assert!(profile.counts.gets <= 3);
    assert_eq!(profile.counts.get_many, 6);
    assert_eq!(profile.counts.get_many_keys, 28);
    assert!(profile.counts.ranges <= 4);
    assert!(profile.counts.transaction_bytes < 4_096);

    counted.reset();
    let missing = block_on(counted.get(key(b"empty"))).expect("empty read");
    assert!(missing.is_none());
    let empty_counts = counted.snapshot();
    assert_eq!(empty_counts.gets, 1);
    assert_eq!(empty_counts.commits, 0);
    assert_eq!(empty_counts.ranges, 0);

    counted.reset();
    let key = key(b"retry-budget");
    assert_eq!(
        commit(
            &counted,
            vec![],
            vec![Mutation::Put(key.clone(), Bytes::from_static(b"ready"))],
        ),
        CommitOutcome::Committed
    );
    let first = transaction(
        &counted,
        vec![Check::Value(key.clone(), Bytes::from_static(b"ready"))],
        vec![Mutation::Put(key.clone(), Bytes::from_static(b"done"))],
    );
    let stale = first.clone();
    assert_eq!(
        commit(
            &counted,
            vec![],
            vec![Mutation::Put(key.clone(), Bytes::from_static(b"other"))]
        ),
        CommitOutcome::Committed
    );
    assert_eq!(
        block_on(counted.commit(&stale)).expect("conflict result"),
        CommitOutcome::Conflict
    );
    assert!(counted.snapshot().commits <= 3);
}

#[test]
fn given_native_batch_store_when_generic_runner_runs_then_batch_budget_stays_native() {
    let native = NativeBatchStore::new();
    let counted = bg_jobs_conformance::CountingStore::new(FaultStore::new(native.clone()));
    let profile = block_on(run_operation_profile(
        &counted,
        &ConformanceConfig::default(),
    ))
    .expect("generic conformance should pass through a native batch store");
    let counts = profile.counts;

    assert_eq!(profile.report.get_many, 4);
    assert_eq!(counts.get_many, 6);
    assert_eq!(counts.get_many_keys, 28);
    assert_eq!(counts.gets, profile.report.reads as u64);
    assert_eq!(native.native_batch_calls(), 5);
    assert_eq!(native.serial_get_calls(), counts.gets as usize);
}

#[test]
fn given_malformed_batch_adapters_when_generic_runner_runs_then_contract_violation_is_reported() {
    for shape in [
        BatchShape::Reordered,
        BatchShape::Short,
        BatchShape::Deduplicated,
    ] {
        let store = NativeBatchStore::with_batch_shape(shape);
        let result = block_on(run_basic(&store, &ConformanceConfig::default()));
        assert!(matches!(result, Err(ConformanceError::Invalid(_))));
    }
}

#[test]
fn given_native_batch_store_when_wrapped_then_get_many_is_forwarded_once() {
    let native = NativeBatchStore::new();
    let present = key(b"batch/present");
    assert_eq!(
        commit(
            &native,
            vec![],
            vec![Mutation::Put(present.clone(), Bytes::from_static(b"value"),)],
        ),
        CommitOutcome::Committed
    );
    let counted = bg_jobs_conformance::CountingStore::new(FaultStore::new(native.clone()));
    let keys = vec![
        key(b"batch/missing"),
        present.clone(),
        key(b"batch/missing"),
    ];
    let values = block_on(counted.get_many(&keys)).expect("native batch read should succeed");

    assert_eq!(values, vec![None, Some(Bytes::from_static(b"value")), None]);
    assert_eq!(native.native_batch_calls(), 1);
    assert_eq!(native.serial_get_calls(), 0);
    assert_eq!(counted.snapshot().gets, 0);
    assert_eq!(counted.snapshot().get_many, 1);
    assert_eq!(counted.snapshot().get_many_keys, 3);

    let native = NativeBatchStore::new();
    let counted = bg_jobs_conformance::CountingStore::new(native.clone());
    let fault = FaultStore::new(counted.clone());
    let values = block_on(fault.get_many(&keys)).expect("native batch read should succeed");

    assert_eq!(values, vec![None, None, None]);
    assert_eq!(native.native_batch_calls(), 1);
    assert_eq!(native.serial_get_calls(), 0);
    assert_eq!(counted.snapshot().gets, 0);
    assert_eq!(counted.snapshot().get_many, 1);
}

#[test]
fn given_get_many_faults_when_nested_around_counting_store_then_native_read_is_not_called() {
    let native = NativeBatchStore::new();
    let fault = FaultStore::new(native.clone());
    let counted = bg_jobs_conformance::CountingStore::new(fault.clone());
    let keys = vec![key(b"fault/a"), key(b"fault/a")];
    fault
        .queue_read_fault(FaultOperation::GetMany, ReadFaultKind::Unavailable)
        .expect("get_many fault should queue");
    assert!(matches!(
        block_on(counted.get_many(&keys)),
        Err(FaultStoreError::Unavailable)
    ));
    assert_eq!(native.native_batch_calls(), 0);
    assert_eq!(native.serial_get_calls(), 0);
    assert_eq!(counted.snapshot().gets, 0);
    assert_eq!(counted.snapshot().get_many, 1);

    let native = NativeBatchStore::new();
    let counted = bg_jobs_conformance::CountingStore::new(native.clone());
    let fault = FaultStore::new(counted.clone());

    for kind in [ReadFaultKind::Unavailable, ReadFaultKind::Timeout] {
        fault
            .queue_read_fault(FaultOperation::GetMany, kind)
            .expect("get_many fault should queue");
        let result = block_on(fault.get_many(&keys));
        assert!(matches!(
            (kind, result),
            (
                ReadFaultKind::Unavailable,
                Err(FaultStoreError::Unavailable)
            ) | (ReadFaultKind::Timeout, Err(FaultStoreError::Timeout))
        ));
    }

    assert_eq!(native.native_batch_calls(), 0);
    assert_eq!(native.serial_get_calls(), 0);
    assert_eq!(counted.snapshot().gets, 0);
    assert_eq!(counted.snapshot().get_many, 0);
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::yield_now();
    }
}

#[derive(Clone)]
struct MalformedRangeStore {
    inner: FakeStore,
    shape: RangeShape,
}

#[derive(Clone, Copy)]
enum RangeShape {
    Reordered,
    OversizedItems,
    OversizedBytes,
    WrongCursor,
}

impl MalformedRangeStore {
    fn new(shape: RangeShape) -> Self {
        Self {
            inner: FakeStore::local(),
            shape,
        }
    }
}

impl JobStore for MalformedRangeStore {
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
        let mut page = self.inner.read_range(request).await?;
        match self.shape {
            RangeShape::Reordered => page.entries.reverse(),
            RangeShape::OversizedItems => {
                let Some(entry) = page.entries.first().cloned() else {
                    return Ok(page);
                };
                page.entries.push(entry);
            }
            RangeShape::OversizedBytes => {
                if let Some(entry) = page.entries.first_mut() {
                    entry.value = Bytes::from(vec![0; 1_025]);
                }
            }
            RangeShape::WrongCursor => {
                if page.continuation.is_some() {
                    page.continuation = page.entries.first().map(|entry| entry.key.clone());
                }
            }
        }
        Ok(page)
    }

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        self.inner.commit(transaction).await
    }
}

#[derive(Clone)]
struct PartialCommitStore {
    inner: FakeStore,
}

impl PartialCommitStore {
    fn new() -> Self {
        Self {
            inner: FakeStore::local(),
        }
    }
}

impl JobStore for PartialCommitStore {
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
        if transaction.checks().len() >= 2 && transaction.mutations().len() >= 2 {
            let partial = StoreTransaction::try_from(StoreTransactionInput {
                operation_id: commit_operation_id(),
                checks: vec![],
                mutations: vec![transaction.mutations()[0].clone()],
                limits: transaction.limits(),
            })
            .expect("partial transaction is within the original limits");
            self.inner.commit(&partial).await?;
            return Ok(CommitOutcome::Conflict);
        }
        self.inner.commit(transaction).await
    }
}

#[derive(Clone)]
struct DeleteNoopStore {
    inner: FakeStore,
}

impl DeleteNoopStore {
    fn new() -> Self {
        Self {
            inner: FakeStore::local(),
        }
    }
}

impl JobStore for DeleteNoopStore {
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
        let delete_only = !transaction.mutations().is_empty()
            && transaction
                .mutations()
                .iter()
                .all(|mutation| matches!(mutation, Mutation::Delete(_)));
        if delete_only {
            return Ok(CommitOutcome::Committed);
        }
        self.inner.commit(transaction).await
    }
}

fn tiny_capability_store() -> FakeStore {
    let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
        level: StoreLevel::Local,
        max_key_bytes: nonzero_usize(8),
        max_value_bytes: nonzero_usize(8),
        max_get_many_keys: nonzero_u32(2),
        max_get_many_key_bytes: nonzero_usize(16),
        max_transaction_bytes: nonzero_usize(16),
        max_transaction_keys: nonzero_u32(4),
        max_range_items: nonzero_u32(2),
        max_range_bytes: nonzero_usize(16),
        max_transaction_duration: Duration::from_millis(1),
    })
    .expect("tiny capabilities are coherent");
    FakeStore::with_capabilities(capabilities)
}

#[derive(Clone)]
struct NativeBatchStore {
    inner: FakeStore,
    native_batch_calls: Arc<AtomicUsize>,
    serial_get_calls: Arc<AtomicUsize>,
    batch_shape: BatchShape,
}

#[derive(Clone, Copy)]
enum BatchShape {
    Native,
    Reordered,
    Short,
    Deduplicated,
}

impl NativeBatchStore {
    fn new() -> Self {
        Self::with_batch_shape(BatchShape::Native)
    }

    fn with_batch_shape(batch_shape: BatchShape) -> Self {
        Self {
            inner: FakeStore::local(),
            native_batch_calls: Arc::new(AtomicUsize::new(0)),
            serial_get_calls: Arc::new(AtomicUsize::new(0)),
            batch_shape,
        }
    }

    fn native_batch_calls(&self) -> usize {
        self.native_batch_calls.load(Ordering::SeqCst)
    }

    fn serial_get_calls(&self) -> usize {
        self.serial_get_calls.load(Ordering::SeqCst)
    }
}

impl JobStore for NativeBatchStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.serial_get_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(key).await
    }

    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.native_batch_calls.fetch_add(1, Ordering::SeqCst);
        let mut values = self.inner.get_many(keys).await?;
        match self.batch_shape {
            BatchShape::Native => {}
            BatchShape::Reordered => values.reverse(),
            BatchShape::Short => {
                values.pop();
            }
            BatchShape::Deduplicated => {
                if values.len() > 2 {
                    values.remove(2);
                }
            }
        }
        Ok(values)
    }

    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.inner.read_range(request).await
    }

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        self.inner.commit(transaction).await
    }
}

#[test]
fn given_empty_get_many_when_using_a_native_adapter_then_no_backend_batch_is_issued() {
    let native = NativeBatchStore::new();
    let counted = bg_jobs_conformance::CountingStore::new(native.clone());

    let values = block_on(counted.get_many(&[])).expect("empty native batch should succeed");

    assert!(values.is_empty());
    assert_eq!(counted.snapshot().get_many, 1);
    assert_eq!(native.native_batch_calls(), 0);
    assert_eq!(native.serial_get_calls(), 0);
}

fn key(value: &[u8]) -> StoreKey {
    StoreKey::try_from(value).expect("test key is non-empty")
}

fn transaction<S: JobStore>(
    store: &S,
    checks: Vec<Check>,
    mutations: Vec<Mutation>,
) -> StoreTransaction {
    StoreTransaction::try_from(StoreTransactionInput {
        operation_id: commit_operation_id(),
        checks,
        mutations,
        limits: transaction_limits(store.capabilities()),
    })
    .expect("test transaction is within capabilities")
}

fn commit_operation_id() -> CommitOperationId {
    CommitOperationId::generate().expect("test commit operation entropy")
}

fn commit<S: JobStore>(store: &S, checks: Vec<Check>, mutations: Vec<Mutation>) -> CommitOutcome {
    let transaction = transaction(store, checks, mutations);
    block_on(store.commit(&transaction)).expect("test commit result")
}

fn transaction_limits(capabilities: StoreCapabilities) -> TransactionLimits {
    TransactionLimits {
        max_checks: capabilities.max_transaction_keys(),
        max_mutations: capabilities.max_transaction_keys(),
        max_bytes: capabilities.max_transaction_bytes(),
    }
}

fn range_request(prefix: &[u8]) -> RangeRequest {
    let start = key(prefix);
    let mut end_bytes = start.as_bytes().to_vec();
    end_bytes.push(0xff);
    RangeRequest::try_from(RangeRequestInput {
        start: Some(start),
        end: Some(key(&end_bytes)),
        direction: RangeDirection::Forward,
        item_limit: nonzero_u32(2),
        byte_limit: nonzero_usize(512),
        continuation: None,
    })
    .expect("test range request is valid")
}

fn measure_allocations(
    label: &'static str,
    action: impl FnOnce(),
) -> alloc_counter::AllocationReport<'static> {
    let guard = AllocationGuard::start(module_path!(), label, file!(), line!(), Some(LABEL));
    action();
    guard.finish()
}

fn nonzero_u32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("test value is non-zero")
}

fn nonzero_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("test value is non-zero")
}
