use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;

use crate::{
    DriveRequest, DriveRequestInput, EffectMode, FairnessPolicy, HandlerDefinition, HandlerFuture,
    HandlerRegistry, JobHandler, JobOutcome, JobSystem, MonotonicDeadline, Namespace, OutcomeCode,
    OwnerId, QueueName, QueueSelection, RetryPreset, RetrySelection,
    ids::{JobId, JobKind},
    test_helper::{FakeStore, block_on, low_volume_job, system, wake_scheduler},
    time::Timestamp,
};

struct WallTimeHandler {
    observed: Arc<Mutex<Option<Timestamp>>>,
}

impl JobHandler for WallTimeHandler {
    fn execute<'a>(
        &'a self,
        context: super::ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        let observed = Arc::clone(&self.observed);
        Box::pin(async move {
            *observed.lock().expect("wall-time observation lock") = Some(context.wall_now());
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("completed").expect("test outcome is valid"),
            ))
        })
    }
}

#[derive(Clone)]
struct IdentityHandler {
    observed: Arc<Mutex<Vec<(Namespace, JobId, u64)>>>,
}

impl JobHandler for IdentityHandler {
    fn execute<'a>(
        &'a self,
        context: super::ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        let observed = Arc::clone(&self.observed);
        Box::pin(async move {
            observed.lock().expect("identity observation lock").push((
                context.namespace().clone(),
                context.job_id(),
                context.fence().get(),
            ));
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("completed").expect("test outcome is valid"),
            ))
        })
    }
}

fn build_identity_system(
    store: FakeStore,
    namespace: Namespace,
    handler: IdentityHandler,
) -> JobSystem<FakeStore> {
    let mut registry = HandlerRegistry::new();
    registry
        .register(HandlerDefinition {
            kind: JobKind::try_new("email").expect("test kind is valid"),
            schema_version: NonZeroU16::MIN,
            queue: QueueName::try_new("default").expect("test queue is valid"),
            effect_mode: EffectMode::Idempotent,
            cost_units: NonZeroU16::MIN,
            fairness_policy: FairnessPolicy::low_volume(),
            default_retry: RetrySelection::Preset(RetryPreset::Interactive),
            default_timeout: Duration::from_secs(1),
            handler,
        })
        .expect("test registration is valid");
    JobSystem::new(
        store,
        crate::JobCatalog::from_registry(registry),
        namespace,
        OwnerId::from([1; 16]),
        wake_scheduler(),
    )
}

fn build_identity_drive_request() -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: NonZeroU32::MIN,
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::new(1_024).expect("payload budget is non-zero"),
        max_completion_details: 1,
        max_store_operations: NonZeroU32::new(64).expect("store budget is non-zero"),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid")
}

#[test]
fn given_equal_job_ids_in_distinct_namespaces_when_driven_then_handlers_observe_their_claimed_scope()
 {
    let store = FakeStore::new();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let handler = IdentityHandler {
        observed: Arc::clone(&observed),
    };
    let namespaces = [
        Namespace::try_new(b"first").expect("first namespace is valid"),
        Namespace::try_new(b"second").expect("second namespace is valid"),
    ];
    for namespace in &namespaces {
        let system = build_identity_system(store.clone(), namespace.clone(), handler.clone());
        block_on(system.enqueue_raw(low_volume_job(7, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
        let report = block_on(system.drive(
            build_identity_drive_request(),
            Timestamp::ZERO,
            || MonotonicDeadline::ZERO,
        ))
        .expect("drive completes");
        assert_eq!(report.counts.succeeded, 1);
    }

    assert_eq!(
        *observed.lock().expect("identity observation lock"),
        namespaces
            .map(|namespace| (namespace, JobId::from([7; 16]), 1))
            .to_vec()
    );
}

#[test]
fn given_a_claim_without_completion_when_reclaimed_then_handler_scope_is_stable_and_fence_increases()
 {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let handler = IdentityHandler {
        observed: Arc::clone(&observed),
    };
    let namespace = Namespace::try_new(b"reclaim").expect("namespace is valid");
    let job_id = JobId::from([9; 16]);
    let system = build_identity_system(FakeStore::new(), namespace.clone(), handler.clone());
    block_on(system.enqueue_raw(low_volume_job(9, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let first_claim = block_on(system.claim(job_id, Timestamp::ZERO)).expect("first claim commits");
    let outcome = block_on(handler.execute(
        first_claim.context().expect("leased context"),
        first_claim.payload(),
    ))
    .expect("first handler completes");
    // The handler result is lost before the lifecycle outcome transaction.
    drop(outcome);
    drop(first_claim);

    let report = block_on(system.drive(
        build_identity_drive_request(),
        Timestamp::from_millis(1_001),
        || MonotonicDeadline::ZERO,
    ))
    .expect("expired claim is driven again");

    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(
        *observed.lock().expect("identity observation lock"),
        vec![(namespace.clone(), job_id, 1), (namespace, job_id, 2)]
    );
}

#[test]
fn continued_checkpoint_is_available_to_the_next_execution_context() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let job_id = JobId::from([1; 16]);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let first_claim = block_on(system.claim(job_id, Timestamp::ZERO)).expect("first claim commits");
    assert_eq!(
        first_claim.context().expect("leased context").checkpoint(),
        None
    );

    let checkpoint = Bytes::from_static(b"cursor-17");
    block_on(system.apply_outcome(
        first_claim,
        JobOutcome::Continue {
            not_before: Timestamp::from_millis(1),
            checkpoint: checkpoint.clone(),
        },
        Timestamp::ZERO,
    ))
    .expect("continuation commits");

    let resumed =
        block_on(system.claim(job_id, Timestamp::from_millis(1))).expect("resumed claim commits");
    assert_eq!(
        resumed.context().expect("resumed context").checkpoint(),
        Some(checkpoint.as_ref())
    );
}

#[test]
fn handler_observes_the_exact_wall_time_supplied_to_drive() {
    let store = FakeStore::new();
    let observed = Arc::new(Mutex::new(None));
    let mut registry = HandlerRegistry::new();
    registry
        .register(HandlerDefinition {
            kind: JobKind::try_new("email").expect("test kind is valid"),
            schema_version: NonZeroU16::MIN,
            queue: QueueName::try_new("default").expect("test queue is valid"),
            effect_mode: EffectMode::Idempotent,
            cost_units: NonZeroU16::MIN,
            fairness_policy: FairnessPolicy::low_volume(),
            default_retry: RetrySelection::Preset(RetryPreset::Interactive),
            default_timeout: Duration::from_secs(1),
            handler: WallTimeHandler {
                observed: Arc::clone(&observed),
            },
        })
        .expect("test registration is valid");
    let system = JobSystem::new(
        store,
        crate::JobCatalog::from_registry(registry),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([1; 16]),
        wake_scheduler(),
    );
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let wall_now = Timestamp::from_millis(1_234);
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: NonZeroU32::MIN,
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::new(1_024).expect("payload budget is non-zero"),
        max_completion_details: 1,
        max_store_operations: NonZeroU32::new(64).expect("store budget is non-zero"),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(2),
    })
    .expect("drive request is valid");

    block_on(system.drive(request, wall_now, || MonotonicDeadline::ZERO)).expect("drive completes");

    assert_eq!(
        *observed.lock().expect("wall-time observation lock"),
        Some(wall_now)
    );
}
