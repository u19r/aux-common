use std::{hint::black_box, time::Instant};

use alloc_counter::AllocationGuard;

use super::{redrive::prepare_redrive, repository::load_job_operation};
use crate::{
    failure::{RedriveExecution, RedriveRequest},
    test_helper::{block_on, low_volume_job, system},
    *,
};

#[test]
fn given_owned_redrive_records_when_successor_is_prepared_then_reports_three_samples() {
    const ITERATIONS: usize = 10_000;
    let system = crate::test_helper::system(
        crate::test_helper::FakeStore::new(),
        crate::policy::FairnessPolicy::low_volume(),
        0x75,
    );
    let job_id = crate::ids::JobId::from([0x75; 16]);
    crate::test_helper::block_on(system.enqueue_raw(
        crate::test_helper::low_volume_job(0x75, crate::time::Timestamp::ZERO),
        crate::time::Timestamp::ZERO,
    ))
    .expect("redrive benchmark enqueue");
    let record = crate::test_helper::block_on(load_job_operation(&system, job_id))
        .expect("redrive benchmark load")
        .record;
    let request = RedriveRequest::new(
        1,
        crate::ids::OperationId::generate().expect("redrive benchmark operation"),
        RedriveExecution::ReuseExecutionId,
        crate::time::Timestamp::from_millis(10),
    );
    for _ in 0..2 {
        let records = vec![record.clone(); ITERATIONS];
        for record in records {
            black_box(prepare_redrive(&system, record, &request).expect("redrive successor"));
        }
    }
    for sample in 0..3 {
        let records = vec![record.clone(); ITERATIONS];
        let guard = AllocationGuard::start(
            module_path!(),
            "given_owned_redrive_records_when_successor_is_prepared_then_reports_three_samples",
            file!(),
            line!(),
            Some("candidate"),
        );
        let started = Instant::now();
        for record in records {
            black_box(prepare_redrive(&system, record, &request).expect("redrive successor"));
        }
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        println!(
            "bg_jobs_perf_realistic suite=redrive_prepare phase=sample sample={} iterations={} \
             elapsed_nanos={} allocations={} allocated_bytes={}",
            sample,
            ITERATIONS,
            elapsed_nanos,
            allocations.allocation_count,
            allocations.allocated_bytes,
        );
    }
}

fn dead_lettered(system: &JobSystem<FakeStore>, id: u8) -> (JobId, ExecutionId, u64, OperationId) {
    let job_id = JobId::from([id; 16]);
    block_on(system.enqueue_raw(low_volume_job(id, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(job_id, Timestamp::ZERO)).expect("claim commits");
    let execution = claim.record().execution_id;
    block_on(system.apply_outcome(
        claim,
        JobOutcome::DeadLetter {
            code: OutcomeCode::try_new("permanent").expect("code is valid"),
        },
        Timestamp::from_millis(1),
    ))
    .expect("dead-letter commits");
    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &job_id).expect("job key")),
    )
    .expect("job read succeeds")
    .expect("job exists");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    let operation_value = block_on(
        system
            .store()
            .get(crate::keys::operation_key(system.namespace(), &job_id).expect("operation key")),
    )
    .expect("operation read succeeds")
    .expect("operation exists");
    let operation = crate::keys::decode_active_operation(&operation_value, &job_id)
        .expect("operation decodes")
        .0;
    (job_id, execution, record.revision, operation)
}

#[test]
fn given_a_dead_letter_when_redriving_with_reuse_then_generation_and_retry_state_reset() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let (id, execution, revision, operation) = dead_lettered(&system, 2);
    let result = block_on(system.redrive_job(
        id,
        RedriveRequest::new(
            revision,
            operation,
            RedriveExecution::ReuseExecutionId,
            Timestamp::from_millis(10),
        ),
    ))
    .expect("redrive commits");
    assert_eq!(result.execution_id, execution);
    assert!(result.reused_execution);
    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &id).expect("job key")),
    )
    .expect("job read succeeds")
    .expect("job exists");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    assert!(matches!(record.state, JobState::Scheduled));
    assert_eq!(record.generation, 2);
    assert!(record.attempts.is_none());
    assert!(record.checkpoint.is_none());
}

#[test]
fn given_a_dead_letter_when_redriving_with_rotation_then_execution_identity_changes_explicitly() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let (id, execution, revision, operation) = dead_lettered(&system, 3);
    let result = block_on(system.redrive_job(
        id,
        RedriveRequest::new(
            revision,
            operation,
            RedriveExecution::NewExecutionId,
            Timestamp::from_millis(10),
        ),
    ))
    .expect("redrive commits");
    assert_ne!(result.execution_id, execution);
    assert!(!result.reused_execution);
}

#[test]
fn given_stale_redrive_authority_when_redriving_then_the_dead_letter_remains_unchanged() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    let (id, _, revision, operation) = dead_lettered(&system, 4);
    assert!(matches!(
        block_on(system.redrive_job(
            id,
            RedriveRequest::new(
                revision - 1,
                operation,
                RedriveExecution::ReuseExecutionId,
                Timestamp::from_millis(10),
            ),
        )),
        Err(JobSystemError::LeaseConflict)
    ));
    assert!(matches!(
        block_on(system.redrive_job(
            id,
            RedriveRequest::new(
                revision,
                OperationId::from([99; 16]),
                RedriveExecution::ReuseExecutionId,
                Timestamp::from_millis(10),
            ),
        )),
        Err(JobSystemError::LeaseLost)
    ));
}

#[test]
fn given_a_dead_letter_with_a_foreign_namespace_when_redriving_then_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let (id, _, revision, operation) = dead_lettered(&system, 7);
    let job_key = crate::keys::job_key(system.namespace(), &id).expect("job key is valid");
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
        block_on(system.redrive_job(
            id,
            RedriveRequest::new(
                revision,
                operation,
                RedriveExecution::ReuseExecutionId,
                Timestamp::from_millis(10),
            ),
        )),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "identity rejection must not resurrect or rewrite the dead letter"
    );
}

#[test]
fn given_a_dead_letter_with_a_foreign_job_id_when_redriving_then_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let (id, _, revision, operation) = dead_lettered(&system, 8);
    let job_key = crate::keys::job_key(system.namespace(), &id).expect("job key is valid");
    let encoded = block_on(store.get(job_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    record.job_id = JobId::from([0xee; 16]);
    store
        .put_raw(
            job_key,
            crate::codec::encode_job_record(&record).expect("tampered record encodes"),
        )
        .expect("tampered record write succeeds");
    let before_rejection = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(system.redrive_job(
            id,
            RedriveRequest::new(
                revision,
                operation,
                RedriveExecution::ReuseExecutionId,
                Timestamp::from_millis(10),
            ),
        )),
        Err(JobSystemError::LeaseConflict)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "identity rejection must not create a route for the foreign job"
    );
}

#[test]
fn given_a_dead_letter_with_a_foreign_payload_chunk_when_redriving_then_payload_identity_is_rejected_and_state_is_unchanged()
 {
    let store = FakeStore::new();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let (id, _, revision, operation) = dead_lettered(&system, 9);
    let job_key = crate::keys::job_key(system.namespace(), &id).expect("job key is valid");
    let encoded = block_on(store.get(job_key.clone()))
        .expect("job read succeeds")
        .expect("job exists");
    let mut record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    let foreign_id = JobId::from([0xee; 16]);
    record.payload.chunk_keys[0] =
        crate::keys::payload_key(system.namespace(), &foreign_id, 0).expect("payload key");
    store
        .put_raw(
            job_key,
            crate::codec::encode_job_record(&record).expect("tampered record encodes"),
        )
        .expect("tampered record write succeeds");
    let before_rejection = store.snapshot().expect("snapshot succeeds");

    assert!(matches!(
        block_on(system.redrive_job(
            id,
            RedriveRequest::new(
                revision,
                operation,
                RedriveExecution::ReuseExecutionId,
                Timestamp::from_millis(10),
            ),
        )),
        Err(JobSystemError::PayloadCorrupt)
    ));
    assert_eq!(
        store.snapshot().expect("snapshot succeeds"),
        before_rejection,
        "payload identity rejection must not resurrect or rewrite the dead letter"
    );
}
