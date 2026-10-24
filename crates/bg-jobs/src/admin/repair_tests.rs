use std::sync::{Arc, Mutex};

use crate::{
    codec::{decode_job_record, encode_job_record},
    engine::JobSystem,
    error::JobSystemError,
    ids::{JobId, LeaseToken, OperationId, OwnerId, QueueName},
    keys,
    model::{JobState, Lease},
    observer::{JobEvent, JobObserver},
    policy::FairnessPolicy,
    store::JobStore,
    test_helper::{FakeStore, block_on, low_volume_job, system},
    time::Timestamp,
};

#[derive(Clone, Default)]
struct RepairEvents {
    events: Arc<Mutex<Vec<JobEvent>>>,
}

impl RepairEvents {
    fn clear(&self) {
        self.events.lock().expect("observer lock").clear();
    }

    fn repaired(&self) -> Vec<QueueName> {
        self.events
            .lock()
            .expect("observer lock")
            .iter()
            .filter_map(|event| match event {
                JobEvent::Repaired { queue } => Some(queue.clone()),
                _ => None,
            })
            .collect()
    }
}

impl JobObserver for RepairEvents {
    fn observe(&self, event: JobEvent) {
        self.events.lock().expect("observer lock").push(event);
    }
}

fn repair_fixture(
    system: &JobSystem<FakeStore>,
    store: &FakeStore,
) -> (JobId, u64, OperationId, QueueName) {
    let id = JobId::from([1; 16]);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let job_key = keys::job_key(system.namespace(), &id).expect("job key is valid");
    let encoded = block_on(system.store().get(job_key))
        .expect("job read succeeds")
        .expect("job exists");
    let record = decode_job_record(&encoded).expect("record decodes");
    let operation = OperationId::from([9; 16]);
    store
        .put_raw(
            keys::operation_key(system.namespace(), &id).expect("operation key is valid"),
            keys::operation_value(&id, &operation, 0).expect("operation value is valid"),
        )
        .expect("operation marker writes");
    (id, record.revision, operation, record.queue)
}

#[test]
fn given_a_confirmed_repair_when_repairing_twice_then_one_repaired_event_is_observed() {
    let store = FakeStore::new();
    let events = RepairEvents::default();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1)
        .with_observer(Arc::new(events.clone()));
    let (id, revision, operation, queue) = repair_fixture(&system, &store);
    events.clear();

    block_on(system.repair_job(id, revision, operation)).expect("repair commits");
    let duplicate = block_on(system.repair_job(id, revision, operation));

    assert!(matches!(duplicate, Err(JobSystemError::LeaseConflict)));
    assert_eq!(events.repaired(), vec![queue]);
}

#[test]
fn given_failed_or_ambiguous_repairs_when_repairing_then_no_repaired_event_is_observed() {
    let store = FakeStore::new();
    let events = RepairEvents::default();
    let system = system(store.clone(), FairnessPolicy::low_volume(), 1)
        .with_observer(Arc::new(events.clone()));
    let (id, revision, operation, _) = repair_fixture(&system, &store);
    events.clear();

    let stale = block_on(system.repair_job(id, revision + 1, operation));
    let wrong_operation = block_on(system.repair_job(id, revision, OperationId::from([8; 16])));
    store
        .queue_unknown_before_commit()
        .expect("first ambiguous commit queues");
    store
        .queue_unknown_before_commit()
        .expect("second ambiguous commit queues");
    let ambiguous = block_on(system.repair_job(id, revision, operation));

    assert!(matches!(stale, Err(JobSystemError::LeaseConflict)));
    assert!(matches!(wrong_operation, Err(JobSystemError::LeaseLost)));
    assert!(matches!(ambiguous, Err(JobSystemError::UnknownCommit)));
    assert!(events.repaired().is_empty());
}

#[test]
fn given_each_non_scheduled_state_when_repairing_then_state_is_rejected_unchanged() {
    for state in [
        JobState::Leased(
            Lease::try_new(
                OwnerId::from([1; 16]),
                LeaseToken::from([3; 16]),
                std::num::NonZeroU64::MIN,
                Timestamp::from_millis(1),
            )
            .expect("active lease is valid"),
        ),
        JobState::DeadLettered,
        JobState::Cancelled,
    ] {
        let store = FakeStore::new();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        let id = JobId::from([1; 16]);
        block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
        let job_key = keys::job_key(system.namespace(), &id).expect("job key is valid");
        let encoded = block_on(system.store().get(job_key.clone()))
            .expect("job read succeeds")
            .expect("job exists");
        let mut record = decode_job_record(&encoded).expect("record decodes");
        record.state = state;
        let tampered = encode_job_record(&record).expect("state fixture encodes");
        store
            .put_raw(job_key, tampered)
            .expect("state fixture writes");
        let operation = OperationId::from([9; 16]);
        store
            .put_raw(
                keys::operation_key(system.namespace(), &id).expect("operation key is valid"),
                keys::operation_value(&id, &operation, 0).expect("operation value is valid"),
            )
            .expect("operation marker writes");
        let before = store.snapshot().expect("snapshot succeeds");

        let result = block_on(system.repair_job(id, record.revision, operation));

        assert!(matches!(result, Err(JobSystemError::LeaseConflict)));
        assert_eq!(store.snapshot().expect("snapshot succeeds"), before);
    }
}
