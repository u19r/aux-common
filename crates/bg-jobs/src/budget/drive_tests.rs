use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicU32, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
};

use bytes::Bytes;

use crate::{
    test_helper::{
        TestProfile, block_on, completion as complete_outcome, job, low_volume_job, one,
        registry as default_registry, scoped_fairness, system,
    },
    *,
};

fn request_input(
    max_claims: NonZeroU32,
    max_completion_details: u32,
    stop_claiming_at: MonotonicDeadline,
    finish_by: MonotonicDeadline,
) -> DriveRequestInput {
    DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims,
        max_concurrency: NonZeroU16::new(1).expect("one concurrent claim"),
        max_payload_bytes_in_flight: NonZeroUsize::new(1).expect("one payload byte"),
        max_completion_details,
        max_store_operations: NonZeroU32::new(1).expect("one store operation"),
        stop_claiming_at,
        finish_by,
    }
}

#[test]
fn given_zero_completion_receipts_when_constructing_a_drive_then_the_request_is_still_valid() {
    let input = request_input(
        NonZeroU32::new(1).expect("one claim"),
        0,
        MonotonicDeadline::from_nanos(10),
        MonotonicDeadline::from_nanos(20),
    );

    let request = DriveRequest::try_from(input).expect("zero receipts means omit all details");
    assert_eq!(request.max_completion_details(), 0);
}

#[test]
fn given_a_machine_sized_completion_limit_when_initializing_a_report_then_reserve_is_bounded() {
    assert_eq!(crate::drive::initial_completion_capacity(u32::MAX), 4_096);
}

#[test]
fn given_machine_sized_store_limits_when_discovering_then_range_requests_stay_library_bounded() {
    let store = RangeLimitStore::new();
    let system = range_limit_system(store.clone());
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: NonZeroU32::new(u32::MAX).expect("maximum claims are non-zero"),
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::new(usize::MAX)
            .expect("maximum payload bytes are non-zero"),
        max_completion_details: 0,
        max_store_operations: one(3),
        stop_claiming_at: MonotonicDeadline::ZERO,
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("bounded request is valid");

    block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("empty discovery reports");

    assert_eq!(store.calls(), 3, "two index reads and one owner load");
    assert_eq!(store.ranges().len(), 2, "due and lease each read one page");
    for (items, bytes) in store.ranges() {
        assert!(
            items == crate::transition::MAX_INDEX_RANGE_ITEMS as u32,
            "machine-sized backend must be capped at the library item limit"
        );
        assert!(
            bytes == crate::transition::MAX_INDEX_RANGE_BYTES,
            "machine-sized backend must be capped at the library byte limit"
        );
    }
}

#[test]
fn given_empty_discovery_when_driving_then_idle_selection_is_attempted_once() {
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 1);
    let mut input = request_input(
        one(1),
        0,
        MonotonicDeadline::ZERO,
        MonotonicDeadline::from_nanos(u64::MAX),
    );
    input.max_store_operations = one(3);
    let request = DriveRequest::try_from(input).expect("bounded request is valid");

    crate::fairness::FairDispatchOwner::reset_selection_passes();
    block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("empty discovery reports");

    assert_eq!(
        crate::fairness::FairDispatchOwner::selection_passes(),
        1,
        "an idle scheduler must not rescan the ledger after its only selection pass"
    );
}

#[test]
fn given_many_records_and_a_machine_sized_value_limit_when_discovering_then_get_many_is_batched() {
    let store = RangeLimitStore::new();
    let system = range_limit_system(store.clone());
    for id in 100..140 {
        block_on(system.enqueue_raw(
            job(
                id,
                Bytes::from_static(b"payload"),
                FairnessClass::low_volume(),
                Timestamp::ZERO,
                None,
                None,
            ),
            Timestamp::ZERO,
        ))
        .expect("fixture enqueue commits");
    }
    store.reset_logs();
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: NonZeroU32::new(u32::MAX).expect("maximum claims are non-zero"),
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::new(usize::MAX)
            .expect("maximum payload bytes are non-zero"),
        max_completion_details: 0,
        max_store_operations: one(6),
        stop_claiming_at: MonotonicDeadline::ZERO,
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("bounded request is valid");

    block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("discovery reports");

    assert_eq!(
        store.calls(),
        5,
        "two index reads and three bounded record operations: {:?}",
        store.get_many_batches()
    );
    let batches = store.get_many_batches();
    assert_eq!(batches.len(), 3, "records are split into bounded batches");
    assert!(batches.iter().all(|batch| *batch <= 16));
    assert_eq!(batches.iter().sum::<usize>(), 40);
}

#[test]
fn given_oversized_authoritative_records_when_discovering_then_retained_bytes_stay_bounded() {
    let store = RangeLimitStore::new();
    let system = range_limit_system(store.clone());
    for id in 200..218 {
        block_on(system.enqueue_raw(
            job(
                id,
                Bytes::from_static(b"payload"),
                FairnessClass::low_volume(),
                Timestamp::ZERO,
                None,
                None,
            ),
            Timestamp::ZERO,
        ))
        .expect("fixture enqueue commits");
    }
    store.replace_job_values_with_max(system.namespace(), 200..218);
    store.reset_logs();

    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: NonZeroU32::new(u32::MAX).expect("maximum claims are non-zero"),
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::new(usize::MAX)
            .expect("maximum payload bytes are non-zero"),
        max_completion_details: 0,
        max_store_operations: one(5),
        stop_claiming_at: MonotonicDeadline::ZERO,
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("bounded request is valid");

    block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("oversized records are skipped within the discovery budget");

    let batches = store.get_many_batches();
    assert_eq!(
        batches,
        vec![15],
        "the first response fills the bounded budget"
    );
    assert!(
        store.get_many_bytes().into_iter().sum::<usize>()
            <= crate::transition::MAX_INDEX_RANGE_BYTES,
        "authoritative responses must stay within the aggregate byte budget"
    );
}

#[test]
fn given_more_completion_receipts_than_claims_when_constructing_a_drive_then_validation_fails() {
    let input = request_input(
        NonZeroU32::new(1).expect("one claim"),
        2,
        MonotonicDeadline::from_nanos(10),
        MonotonicDeadline::from_nanos(20),
    );

    assert!(matches!(
        DriveRequest::try_from(input),
        Err(ValidationError::InvalidValue {
            field: "max completion details"
        })
    ));
}

#[test]
fn given_a_finish_deadline_before_claim_stop_when_constructing_a_drive_then_ordering_fails() {
    let input = request_input(
        NonZeroU32::new(1).expect("one claim"),
        1,
        MonotonicDeadline::from_nanos(20),
        MonotonicDeadline::from_nanos(10),
    );

    assert!(matches!(
        DriveRequest::try_from(input),
        Err(ValidationError::Ordering {
            field: "drive deadlines"
        })
    ));
}

#[test]
fn given_the_largest_machine_byte_budget_when_constructing_a_drive_then_it_does_not_wrap() {
    let mut input = request_input(
        NonZeroU32::new(u32::MAX).expect("maximum claims is non-zero"),
        0,
        MonotonicDeadline::ZERO,
        MonotonicDeadline::from_nanos(u64::MAX),
    );
    input.max_payload_bytes_in_flight = NonZeroUsize::new(usize::MAX).expect("maximum is non-zero");

    let request =
        DriveRequest::try_from(input).expect("the caller supplied a bounded machine value");
    assert_eq!(request.max_payload_bytes_in_flight().get(), usize::MAX);
}

#[test]
fn given_zero_nonzero_budget_inputs_when_constructing_the_inputs_then_the_type_rejects_zero() {
    assert!(NonZeroU32::new(0).is_none());
    assert!(NonZeroU16::new(0).is_none());
    assert!(NonZeroUsize::new(0).is_none());
}

#[test]
fn given_an_empty_queue_selection_when_constructing_it_then_validation_fails() {
    assert!(matches!(
        QueueSelection::only(Vec::new()),
        Err(ValidationError::Empty {
            field: "queue selection"
        })
    ));
}

#[test]
fn given_more_than_sixty_four_queues_when_constructing_a_selection_then_validation_fails() {
    let queue = QueueName::try_new("queue").expect("queue name is valid");
    let queues = vec![queue; QueueSelection::MAX_QUEUES + 1];

    assert!(matches!(
        QueueSelection::only(queues),
        Err(ValidationError::TooLong {
            field: "queue selection",
            maximum: QueueSelection::MAX_QUEUES,
            actual: 65,
        })
    ));
}

#[test]
fn given_one_concurrent_worker_when_store_budget_is_below_discovery_and_claim_then_drive_stops_before_handler()
 {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(1),
        max_concurrency: NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: NonZeroUsize::new(1024).expect("payload budget is non-zero"),
        max_completion_details: 1,
        max_store_operations: one(11),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid");

    let report = block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("drive reports");

    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.counts.succeeded, 0);
    assert_eq!(report.stop_reason, DriveStopReason::Capacity);
}

#[test]
fn given_one_claim_budget_when_first_candidate_conflicts_then_both_scheduler_widths_can_claim_later_candidate()
 {
    fn drive_after_first_conflict(max_concurrency: u16) -> DriveReport {
        let store = FakeStore::new();
        let system = system(store.clone(), FairnessPolicy::low_volume(), 1);
        block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
            .expect("first enqueue commits");
        block_on(system.enqueue_raw(low_volume_job(2, Timestamp::ZERO), Timestamp::ZERO))
            .expect("second enqueue commits");
        store
            .queue_commit_outcome(CommitOutcome::Committed)
            .expect("owner reservation commit is queued");
        store
            .queue_commit_outcome(CommitOutcome::Conflict)
            .expect("first claim conflict is queued");
        let request = DriveRequest::try_from(DriveRequestInput {
            queues: QueueSelection::all(),
            max_claims: one(1),
            max_concurrency: NonZeroU16::new(max_concurrency).expect("concurrency is non-zero"),
            max_payload_bytes_in_flight: NonZeroUsize::new(1024)
                .expect("payload budget is non-zero"),
            max_completion_details: 1,
            max_store_operations: one(64),
            stop_claiming_at: MonotonicDeadline::from_nanos(1),
            finish_by: MonotonicDeadline::from_nanos(u64::MAX),
        })
        .expect("drive request is valid");

        block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("drive reports")
    }

    for report in [drive_after_first_conflict(1), drive_after_first_conflict(2)] {
        assert_eq!(report.counts.lease_conflicts, 1);
        assert_eq!(report.counts.claimed, 1);
        assert_eq!(report.counts.succeeded, 1);
        assert_eq!(report.stop_reason, DriveStopReason::ClaimsExhausted);
    }
}

#[test]
fn given_registered_low_volume_backlog_when_driving_again_then_the_next_job_is_admitted() {
    let system = system(FakeStore::new(), FairnessPolicy::low_volume(), 46);
    for id in [46, 47] {
        block_on(system.enqueue_raw(low_volume_job(id, Timestamp::ZERO), Timestamp::ZERO))
            .expect("low-volume enqueue commits");
    }

    let first = block_on(system.drive(
        permissive_request(
            2,
            128,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive reports");

    assert_eq!(first.counts.claimed, 1);
    assert_eq!(first.counts.succeeded, 1);
    assert_eq!(first.completions.len(), 1);
    assert_eq!(first.stop_reason, DriveStopReason::Capacity);

    let second = block_on(system.drive(
        permissive_request(
            2,
            128,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::from_millis(1),
        || MonotonicDeadline::ZERO,
    ))
    .expect("later drive reports");

    assert_eq!(second.counts.claimed, 1);
    assert_eq!(second.counts.succeeded, 1);
    assert_eq!(second.completions.len(), 1);
}

#[test]
fn given_a_recurring_low_volume_job_when_the_same_system_drives_then_it_runs_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store,
        FairnessPolicy::low_volume(),
        ContinuingHandler::new(Arc::clone(&calls)),
    );
    block_on(system.enqueue_raw(low_volume_job(48, Timestamp::ZERO), Timestamp::ZERO))
        .expect("low-volume enqueue commits");

    let first_report = block_on(system.drive(
        permissive_request(
            1,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("first drive reports");
    let second_report = block_on(system.drive(
        permissive_request(
            1,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::from_millis(60_000),
        || MonotonicDeadline::ZERO,
    ))
    .expect("second drive reports");

    assert_eq!(first_report.counts.continued, 1);
    assert_eq!(
        first_report.next_wake,
        crate::WakeHint::At(Timestamp::from_millis(1))
    );
    assert_eq!(
        second_report.counts.continued, 1,
        "second drive report: {second_report:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn given_owner_reservation_conflict_when_drive_starts_then_no_handler_or_job_effect_occurs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store.clone(),
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    let job_id = JobId::from([43; 16]);
    block_on(system.enqueue_raw(low_volume_job(43, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    store
        .queue_commit_outcome(CommitOutcome::Conflict)
        .expect("owner reservation conflict is queued");

    let result = block_on(system.drive(
        permissive_request(
            1,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ));

    let report = result.expect("owner contention yields a resumable report");
    assert_eq!(report.counts.lease_conflicts, 1);
    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.next_wake, WakeHint::Now);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let encoded = block_on(
        system
            .store()
            .get(crate::keys::job_key(system.namespace(), &job_id).expect("job key is valid")),
    )
    .expect("job read succeeds")
    .expect("job remains after reservation conflict");
    let record = crate::codec::decode_job_record(&encoded).expect("job record decodes");
    assert_eq!(record.state, JobState::Scheduled);
    let resumed = block_on(system.drive(
        permissive_request(
            1,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("a later drive resumes unclaimed work");
    assert_eq!(resumed.counts.succeeded, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn given_admitted_work_when_another_owner_reservation_conflicts_then_drive_drains_and_later_resumes()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store.clone(),
        FairnessPolicy::Scoped {
            weight: NonZeroU16::MIN,
        },
        RecordingHandler::new(Arc::clone(&calls)),
    );
    for id in [48, 49] {
        block_on(system.enqueue_raw(
            job(
                id,
                Bytes::from_static(b"payload"),
                scoped_fairness(),
                Timestamp::ZERO,
                None,
                None,
            ),
            Timestamp::ZERO,
        ))
        .expect("enqueue commits");
    }
    store
        .queue_commit_outcome(CommitOutcome::Committed)
        .unwrap();
    store.queue_commit_outcome(CommitOutcome::Conflict).unwrap();
    let request = permissive_request_with_concurrency(
        2,
        128,
        MonotonicDeadline::from_nanos(1),
        MonotonicDeadline::from_nanos(u64::MAX),
        2,
    );
    let report =
        block_on(system.drive(request.clone(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("known contention does not discard admitted work");
    assert_eq!(report.counts.lease_conflicts, 1);
    assert_eq!(report.counts.claimed, 1);
    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(report.completions.len(), 1);
    assert_eq!(report.next_wake, WakeHint::Now);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let resumed = block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("a subsequent drive admits the remaining work");
    assert_eq!(resumed.counts.claimed, 1);
    assert_eq!(resumed.counts.succeeded, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn given_unresolved_owner_commit_when_drive_starts_then_error_is_retained_without_handler_effects()
{
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store.clone(),
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    block_on(system.enqueue_raw(low_volume_job(47, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    for _ in 0..2 {
        store
            .queue_unknown_before_commit()
            .expect("lost acknowledgement is queued");
    }
    let result = block_on(system.drive(
        permissive_request(
            1,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ));
    assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let encoded =
        block_on(store.get(
            crate::keys::job_key(system.namespace(), &JobId::from([47; 16])).expect("job key"),
        ))
        .expect("job read succeeds")
        .expect("unknown reservation retains the job");
    assert_eq!(
        crate::codec::decode_job_record(&encoded).unwrap().state,
        JobState::Scheduled
    );
}

#[test]
fn given_two_drives_at_the_same_owner_version_when_one_reservation_conflicts_then_only_one_handler_runs()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let inner = FakeStore::new();
    let namespace = Namespace::try_new(b"jobs").expect("test namespace is valid");
    let barrier_store = ReservationBarrierStore::new(
        inner.clone(),
        crate::keys::fair_state_key(&namespace).expect("fair owner key is valid"),
    );
    let system_a = system_with_barrier_handler(
        barrier_store.clone(),
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
        44,
    );
    let system_b = system_with_barrier_handler(
        barrier_store.clone(),
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
        45,
    );
    block_on(system_a.enqueue_raw(low_volume_job(44, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    inner
        .queue_commit_outcome(CommitOutcome::Conflict)
        .expect("one reservation conflict is queued");
    let request = permissive_request(
        1,
        64,
        MonotonicDeadline::from_nanos(1),
        MonotonicDeadline::from_nanos(u64::MAX),
    );
    let start = Arc::new(Barrier::new(3));
    let start_a = Arc::clone(&start);
    let start_b = Arc::clone(&start);
    let request_a = request.clone();
    let thread_a = std::thread::spawn(move || {
        start_a.wait();
        block_on(system_a.drive(request_a, Timestamp::ZERO, || MonotonicDeadline::ZERO))
    });
    let thread_b = std::thread::spawn(move || {
        start_b.wait();
        block_on(system_b.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
    });
    start.wait();
    let result_a = thread_a.join().expect("first drive thread completes");
    let result_b = thread_b.join().expect("second drive thread completes");

    let mut conflicts = 0;
    let mut completed = 0;
    for result in [result_a, result_b] {
        let report = result.expect("both competing drives report their bounded progress");
        conflicts += report.counts.lease_conflicts;
        completed += report.counts.succeeded;
        assert_eq!(report.counts.claimed, report.counts.succeeded);
        if report.counts.lease_conflicts > 0 {
            assert_eq!(report.next_wake, WakeHint::Now);
        }
    }
    assert_eq!(barrier_store.reservation_commits(), 2);
    assert!(barrier_store.owner_reads() >= 2);
    assert_eq!(conflicts, 1);
    assert_eq!(completed, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn given_out_of_order_capacity_and_completion_when_drive_applies_results_then_buffered_completion_is_applied()
 {
    let report = crate::drive::apply_buffered_results_for_test();

    assert_eq!(report.counts.capacity_deferrals, 1);
    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(report.completions.len(), 1);
}

#[test]
fn given_an_expired_stop_deadline_when_driving_through_the_public_api_then_no_work_starts() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store,
        scoped_policy(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    block_on(system.enqueue_raw(scoped_job(31, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let request = permissive_request(
        1,
        64,
        MonotonicDeadline::ZERO,
        MonotonicDeadline::from_nanos(u64::MAX),
    );

    let report = block_on(system.drive(request, Timestamp::ZERO, || {
        MonotonicDeadline::from_nanos(1)
    }))
    .expect("drive reports");

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.stop_reason, DriveStopReason::Deadline);
}

#[test]
fn given_an_expired_finish_deadline_when_driving_through_the_public_api_then_no_work_starts() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store,
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    block_on(system.enqueue_raw(low_volume_job(32, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let request = permissive_request(
        1,
        64,
        MonotonicDeadline::ZERO,
        MonotonicDeadline::from_nanos(1),
    );

    let report = block_on(system.drive(request, Timestamp::ZERO, || {
        MonotonicDeadline::from_nanos(1)
    }))
    .expect("drive reports");

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.stop_reason, DriveStopReason::Deadline);
}

#[test]
fn given_time_advances_between_candidates_when_driving_then_new_claims_stop_at_the_deadline() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store,
        scoped_policy(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    for id in [33, 34] {
        block_on(system.enqueue_raw(scoped_job(id, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
    }
    let request = permissive_request(
        2,
        64,
        MonotonicDeadline::from_nanos(10),
        MonotonicDeadline::from_nanos(u64::MAX),
    );

    let report = block_on(system.drive(request, Timestamp::ZERO, || {
        if calls.load(Ordering::SeqCst) == 0 {
            MonotonicDeadline::ZERO
        } else {
            MonotonicDeadline::from_nanos(10)
        }
    }))
    .expect("drive reports");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(report.stop_reason, DriveStopReason::Deadline);
}

#[test]
fn given_insufficient_handler_time_when_driving_then_execution_is_not_started() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store,
        scoped_policy(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    block_on(system.enqueue_raw(scoped_job(35, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let request = permissive_request(
        1,
        64,
        MonotonicDeadline::from_nanos(1),
        MonotonicDeadline::from_nanos(1),
    );

    let report = block_on(system.drive(request, Timestamp::ZERO, || {
        MonotonicDeadline::from_nanos(1)
    }))
    .expect("drive reports");

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.stop_reason, DriveStopReason::Deadline);
}

#[test]
fn given_a_panicking_handler_when_public_drive_buffers_another_candidate_then_retry_is_durable() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store,
        scoped_policy(),
        PanicThenCompleteHandler::new(Arc::clone(&calls)),
    );
    for id in [36, 37] {
        block_on(system.enqueue_raw(scoped_job(id, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
    }
    let request = permissive_request_with_concurrency(
        2,
        128,
        MonotonicDeadline::from_nanos(u64::MAX / 2),
        MonotonicDeadline::from_nanos(u64::MAX),
        2,
    );

    let result = catch_unwind(AssertUnwindSafe(|| {
        block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
    }));

    assert!(result.is_ok(), "handler panic escaped the public drive");
    let report = result
        .expect("panic was contained")
        .expect("drive reports after a contained panic");
    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(report.counts.retried, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let retry_request = permissive_request(
        1,
        128,
        MonotonicDeadline::from_nanos(u64::MAX / 2),
        MonotonicDeadline::from_nanos(u64::MAX),
    );
    let retry = block_on(
        system.drive(retry_request, Timestamp::from_millis(1_000), || {
            MonotonicDeadline::ZERO
        }),
    )
    .expect("durable retry drive reports");
    assert_eq!(retry.counts.succeeded, 1);
}

#[test]
fn given_exact_store_operation_budgets_when_public_drive_runs_then_calls_stay_within_budget() {
    let mut violations = Vec::new();
    for budget in [1, 4, 8, 12, 25, 28, 29] {
        let store = CountingStore::new();
        let system = counting_system(store.clone());
        block_on(system.enqueue_raw(low_volume_job(40, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
        store.reset();
        if budget == 29 {
            store
                .queue_commit_outcome(CommitOutcome::Committed)
                .expect("owner reservation commit is queued");
            store
                .queue_commit_outcome(CommitOutcome::Conflict)
                .expect("claim conflict is queued");
        }
        let request = permissive_request(
            1,
            budget,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        );

        let report = block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("drive reports");
        if budget == 29 {
            assert_eq!(report.counts.lease_conflicts, 1);
        } else {
            assert_eq!(report.counts.claimed, 0);
            assert_eq!(report.stop_reason, DriveStopReason::Capacity);
        }
        if store.calls() > budget {
            violations.push((budget, store.calls()));
        }
    }
    assert!(
        violations.is_empty(),
        "store-operation budget violations: {violations:?}"
    );
}

#[test]
fn given_permit_discovery_would_exhaust_the_operation_budget_then_drive_stops_before_the_probe() {
    let store = CountingStore::new();
    let system = counting_scoped_system(store.clone());
    block_on(system.enqueue_raw(
        job(
            41,
            Bytes::from_static(b"payload"),
            scoped_fairness(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");
    store.reset();

    let report = block_on(system.drive(
        permissive_request(
            1,
            11,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive reports");

    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.stop_reason, DriveStopReason::Capacity);
    assert_eq!(store.calls(), 3, "the permit probe must not consume a call");
}

#[test]
fn given_batched_permit_recovery_exceeds_the_operation_budget_when_driving_then_no_probe_starts() {
    let store = CountingStore::with_get_many_limit(100);
    let system = counting_scoped_system(store.clone());
    block_on(system.enqueue_raw(
        job(
            42,
            Bytes::from_static(b"payload"),
            scoped_fairness(),
            Timestamp::ZERO,
            None,
            None,
        ),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");
    let claim = block_on(system.claim(JobId::from([42; 16]), Timestamp::ZERO))
        .expect("initial claim commits");
    let lease_expiry = match &claim.record().state {
        JobState::Leased(lease) => lease.expires_at,
        state => panic!("expected leased job, got {state:?}"),
    };
    drop(claim);
    store.reset();

    let operation_limit = 25;
    let report = block_on(system.drive(
        permissive_request(
            1,
            operation_limit,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        lease_expiry,
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive reports");

    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.stop_reason, DriveStopReason::Capacity);
    assert!(
        store.calls() <= operation_limit,
        "store calls exceeded the drive budget: {} > {operation_limit}",
        store.calls()
    );
}

#[test]
fn given_due_work_beyond_the_first_range_page_when_driving_then_each_due_item_is_claimed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = paged_store();
    let system = system_with_handler(
        store,
        scoped_policy(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    for id in [61, 62] {
        block_on(system.enqueue_raw(scoped_job(id, Timestamp::ZERO), Timestamp::ZERO))
            .expect("enqueue commits");
    }

    let report = block_on(system.drive(
        permissive_request(
            2,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive reports");

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(report.counts.claimed, 2);
    assert_eq!(report.counts.succeeded, 2);
}

#[test]
fn given_expired_leases_beyond_the_first_range_page_when_driving_then_each_lease_is_claimed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = paged_store();
    let system = system_with_handler(
        store,
        scoped_policy(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    for id in [63, 64] {
        block_on(system.enqueue_raw(
            scoped_job_with_primary(id, id, Timestamp::ZERO),
            Timestamp::ZERO,
        ))
        .expect("enqueue commits");
        block_on(system.claim(JobId::from([id; 16]), Timestamp::ZERO)).expect("claim commits");
    }

    let report = block_on(system.drive(
        permissive_request(
            2,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::from_millis(2_000),
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive reports");

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(report.counts.claimed, 2);
    assert_eq!(report.counts.succeeded, 2);
}

#[test]
fn given_a_mismatched_complete_permit_set_when_reclaiming_expired_lease_then_conflict_leaves_state_unchanged()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store.clone(),
        scoped_policy(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    let expired_id = JobId::from([73; 16]);
    let live_id = JobId::from([74; 16]);
    block_on(system.enqueue_raw(
        scoped_job_with_primary(73, 73, Timestamp::ZERO),
        Timestamp::ZERO,
    ))
    .expect("expired fixture enqueue commits");
    block_on(system.enqueue_raw(
        scoped_job_with_primary(74, 74, Timestamp::ZERO),
        Timestamp::ZERO,
    ))
    .expect("live fixture enqueue commits");
    block_on(system.claim(expired_id, Timestamp::ZERO)).expect("expired fixture claim commits");
    block_on(system.claim(live_id, Timestamp::from_millis(1_500)))
        .expect("live fixture claim commits");

    let load_record = |job_id| {
        let key = crate::keys::job_key(system.namespace(), &job_id).expect("job key is valid");
        let encoded = block_on(store.get(key))
            .expect("job read succeeds")
            .expect("job exists");
        crate::codec::decode_job_record(&encoded).expect("job record decodes")
    };
    let expired_record = load_record(expired_id);
    let live_record = load_record(live_id);
    let expired_permit_keys =
        crate::keys::permit_key_sets(system.namespace(), &expired_record, NonZeroU16::MIN)
            .expect("expired permit keys are valid")
            .into_iter()
            .next()
            .expect("expired permit set exists");
    assert!(
        !expired_permit_keys.is_empty(),
        "scoped work has a permit set"
    );
    let live_permit_value =
        crate::keys::permit_value_for_record(&live_record).expect("live permit value encodes");
    for key in expired_permit_keys {
        store
            .put_raw(key, live_permit_value.clone())
            .expect("mismatched permit writes");
    }
    let before = store.snapshot().expect("snapshot before reclaim succeeds");

    let report = block_on(system.drive(
        permissive_request(
            1,
            128,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::from_millis(2_000),
        || MonotonicDeadline::ZERO,
    ))
    .expect("reclaim drive reports");

    assert_eq!(report.counts.lease_conflicts, 1);
    assert_eq!(report.counts.claimed, 0);
    assert_eq!(report.counts.succeeded, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let fair_state_key =
        crate::keys::fair_state_key(system.namespace()).expect("fair owner key is valid");
    let after = store.snapshot().expect("snapshot after reclaim succeeds");
    // The scheduler commits its advisory owner reservation before attempting
    // the authoritative claim. Compare all lifecycle-owned entries here; the
    // owner projection is expected to contain that committed reservation.
    let authoritative_entries = |snapshot: Vec<_>| {
        snapshot
            .into_iter()
            .filter(|(key, _)| key != &fair_state_key)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        authoritative_entries(after),
        authoritative_entries(before),
        "mismatched permit ownership must not cause partial authoritative writes"
    );
}

#[test]
fn given_a_malformed_due_entry_before_valid_work_when_driving_then_valid_work_still_completes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = paged_store();
    let system = system_with_handler(
        store.clone(),
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    let queue = QueueName::try_new("default").expect("test queue is valid");
    block_on(system.enqueue_raw(low_volume_job(71, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let mut malformed_bytes = crate::keys::due_queue_prefix(system.namespace(), &queue)
        .expect("due prefix is valid")
        .into_bytes();
    malformed_bytes.extend_from_slice(&0_u32.to_be_bytes());
    let malformed_key = crate::store::StoreKey::try_from(malformed_bytes)
        .expect("malformed due key remains a store key");
    store
        .put_raw(malformed_key.clone(), Bytes::from_static(b"malformed"))
        .expect("malformed due entry writes");

    let report = block_on(system.drive(
        permissive_queue_request(queue, 1, 128),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive skips one malformed entry and reports valid work");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.counts.claimed, 1);
    assert_eq!(report.counts.succeeded, 1);
    assert!(
        store
            .contains(&malformed_key)
            .expect("malformed entry remains")
    );
}

#[test]
fn given_a_malformed_lease_entry_before_valid_work_when_driving_then_valid_work_still_completes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = paged_store();
    let system = system_with_handler(
        store.clone(),
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    let queue = QueueName::try_new("default").expect("test queue is valid");
    let id = JobId::from([72; 16]);
    block_on(system.enqueue_raw(low_volume_job(72, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    block_on(system.claim(id, Timestamp::ZERO)).expect("claim creates an expired-lease route");
    let mut malformed_bytes = crate::keys::lease_queue_prefix(system.namespace(), &queue)
        .expect("lease prefix is valid")
        .into_bytes();
    malformed_bytes.extend_from_slice(&0_u32.to_be_bytes());
    let malformed_key = crate::store::StoreKey::try_from(malformed_bytes)
        .expect("malformed lease key remains a store key");
    store
        .put_raw(malformed_key.clone(), Bytes::from_static(b"malformed"))
        .expect("malformed lease entry writes");

    let report = block_on(system.drive(
        permissive_queue_request(queue, 1, 128),
        Timestamp::from_millis(2_000),
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive skips one malformed entry and reports valid work");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.counts.claimed, 1);
    assert_eq!(report.counts.succeeded, 1);
    assert!(
        store
            .contains(&malformed_key)
            .expect("malformed entry remains")
    );
}

#[test]
fn given_a_transplanted_lease_route_for_job_a_when_it_fetches_job_b_then_job_b_is_not_claimed_and_bytes_remain_unchanged()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = paged_store();
    let system = system_with_handler(
        store.clone(),
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    let queue = QueueName::try_new("default").expect("test queue is valid");
    let job_a = JobId::from([75; 16]);
    let job_b = JobId::from([76; 16]);
    let job_c = JobId::from([77; 16]);
    block_on(system.enqueue_raw(low_volume_job(76, Timestamp::ZERO), Timestamp::ZERO))
        .expect("job B enqueue commits");
    block_on(system.claim(job_b, Timestamp::ZERO)).expect("job B claim commits");

    let job_b_key = crate::keys::job_key(system.namespace(), &job_b).expect("job B key is valid");
    let encoded_b = block_on(store.get(job_b_key.clone()))
        .expect("job B record reads")
        .expect("job B record exists");
    let lease_b_key = crate::keys::lease_key(system.namespace(), &queue, &job_b)
        .expect("job B lease key is valid");
    store
        .delete_raw(&lease_b_key)
        .expect("job B lease route deletes");

    let job_a_key = crate::keys::job_key(system.namespace(), &job_a).expect("job A key is valid");
    let lease_a_key = crate::keys::lease_key(system.namespace(), &queue, &job_a)
        .expect("job A lease key is valid");
    let lease_a_value = crate::keys::lease_value(&job_a).expect("job A lease marker is valid");
    store
        .put_raw(job_a_key.clone(), encoded_b.clone())
        .expect("transplanted job B record writes under job A key");
    store
        .put_raw(lease_a_key.clone(), lease_a_value.clone())
        .expect("job A lease route writes");
    block_on(system.enqueue_raw(low_volume_job(77, Timestamp::ZERO), Timestamp::ZERO))
        .expect("job C enqueue commits");
    block_on(system.claim(job_c, Timestamp::ZERO)).expect("job C claim commits");

    let report = block_on(system.drive(
        permissive_queue_request(queue, 1, 128),
        Timestamp::from_millis(2_000),
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive reports the corrupt route");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.counts.claimed, 1);
    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(
        block_on(store.get(job_a_key)).expect("transplanted record reads"),
        Some(encoded_b.clone())
    );
    assert_eq!(
        block_on(store.get(lease_a_key)).expect("job A route reads"),
        Some(lease_a_value)
    );
    assert_eq!(
        block_on(store.get(job_b_key)).expect("job B record reads after drive"),
        Some(encoded_b)
    );
}

#[test]
fn given_a_malformed_job_record_before_valid_expired_work_when_driving_then_valid_work_completes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = paged_store();
    let system = system_with_handler(
        store.clone(),
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    let queue = QueueName::try_new("default").expect("test queue is valid");
    let corrupt_id = JobId::from([73; 16]);
    let valid_id = JobId::from([74; 16]);
    block_on(system.enqueue_raw(low_volume_job(74, Timestamp::ZERO), Timestamp::ZERO))
        .expect("valid enqueue commits");
    block_on(system.claim(valid_id, Timestamp::ZERO)).expect("valid claim commits");
    let corrupt_job_key =
        crate::keys::job_key(system.namespace(), &corrupt_id).expect("corrupt job key is valid");
    let corrupt_lease_key = crate::keys::lease_key(system.namespace(), &queue, &corrupt_id)
        .expect("corrupt lease key is valid");
    store
        .put_raw(corrupt_job_key.clone(), Bytes::from_static(b"malformed"))
        .expect("malformed job record writes");
    store
        .put_raw(
            corrupt_lease_key.clone(),
            crate::keys::lease_value(&corrupt_id).expect("lease marker is valid"),
        )
        .expect("malformed job lease route writes");

    let report = block_on(system.drive(
        permissive_queue_request(queue, 1, 128),
        Timestamp::from_millis(2_000),
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive skips one malformed record and reports valid work");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.counts.claimed, 1);
    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(
        block_on(store.get(corrupt_job_key.clone())).expect("corrupt record reads"),
        Some(Bytes::from_static(b"malformed"))
    );
    assert_eq!(
        block_on(store.get(corrupt_lease_key)).expect("corrupt lease route reads"),
        Some(crate::keys::lease_value(&corrupt_id).expect("lease marker is valid"))
    );
}

#[test]
fn given_a_terminal_record_missing_from_discovery_when_driving_then_the_durable_owner_is_reconciled()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = system_with_handler(
        store,
        FairnessPolicy::low_volume(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    let terminal_job = JobId::from([65; 16]);
    block_on(system.enqueue_raw(low_volume_job(65, Timestamp::ZERO), Timestamp::ZERO))
        .expect("terminal enqueue commits");
    block_on(system.enqueue_raw(low_volume_job(66, Timestamp::ZERO), Timestamp::ZERO))
        .expect("remaining enqueue commits");

    // A terminal transition can commit while the corresponding owner save is
    // lost.  A shutdown drive gives us the same durable owner state without
    // relying on commit-outcome ordering in this test.
    system.request_shutdown();
    let seeded = block_on(system.drive(
        permissive_request(
            2,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("owner seed drive reports");
    assert_eq!(seeded.stop_reason, DriveStopReason::Shutdown);
    system.clear_shutdown();

    let claim = block_on(system.claim(terminal_job, Timestamp::ZERO)).expect("claim commits");
    block_on(system.complete(claim, complete_outcome(), Timestamp::ZERO))
        .expect("terminal transition commits");

    let report = block_on(system.drive(
        permissive_request(
            1,
            64,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive reports");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.counts.claimed, 1);
    assert_eq!(report.counts.succeeded, 1);
}

#[test]
fn given_shutdown_after_owner_reservation_when_the_lease_expires_then_drive_reclaims_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (started, started_rx) = mpsc::channel();
    let (system, profile, sleep_receiver) = system_with_handler_and_profile(
        FakeStore::new(),
        scoped_policy(),
        PendingThenCompleteHandler::new(Arc::clone(&calls), started),
    );
    let system = Arc::new(system);
    block_on(system.enqueue_raw(scoped_job(67, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let runner = Arc::clone(&system);
    let first_drive = thread::spawn(move || {
        block_on(runner.drive(
            permissive_request(
                1,
                128,
                MonotonicDeadline::from_nanos(1),
                MonotonicDeadline::from_nanos(u64::MAX),
            ),
            Timestamp::ZERO,
            || MonotonicDeadline::ZERO,
        ))
    });
    started_rx
        .recv()
        .expect("the first handler starts after reservation commit");
    sleep_receiver
        .recv()
        .expect("handler deadline is scheduled");
    system.request_shutdown();
    sleep_receiver.recv().expect("shutdown grace is scheduled");
    profile.advance(std::time::Duration::from_millis(50));
    let first_report = first_drive
        .join()
        .expect("shutdown drive joins")
        .expect("shutdown drive reports");
    assert_eq!(first_report.stop_reason, DriveStopReason::Shutdown);
    assert_eq!(first_report.counts.claimed, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    system.clear_shutdown();
    let second_report = block_on(system.drive(
        permissive_request(
            1,
            128,
            MonotonicDeadline::from_nanos(1),
            MonotonicDeadline::from_nanos(u64::MAX),
        ),
        Timestamp::from_millis(2_000),
        || MonotonicDeadline::ZERO,
    ))
    .expect("expired lease drive reports");

    assert_eq!(second_report.counts.claimed, 1);
    assert_eq!(second_report.counts.succeeded, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn given_queue_only_after_completion_when_same_scope_work_arrives_then_drive_claims_it() {
    let calls = Arc::new(AtomicUsize::new(0));
    let system = system_with_handler(
        FakeStore::new(),
        scoped_policy(),
        RecordingHandler::new(Arc::clone(&calls)),
    );
    let queue = QueueName::try_new("default").expect("test queue is valid");
    let queues = QueueSelection::only(vec![queue]).expect("queue selection is valid");
    block_on(system.enqueue_raw(scoped_job(68, Timestamp::ZERO), Timestamp::ZERO))
        .expect("first enqueue commits");
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: queues.clone(),
        max_claims: one(1),
        max_concurrency: NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: NonZeroUsize::new(1024).expect("payload budget is non-zero"),
        max_completion_details: 1,
        max_store_operations: one(128),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid");

    let first_report =
        block_on(system.drive(request.clone(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("first drive reports");
    assert_eq!(first_report.counts.succeeded, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    block_on(system.enqueue_raw(scoped_job(69, Timestamp::ZERO), Timestamp::ZERO))
        .expect("second enqueue commits");
    let second_report =
        block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("second drive reports");

    assert_eq!(second_report.counts.claimed, 1);
    assert_eq!(second_report.counts.succeeded, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn given_queue_only_drive_when_a_foreign_owner_candidate_exists_then_its_projection_is_unchanged() {
    let calls = Arc::new(AtomicUsize::new(0));
    let queue_a = QueueName::try_new("queue-a").expect("queue A is valid");
    let queue_b = QueueName::try_new("queue-b").expect("queue B is valid");
    let kind_a = JobKind::try_new("email-a").expect("kind A is valid");
    let kind_b = JobKind::try_new("email-b").expect("kind B is valid");
    let mut registry = HandlerRegistry::new();
    for (kind, queue) in [
        (kind_a.clone(), queue_a.clone()),
        (kind_b.clone(), queue_b.clone()),
    ] {
        registry
            .register(HandlerDefinition {
                kind,
                schema_version: NonZeroU16::MIN,
                queue,
                effect_mode: EffectMode::Idempotent,
                cost_units: NonZeroU16::MIN,
                fairness_policy: FairnessPolicy::from(NonZeroU16::MIN),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: std::time::Duration::from_secs(1),
                handler: RecordingHandler::new(Arc::clone(&calls)),
            })
            .expect("queue registration is valid");
    }
    let store = FakeStore::new();
    let system = JobSystem::new(
        store.clone(),
        JobCatalog::from_registry(registry),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([49; 16]),
        crate::test_helper::wake_scheduler(),
    );
    let fairness_a = crate::policy::FairnessClass::from(crate::policy::FairnessPath::new(
        crate::ids::FairnessKey::try_new(b"queue-a-scope").expect("scope A is valid"),
        None,
    ));
    let fairness_b = crate::policy::FairnessClass::from(crate::policy::FairnessPath::new(
        crate::ids::FairnessKey::try_new(b"queue-b-scope").expect("scope B is valid"),
        None,
    ));
    let metadata = |kind: &JobKind| crate::fairness::FairCandidateMetadata {
        handler_kind: kind.clone(),
        schema_version: NonZeroU16::MIN,
        batch_key: crate::batch::BatchKey::new(1),
        auth_config: crate::batch::AuthConfigId::new(1),
        effect_mode: EffectMode::Idempotent,
        retry_policy: crate::policy::RetryPolicy::preset(RetryPreset::Network),
        timeout: std::time::Duration::from_secs(1),
        enqueued_at: Timestamp::ZERO,
        batch_deadline: Timestamp::ZERO,
    };
    let id_a = JobId::from([81; 16]);
    let id_b = JobId::from([82; 16]);
    for (job_id, fairness, queue_kind) in [
        (id_a, fairness_a.clone(), kind_a.clone()),
        (id_b, fairness_b.clone(), kind_b.clone()),
    ] {
        block_on(crate::drive::fair_dispatch_configure(
            &system,
            crate::drive::FairDispatchCandidateSpec {
                job_id,
                payload: Bytes::from_static(b"payload"),
                fairness,
                volume_mode: crate::fairness::FairVolumeMode::Scoped,
                priority: Priority::Default,
                cost_units: NonZeroU16::MIN,
                scheduled_at: Timestamp::ZERO,
                ordering_key: None,
                ordering_position: 0,
                metadata: metadata(&queue_kind),
            },
            Timestamp::ZERO,
        ))
        .expect("candidate configuration commits");
    }
    let owner_before = block_on(crate::fairness::FairDispatchOwner::load(&system))
        .expect("owner reads")
        .expect("owner exists");
    let foreign_scope = crate::fairness::FairScope::from(&fairness_b);
    let foreign_candidate = owner_before.candidate_snapshot(id_b);
    let foreign_accounting = owner_before.ledger().scope_snapshot(&foreign_scope);
    let foreign_metadata = owner_before.metadata(id_b).cloned();
    let foreign_job_key =
        crate::keys::job_key(system.namespace(), &id_b).expect("job key is valid");
    let foreign_job = block_on(store.get(foreign_job_key.clone()))
        .expect("foreign job reads")
        .expect("foreign job exists");
    let foreign_due_key =
        crate::keys::due_key(system.namespace(), &queue_b, Timestamp::ZERO, &id_b)
            .expect("foreign due key is valid");
    let foreign_due = block_on(store.get(foreign_due_key.clone())).expect("foreign due reads");

    let report = block_on(system.drive(
        permissive_queue_request(queue_a, 1, 128),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("queue A drive reports");

    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let owner_after = block_on(crate::fairness::FairDispatchOwner::load(&system))
        .expect("owner reads after drive")
        .expect("owner remains present");
    assert_eq!(owner_after.candidate_snapshot(id_b), foreign_candidate);
    assert_eq!(
        owner_after.ledger().scope_snapshot(&foreign_scope),
        foreign_accounting
    );
    assert_eq!(owner_after.metadata(id_b).cloned(), foreign_metadata);
    assert_eq!(
        block_on(store.get(foreign_job_key)).expect("foreign job reads after drive"),
        Some(foreign_job)
    );
    assert_eq!(
        block_on(store.get(foreign_due_key)).expect("foreign due reads after drive"),
        foreign_due
    );
    assert_eq!(
        owner_after.candidate_state(id_b),
        Some(crate::fairness::FairCandidateState::Scheduled)
    );
}

fn paged_store() -> FakeStore {
    let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
        level: StoreLevel::Local,
        max_key_bytes: NonZeroUsize::new(4_096).expect("key limit is non-zero"),
        max_value_bytes: NonZeroUsize::new(1_048_576).expect("value limit is non-zero"),
        max_get_many_keys: NonZeroU32::new(1_024).expect("get-many limit is non-zero"),
        max_get_many_key_bytes: NonZeroUsize::new(2 * 1_048_576)
            .expect("get-many byte limit is non-zero"),
        max_transaction_bytes: NonZeroUsize::new(2 * 1_048_576)
            .expect("transaction limit is non-zero"),
        max_transaction_keys: NonZeroU32::new(128).expect("transaction keys are non-zero"),
        max_range_items: NonZeroU32::MIN,
        max_range_bytes: NonZeroUsize::new(4_096).expect("range limit is non-zero"),
        max_transaction_duration: std::time::Duration::from_secs(5),
    })
    .expect("paged capabilities are valid");
    FakeStore::with_capabilities(capabilities)
}

fn permissive_request(
    max_claims: u32,
    max_store_operations: u32,
    stop_claiming_at: MonotonicDeadline,
    finish_by: MonotonicDeadline,
) -> DriveRequest {
    permissive_request_with_concurrency(
        max_claims,
        max_store_operations,
        stop_claiming_at,
        finish_by,
        1,
    )
}

fn permissive_request_with_concurrency(
    max_claims: u32,
    max_store_operations: u32,
    stop_claiming_at: MonotonicDeadline,
    finish_by: MonotonicDeadline,
    max_concurrency: u16,
) -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(max_claims),
        max_concurrency: NonZeroU16::new(max_concurrency).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: NonZeroUsize::new(1024).expect("payload budget is non-zero"),
        max_completion_details: max_claims,
        max_store_operations: one(max_store_operations),
        stop_claiming_at,
        finish_by,
    })
    .expect("drive request is valid")
}

fn permissive_queue_request(
    queue: QueueName,
    max_claims: u32,
    max_store_operations: u32,
) -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::only(vec![queue]).expect("queue selection is valid"),
        max_claims: one(max_claims),
        max_concurrency: NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: NonZeroUsize::new(1024).expect("payload budget is non-zero"),
        max_completion_details: max_claims,
        max_store_operations: one(max_store_operations),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid")
}

fn system_with_handler<H: JobHandler>(
    store: FakeStore,
    fairness_policy: FairnessPolicy,
    handler: H,
) -> JobSystem<FakeStore> {
    system_with_handler_and_scheduler(
        store,
        fairness_policy,
        handler,
        crate::test_helper::wake_scheduler(),
    )
}

fn system_with_handler_and_profile<H: JobHandler>(
    store: FakeStore,
    fairness_policy: FairnessPolicy,
    handler: H,
) -> (
    JobSystem<FakeStore>,
    TestProfile,
    mpsc::Receiver<std::time::Duration>,
) {
    let profile = TestProfile::new();
    let (sleep_sender, sleep_receiver) = mpsc::channel();
    let system = system_with_handler_and_scheduler(
        store,
        fairness_policy,
        handler,
        Arc::new(RecordingScheduler {
            profile: profile.clone(),
            sleep_sender,
        }),
    );
    (system, profile, sleep_receiver)
}

struct RecordingScheduler {
    profile: TestProfile,
    sleep_sender: mpsc::Sender<std::time::Duration>,
}

impl WakeScheduler for RecordingScheduler {
    fn sleep(&self, delay: std::time::Duration) -> Result<WakeFuture, WakeSchedulerError> {
        let future = self.profile.sleep(delay)?;
        let _ = self.sleep_sender.send(delay);
        Ok(future)
    }
}

fn scoped_job(id: u8, scheduled_at: Timestamp) -> NewJob {
    scoped_job_with_primary(id, 1, scheduled_at)
}

fn scoped_job_with_primary(id: u8, primary: u8, scheduled_at: Timestamp) -> NewJob {
    job(
        id,
        Bytes::from_static(b"payload"),
        FairnessClass::from(FairnessPath::new(
            FairnessKey::try_new([primary]).expect("fairness key is valid"),
            None,
        )),
        scheduled_at,
        None,
        None,
    )
}

fn scoped_policy() -> FairnessPolicy {
    FairnessPolicy::from(NonZeroU16::MIN)
}

fn system_with_handler_and_scheduler<H: JobHandler>(
    store: FakeStore,
    fairness_policy: FairnessPolicy,
    handler: H,
    scheduler: Arc<dyn WakeScheduler>,
) -> JobSystem<FakeStore> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(registry_with_handler(fairness_policy, handler)),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([41; 16]),
        scheduler,
    )
}

fn system_with_barrier_handler<H: JobHandler>(
    store: ReservationBarrierStore,
    fairness_policy: FairnessPolicy,
    handler: H,
    owner: u8,
) -> JobSystem<ReservationBarrierStore> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(registry_with_handler(fairness_policy, handler)),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([owner; 16]),
        crate::test_helper::wake_scheduler(),
    )
}

fn registry_with_handler<H: JobHandler>(
    fairness_policy: FairnessPolicy,
    handler: H,
) -> HandlerRegistry {
    let mut registry = HandlerRegistry::new();
    registry
        .register(HandlerDefinition {
            kind: JobKind::try_new("email").expect("test kind is valid"),
            schema_version: NonZeroU16::new(1).expect("schema is non-zero"),
            queue: QueueName::try_new("default").expect("test queue is valid"),
            effect_mode: EffectMode::Idempotent,
            cost_units: NonZeroU16::new(1).expect("cost is non-zero"),
            fairness_policy,
            default_retry: RetrySelection::Preset(RetryPreset::Interactive),
            default_timeout: std::time::Duration::from_secs(1),
            handler,
        })
        .expect("test registration is valid");
    registry
}

fn counting_system(store: CountingStore) -> JobSystem<CountingStore> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(default_registry(FairnessPolicy::low_volume())),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([42; 16]),
        crate::test_helper::wake_scheduler(),
    )
}

fn counting_scoped_system(store: CountingStore) -> JobSystem<CountingStore> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(default_registry(FairnessPolicy::from(
            NonZeroU16::new(1).expect("scope weight is non-zero"),
        ))),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([42; 16]),
        crate::test_helper::wake_scheduler(),
    )
}

struct RecordingHandler {
    calls: Arc<AtomicUsize>,
}

impl RecordingHandler {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self { calls }
    }
}

impl JobHandler for RecordingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(complete_outcome()) })
    }
}

struct ContinuingHandler {
    calls: Arc<AtomicUsize>,
}

impl ContinuingHandler {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self { calls }
    }
}

impl JobHandler for ContinuingHandler {
    fn execute<'a>(
        &'a self,
        context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(JobOutcome::Continue {
                not_before: context
                    .wall_now()
                    .checked_add(std::time::Duration::from_millis(1))
                    .expect("continuation timestamp remains representable"),
                checkpoint: Bytes::from_static(b"checkpoint"),
            })
        })
    }
}

struct PanicThenCompleteHandler {
    calls: Arc<AtomicUsize>,
}

struct PendingThenCompleteHandler {
    calls: Arc<AtomicUsize>,
    started: mpsc::Sender<()>,
}

impl PendingThenCompleteHandler {
    fn new(calls: Arc<AtomicUsize>, started: mpsc::Sender<()>) -> Self {
        Self { calls, started }
    }
}

impl JobHandler for PendingThenCompleteHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            let _ = self.started.send(());
            Box::pin(std::future::pending())
        } else {
            Box::pin(async { Ok(complete_outcome()) })
        }
    }
}

#[derive(Clone)]
struct ReservationBarrierStore {
    inner: FakeStore,
    fair_state_key: StoreKey,
    reservation_barrier: Arc<Barrier>,
    reservation_commits: Arc<AtomicUsize>,
    owner_reads: Arc<AtomicUsize>,
}

impl ReservationBarrierStore {
    fn new(inner: FakeStore, fair_state_key: StoreKey) -> Self {
        Self {
            inner,
            fair_state_key,
            reservation_barrier: Arc::new(Barrier::new(2)),
            reservation_commits: Arc::new(AtomicUsize::new(0)),
            owner_reads: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn reservation_commits(&self) -> usize {
        self.reservation_commits.load(Ordering::SeqCst)
    }

    fn owner_reads(&self) -> usize {
        self.owner_reads.load(Ordering::SeqCst)
    }
}

impl JobStore for ReservationBarrierStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        if key == self.fair_state_key {
            self.owner_reads.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.get(key).await
    }

    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.inner.get_many(keys).await
    }

    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.inner.read_range(request).await
    }

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        let is_reservation = transaction
            .mutations()
            .iter()
            .any(|mutation| mutation.key() == &self.fair_state_key);
        if is_reservation {
            self.reservation_commits.fetch_add(1, Ordering::SeqCst);
            self.reservation_barrier.wait();
        }
        self.inner.commit(transaction).await
    }
}

impl PanicThenCompleteHandler {
    fn new(calls: Arc<AtomicUsize>) -> Self {
        Self { calls }
    }
}

impl JobHandler for PanicThenCompleteHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("test handler panic");
        }
        Box::pin(async { Ok(complete_outcome()) })
    }
}

#[derive(Clone)]
struct CountingStore {
    inner: FakeStore,
    calls: Arc<AtomicU32>,
}

impl CountingStore {
    fn new() -> Self {
        Self::with_store(FakeStore::new())
    }

    fn with_get_many_limit(limit: u32) -> Self {
        let defaults = FakeStore::local().capabilities();
        let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
            level: defaults.level(),
            max_key_bytes: defaults.max_key_bytes(),
            max_value_bytes: defaults.max_value_bytes(),
            max_get_many_keys: NonZeroU32::new(limit).expect("test limit is non-zero"),
            max_get_many_key_bytes: defaults.max_get_many_key_bytes(),
            max_transaction_bytes: defaults.max_transaction_bytes(),
            max_transaction_keys: defaults.max_transaction_keys(),
            max_range_items: defaults.max_range_items(),
            max_range_bytes: defaults.max_range_bytes(),
            max_transaction_duration: defaults.max_transaction_duration(),
        })
        .expect("test capabilities are valid");
        Self::with_store(FakeStore::with_capabilities(capabilities))
    }

    fn with_store(inner: FakeStore) -> Self {
        Self {
            inner,
            calls: Arc::new(AtomicU32::new(0)),
        }
    }

    fn reset(&self) {
        self.calls.store(0, Ordering::SeqCst);
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }

    fn count_call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }

    fn queue_commit_outcome(&self, outcome: CommitOutcome) -> Result<(), FakeStoreError> {
        self.inner.queue_commit_outcome(outcome)
    }
}

impl JobStore for CountingStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.count_call();
        self.inner.get(key).await
    }

    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.count_call();
        self.inner.get_many(keys).await
    }

    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.count_call();
        self.inner.read_range(request).await
    }

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        self.count_call();
        self.inner.commit(transaction).await
    }
}

#[derive(Clone)]
struct RangeLimitStore {
    inner: FakeStore,
    calls: Arc<AtomicUsize>,
    ranges: Arc<Mutex<Vec<(u32, usize)>>>,
    get_many_batches: Arc<Mutex<Vec<usize>>>,
    get_many_bytes: Arc<Mutex<Vec<usize>>>,
}

impl RangeLimitStore {
    fn new() -> Self {
        let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
            level: StoreLevel::Local,
            max_key_bytes: NonZeroUsize::new(4_096).expect("key limit is non-zero"),
            max_value_bytes: NonZeroUsize::new(1_048_576).expect("value limit is non-zero"),
            max_get_many_keys: NonZeroU32::new(1_024).expect("get-many limit is non-zero"),
            max_get_many_key_bytes: NonZeroUsize::new(2 * 1_048_576)
                .expect("get-many byte limit is non-zero"),
            max_transaction_bytes: NonZeroUsize::new(2 * 1_048_576)
                .expect("transaction limit is non-zero"),
            max_transaction_keys: NonZeroU32::new(128).expect("transaction keys are non-zero"),
            max_range_items: NonZeroU32::new(u32::MAX).expect("range items are non-zero"),
            max_range_bytes: NonZeroUsize::new(usize::MAX).expect("range bytes are non-zero"),
            max_transaction_duration: std::time::Duration::from_secs(5),
        })
        .expect("machine-sized capabilities are valid");
        Self {
            inner: FakeStore::with_capabilities(capabilities),
            calls: Arc::new(AtomicUsize::new(0)),
            ranges: Arc::new(Mutex::new(Vec::new())),
            get_many_batches: Arc::new(Mutex::new(Vec::new())),
            get_many_bytes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn ranges(&self) -> Vec<(u32, usize)> {
        self.ranges.lock().expect("range log is healthy").clone()
    }

    fn get_many_batches(&self) -> Vec<usize> {
        self.get_many_batches
            .lock()
            .expect("get_many log is healthy")
            .clone()
    }

    fn get_many_bytes(&self) -> Vec<usize> {
        self.get_many_bytes
            .lock()
            .expect("get_many byte log is healthy")
            .clone()
    }

    fn replace_job_values_with_max(
        &self,
        namespace: &Namespace,
        ids: impl IntoIterator<Item = u8>,
    ) {
        let value = Bytes::from(vec![0; self.inner.capabilities().max_value_bytes().get()]);
        for id in ids {
            let key =
                crate::keys::job_key(namespace, &JobId::from([id; 16])).expect("job key is valid");
            self.inner
                .put_raw(key, value.clone())
                .expect("maximum record value is accepted");
        }
    }

    fn reset_logs(&self) {
        self.calls.store(0, Ordering::SeqCst);
        self.ranges.lock().expect("range log is healthy").clear();
        self.get_many_batches
            .lock()
            .expect("get_many log is healthy")
            .clear();
        self.get_many_bytes
            .lock()
            .expect("get_many byte log is healthy")
            .clear();
    }

    fn count_call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl JobStore for RangeLimitStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.count_call();
        self.inner.get(key).await
    }

    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        self.count_call();
        self.get_many_batches
            .lock()
            .expect("get_many log is healthy")
            .push(keys.len());
        let values = self.inner.get_many(keys).await?;
        let bytes = keys
            .iter()
            .zip(&values)
            .map(|(key, value)| key.as_bytes().len() + value.as_ref().map_or(0, Bytes::len))
            .sum();
        self.get_many_bytes
            .lock()
            .expect("get_many byte log is healthy")
            .push(bytes);
        Ok(values)
    }

    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.count_call();
        self.ranges
            .lock()
            .expect("range log is healthy")
            .push((request.item_limit().get(), request.byte_limit().get()));
        self.inner.read_range(request).await
    }

    async fn commit(&self, transaction: &StoreTransaction) -> Result<CommitOutcome, Self::Error> {
        self.count_call();
        self.inner.commit(transaction).await
    }
}

fn range_limit_system(store: RangeLimitStore) -> JobSystem<RangeLimitStore> {
    JobSystem::new(
        store,
        JobCatalog::from_registry(default_registry(FairnessPolicy::low_volume())),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([48; 16]),
        crate::test_helper::wake_scheduler(),
    )
}
