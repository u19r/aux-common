use std::{
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::{
    budget::{DriveRequestInput, QueueSelection},
    test_helper::{block_on, low_volume_job, one, system},
    *,
};

fn report(next_wake: WakeHint, has_work: bool) -> DriveReport {
    DriveReport {
        counts: DriveCounts::default(),
        completions: Vec::new(),
        completions_omitted: 0,
        has_immediately_visible_work: has_work,
        next_wake,
        stop_reason: DriveStopReason::NoVisibleWork,
    }
}

fn request(max_pulses: u16, stop_by: u64) -> ActivePulseRequest {
    ActivePulseRequest::new(
        NonZeroU16::new(max_pulses).expect("pulse budget is non-zero"),
        MonotonicDeadline::from_nanos(stop_by),
    )
}

#[test]
fn given_now_reports_with_immediate_work_when_driving_a_pulse_then_it_yields_between_drives_and_exits_on_future_work()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let pulse = crate::test_helper::block_on(request(5, 100).drive(
        || MonotonicDeadline::from_nanos(0),
        move || {
            let call = observed.fetch_add(1, Ordering::SeqCst);
            async move {
                Ok::<_, ()>(if call < 2 {
                    report(WakeHint::Now, true)
                } else {
                    report(WakeHint::At(Timestamp::from_millis(60)), false)
                })
            }
        },
    ))
    .expect("active pulse succeeds");

    assert_eq!(pulse.drives.len(), 3);
    assert_eq!(pulse.stop_reason, ActivePulseStopReason::NoImmediateWork);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[test]
fn given_none_or_future_wake_reports_when_driving_a_pulse_then_the_first_report_ends_the_pulse() {
    for next_wake in [WakeHint::None, WakeHint::At(Timestamp::from_millis(1))] {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let pulse = crate::test_helper::block_on(request(5, 100).drive(
            || MonotonicDeadline::from_nanos(0),
            move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async move { Ok::<_, ()>(report(next_wake, false)) }
            },
        ))
        .expect("active pulse succeeds");

        assert_eq!(pulse.drives.len(), 1);
        assert_eq!(pulse.stop_reason, ActivePulseStopReason::NoImmediateWork);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn given_a_pulse_cap_when_every_report_is_immediate_then_no_more_than_the_cap_is_driven() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let pulse = crate::test_helper::block_on(request(2, 100).drive(
        || MonotonicDeadline::from_nanos(0),
        move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, ()>(report(WakeHint::Now, true)) }
        },
    ))
    .expect("active pulse succeeds");

    assert_eq!(pulse.drives.len(), 2);
    assert_eq!(pulse.stop_reason, ActivePulseStopReason::MaxPulses);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn given_a_deadline_reached_before_the_next_drive_when_driving_a_pulse_then_no_new_drive_starts() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let pulse = crate::test_helper::block_on(request(5, 5).drive(
        || MonotonicDeadline::from_nanos(5),
        move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, ()>(report(WakeHint::Now, true)) }
        },
    ))
    .expect("active pulse succeeds");

    assert!(pulse.drives.is_empty());
    assert_eq!(pulse.stop_reason, ActivePulseStopReason::Deadline);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn given_a_due_job_when_the_claim_deadline_is_reached_then_drive_does_not_claim_past_it() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 7);
    let job_id = JobId::from([7; 16]);
    block_on(system.enqueue_raw(low_volume_job(7, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(1),
        max_concurrency: NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024)
            .expect("payload budget is non-zero"),
        max_completion_details: 1,
        max_store_operations: one(64),
        stop_claiming_at: MonotonicDeadline::ZERO,
        finish_by: MonotonicDeadline::from_nanos(1),
    })
    .expect("drive request is valid");

    let report = block_on(system.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("drive reports");

    assert_eq!(report.stop_reason, DriveStopReason::Deadline);
    assert_eq!(report.counts.claimed, 0);
    assert!(block_on(system.claim(job_id, Timestamp::ZERO)).is_ok());
}
