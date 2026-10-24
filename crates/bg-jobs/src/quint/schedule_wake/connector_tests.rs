use std::num::{NonZeroU16, NonZeroU32, NonZeroUsize};

use bytes::Bytes;

use crate::{
    ActivePulseRequest, Cadence, DriveRequest, DriveRequestInput, FairnessClass, FairnessPolicy,
    FakeStore, JobKind, JobSystem, JobTemplate, JobTemplateInput, MonotonicDeadline,
    QueueSelection, RecurringSchedule, RecurringScheduleInput, ScheduleControl,
    ScheduleControlResult, ScheduleCursor, ScheduleId, Timestamp, WakeCandidates, WakeHint,
    WakeWatermark, test_helper::block_on,
};

fn system() -> JobSystem<FakeStore> {
    crate::test_helper::system(FakeStore::distributed(), FairnessPolicy::low_volume(), 11)
}

fn schedule(enabled: bool) -> RecurringSchedule {
    RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([42; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("email").expect("kind is valid"),
            schema_version: NonZeroU16::MIN,
            payload: Bytes::from_static(b"connector"),
            fairness: FairnessClass::low_volume(),
            ordering_key: None,
            priority: crate::Priority::Default,
            expires_after: None,
            retry_override: None,
            deduplication: None,
        })
        .expect("template is valid"),
        cadence: Cadence::CronUtc(
            crate::CronExpression::try_new("*/5 * * * *").expect("cron is portable"),
        ),
        misfire: crate::MisfirePolicy::FireOnce,
        overlap: crate::OverlapPolicy::Allow,
        enabled,
    })
}

#[test]
fn given_public_schedule_and_wake_boundaries_when_driven_then_real_state_remains_bounded() {
    let system = system();
    let schedule = schedule(false);
    let cursor = schedule
        .cursor_after(Timestamp::ZERO)
        .expect("cursor is valid");
    let materialized = block_on(system.materialize_schedule(
        &schedule,
        &cursor,
        Timestamp::from_millis(5 * 60 * 1_000),
    ))
    .expect("materialization boundary succeeds");
    assert!(materialized.occurrences.is_empty());
    assert_eq!(materialized.next_wake, WakeHint::None);

    let mut controlled = ScheduleCursor::new(cursor.next_due(), cursor.is_enabled());
    assert_eq!(
        controlled.apply_control(1, 0, ScheduleControl::Pause),
        ScheduleControlResult::Conflict {
            revision: 0,
            generation: 0
        }
    );
    assert_eq!(
        controlled.apply_control(0, 0, ScheduleControl::Pause),
        ScheduleControlResult::Applied {
            revision: 1,
            generation: 1
        }
    );

    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: NonZeroU32::MIN,
        max_concurrency: NonZeroU16::MIN,
        max_payload_bytes_in_flight: NonZeroUsize::new(1024).expect("bytes are non-zero"),
        max_completion_details: 1,
        max_store_operations: NonZeroU32::new(64).expect("budget is non-zero"),
        stop_claiming_at: MonotonicDeadline::ZERO,
        finish_by: MonotonicDeadline::from_nanos(1),
    })
    .expect("drive request is valid");
    let report = block_on(system.drive(request, Timestamp::ZERO, || {
        MonotonicDeadline::from_nanos(1)
    }))
    .expect("drive boundary succeeds");
    assert_eq!(report.counts.claimed, 0);

    let mut watermark = WakeWatermark::new();
    assert!(watermark.lower(Timestamp::from_millis(50)));
    let merged = WakeCandidates {
        watermarks: vec![watermark.hint()],
        due_heads: vec![WakeHint::At(Timestamp::from_millis(25))],
        schedule_heads: vec![materialized.next_wake],
    };
    assert_eq!(
        merged.merge(NonZeroU32::new(2).expect("merge limit is non-zero")),
        WakeHint::At(Timestamp::from_millis(25))
    );

    let pulse = block_on(
        ActivePulseRequest::new(NonZeroU16::MIN, MonotonicDeadline::from_nanos(u64::MAX)).drive(
            || MonotonicDeadline::from_nanos(u64::MAX),
            || async { Ok::<_, crate::FakeStoreError>(report.clone()) },
        ),
    )
    .expect("active pulse boundary succeeds");
    assert_eq!(pulse.drives.len(), 0);
}
