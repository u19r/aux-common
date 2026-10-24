use crate::*;

fn schedule(overlap: OverlapPolicy, enabled: bool) -> RecurringSchedule {
    RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([8; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("email").expect("kind is valid"),
            schema_version: std::num::NonZeroU16::new(1).expect("schema is non-zero"),
            payload: bytes::Bytes::from_static(b"scheduled"),
            fairness: FairnessClass::low_volume(),
            ordering_key: None,
            priority: Priority::Default,
            expires_after: None,
            retry_override: None,
            deduplication: None,
        })
        .expect("template is valid"),
        cadence: Cadence::CronUtc(
            CronExpression::try_new("0 * * * *").expect("hourly cron parses"),
        ),
        misfire: MisfirePolicy::FireOnce,
        overlap,
        enabled,
    })
}

#[test]
fn given_forbid_overlap_when_a_slow_occurrence_is_active_then_evaluation_is_blocked_until_completion()
 {
    let schedule = schedule(OverlapPolicy::Forbid, true);
    let mut cursor = ScheduleCursor::new(Some(Timestamp::ZERO), true);
    assert!(cursor.mark_started(cursor.generation(), cursor.revision()));

    let blocked = schedule
        .evaluate(&cursor, Timestamp::from_millis(60 * 60 * 1_000))
        .expect("blocked evaluation succeeds");
    assert!(blocked.blocked_by_overlap);
    assert!(blocked.occurrences.is_empty());
    assert_eq!(blocked.wake, WakeHint::None);

    assert!(cursor.mark_completed(cursor.generation(), cursor.revision()));
    let available = schedule
        .evaluate(&cursor, Timestamp::from_millis(60 * 60 * 1_000))
        .expect("post-completion evaluation succeeds");
    assert_eq!(available.occurrences.len(), 1);
}

#[test]
fn given_allow_overlap_when_a_slow_occurrence_is_active_then_a_new_occurrence_can_be_evaluated() {
    let schedule = schedule(OverlapPolicy::Allow, true);
    let mut cursor = ScheduleCursor::new(Some(Timestamp::ZERO), true);
    assert!(cursor.mark_started(cursor.generation(), cursor.revision()));

    let evaluation = schedule
        .evaluate(&cursor, Timestamp::from_millis(60 * 60 * 1_000))
        .expect("allow evaluation succeeds");
    assert_eq!(evaluation.occurrences.len(), 1);
}

#[test]
fn given_pause_resume_generation_race_when_a_stale_worker_completes_then_only_the_current_generation_changes_state()
 {
    let mut cursor = ScheduleCursor::new(Some(Timestamp::ZERO), true);
    let initial_generation = cursor.generation();
    let initial_revision = cursor.revision();
    assert!(cursor.mark_started(initial_generation, initial_revision));
    let started_revision = cursor.revision();

    assert_eq!(
        cursor.apply_control(started_revision, initial_generation, ScheduleControl::Pause),
        ScheduleControlResult::Applied {
            revision: started_revision + 1,
            generation: initial_generation + 1,
        }
    );
    assert!(cursor.is_paused());
    assert!(!cursor.is_active());
    assert!(!cursor.mark_completed(initial_generation, started_revision));

    let paused_revision = cursor.revision();
    let resumed = cursor.apply_control(
        paused_revision,
        cursor.generation(),
        ScheduleControl::Resume,
    );
    assert_eq!(
        resumed,
        ScheduleControlResult::Applied {
            revision: paused_revision + 1,
            generation: initial_generation + 2,
        }
    );
    assert!(!cursor.is_paused());
    assert!(!cursor.mark_started(initial_generation, started_revision));
    assert!(cursor.mark_started(cursor.generation(), cursor.revision()));
}

#[test]
fn given_a_disabled_schedule_when_evaluating_then_no_occurrence_or_wake_is_advertised() {
    let schedule = schedule(OverlapPolicy::Allow, false);
    let cursor = schedule
        .cursor_after(Timestamp::ZERO)
        .expect("disabled schedule creates a cursor");

    let evaluation = schedule
        .evaluate(&cursor, Timestamp::from_millis(60 * 60 * 1_000))
        .expect("disabled evaluation succeeds");
    assert!(evaluation.occurrences.is_empty());
    assert_eq!(evaluation.wake, WakeHint::None);
}

#[test]
fn given_a_disabled_definition_when_a_cursor_is_created_then_the_cursor_starts_disabled() {
    let disabled = schedule(OverlapPolicy::Allow, false);
    let enabled = schedule(OverlapPolicy::Allow, true);

    assert!(
        !disabled
            .cursor_after(Timestamp::ZERO)
            .expect("disabled schedule creates a cursor")
            .is_enabled()
    );
    assert!(
        enabled
            .cursor_after(Timestamp::ZERO)
            .expect("enabled schedule creates a cursor")
            .is_enabled()
    );
}

#[test]
fn given_a_cursor_enabled_by_its_durable_state_when_the_definition_is_disabled_then_cursor_controls_evaluation()
 {
    let schedule = schedule(OverlapPolicy::Allow, false);
    let cursor = ScheduleCursor::new(Some(Timestamp::ZERO), true);

    let evaluation = schedule
        .evaluate(&cursor, Timestamp::from_millis(60 * 60 * 1_000))
        .expect("cursor-enabled evaluation succeeds");
    assert_eq!(evaluation.occurrences.len(), 1);
}
