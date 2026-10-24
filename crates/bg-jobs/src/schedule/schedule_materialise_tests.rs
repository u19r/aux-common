use std::{collections::BTreeSet, num::NonZeroU16};

use bytes::Bytes;

use crate::{
    test_helper::{block_on, system},
    *,
};

fn schedule(misfire: MisfirePolicy, overlap: OverlapPolicy) -> RecurringSchedule {
    RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([7; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("email").expect("kind is valid"),
            schema_version: NonZeroU16::new(1).expect("schema is non-zero"),
            payload: Bytes::from_static(b"scheduled"),
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
        misfire,
        overlap,
        enabled: true,
    })
}

fn cursor() -> ScheduleCursor {
    ScheduleCursor::new(Some(Timestamp::ZERO), true)
}

#[test]
fn given_two_nodes_materialising_the_same_occurrence_when_the_store_is_shared_then_identity_is_stable_and_one_enqueue_wins()
 {
    let store = FakeStore::distributed();
    let first = system(store.clone(), FairnessPolicy::low_volume(), 1);
    let second = system(store, FairnessPolicy::low_volume(), 2);
    let schedule = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow);
    let initial = cursor();
    let now = Timestamp::from_millis(3 * 60 * 60 * 1_000);

    let first_result = block_on(first.materialize_schedule(&schedule, &initial, now))
        .expect("first materialisation succeeds");
    let second_result = block_on(second.materialize_schedule(&schedule, &initial, now))
        .expect("second materialisation reconciles");

    assert_eq!(first_result.occurrences.len(), 1);
    assert_eq!(second_result.occurrences.len(), 1);
    assert_eq!(
        first_result.occurrences[0].occurrence.occurrence_id(),
        second_result.occurrences[0].occurrence.occurrence_id()
    );
    assert_ne!(
        first_result.occurrences[0].enqueue.disposition,
        second_result.occurrences[0].enqueue.disposition
    );
    assert!(
        [
            first_result.occurrences[0].enqueue.disposition,
            second_result.occurrences[0].enqueue.disposition,
        ]
        .contains(&EnqueueDisposition::Enqueued)
    );
    assert!(
        [
            first_result.occurrences[0].enqueue.disposition,
            second_result.occurrences[0].enqueue.disposition,
        ]
        .contains(&EnqueueDisposition::AlreadyPresent)
    );
}

#[test]
fn given_a_long_downtime_when_each_misfire_policy_is_evaluated_then_emission_is_exact_and_bounded()
{
    let now = Timestamp::from_millis(5 * 60 * 60 * 1_000);
    let skip = schedule(MisfirePolicy::Skip, OverlapPolicy::Allow)
        .evaluate(&cursor(), now)
        .expect("skip evaluates");
    let fire_once = schedule(MisfirePolicy::FireOnce, OverlapPolicy::Allow)
        .evaluate(&cursor(), now)
        .expect("fire-once evaluates");
    let catch_up = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(2).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    )
    .evaluate(&cursor(), now)
    .expect("catch-up evaluates");

    assert!(skip.occurrences.is_empty());
    assert_eq!(skip.skipped, 6);
    assert_eq!(
        skip.cursor.next_due(),
        Some(Timestamp::from_millis(6 * 60 * 60 * 1_000))
    );

    assert_eq!(fire_once.occurrences.len(), 1);
    assert_eq!(fire_once.skipped, 5);
    assert_eq!(
        fire_once.occurrences[0].intended_at,
        Timestamp::from_millis(5 * 60 * 60 * 1_000)
    );
    assert_eq!(
        fire_once.cursor.watermark(),
        Some(fire_once.occurrences[0].intended_at)
    );

    assert_eq!(catch_up.occurrences.len(), 2);
    assert_eq!(catch_up.skipped, 4);
    assert_eq!(
        catch_up.cursor.watermark(),
        Some(Timestamp::from_millis(60 * 60 * 1_000))
    );
    assert!(catch_up.cursor.next_due().is_some_and(|next| next > now));
}

#[test]
fn given_repeated_evaluation_after_the_cursor_advanced_when_no_new_time_is_due_then_it_does_not_reemit()
 {
    let schedule = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(2).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    );
    let now = Timestamp::from_millis(2 * 60 * 60 * 1_000);
    let first = schedule
        .evaluate(&cursor(), now)
        .expect("first evaluation succeeds");
    let second = schedule
        .evaluate(&first.cursor, now)
        .expect("second evaluation succeeds");

    assert_eq!(first.occurrences.len(), 2);
    assert!(second.occurrences.is_empty());
    assert_eq!(second.skipped, 0);
}

#[test]
fn given_a_large_catch_up_backlog_when_materialization_budget_is_small_then_the_cursor_resumes() {
    let schedule = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(u16::MAX).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    );
    let initial = cursor();
    let now = Timestamp::from_millis(10 * 60 * 60 * 1_000);
    let budget = ScheduleMaterializationBudget::try_new(
        3,
        12,
        crate::MonotonicDeadline::from_nanos(u64::MAX),
    )
    .expect("materialization budget is valid");
    let system = crate::test_helper::system(
        crate::FakeStore::distributed(),
        crate::FairnessPolicy::low_volume(),
        17,
    );

    let first = crate::test_helper::block_on(system.materialize_schedule_with_budget(
        &schedule,
        &initial,
        now,
        budget,
        || crate::MonotonicDeadline::from_nanos(u64::MAX - 1),
    ))
    .expect("first bounded materialization succeeds");

    assert_eq!(first.occurrences.len(), 3);
    assert_eq!(first.skipped, 0);
    assert!(first.cursor.next_due().is_some_and(|next| next <= now));
    assert_eq!(first.next_wake, WakeHint::Now);

    let second = crate::test_helper::block_on(system.materialize_schedule_with_budget(
        &schedule,
        &first.cursor,
        now,
        budget,
        || crate::MonotonicDeadline::from_nanos(u64::MAX - 1),
    ))
    .expect("second bounded materialization succeeds");

    assert_eq!(second.occurrences.len(), 3);
    assert_eq!(second.skipped, 0);
    assert_ne!(
        first.occurrences[0].occurrence.occurrence_id(),
        second.occurrences[0].occurrence.occurrence_id()
    );

    let mut seen = first
        .occurrences
        .iter()
        .chain(second.occurrences.iter())
        .map(|entry| entry.occurrence.occurrence_id())
        .collect::<BTreeSet<_>>();
    let mut cursor = second.cursor;
    let mut total = 6;
    let mut complete = second.complete;
    for _ in 0..4 {
        if complete {
            break;
        }
        let next = crate::test_helper::block_on(system.materialize_schedule_with_budget(
            &schedule,
            &cursor,
            now,
            budget,
            || crate::MonotonicDeadline::from_nanos(u64::MAX - 1),
        ))
        .expect("continuation materialization succeeds");
        for occurrence in &next.occurrences {
            assert!(seen.insert(occurrence.occurrence.occurrence_id()));
        }
        total += next.occurrences.len();
        cursor = next.cursor;
        complete = next.complete;
    }
    assert!(complete, "the resumable cursor must eventually complete");
    assert_eq!(total, 11);
    assert_eq!(
        seen.len(),
        11,
        "continuations must not duplicate identities"
    );
}

#[test]
fn given_a_materialization_operation_budget_below_one_enqueue_then_no_occurrence_is_emitted() {
    let system = system(FakeStore::distributed(), FairnessPolicy::low_volume(), 18);
    let schedule = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(3).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    );
    let initial = cursor();
    let budget =
        ScheduleMaterializationBudget::try_new(3, 3, MonotonicDeadline::from_nanos(u64::MAX))
            .expect("materialization budget is valid");

    let result = block_on(system.materialize_schedule_with_budget(
        &schedule,
        &initial,
        Timestamp::from_millis(3 * 60 * 60 * 1_000),
        budget,
        || MonotonicDeadline::from_nanos(u64::MAX - 1),
    ))
    .expect("empty bounded materialization succeeds");

    assert!(result.occurrences.is_empty());
    assert_eq!(result.cursor, initial);
    assert!(!result.complete);
    assert_eq!(result.next_wake, WakeHint::Now);
}

#[test]
fn given_a_materialization_deadline_between_occurrences_then_the_cursor_remains_resumable() {
    let system = system(FakeStore::distributed(), FairnessPolicy::low_volume(), 19);
    let schedule = schedule(
        MisfirePolicy::CatchUp {
            maximum_occurrences: NonZeroU16::new(3).expect("catch-up limit is non-zero"),
        },
        OverlapPolicy::Allow,
    );
    let initial = cursor();
    let budget = ScheduleMaterializationBudget::try_new(3, 12, MonotonicDeadline::from_nanos(5))
        .expect("materialization budget is valid");
    let mut clock = [MonotonicDeadline::ZERO, MonotonicDeadline::from_nanos(5)].into_iter();

    let result = block_on(system.materialize_schedule_with_budget(
        &schedule,
        &initial,
        Timestamp::from_millis(3 * 60 * 60 * 1_000),
        budget,
        || clock.next().unwrap_or(MonotonicDeadline::from_nanos(5)),
    ))
    .expect("deadline-bounded materialization succeeds");

    assert_eq!(result.occurrences.len(), 1);
    assert!(!result.complete);
    assert_eq!(result.next_wake, WakeHint::Now);
    assert_eq!(
        result.cursor.watermark(),
        Some(result.occurrences[0].occurrence.intended_at)
    );
    assert!(
        result
            .cursor
            .next_due()
            .is_some_and(|next| next > result.occurrences[0].occurrence.intended_at)
    );
}
