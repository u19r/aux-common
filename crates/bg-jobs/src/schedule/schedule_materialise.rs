//! Bounded schedule occurrence materialisation.

use super::{
    RecurringSchedule, ScheduleCursor, ScheduleEvaluation, ScheduleMaterializationBudget,
    ScheduleOccurrence, constants::ENQUEUE_WORST_CASE_STORE_OPERATIONS,
};
use crate::{
    engine::JobSystem,
    error::{JobResult, ValidationError},
    model::EnqueueResult,
    store::JobStore,
    time::{MonotonicDeadline, Timestamp, WakeHint},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedOccurrence {
    pub occurrence: ScheduleOccurrence,
    pub enqueue: EnqueueResult,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleMaterialization {
    pub occurrences: Vec<MaterializedOccurrence>,
    pub skipped: u32,
    pub next_wake: WakeHint,
    pub cursor: ScheduleCursor,
    /// Whether the returned cursor has passed every occurrence due at `now`.
    /// `false` means a later call should resume from the cursor.
    pub complete: bool,
}

pub(crate) async fn materialize<S: JobStore, C: FnMut() -> MonotonicDeadline>(
    system: &JobSystem<S>,
    schedule: &RecurringSchedule,
    cursor: &ScheduleCursor,
    now: Timestamp,
    budget: ScheduleMaterializationBudget,
    mut monotonic_now: C,
) -> JobResult<ScheduleMaterialization, S::Error> {
    let Some(item_limit) = materialization_item_limit(budget)? else {
        return Ok(ScheduleMaterialization {
            occurrences: Vec::new(),
            skipped: 0,
            next_wake: WakeHint::Now,
            cursor: cursor.clone(),
            complete: false,
        });
    };
    let evaluation = schedule.evaluate_for_materialization(cursor, now, item_limit)?;
    materialize_occurrences(
        system,
        schedule,
        cursor,
        now,
        budget,
        evaluation,
        &mut monotonic_now,
    )
    .await
}

fn materialization_item_limit(
    budget: ScheduleMaterializationBudget,
) -> Result<Option<u32>, ValidationError> {
    let item_limit =
        usize::try_from(budget.max_occurrences()).map_err(|_| ValidationError::Overflow {
            field: "schedule materialization occurrences",
        })?;
    let operation_limit =
        usize::try_from(budget.max_store_operations()).map_err(|_| ValidationError::Overflow {
            field: "schedule materialization store operations",
        })?;
    let item_limit = item_limit.min(operation_limit / ENQUEUE_WORST_CASE_STORE_OPERATIONS);
    if item_limit == 0 {
        return Ok(None);
    }
    u32::try_from(item_limit)
        .map(Some)
        .map_err(|_| ValidationError::Overflow {
            field: "schedule materialization occurrences",
        })
}

async fn materialize_occurrences<S: JobStore, C: FnMut() -> MonotonicDeadline>(
    system: &JobSystem<S>,
    schedule: &RecurringSchedule,
    cursor: &ScheduleCursor,
    now: Timestamp,
    budget: ScheduleMaterializationBudget,
    evaluation: ScheduleEvaluation,
    monotonic_now: &mut C,
) -> JobResult<ScheduleMaterialization, S::Error> {
    let mut materialized: Vec<MaterializedOccurrence> =
        Vec::with_capacity(evaluation.occurrences.len());
    for occurrence in &evaluation.occurrences {
        if budget.finish_by().is_at_or_before(monotonic_now()) {
            return Ok(resume_materialization(
                schedule,
                cursor,
                &evaluation,
                materialized,
            )?);
        }
        let enqueue = system
            .enqueue_impl(
                schedule
                    .job_template
                    .occurrence_job(occurrence, schedule.overlap)?,
                now,
            )
            .await?;
        materialized.push(MaterializedOccurrence {
            occurrence: *occurrence,
            enqueue,
        });
    }
    Ok(ScheduleMaterialization {
        occurrences: materialized,
        skipped: evaluation.skipped,
        next_wake: evaluation.wake,
        cursor: evaluation.cursor,
        complete: !evaluation.resumable,
    })
}

fn resume_materialization(
    schedule: &RecurringSchedule,
    cursor: &ScheduleCursor,
    evaluation: &ScheduleEvaluation,
    materialized: Vec<MaterializedOccurrence>,
) -> Result<ScheduleMaterialization, ValidationError> {
    let cursor = if let Some(entry) = materialized.last() {
        let last_intended = entry.occurrence.intended_at;
        let next_due = schedule.first_due_after(last_intended)?;
        resume_cursor(&evaluation.cursor, next_due, last_intended)
    } else {
        cursor.clone()
    };
    Ok(ScheduleMaterialization {
        occurrences: materialized,
        skipped: 0,
        next_wake: WakeHint::Now,
        cursor,
        complete: false,
    })
}

fn resume_cursor(
    cursor: &ScheduleCursor,
    next_due: Option<Timestamp>,
    last_intended: Timestamp,
) -> ScheduleCursor {
    let mut resumed = cursor.clone();
    resumed.next_due = next_due;
    resumed.watermark = Some(last_intended);
    resumed.last_intended = Some(last_intended);
    resumed
}
