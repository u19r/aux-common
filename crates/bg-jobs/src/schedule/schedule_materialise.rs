//! Atomic occurrence admission and durable cursor advancement.

use super::{
    RecurringSchedule, ScheduleCursor, ScheduleEvaluation, ScheduleMaterializationBudget,
    ScheduleOccurrence, constants::ENQUEUE_WORST_CASE_STORE_OPERATIONS,
};
use crate::{
    catalog::CurrentSchedule,
    engine::JobSystem,
    error::{JobResult, JobSystemError, ValidationError},
    model::EnqueueResult,
    policy::OverlapPolicy,
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
    pub complete: bool,
}

/// Definition, initial cursor and bounds for one materialization call. The
/// initial cursor is used only until the configured schedule has durable state.
pub struct ScheduleMaterializationRequest<'a> {
    schedule: &'a RecurringSchedule,
    initial: &'a ScheduleCursor,
    now: Timestamp,
    budget: ScheduleMaterializationBudget,
}

impl<'a> ScheduleMaterializationRequest<'a> {
    pub fn new(
        schedule: &'a RecurringSchedule,
        initial: &'a ScheduleCursor,
        now: Timestamp,
        budget: ScheduleMaterializationBudget,
    ) -> Self {
        Self {
            schedule,
            initial,
            now,
            budget,
        }
    }

    pub(crate) async fn execute<S: JobStore, C: FnMut() -> MonotonicDeadline>(
        self,
        system: &JobSystem<S>,
        mut clock: C,
    ) -> JobResult<ScheduleMaterialization, S::Error> {
        let item_limit = self.item_limit()?;
        if item_limit == 0 || self.budget.finish_by().is_at_or_before(clock()) {
            return Ok(resumable(self.initial.clone(), Vec::new()));
        }
        let digest = self.schedule.definition_digest(system)?;
        let current = system
            .load_schedule_progress(self.schedule.schedule_id, digest, self.initial)
            .await?;
        let evaluation =
            self.schedule
                .evaluate_for_materialization(current.cursor(), self.now, item_limit)?;
        let mut pass = MaterializationPass {
            request: self,
            digest,
            occurrences: Vec::new(),
        };
        pass.run(system, current, evaluation, &mut clock).await
    }

    fn item_limit(&self) -> Result<u32, ValidationError> {
        let operations = usize::try_from(self.budget.max_store_operations()).map_err(|_| {
            ValidationError::Overflow {
                field: "schedule operation budget",
            }
        })?;
        let available = operations.saturating_sub(1) / ENQUEUE_WORST_CASE_STORE_OPERATIONS;
        let limit = self
            .budget
            .max_occurrences()
            .min(
                u32::try_from(available).map_err(|_| ValidationError::Overflow {
                    field: "schedule occurrence budget",
                })?,
            );
        Ok(if self.schedule.overlap == OverlapPolicy::Forbid {
            limit.min(1)
        } else {
            limit
        })
    }
}

struct MaterializationPass<'a> {
    request: ScheduleMaterializationRequest<'a>,
    digest: [u8; 32],
    occurrences: Vec<MaterializedOccurrence>,
}

impl MaterializationPass<'_> {
    async fn run<S: JobStore, C: FnMut() -> MonotonicDeadline>(
        &mut self,
        system: &JobSystem<S>,
        mut current: CurrentSchedule,
        evaluation: ScheduleEvaluation,
        clock: &mut C,
    ) -> JobResult<ScheduleMaterialization, S::Error> {
        if evaluation.occurrences.is_empty() {
            current.persist(system, evaluation.cursor.clone()).await?;
            return Ok(self.finish_materialization(&evaluation, evaluation.cursor.clone()));
        }
        for (index, occurrence) in evaluation.occurrences.iter().enumerate() {
            if self.request.budget.finish_by().is_at_or_before(clock()) {
                return Ok(resumable(
                    current.cursor().clone(),
                    std::mem::take(&mut self.occurrences),
                ));
            }
            let last = index + 1 == evaluation.occurrences.len();
            let next = self.next_cursor(
                current.cursor(),
                occurrence,
                last.then_some(&evaluation.cursor),
            )?;
            if let Some(changed) = self
                .admit(system, current, *occurrence, next.clone())
                .await?
            {
                return Ok(resumable(changed, std::mem::take(&mut self.occurrences)));
            }
            if last {
                return Ok(self.finish_materialization(&evaluation, next));
            }
            current = self.load_current(system).await?;
            if current.cursor() != &next {
                return Ok(resumable(
                    current.cursor().clone(),
                    std::mem::take(&mut self.occurrences),
                ));
            }
        }
        Err(JobSystemError::PayloadCorrupt)
    }

    fn finish_materialization(
        &mut self,
        evaluation: &ScheduleEvaluation,
        cursor: ScheduleCursor,
    ) -> ScheduleMaterialization {
        ScheduleMaterialization {
            occurrences: std::mem::take(&mut self.occurrences),
            skipped: evaluation.skipped,
            next_wake: evaluation.wake,
            cursor,
            complete: !evaluation.resumable,
        }
    }

    fn next_cursor(
        &self,
        current: &ScheduleCursor,
        occurrence: &ScheduleOccurrence,
        final_cursor: Option<&ScheduleCursor>,
    ) -> Result<ScheduleCursor, ValidationError> {
        let mut next = if let Some(final_cursor) = final_cursor {
            current.advance(
                final_cursor.next_due(),
                final_cursor.watermark(),
                final_cursor.last_intended(),
            )?
        } else {
            current.advance(
                self.request
                    .schedule
                    .first_due_after(occurrence.intended_at)?,
                Some(occurrence.intended_at),
                Some(occurrence.intended_at),
            )?
        };
        if self.request.schedule.overlap == OverlapPolicy::Forbid {
            next.active = true;
        }
        Ok(next)
    }

    async fn admit<S: JobStore>(
        &mut self,
        system: &JobSystem<S>,
        current: CurrentSchedule,
        occurrence: ScheduleOccurrence,
        next: ScheduleCursor,
    ) -> JobResult<Option<ScheduleCursor>, S::Error> {
        let expected = current.cursor().clone();
        let admission = current
            .admission(next)?
            .ok_or(JobSystemError::PayloadCorrupt)?;
        let job = self
            .request
            .schedule
            .job_template
            .occurrence_job(&occurrence, self.request.schedule.overlap)?;
        match crate::enqueue::enqueue_scheduled_occurrence(system, job, self.request.now, admission)
            .await
        {
            Ok(enqueue) => {
                self.occurrences.push(MaterializedOccurrence {
                    occurrence,
                    enqueue,
                });
                Ok(None)
            }
            Err(error @ (JobSystemError::UnknownCommit | JobSystemError::CatalogConflict)) => {
                let observed = self.load_current(system).await?;
                if observed.cursor() == &expected {
                    return Err(error);
                }
                Ok(Some(observed.cursor().clone()))
            }
            Err(error) => Err(error),
        }
    }

    async fn load_current<S: JobStore>(
        &self,
        system: &JobSystem<S>,
    ) -> JobResult<CurrentSchedule, S::Error> {
        system
            .load_schedule_progress(
                self.request.schedule.schedule_id,
                self.digest,
                self.request.initial,
            )
            .await
    }
}

fn resumable(
    cursor: ScheduleCursor,
    occurrences: Vec<MaterializedOccurrence>,
) -> ScheduleMaterialization {
    ScheduleMaterialization {
        occurrences,
        skipped: 0,
        next_wake: WakeHint::Now,
        cursor,
        complete: false,
    }
}
