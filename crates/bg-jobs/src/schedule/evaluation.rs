use super::{RecurringSchedule, ScheduleCursor, constants::MAX_OCCURRENCE_SCAN};
use crate::{
    error::ValidationError,
    ids::{OccurrenceId, ScheduleId},
    policy::{MisfirePolicy, OverlapPolicy},
    time::{Timestamp, WakeHint},
};

impl RecurringSchedule {
    pub fn evaluate(
        &self,
        cursor: &ScheduleCursor,
        now: Timestamp,
    ) -> Result<ScheduleEvaluation, ValidationError> {
        self.evaluate_with_limit(cursor, now, None)
    }

    pub(crate) fn evaluate_for_materialization(
        &self,
        cursor: &ScheduleCursor,
        now: Timestamp,
        max_occurrences: u32,
    ) -> Result<ScheduleEvaluation, ValidationError> {
        self.evaluate_with_limit(cursor, now, Some(max_occurrences))
    }

    fn evaluate_with_limit(
        &self,
        cursor: &ScheduleCursor,
        now: Timestamp,
        materialization_limit: Option<u32>,
    ) -> Result<ScheduleEvaluation, ValidationError> {
        if !cursor.enabled || cursor.paused {
            return Ok(ScheduleEvaluation::idle(cursor.clone(), WakeHint::None));
        }
        if self.overlap == OverlapPolicy::Forbid && cursor.active {
            return Ok(ScheduleEvaluation::blocked(cursor.clone()));
        }
        let crate::policy::Cadence::CronUtc(cron) = &self.cadence;
        let Some(next_due) = cursor.next_due else {
            return Ok(ScheduleEvaluation::idle(cursor.clone(), WakeHint::None));
        };
        let limits = EvaluationLimits::try_new(self.misfire, materialization_limit)?;
        let backlog = collect_backlog(BacklogQuery {
            cron,
            next_due,
            now,
            policy: self.misfire,
            schedule_id: self.schedule_id,
            generation: cursor.generation,
            selected_limit: limits.selected_limit,
            stop_after_selection: limits.stop_after_selection,
        })?;
        finish_evaluation(self, cursor, now, cron, backlog)
    }
}

/// One intended schedule occurrence. Its job identity is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScheduleOccurrence {
    pub schedule_id: ScheduleId,
    pub intended_at: Timestamp,
    pub generation: u32,
}

impl ScheduleOccurrence {
    pub fn job_id(self) -> crate::ids::JobId {
        crate::ids::JobId::from(self.occurrence_id().into_bytes())
    }

    pub fn occurrence_id(self) -> OccurrenceId {
        OccurrenceId::derive(&self.schedule_id, self.intended_at)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduleEvaluation {
    pub occurrences: Vec<ScheduleOccurrence>,
    pub skipped: u32,
    pub cursor: ScheduleCursor,
    pub wake: WakeHint,
    pub blocked_by_overlap: bool,
    pub(crate) resumable: bool,
}

impl ScheduleEvaluation {
    fn idle(cursor: ScheduleCursor, wake: WakeHint) -> Self {
        Self {
            occurrences: Vec::new(),
            skipped: 0,
            cursor,
            wake,
            blocked_by_overlap: false,
            resumable: false,
        }
    }

    fn blocked(cursor: ScheduleCursor) -> Self {
        Self {
            occurrences: Vec::new(),
            skipped: 0,
            cursor,
            wake: WakeHint::None,
            blocked_by_overlap: true,
            resumable: false,
        }
    }
}

struct Backlog {
    first: Option<Timestamp>,
    last: Option<Timestamp>,
    count: usize,
    selected: Vec<ScheduleOccurrence>,
    resumable: bool,
}

struct BacklogQuery<'a> {
    cron: &'a crate::time::CronExpression,
    next_due: Timestamp,
    now: Timestamp,
    policy: MisfirePolicy,
    schedule_id: ScheduleId,
    generation: u32,
    selected_limit: usize,
    stop_after_selection: bool,
}

struct EvaluationLimits {
    selected_limit: usize,
    stop_after_selection: bool,
}

impl EvaluationLimits {
    fn try_new(
        policy: MisfirePolicy,
        materialization_limit: Option<u32>,
    ) -> Result<Self, ValidationError> {
        let configured_limit = match policy {
            MisfirePolicy::CatchUp {
                maximum_occurrences,
            } => usize::from(maximum_occurrences.get()),
            MisfirePolicy::Skip | MisfirePolicy::FireOnce => 0,
        };
        let materialization_limit = materialization_limit
            .map(usize::try_from)
            .transpose()
            .map_err(|_| ValidationError::Overflow {
                field: "schedule materialization occurrences",
            })?;
        Ok(Self {
            selected_limit: materialization_limit
                .map_or(configured_limit, |limit| configured_limit.min(limit)),
            stop_after_selection: matches!(policy, MisfirePolicy::CatchUp { .. })
                && materialization_limit.is_some_and(|limit| limit < configured_limit),
        })
    }
}

fn finish_evaluation(
    schedule: &RecurringSchedule,
    cursor: &ScheduleCursor,
    now: Timestamp,
    cron: &crate::time::CronExpression,
    backlog: Backlog,
) -> Result<ScheduleEvaluation, ValidationError> {
    if backlog.count == 0 {
        let wake = WakeHint::from_optional_timestamp(cron.next_at_or_after(now)?);
        return Ok(ScheduleEvaluation::idle(cursor.clone(), wake));
    }
    let resumable = backlog.resumable;
    let backlog_last = backlog.last;
    let (occurrences, skipped, watermark, last_intended) = occurrences(
        schedule.schedule_id,
        cursor.generation,
        backlog,
        schedule.misfire,
    );
    let next_due = if resumable {
        backlog_last
            .map(|last| cron.next_after(last))
            .transpose()?
            .flatten()
    } else {
        cron.next_after(now)?
    };
    let next_cursor = advance_cursor(cursor, next_due, watermark, last_intended);
    let wake = if resumable {
        WakeHint::Now
    } else {
        WakeHint::from_optional_timestamp(next_due)
    };
    Ok(ScheduleEvaluation {
        occurrences,
        skipped,
        cursor: next_cursor,
        wake,
        blocked_by_overlap: false,
        resumable,
    })
}

fn collect_backlog(query: BacklogQuery<'_>) -> Result<Backlog, ValidationError> {
    let mut backlog = Backlog::new(&query);
    let mut cursor = query.first_after();
    while backlog.count < usize::from(MAX_OCCURRENCE_SCAN) {
        let Some(next) = query.cron.next_after(cursor)? else {
            break;
        };
        if next > query.now {
            break;
        }
        backlog.record(next, &query);
        cursor = next;
        if backlog.reached_selection(&query, cursor)? {
            break;
        }
    }
    Ok(backlog)
}

impl BacklogQuery<'_> {
    fn first_after(&self) -> Timestamp {
        self.next_due
            .as_millis()
            .checked_sub(1)
            .map(Timestamp::from_millis)
            .unwrap_or(self.next_due)
    }

    fn selected_limit(&self) -> usize {
        match self.policy {
            MisfirePolicy::CatchUp { .. } => self.selected_limit,
            MisfirePolicy::Skip | MisfirePolicy::FireOnce => 0,
        }
    }
}

impl Backlog {
    fn new(query: &BacklogQuery<'_>) -> Self {
        Self {
            first: None,
            last: None,
            count: 0,
            selected: Vec::with_capacity(query.selected_limit()),
            resumable: false,
        }
    }

    fn record(&mut self, next: Timestamp, query: &BacklogQuery<'_>) {
        self.first.get_or_insert(next);
        self.last = Some(next);
        self.count = self.count.saturating_add(1);
        if self.selected.len() < query.selected_limit() {
            self.selected.push(ScheduleOccurrence {
                schedule_id: query.schedule_id,
                intended_at: next,
                generation: query.generation,
            });
        }
    }

    fn reached_selection(
        &mut self,
        query: &BacklogQuery<'_>,
        cursor: Timestamp,
    ) -> Result<bool, ValidationError> {
        if !query.stop_after_selection || self.selected.len() < query.selected_limit() {
            return Ok(false);
        }
        self.resumable = query
            .cron
            .next_after(cursor)?
            .is_some_and(|following| following <= query.now);
        Ok(true)
    }
}

fn occurrences(
    schedule_id: ScheduleId,
    generation: u32,
    backlog: Backlog,
    policy: MisfirePolicy,
) -> (
    Vec<ScheduleOccurrence>,
    u32,
    Option<Timestamp>,
    Option<Timestamp>,
) {
    let last_intended = backlog.last;
    let selected = match policy {
        MisfirePolicy::Skip => 0,
        MisfirePolicy::FireOnce => usize::from(backlog.count != 0),
        MisfirePolicy::CatchUp {
            maximum_occurrences,
        } => backlog
            .selected
            .len()
            .min(usize::from(maximum_occurrences.get())),
    };
    let skipped = u32::try_from(backlog.count.saturating_sub(selected)).unwrap_or(u32::MAX);
    let watermark = match policy {
        MisfirePolicy::Skip => backlog.first,
        MisfirePolicy::FireOnce => backlog.last,
        MisfirePolicy::CatchUp { .. } => backlog
            .selected
            .get(selected.saturating_sub(1))
            .map(|occurrence| occurrence.intended_at),
    };
    let mut occurrences = match policy {
        MisfirePolicy::CatchUp { .. } => backlog.selected,
        MisfirePolicy::Skip | MisfirePolicy::FireOnce => Vec::with_capacity(selected),
    };
    match policy {
        MisfirePolicy::Skip => {}
        MisfirePolicy::FireOnce => {
            if let Some(intended_at) = backlog.last {
                occurrences.push(ScheduleOccurrence {
                    schedule_id,
                    intended_at,
                    generation,
                });
            }
        }
        MisfirePolicy::CatchUp { .. } => {
            occurrences.truncate(selected);
        }
    }
    (occurrences, skipped, watermark, last_intended)
}

fn advance_cursor(
    cursor: &ScheduleCursor,
    next_due: Option<Timestamp>,
    watermark: Option<Timestamp>,
    last_intended: Option<Timestamp>,
) -> ScheduleCursor {
    let mut next_cursor = cursor.clone();
    next_cursor.next_due = next_due;
    next_cursor.watermark = watermark.or(cursor.watermark);
    next_cursor.revision = cursor.revision.saturating_add(1);
    next_cursor.last_intended = last_intended;
    next_cursor
}
