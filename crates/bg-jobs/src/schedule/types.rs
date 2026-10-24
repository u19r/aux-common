//! Portable recurring schedules and bounded occurrence materialisation.

use std::{num::NonZeroU16, time::Duration};

use bytes::Bytes;

use super::{evaluation::ScheduleOccurrence, schedule_control::ScheduleCursor};
use crate::{
    error::ValidationError,
    ids::{OrderingKey, ScheduleId},
    model::{MAX_INLINE_PAYLOAD_BYTES, NewJob},
    policy::{
        Cadence, Deduplication, FairnessClass, MisfirePolicy, OverlapPolicy, Priority,
        RetrySelection,
    },
    time::{MonotonicDeadline, Timestamp},
};

/// Bounds one schedule materialisation call.  Catch-up work that does not fit
/// remains represented by the returned cursor and can be resumed by the next
/// call.  The operation bound reserves the worst-case read/commit/readback
/// sequence for one enqueue, so a store acknowledgement outcome cannot make a
/// call exceed its advertised budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleMaterializationBudget {
    max_occurrences: u32,
    max_store_operations: u32,
    finish_by: MonotonicDeadline,
}

impl ScheduleMaterializationBudget {
    pub fn try_new(
        max_occurrences: u32,
        max_store_operations: u32,
        finish_by: MonotonicDeadline,
    ) -> Result<Self, ValidationError> {
        if max_occurrences == 0 {
            return Err(ValidationError::InvalidValue {
                field: "schedule materialization occurrences",
            });
        }
        if max_store_operations == 0 {
            return Err(ValidationError::InvalidValue {
                field: "schedule materialization store operations",
            });
        }
        Ok(Self {
            max_occurrences,
            max_store_operations,
            finish_by,
        })
    }

    pub const fn max_occurrences(self) -> u32 {
        self.max_occurrences
    }

    pub const fn max_store_operations(self) -> u32 {
        self.max_store_operations
    }

    pub const fn finish_by(self) -> MonotonicDeadline {
        self.finish_by
    }
}

impl Default for ScheduleMaterializationBudget {
    fn default() -> Self {
        Self {
            max_occurrences: 256,
            max_store_operations: 1_024,
            finish_by: MonotonicDeadline::from_nanos(u64::MAX),
        }
    }
}

/// Immutable job fields copied into every occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTemplate {
    pub kind: crate::ids::JobKind,
    pub schema_version: NonZeroU16,
    pub payload: Bytes,
    pub fairness: FairnessClass,
    pub ordering_key: Option<OrderingKey>,
    pub priority: Priority,
    pub expires_after: Option<Duration>,
    pub retry_override: Option<RetrySelection>,
    pub deduplication: Option<Deduplication>,
}

/// Validated inputs for a recurring job template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobTemplateInput {
    pub kind: crate::ids::JobKind,
    pub schema_version: NonZeroU16,
    pub payload: Bytes,
    pub fairness: FairnessClass,
    pub ordering_key: Option<OrderingKey>,
    pub priority: Priority,
    pub expires_after: Option<Duration>,
    pub retry_override: Option<RetrySelection>,
    pub deduplication: Option<Deduplication>,
}

impl JobTemplate {
    pub fn try_new(input: JobTemplateInput) -> Result<Self, ValidationError> {
        if input.payload.len() > MAX_INLINE_PAYLOAD_BYTES {
            return Err(ValidationError::TooLong {
                field: "schedule payload",
                maximum: MAX_INLINE_PAYLOAD_BYTES,
                actual: input.payload.len(),
            });
        }
        if input
            .expires_after
            .is_some_and(|duration| duration.is_zero())
        {
            return Err(ValidationError::InvalidValue {
                field: "schedule expiry",
            });
        }
        Ok(Self {
            kind: input.kind,
            schema_version: input.schema_version,
            payload: input.payload,
            fairness: input.fairness,
            ordering_key: input.ordering_key,
            priority: input.priority,
            expires_after: input.expires_after,
            retry_override: input.retry_override,
            deduplication: input.deduplication,
        })
    }

    pub(super) fn occurrence_job(
        &self,
        occurrence: &ScheduleOccurrence,
        overlap: OverlapPolicy,
    ) -> Result<NewJob, ValidationError> {
        let expires_at = self
            .expires_after
            .map(|duration| occurrence.intended_at.checked_add(duration))
            .transpose()?;
        let ordering_key = match overlap {
            OverlapPolicy::Allow => self.ordering_key.clone(),
            OverlapPolicy::Forbid => Some(
                OrderingKey::try_new(occurrence.schedule_id.as_bytes()).map_err(|_| {
                    ValidationError::InvalidValue {
                        field: "schedule ordering key",
                    }
                })?,
            ),
        };
        Ok(NewJob {
            job_id: occurrence.job_id(),
            kind: self.kind.clone(),
            schema_version: self.schema_version,
            payload: self.payload.clone(),
            fairness: self.fairness.clone(),
            ordering_key,
            priority: self.priority,
            scheduled_at: occurrence.intended_at,
            expires_at,
            retry_override: self.retry_override,
            deduplication: self.deduplication.clone(),
        })
    }
}

/// A validated recurring schedule definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringSchedule {
    pub schedule_id: ScheduleId,
    pub job_template: JobTemplate,
    pub cadence: Cadence,
    pub misfire: MisfirePolicy,
    pub overlap: OverlapPolicy,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringScheduleInput {
    pub schedule_id: ScheduleId,
    pub job_template: JobTemplate,
    pub cadence: Cadence,
    pub misfire: MisfirePolicy,
    pub overlap: OverlapPolicy,
    pub enabled: bool,
}

impl RecurringSchedule {
    pub fn new(input: RecurringScheduleInput) -> Self {
        Self {
            schedule_id: input.schedule_id,
            job_template: input.job_template,
            cadence: input.cadence,
            misfire: input.misfire,
            overlap: input.overlap,
            enabled: input.enabled,
        }
    }

    pub fn first_due_after(&self, after: Timestamp) -> Result<Option<Timestamp>, ValidationError> {
        match &self.cadence {
            Cadence::CronUtc(cron) => cron.next_after(after),
        }
    }

    pub fn cursor_after(&self, after: Timestamp) -> Result<ScheduleCursor, ValidationError> {
        Ok(ScheduleCursor::new(
            self.first_due_after(after)?,
            self.enabled,
        ))
    }
}
