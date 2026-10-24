//! Runtime-neutral bounded active-pulse driving.

use std::{future::Future, num::NonZeroU16};

use crate::{budget::DriveReport, time::MonotonicDeadline};

/// Limits for one externally owned burst of drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivePulseRequest {
    pub max_pulses: NonZeroU16,
    pub stop_by: MonotonicDeadline,
}

impl ActivePulseRequest {
    pub const fn new(max_pulses: NonZeroU16, stop_by: MonotonicDeadline) -> Self {
        Self {
            max_pulses,
            stop_by,
        }
    }

    /// Runs immediate drives until the first non-immediate report, deadline,
    /// or pulse cap. The adapter owns any yielding or jitter between calls.
    pub async fn drive<E, F, Fut, C>(
        self,
        mut monotonic_now: C,
        mut drive: F,
    ) -> Result<ActivePulseReport, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<DriveReport, E>>,
        C: FnMut() -> MonotonicDeadline,
    {
        let mut reports = Vec::with_capacity(usize::from(self.max_pulses.get()));
        loop {
            if reports.len() >= usize::from(self.max_pulses.get()) {
                return Ok(stopped(reports, ActivePulseStopReason::MaxPulses));
            }
            if self.stop_by.is_at_or_before(monotonic_now()) {
                return Ok(stopped(reports, ActivePulseStopReason::Deadline));
            }
            let report = drive().await?;
            let continue_pulse = report.next_wake.is_now() && report.has_immediately_visible_work;
            let deadline = report.stop_reason == crate::DriveStopReason::Deadline;
            reports.push(report);
            if deadline {
                return Ok(stopped(reports, ActivePulseStopReason::Deadline));
            }
            if !continue_pulse {
                return Ok(stopped(reports, ActivePulseStopReason::NoImmediateWork));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivePulseStopReason {
    NoImmediateWork,
    MaxPulses,
    Deadline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivePulseReport {
    pub drives: Vec<DriveReport>,
    pub stop_reason: ActivePulseStopReason,
}

fn stopped(drives: Vec<DriveReport>, stop_reason: ActivePulseStopReason) -> ActivePulseReport {
    ActivePulseReport {
        drives,
        stop_reason,
    }
}
