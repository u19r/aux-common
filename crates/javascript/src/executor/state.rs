use std::{fmt, time::Instant};

use super::limits::JobLimits;
use crate::{JsCancellation, JsError, JsJob, constants::JOB_DEADLINE};

pub(super) struct JobState {
    pub(super) input: Vec<u8>,
    pub(super) input_position: usize,
    pub(super) output: Vec<u8>,
    pub(super) closed_streams: [bool; 3],
    pub(super) limits: JobLimits,
    pub(super) deadline: Instant,
    pub(super) cancellation: JsCancellation,
}
impl JobState {
    pub(super) fn new(job: JsJob, cancellation: JsCancellation) -> Self {
        Self {
            input: job.wire,
            input_position: 0,
            output: Vec::new(),
            closed_streams: [false; 3],
            limits: JobLimits::default(),
            deadline: Instant::now() + JOB_DEADLINE,
            cancellation,
        }
    }
    pub(super) fn check_interrupt(&self) -> Result<(), JsError> {
        if self.cancellation.is_cancelled() {
            return Err(JsError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(JsError::Timeout);
        }
        Ok(())
    }
    pub(super) fn is_stream_open(&self, fd: i32) -> bool {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.closed_streams.get(i))
            .is_some_and(|closed| !closed)
    }
}
#[derive(Debug)]
pub(super) struct GuestExit(pub(super) i32);
impl fmt::Display for GuestExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("guest_exit")
    }
}
impl std::error::Error for GuestExit {}
