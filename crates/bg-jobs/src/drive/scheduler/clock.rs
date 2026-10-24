//! Shared monotonic clock and elapsed wall time for concurrently polled
//! candidates.

use std::{sync::Arc, time::Duration};

use crate::{
    error::ValidationError,
    time::{MonotonicDeadline, Timestamp},
};

pub(crate) struct DriveClock<C> {
    clock: Arc<C>,
    origin: MonotonicDeadline,
    wall_origin: Timestamp,
}

impl<C: Fn() -> MonotonicDeadline> DriveClock<C> {
    pub(crate) fn new(clock: C, wall_origin: Timestamp) -> Self {
        let origin = clock();
        Self {
            clock: Arc::new(clock),
            origin,
            wall_origin,
        }
    }

    pub(crate) fn now(&self) -> MonotonicDeadline {
        (self.clock)()
    }

    pub(crate) fn deadline_at(&self, at: Timestamp) -> Result<MonotonicDeadline, ValidationError> {
        let duration = at.duration_since(self.wall_origin)?;
        self.origin.checked_add(duration, "handler deadline")
    }

    pub(crate) fn deadline_after(
        &self,
        delay: Duration,
    ) -> Result<MonotonicDeadline, ValidationError> {
        self.now().checked_add(delay, "handler deadline")
    }

    pub(crate) fn wall_now(&self) -> Result<Timestamp, ValidationError> {
        self.wall_at(self.now())
    }

    pub(crate) fn wall_at(&self, at: MonotonicDeadline) -> Result<Timestamp, ValidationError> {
        let elapsed = at.as_nanos().checked_sub(self.origin.as_nanos()).ok_or(
            ValidationError::InvalidValue {
                field: "monotonic clock",
            },
        )?;
        self.wall_origin.checked_add(Duration::from_nanos(elapsed))
    }
}

impl<C> Clone for DriveClock<C> {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            origin: self.origin,
            wall_origin: self.wall_origin,
        }
    }
}
