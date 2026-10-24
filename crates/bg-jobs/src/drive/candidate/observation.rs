use std::time::Duration;

use super::super::scheduler::DriveClock;
use crate::{
    engine::JobSystem,
    ids::{JobKind, QueueName},
    lifecycle::ClaimedJob,
    observer::JobEvent,
    store::JobStore,
    time::{MonotonicDeadline, Timestamp},
};

/// Keeps the active gauge balanced when an attempt errors or its future is
/// dropped.
pub(super) struct AttemptObservation<'a, S: JobStore, C: Fn() -> MonotonicDeadline> {
    system: &'a JobSystem<S>,
    queue: QueueName,
    kind: JobKind,
    clock: DriveClock<C>,
    started: MonotonicDeadline,
}

impl<'a, S: JobStore, C: Fn() -> MonotonicDeadline> AttemptObservation<'a, S, C> {
    pub(super) fn start(
        system: &'a JobSystem<S>,
        claim: &ClaimedJob,
        clock: DriveClock<C>,
        due_at: Timestamp,
    ) -> Self {
        let queue = claim.record().queue.clone();
        let kind = claim.record().kind.clone();
        let due_delay = clock
            .wall_now()
            .and_then(|now| now.duration_since(due_at))
            .unwrap_or_default();
        system.observe(JobEvent::AttemptStarted {
            queue: queue.clone(),
            kind: kind.clone(),
            due_delay,
        });
        Self {
            system,
            queue,
            kind,
            started: clock.now(),
            clock,
        }
    }
}

impl<S: JobStore, C: Fn() -> MonotonicDeadline> Drop for AttemptObservation<'_, S, C> {
    fn drop(&mut self) {
        let elapsed = self
            .clock
            .now()
            .as_nanos()
            .saturating_sub(self.started.as_nanos());
        self.system.observe(JobEvent::AttemptFinished {
            queue: self.queue.clone(),
            kind: self.kind.clone(),
            duration: Duration::from_nanos(elapsed),
        });
    }
}
