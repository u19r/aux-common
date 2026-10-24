//! Public drive entrypoint and deadline checks.

use crate::{
    budget::{DriveReport, DriveRequest},
    engine::JobSystem,
    error::JobResult,
    store::JobStore,
    time::{MonotonicDeadline, Timestamp},
};

pub(crate) async fn drive<S, C>(
    system: &JobSystem<S>,
    request: DriveRequest,
    wall_now: Timestamp,
    monotonic_now: C,
) -> JobResult<DriveReport, S::Error>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
    crate::drive::scheduler::run(system, request, wall_now, monotonic_now).await
}

pub(in crate::drive) fn claim_deadline_reached(
    request: &DriveRequest,
    current: MonotonicDeadline,
) -> bool {
    request.stop_claiming_at().is_at_or_before(current)
        || request.finish_by().is_at_or_before(current)
}
