use std::{
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::Poll,
    time::Duration,
};

use super::ClaimedJob;
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    model::PanicSafeFuture,
    store::JobStore,
};

pub(super) async fn publish_claim<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    deadline: Option<super::ClaimDeadline<'_>>,
) -> JobResult<(), S::Error> {
    let registration = system
        .registry()
        .get_ref(&claim.record().kind, claim.record().schema_version)
        .ok_or(JobSystemError::UnregisteredHandler)?;
    let remaining = || -> JobResult<Duration, S::Error> {
        let Some(bound) = deadline else {
            return Ok(registration.default_timeout());
        };
        let now = (bound.wall_now)()?;
        let lease = claim.lease_at(now).ok_or(JobSystemError::LeaseLost)?;
        Ok(lease.expires_at.duration_since(now)?)
    };
    let _ = remaining()?;
    let context = claim.context().ok_or(JobSystemError::LeaseLost)?;
    let publication = catch_unwind(AssertUnwindSafe(|| {
        registration.handler().publish_claim(&context)
    }))
    .map_err(|_| JobSystemError::ClaimPublicationUnacknowledged)?;
    let Some(publication) = publication else {
        return remaining().map(|_| ());
    };
    let mut publication = PanicSafeFuture::new(publication);
    let mut timeout = system
        .sleep(remaining()?)
        .map_err(JobSystemError::WakeScheduler)?;
    poll_fn(|context| {
        if let Err(error) = remaining() {
            return Poll::Ready(Err(error));
        }
        if timeout.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(JobSystemError::LeaseLost));
        }
        match Pin::new(&mut publication).poll(context) {
            Poll::Ready(Ok(Ok(()))) => Poll::Ready(remaining().map(|_| ())),
            Poll::Ready(Ok(Err(_)) | Err(_)) => {
                Poll::Ready(Err(JobSystemError::ClaimPublicationUnacknowledged))
            }
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
