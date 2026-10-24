use std::task::{Context, Poll};

use super::{super::constants::SHUTDOWN_GRACE, CompletedCandidate, InFlightCandidate};
use crate::{
    engine::JobSystem,
    error::JobSystemError,
    fairness::{FairDispatchOwner, FairRelease},
    model::WakeFuture,
    store::JobStore,
};

type ShutdownPoll<E> =
    Result<Option<(CompletedCandidate<E>, crate::fairness::FairPermit)>, JobSystemError<E>>;

pub(super) struct ShutdownGrace {
    sleep: Option<WakeFuture>,
}

impl ShutdownGrace {
    fn new() -> Self {
        Self { sleep: None }
    }

    fn poll<S: JobStore>(
        &mut self,
        system: &JobSystem<S>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), crate::model::WakeSchedulerError>> {
        if self.sleep.is_none() {
            self.sleep = match system.sleep(SHUTDOWN_GRACE) {
                Ok(future) => Some(future),
                Err(error) => return Poll::Ready(Err(error)),
            };
        }
        if let Some(sleep) = self.sleep.as_mut()
            && sleep.as_mut().poll(context).is_ready()
        {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }

    fn cancel(&mut self) {
        self.sleep.take();
    }
}

pub(super) struct ShutdownController {
    grace: Option<ShutdownGrace>,
    requested: bool,
    signaled: bool,
}

impl ShutdownController {
    pub(super) fn new() -> Self {
        Self {
            grace: None,
            requested: false,
            signaled: false,
        }
    }

    pub(super) fn requested(&self) -> bool {
        self.requested
    }

    pub(super) fn request<S: JobStore>(&mut self, system: &JobSystem<S>) {
        self.requested = true;
        if self.signaled {
            return;
        }
        self.signaled = true;
        system.signal_active_attempts();
    }

    pub(super) fn poll<S: JobStore>(
        &mut self,
        system: &JobSystem<S>,
        active: &mut Vec<InFlightCandidate<'_, S>>,
        context: &mut Context<'_>,
    ) -> Poll<ShutdownPoll<S::Error>> {
        if system.is_shutdown() {
            self.request(system);
            if let Some(result) = poll_in_flight(active, context) {
                return Poll::Ready(Ok(Some(result)));
            }
            let grace = self.grace.get_or_insert_with(ShutdownGrace::new);
            match grace.poll(system, context) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(None)),
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(JobSystemError::WakeScheduler(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        poll_in_flight(active, context)
            .map_or(Poll::Pending, |result| Poll::Ready(Ok(Some(result))))
    }

    pub(super) fn drain<S: JobStore>(
        &mut self,
        owner: &mut FairDispatchOwner,
        active: &mut Vec<InFlightCandidate<'_, S>>,
    ) -> u32 {
        let mut drained = 0u32;
        for candidate in active.drain(..) {
            let _ = owner.release(candidate.permit, FairRelease::Retry);
            drained = drained.saturating_add(1);
        }
        if let Some(grace) = self.grace.as_mut() {
            grace.cancel();
        }
        drained
    }
}

fn poll_in_flight<'a, S: JobStore>(
    active: &mut Vec<InFlightCandidate<'a, S>>,
    context: &mut Context<'_>,
) -> Option<(CompletedCandidate<S::Error>, crate::fairness::FairPermit)> {
    for index in 0..active.len() {
        if let Poll::Ready(result) = active[index].future.as_mut().poll(context) {
            let candidate = active.swap_remove(index);
            return Some((
                CompletedCandidate {
                    order: candidate.order,
                    payload_bytes: candidate.payload_bytes,
                    result,
                },
                candidate.permit,
            ));
        }
    }
    None
}
