use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;

use crate::{
    drive::scheduler::DriveClock,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    model::{
        CancellationToken, ExecutionContext, HandlerFuture, HandlerPanic, JobExecution, JobHandler,
        JobOutcome, PanicSafeFuture, WakeFuture,
    },
    store::JobStore,
    time::MonotonicDeadline,
};

pub(crate) enum HandlerContext<'a> {
    Standard(ExecutionContext<'a>),
    Checkpointed(JobExecution<'a>),
}

impl HandlerContext<'_> {
    fn cancellation(&self) -> Option<CancellationToken> {
        match self {
            Self::Standard(context) => Some(context.cancellation()),
            Self::Checkpointed(execution) => execution
                .context()
                .ok()
                .map(|context| context.cancellation()),
        }
    }
}

pub(crate) struct HandlerInvocation<'system, 'handler, S, C>
where S: JobStore
{
    pub(crate) system: &'system JobSystem<S>,
    pub(crate) finish_by: MonotonicDeadline,
    pub(crate) clock: DriveClock<C>,
    pub(crate) handler: &'handler dyn JobHandler,
    pub(crate) context: HandlerContext<'handler>,
    pub(crate) payload: &'handler Bytes,
}

pub(crate) async fn execute_handler<'system, 'handler, S, C, E>(
    invocation: HandlerInvocation<'system, 'handler, S, C>,
) -> JobResult<HandlerExecution, E>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
    let HandlerInvocation {
        system,
        finish_by,
        clock,
        handler,
        context,
        payload,
    } = invocation;
    let cancellation = context.cancellation().ok_or(JobSystemError::LeaseLost)?;
    let future = match catch_unwind(AssertUnwindSafe(|| match context {
        HandlerContext::Standard(context) => handler.execute(context, payload),
        HandlerContext::Checkpointed(execution) => handler.execute_checkpointed(execution, payload),
    })) {
        Ok(future) => future,
        Err(_) => return Ok(HandlerExecution::Outcome(handler_retry("handler_panic")?)),
    };
    let boundary = HandlerBoundary {
        system,
        finish_by,
        clock,
        future: PanicSafeFuture::new(future),
        cancellation,
        deadline: None,
        cancellation_observed: false,
    };
    boundary.await.into_execution()
}

pub(crate) enum HandlerExecution {
    Outcome(JobOutcome),
    Deadline,
}

enum HandlerBoundaryResult {
    Finished(Result<Result<JobOutcome, Box<dyn std::error::Error + Send + Sync>>, HandlerPanic>),
    Deadline,
    WakeScheduler(crate::model::WakeSchedulerError),
}

impl HandlerBoundaryResult {
    fn into_execution<E>(self) -> JobResult<HandlerExecution, E> {
        match self {
            Self::Deadline => Ok(HandlerExecution::Deadline),
            Self::WakeScheduler(error) => Err(JobSystemError::WakeScheduler(error)),
            Self::Finished(Ok(Ok(outcome))) => Ok(HandlerExecution::Outcome(outcome)),
            Self::Finished(Ok(Err(_))) => {
                Ok(HandlerExecution::Outcome(handler_retry("handler_failed")?))
            }
            Self::Finished(Err(HandlerPanic)) => {
                Ok(HandlerExecution::Outcome(handler_retry("handler_panic")?))
            }
        }
    }
}

struct HandlerBoundary<'system, 'handler, S, C>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
    system: &'system JobSystem<S>,
    finish_by: MonotonicDeadline,
    clock: DriveClock<C>,
    future: PanicSafeFuture<HandlerFuture<'handler>>,
    cancellation: CancellationToken,
    deadline: Option<WakeFuture>,
    cancellation_observed: bool,
}

impl<S, C> Unpin for HandlerBoundary<'_, '_, S, C>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
}

impl<S, C> Future for HandlerBoundary<'_, '_, S, C>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
    type Output = HandlerBoundaryResult;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let boundary = self.get_mut();
        if boundary.deadline_reached() {
            return Poll::Ready(HandlerBoundaryResult::Deadline);
        }
        boundary.poll_handler(context)
    }
}

impl<S, C> HandlerBoundary<'_, '_, S, C>
where
    S: JobStore,
    C: Fn() -> MonotonicDeadline + Send + Sync,
{
    fn poll_handler(&mut self, context: &mut Context<'_>) -> Poll<HandlerBoundaryResult> {
        loop {
            match Pin::new(&mut self.future).poll(context) {
                Poll::Ready(result) => return self.finish_handler(result),
                Poll::Pending => {
                    if self.cancellation_ready(context) {
                        if self.deadline_reached() {
                            return Poll::Ready(HandlerBoundaryResult::Deadline);
                        }
                        continue;
                    }
                    return self.poll_deadline(context);
                }
            }
        }
    }

    fn finish_handler(
        &mut self,
        result: Result<Result<JobOutcome, Box<dyn std::error::Error + Send + Sync>>, HandlerPanic>,
    ) -> Poll<HandlerBoundaryResult> {
        if self.deadline_reached() {
            Poll::Ready(HandlerBoundaryResult::Deadline)
        } else {
            Poll::Ready(HandlerBoundaryResult::Finished(result))
        }
    }

    fn cancellation_ready(&mut self, context: &mut Context<'_>) -> bool {
        let cancelled = self.cancellation.poll_cancelled(context).is_ready();
        if self.cancellation_observed || !cancelled {
            return false;
        }
        self.cancellation_observed = true;
        true
    }

    fn poll_deadline(&mut self, context: &mut Context<'_>) -> Poll<HandlerBoundaryResult> {
        if let Err(result) = self.ensure_deadline() {
            return Poll::Ready(result);
        }
        if self
            .deadline
            .as_mut()
            .is_some_and(|deadline| Pin::new(deadline).poll(context).is_ready())
        {
            Poll::Ready(HandlerBoundaryResult::Deadline)
        } else {
            Poll::Pending
        }
    }

    fn ensure_deadline(&mut self) -> Result<(), HandlerBoundaryResult> {
        if self.deadline.is_some() {
            return Ok(());
        }
        let current = self.clock.now();
        if self.finish_by.is_at_or_before(current) {
            return Err(HandlerBoundaryResult::Deadline);
        }
        let remaining = self.finish_by.remaining_until(current);
        self.deadline = Some(
            self.system
                .sleep(remaining)
                .map_err(HandlerBoundaryResult::WakeScheduler)?,
        );
        Ok(())
    }

    fn deadline_reached(&mut self) -> bool {
        self.finish_by.is_at_or_before(self.clock.now())
    }
}

fn handler_retry<E>(code: &'static str) -> JobResult<JobOutcome, E> {
    Ok(JobOutcome::Retry {
        class: crate::policy::RetryClass::Transient,
        not_before: None,
        code: crate::policy::OutcomeCode::try_new(code).map_err(JobSystemError::Validation)?,
    })
}
