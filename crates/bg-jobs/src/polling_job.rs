use std::{future::Future, num::NonZeroU32, pin::Pin, time::Duration};

use bytes::Bytes;

use crate::{ExecutionContext, HandlerFuture, JobHandler, JobOutcome};

/// Whether a bounded discovery pass found work. An active pass may run again
/// immediately; idle passes back off and failures use the job's retry policy.
pub enum PollActivity {
    Active,
    Idle,
}

pub type PollFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<PollActivity, Box<dyn std::error::Error + Send + Sync>>>
            + Send
            + 'a,
    >,
>;

/// One bounded discovery pass. Implementations own business I/O and safe error
/// diagnostics. They must preserve unaccepted intent when publication fails.
pub trait JobPoller: Send + Sync + 'static {
    fn poll<'a>(&'a self, context: ExecutionContext<'a>) -> PollFuture<'a>;
}

/// A durable polling job. Idle passes retain adaptive polling history;
/// failures consume the ordinary bounded retry policy and dead-letter on
/// exhaustion. Claims, authority, cancellation and shutdown belong to the job
/// runtime.
pub struct PollingJob<P> {
    poller: P,
    interval: Duration,
}

impl<P: JobPoller> PollingJob<P> {
    pub fn new(poller: P, interval_seconds: NonZeroU32) -> Self {
        Self {
            poller,
            interval: Duration::from_secs(u64::from(interval_seconds.get())),
        }
    }
}

impl<P: JobPoller> JobHandler for PollingJob<P> {
    fn execute<'a>(&'a self, context: ExecutionContext<'a>, _: &'a [u8]) -> HandlerFuture<'a> {
        Box::pin(async move {
            if context.is_cancelled() {
                return Ok(JobOutcome::Cancelled);
            }
            let activity = self.poller.poll(context.clone()).await?;
            if context.is_cancelled() {
                return Ok(JobOutcome::Cancelled);
            }
            let delay = match activity {
                PollActivity::Active => {
                    context.record_poll_work_found();
                    Duration::ZERO
                }
                PollActivity::Idle => self.interval,
            };
            Ok(context.continue_poll(Bytes::new(), delay, true)?)
        })
    }
}
