//! A handler checkpoint joins the runtime's existing mutable claim owner.

use std::{error::Error, future::Future, pin::Pin};

use bytes::Bytes;

use super::super::scheduler::DriveClock;
use crate::{
    engine::JobSystem,
    error::JobSystemError,
    lifecycle::ClaimedJob,
    model::{ExecutionContext, InvocationCheckpoint},
    store::JobStore,
    time::MonotonicDeadline,
};

pub(super) struct ClaimCheckpoint<'a, S: JobStore, C> {
    pub(super) system: &'a JobSystem<S>,
    pub(super) claim: &'a mut ClaimedJob,
    pub(super) finish_by: MonotonicDeadline,
    pub(super) clock: DriveClock<C>,
}

impl<S: JobStore, C: Fn() -> MonotonicDeadline + Send + Sync> InvocationCheckpoint
    for ClaimCheckpoint<'_, S, C>
{
    fn context(&self) -> Result<ExecutionContext<'_>, Box<dyn Error + Send + Sync>> {
        crate::transition::current_lease(self.system, self.claim, self.clock.wall_now()?)?;
        self.claim
            .context_with_deadline(self.finish_by)
            .ok_or_else(|| Box::new(JobSystemError::<S::Error>::LeaseLost).into())
    }

    fn save_checkpoint(
        &mut self,
        checkpoint: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send + '_>> {
        Box::pin(async move {
            self.context()?;
            let now = self.clock.wall_now()?;
            self.system
                .checkpoint(self.claim, checkpoint, now)
                .await
                .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)?;
            Ok(())
        })
    }
}
