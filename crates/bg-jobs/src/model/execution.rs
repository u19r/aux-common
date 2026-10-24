//! Runtime-owned access to a claim while its registered handler is executing.

use std::{error::Error, future::Future, pin::Pin};

use bytes::Bytes;

use super::ExecutionContext;

type CheckpointFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), Box<dyn Error + Send + Sync>>> + Send + 'a>>;

pub(crate) trait InvocationCheckpoint: Send {
    fn context(&self) -> Result<ExecutionContext<'_>, Box<dyn Error + Send + Sync>>;

    fn save_checkpoint(&mut self, checkpoint: Bytes) -> CheckpointFuture<'_>;
}

/// The runtime lends this handle only to the registered handler for its current
/// claim. It cannot be constructed or recovered from checkpoint bytes.
pub struct JobExecution<'a> {
    checkpoint: &'a mut dyn InvocationCheckpoint,
}

impl<'a> JobExecution<'a> {
    pub(crate) fn new(checkpoint: &'a mut dyn InvocationCheckpoint) -> Self {
        Self { checkpoint }
    }

    /// Returns the genuine context of the runtime's current claim. A successful
    /// checkpoint updates that same claim before a subsequent context is read.
    pub fn context(&self) -> Result<ExecutionContext<'_>, Box<dyn Error + Send + Sync>> {
        self.checkpoint.context()
    }

    pub(super) fn into_context(self) -> Result<ExecutionContext<'a>, Box<dyn Error + Send + Sync>> {
        self.checkpoint.context()
    }

    /// Awaits the existing fenced checkpoint transaction and its
    /// reconciliation. On an error, do not submit work that depended on
    /// this acknowledgement. This does not prove settlement of an external
    /// effect.
    pub async fn save_checkpoint(
        &mut self,
        checkpoint: Bytes,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.checkpoint.save_checkpoint(checkpoint).await
    }
}
