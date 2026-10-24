use std::{future::Future, sync::Arc};

use futures_util::future::BoxFuture;

use crate::{
    configuration::{Deadline, SinkLimits},
    error::{ConfigurationError, SinkError},
    write_attempt::WriteAttempt,
    write_outcome::WriteOutcome,
    write_sink::{ReplayGuarantee, WriteSink},
};

/// Atomic batch commit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicWriteStatus {
    Applied,
    AlreadyApplied,
}

/// Conversion trait allowing [`AtomicSink`] closures to return either
/// `Result<(), SinkError>` or `Result<AtomicWriteStatus, SinkError>`.
pub trait IntoAtomicWriteStatus {
    fn into_atomic_status(self) -> AtomicWriteStatus;
}

impl IntoAtomicWriteStatus for () {
    fn into_atomic_status(self) -> AtomicWriteStatus {
        AtomicWriteStatus::Applied
    }
}

impl IntoAtomicWriteStatus for AtomicWriteStatus {
    fn into_atomic_status(self) -> AtomicWriteStatus {
        self
    }
}

type FlushFuture = BoxFuture<'static, Result<WriteOutcome, SinkError>>;
type ProbeFn = Arc<dyn Fn(Deadline) -> BoxFuture<'static, Result<(), SinkError>> + Send + Sync>;

/// Reusable closure adapter for atomic batch destinations
/// (`ReplayGuarantee::AtomicBatch`).
pub struct AtomicSink<T> {
    limits: SinkLimits,
    flush: Arc<dyn Fn(WriteAttempt<T>) -> FlushFuture + Send + Sync>,
    probe: Option<ProbeFn>,
}

impl<T> Clone for AtomicSink<T> {
    fn clone(&self) -> Self {
        Self {
            limits: self.limits,
            flush: self.flush.clone(),
            probe: self.probe.clone(),
        }
    }
}

impl<T: Send + Sync + 'static> AtomicSink<T> {
    pub fn try_new<F, Fut, R>(limits: SinkLimits, flush: F) -> Result<Self, ConfigurationError>
    where
        F: Fn(WriteAttempt<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<R, SinkError>> + Send + 'static,
        R: IntoAtomicWriteStatus + Send + 'static,
    {
        limits.validate()?;
        let flush = Arc::new(move |attempt: WriteAttempt<T>| -> FlushFuture {
            let fut = flush(attempt);
            Box::pin(async move {
                let status = fut.await?.into_atomic_status();
                match status {
                    AtomicWriteStatus::Applied | AtomicWriteStatus::AlreadyApplied => {
                        Ok(WriteOutcome::Complete)
                    }
                }
            })
        });
        Ok(Self {
            limits,
            flush,
            probe: None,
        })
    }

    #[must_use]
    pub fn with_probe<P, Fut>(mut self, probe: P) -> Self
    where
        P: Fn(Deadline) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), SinkError>> + Send + 'static,
    {
        self.probe = Some(Arc::new(move |deadline| Box::pin(probe(deadline))));
        self
    }
}

impl<T: Send + Sync + 'static> WriteSink<T> for AtomicSink<T> {
    fn limits(&self) -> &SinkLimits {
        &self.limits
    }

    fn replay_guarantee(&self) -> ReplayGuarantee {
        ReplayGuarantee::AtomicBatch
    }

    fn flush_writes(&self, attempt: WriteAttempt<T>) -> FlushFuture {
        (self.flush)(attempt)
    }

    fn probe(&self, deadline: Deadline) -> Option<BoxFuture<'static, Result<(), SinkError>>> {
        self.probe.as_ref().map(|probe| probe(deadline))
    }
}

/// Reusable closure adapter for independently idempotent partial-write
/// destinations.
pub struct PartialSink<T> {
    limits: SinkLimits,
    flush: Arc<dyn Fn(WriteAttempt<T>) -> FlushFuture + Send + Sync>,
    probe: Option<ProbeFn>,
}

impl<T> Clone for PartialSink<T> {
    fn clone(&self) -> Self {
        Self {
            limits: self.limits,
            flush: self.flush.clone(),
            probe: self.probe.clone(),
        }
    }
}

impl<T: Send + Sync + 'static> PartialSink<T> {
    pub fn try_new<F, Fut>(limits: SinkLimits, flush: F) -> Result<Self, ConfigurationError>
    where
        F: Fn(WriteAttempt<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<WriteOutcome, SinkError>> + Send + 'static,
    {
        limits.validate()?;
        let flush =
            Arc::new(move |attempt: WriteAttempt<T>| -> FlushFuture { Box::pin(flush(attempt)) });
        Ok(Self {
            limits,
            flush,
            probe: None,
        })
    }

    #[must_use]
    pub fn with_probe<P, Fut>(mut self, probe: P) -> Self
    where
        P: Fn(Deadline) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), SinkError>> + Send + 'static,
    {
        self.probe = Some(Arc::new(move |deadline| Box::pin(probe(deadline))));
        self
    }
}

impl<T: Send + Sync + 'static> WriteSink<T> for PartialSink<T> {
    fn limits(&self) -> &SinkLimits {
        &self.limits
    }

    fn replay_guarantee(&self) -> ReplayGuarantee {
        ReplayGuarantee::IndependentlyIdempotent
    }

    fn flush_writes(&self, attempt: WriteAttempt<T>) -> FlushFuture {
        (self.flush)(attempt)
    }

    fn probe(&self, deadline: Deadline) -> Option<BoxFuture<'static, Result<(), SinkError>>> {
        self.probe.as_ref().map(|probe| probe(deadline))
    }
}
