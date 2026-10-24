use std::{future::Future, time::Duration};

/// Transport settlement after one delivery. This does not grant execution
/// authority or replace durable job fencing and replay receipts.
///
/// Propagate the owner's decision to the transport. Even after checking an
/// error with `?`, discarding the decision must not silently complete a retry.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use bg_jobs_tokio::QueueOutcome;
/// fn execute() -> Result<QueueOutcome, ()> {
///     Ok(QueueOutcome::RetryAfter(std::time::Duration::from_secs(30)))
/// }
/// fn dispatch() -> Result<QueueOutcome, ()> {
///     execute()?;
///     Ok(QueueOutcome::Complete)
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "propagate or settle the owner's queue outcome; discarding it can lose a retry"]
pub enum QueueOutcome {
    Complete,
    RetryAfter(Duration),
}

/// Adapter for an existing leased queue transport and its business handler.
///
/// Receive at most one leased delivery per worker. Report diagnostic errors in
/// the adapter; return the retry delay for receive failures. A failed handler
/// or renewal leaves the delivery unsettled so its transport lease can expire.
/// Cancelling receive or execute must leave unfinished work recoverable.
pub trait QueueWorker: Send + Sync + 'static {
    type Message: Send + Sync + 'static;

    fn receive(&self) -> impl Future<Output = Result<Option<Self::Message>, Duration>> + Send;
    fn execute(&self, message: &Self::Message)
    -> impl Future<Output = Option<QueueOutcome>> + Send;
    fn renew(&self, message: &Self::Message) -> impl Future<Output = bool> + Send;
    fn settle(
        &self,
        message: &Self::Message,
        outcome: QueueOutcome,
    ) -> impl Future<Output = ()> + Send;
}
