use std::sync::Arc;

use crate::{
    Clock, Deadline, DeliveryPolicy, Namespace, QueueError, RecordCodec, ReplayQueue,
    WriteObserver, WriteSink,
};

/// Report returned by a bounded [`ReplayWorker::replay_once`] pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayReport {
    pub messages_received: usize,
    pub batches_delivered: usize,
    pub batches_retained: usize,
    pub batches_quarantined: usize,
    pub partial_operations_completed: usize,
}

/// Replay worker that drains a [`ReplayQueue`] into a [`WriteSink`] with
/// visibility renewal, replay age cutoff enforcement, and poison-envelope
/// quarantine.
pub struct ReplayWorker<T> {
    pub(super) namespace: Namespace,
    pub(super) strategy_version: String,
    pub(super) queue: Arc<dyn ReplayQueue>,
    pub(super) sink: Arc<dyn WriteSink<T>>,
    pub(super) codec: Arc<dyn RecordCodec<T>>,
    pub(super) policy: DeliveryPolicy,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) observer: Arc<dyn WriteObserver>,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static> ReplayWorker<T> {
    /// Configure replay with the same namespace, codec, and strategy as the
    /// producer.
    #[must_use]
    pub fn builder(
        namespace: impl Into<String>,
        queue: impl ReplayQueue,
        sink: impl WriteSink<T>,
    ) -> super::builder::ReplayBuilder<T> {
        super::builder::ReplayBuilder::new(namespace.into(), queue, sink)
    }
}

impl<T: Send + Sync + 'static> ReplayWorker<T> {
    pub async fn replay_once(
        &self,
        max_messages: usize,
        deadline: impl Into<Deadline>,
    ) -> Result<ReplayReport, QueueError> {
        let deadline = deadline.into();
        let envelopes = self
            .complete_queue_operation(deadline, || self.queue.receive(max_messages, deadline))
            .await?;
        let mut report = ReplayReport {
            messages_received: envelopes.len(),
            ..ReplayReport::default()
        };
        for envelope in envelopes {
            self.deliver_envelope(envelope, deadline, &mut report)
                .await?;
        }
        Ok(report)
    }

    pub(super) async fn complete_queue_operation<R, F>(
        &self,
        deadline: Deadline,
        operation: impl FnOnce() -> F,
    ) -> Result<R, QueueError>
    where
        F: std::future::Future<Output = Result<R, QueueError>>,
    {
        let result = if deadline.is_expired_at(self.clock.now_instant()) {
            Err(QueueError::DeadlineExceeded)
        } else {
            self.clock
                .complete_before(deadline, async move { operation().await })
                .await
                .unwrap_or(Err(QueueError::DeadlineExceeded))
        };
        if let Err(error) = &result {
            self.observer
                .observe(crate::WriteEvent::QueueFailed { kind: error.into() });
        }
        result
    }
}
