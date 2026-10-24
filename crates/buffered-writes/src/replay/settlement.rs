use super::{
    quarantine::ReplayQuarantine,
    worker::{ReplayReport, ReplayWorker},
};
use crate::{
    Deadline, QuarantineReason, QueueError, ReceivedEnvelope, ReplayObservation, SinkError,
    WriteEvent, write_outcome::ClassifiedWriteOutcome,
};

impl<T: Send + Sync + 'static> ReplayWorker<T> {
    pub(super) async fn handle_sink_result(
        &self,
        envelope: &ReceivedEnvelope,
        result: Result<ClassifiedWriteOutcome, SinkError>,
        deadline: Deadline,
        report: &mut ReplayReport,
    ) -> Result<(), QueueError> {
        let failure = match result {
            Ok(ClassifiedWriteOutcome::Complete) => {
                return self.acknowledge_delivery(envelope, deadline, report).await;
            }
            Ok(ClassifiedWriteOutcome::Incomplete(progress)) => progress,
            Err(error) => error.into(),
        };
        let reason = match failure.error {
            SinkError::IdentityConflict => QuarantineReason::IdentityConflict,
            SinkError::Permanent { .. } => QuarantineReason::PermanentSinkFailure,
            SinkError::Retryable { .. }
            | SinkError::UnknownOutcome { .. }
            | SinkError::InvalidOutcome { .. } => {
                report.batches_retained = report.batches_retained.saturating_add(1);
                self.observer.observe(WriteEvent::ReplayOutcome {
                    outcome: ReplayObservation::RetainedForRetry,
                });
                return Ok(());
            }
        };
        self.quarantine_envelope(
            ReplayQuarantine::from((envelope, reason)).with_completed(failure.completed_ids),
            deadline,
            report,
        )
        .await
    }

    async fn acknowledge_delivery(
        &self,
        envelope: &ReceivedEnvelope,
        deadline: Deadline,
        report: &mut ReplayReport,
    ) -> Result<(), QueueError> {
        self.complete_queue_operation(deadline, || {
            self.queue.acknowledge(&envelope.receipt_handle, deadline)
        })
        .await?;
        report.batches_delivered = report.batches_delivered.saturating_add(1);
        self.observer.observe(WriteEvent::ReplayOutcome {
            outcome: ReplayObservation::Delivered,
        });
        Ok(())
    }

    pub(super) async fn quarantine_envelope(
        &self,
        quarantine: ReplayQuarantine<'_>,
        deadline: Deadline,
        report: &mut ReplayReport,
    ) -> Result<(), QueueError> {
        let bytes = quarantine.encode()?;
        self.complete_queue_operation(deadline, || {
            self.queue.quarantine(
                &quarantine.envelope.receipt_handle,
                bytes,
                "buffered write replay quarantined",
                deadline,
            )
        })
        .await?;
        report.batches_quarantined = report.batches_quarantined.saturating_add(1);
        self.observer.observe(WriteEvent::Quarantined {
            reason: quarantine.reason,
        });
        self.observer.observe(WriteEvent::ReplayOutcome {
            outcome: ReplayObservation::Quarantined,
        });
        Ok(())
    }
}
