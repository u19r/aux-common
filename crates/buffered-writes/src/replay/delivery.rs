use super::{
    quarantine::ReplayQuarantine,
    worker::{ReplayReport, ReplayWorker},
};
use crate::{
    Deadline, QuarantineReason, QueueError, ReceivedEnvelope, SealedBatch, SinkError, WriteAttempt,
};

impl<T: Send + Sync + 'static> ReplayWorker<T> {
    pub(super) async fn deliver_envelope(
        &self,
        envelope: ReceivedEnvelope,
        deadline: Deadline,
        report: &mut ReplayReport,
    ) -> Result<(), QueueError> {
        let attempt = match self.prepare_replay_attempt(&envelope, deadline) {
            Ok(attempt) => attempt,
            Err(reason) => {
                return self
                    .quarantine_envelope(
                        ReplayQuarantine::from((&envelope, reason)),
                        deadline,
                        report,
                    )
                    .await;
            }
        };
        let batch = attempt.sealed_batch().clone();
        self.complete_queue_operation(deadline, || {
            self.queue.renew_visibility(
                &envelope.receipt_handle,
                self.policy.lease_duration,
                deadline,
            )
        })
        .await?;

        let result = self
            .clock
            .complete_before(attempt.deadline(), async {
                self.sink.flush_writes(attempt).await
            })
            .await
            .unwrap_or_else(|| {
                Err(SinkError::unknown_outcome(
                    "replay attempt deadline exceeded",
                ))
            });
        let result = result.and_then(|outcome| outcome.classify(batch.operation_ids()));
        self.observe_partial_progress(&result, batch.operation_ids().len(), report);
        self.handle_sink_result(&envelope, result, deadline, report)
            .await
    }

    fn observe_partial_progress(
        &self,
        result: &Result<crate::write_outcome::ClassifiedWriteOutcome, SinkError>,
        operation_count: usize,
        report: &mut ReplayReport,
    ) {
        if let Ok(crate::write_outcome::ClassifiedWriteOutcome::Incomplete(progress)) = &result {
            let completed = progress.completed_ids.len();
            report.partial_operations_completed = report
                .partial_operations_completed
                .saturating_add(completed);
            self.observer.observe(crate::WriteEvent::PartialProgress {
                completed,
                remaining: operation_count.saturating_sub(completed),
            });
        }
    }

    fn prepare_replay_attempt(
        &self,
        envelope: &ReceivedEnvelope,
        deadline: Deadline,
    ) -> Result<WriteAttempt<T>, QuarantineReason> {
        let poison = QuarantineReason::PoisonReplayEnvelope;
        if envelope.envelope_bytes.len() > self.queue.limits().max_envelope_bytes() {
            return Err(poison);
        }
        let batch =
            SealedBatch::from_envelope_bytes(&envelope.envelope_bytes).map_err(|_| poison)?;
        batch
            .validate_compatibility(
                &self.namespace,
                self.codec.version(),
                &self.strategy_version,
            )
            .map_err(|_| poison)?;
        batch
            .validate_sink_limits(self.sink.limits())
            .map_err(|_| poison)?;
        self.validate_replay_age(&batch)?;
        let now = self.clock.now_instant();
        let attempt_deadline =
            Deadline::from_anchor(now, self.policy.attempt_timeout).shorten_to(deadline, now);
        let pending = batch.operation_ids().into();
        WriteAttempt::try_new(batch, self.codec.as_ref(), pending, attempt_deadline)
            .map_err(|_| poison)
    }

    fn validate_replay_age(&self, batch: &SealedBatch) -> Result<(), QuarantineReason> {
        let Some(max_age) = self.policy.max_replay_age else {
            return Ok(());
        };
        let now = self.clock.now_utc().timestamp_millis();
        if now < batch.first_item_time_ms() {
            return Err(QuarantineReason::UncertainReplayAge);
        }
        if batch.age_at_utc_ms(now) > max_age {
            return Err(QuarantineReason::ExpiredReplayEnvelope);
        }
        Ok(())
    }
}
