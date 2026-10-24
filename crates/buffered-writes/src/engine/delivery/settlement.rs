use super::turn::{AttemptNextStep, DeliveryTurn, HandoffOutcome};
use crate::{
    BufferError, BufferSettleRequest, LeasedSealedBatch, OperationId, QuarantineReason, QueueError,
    SettleDisposition, SinkError, SinkFailureKind, WriteEvent, write_outcome::WriteFailure,
};

impl<T: Send + Sync + 'static> DeliveryTurn<'_, T> {
    pub(super) async fn checkpoint_partial_progress(
        &mut self,
        leased: &mut LeasedSealedBatch,
        completed_ids: Vec<OperationId>,
    ) -> bool {
        // Unconfirmed checkpoint ends the turn; recovery rereads retained
        // membership.
        leased
            .pending_operation_ids
            .retain(|id| !completed_ids.contains(id));
        let completed = completed_ids.len();
        let retry_delay = self.engine.cfg.delivery_policy.retry_base_delay;
        if self
            .settle_leased(
                leased,
                SettleDisposition::PartialProgress {
                    completed_ids,
                    retry_delay,
                },
            )
            .await
            .is_err()
        {
            return false;
        }
        self.report.partial_operations_completed = self
            .report
            .partial_operations_completed
            .saturating_add(completed);
        self.engine
            .cfg
            .observer
            .observe(WriteEvent::PartialProgress {
                completed,
                remaining: leased.pending_operation_ids.len(),
            });
        true
    }

    pub(super) async fn quarantine_failed_writes(
        &mut self,
        leased: &LeasedSealedBatch,
        failure: WriteFailure,
    ) -> AttemptNextStep {
        let (reason, kind) = if matches!(failure.error, SinkError::IdentityConflict) {
            (
                QuarantineReason::IdentityConflict,
                SinkFailureKind::IdentityConflict,
            )
        } else {
            (
                QuarantineReason::PermanentSinkFailure,
                SinkFailureKind::Permanent,
            )
        };
        let completed = failure.completed_ids.len();
        if self
            .settle_leased(
                leased,
                SettleDisposition::Quarantine {
                    reason,
                    completed_ids: failure.completed_ids,
                },
            )
            .await
            .is_err()
        {
            return AttemptNextStep::Unconfirmed;
        }
        self.report.partial_operations_completed = self
            .report
            .partial_operations_completed
            .saturating_add(completed);
        self.engine
            .cfg
            .observer
            .observe(WriteEvent::Quarantined { reason });
        self.report.batches_failed = self.report.batches_failed.saturating_add(1);
        self.report.last_error = Some(kind);
        AttemptNextStep::Settled
    }

    fn retain_queue_failure(&mut self, error: QueueError) -> HandoffOutcome {
        self.engine.cfg.observer.observe(WriteEvent::QueueFailed {
            kind: (&error).into(),
        });
        self.report.queue_error = Some(error);
        HandoffOutcome::Retained
    }

    pub(super) async fn try_handoff_leased(
        &mut self,
        leased: &LeasedSealedBatch,
    ) -> HandoffOutcome {
        let Some(queue) = &self.engine.cfg.queue else {
            return HandoffOutcome::Retained;
        };
        match self
            .engine
            .complete_engine_operation(self.deadline, || {
                queue.publish(leased.batch.clone(), self.deadline)
            })
            .await
        {
            Some(Ok(_)) => {}
            Some(Err(error)) => return self.retain_queue_failure(error),
            None => return self.retain_queue_failure(QueueError::DeadlineExceeded),
        }
        if self
            .settle_leased(leased, SettleDisposition::HandedOffToQueue)
            .await
            .is_err()
        {
            return HandoffOutcome::Unconfirmed;
        }
        self.report.batches_queued = self.report.batches_queued.saturating_add(1);
        self.report.items_settled = self
            .report
            .items_settled
            .saturating_add(leased.unsettled_record_count);
        self.engine.cfg.observer.observe(WriteEvent::QueueHandoff {
            operations: leased.batch.operation_ids().len(),
            bytes: leased.batch.accounted_bytes(),
        });
        HandoffOutcome::Transferred
    }

    pub(super) async fn settle_leased(
        &mut self,
        leased: &LeasedSealedBatch,
        disposition: SettleDisposition,
    ) -> Result<(), BufferError> {
        let result = self
            .engine
            .complete_buffer_operation(self.deadline, || {
                self.engine.cfg.buffer.settle(BufferSettleRequest {
                    batch_id: leased.batch.batch_id(),
                    fencing_token: leased.fencing_token,
                    disposition,
                    now_utc_ms: self.engine.cfg.clock.now_utc().timestamp_millis(),
                    deadline: self.deadline,
                })
            })
            .await;
        if let Err(error) = &result {
            self.report.buffer_error = Some(error.clone());
        }
        result
    }
}
