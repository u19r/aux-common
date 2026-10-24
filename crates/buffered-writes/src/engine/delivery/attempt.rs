use std::time::Instant;

use super::turn::{AttemptNextStep, DeliveryTurn, HandoffOutcome};
use crate::{
    Deadline, DeliveryMode, LeasedSealedBatch, PrepareError, QuarantineReason, SettleDisposition,
    SinkError, SinkFailureKind, SinkHealth, WriteAttempt, WriteEvent, WriteOutcome,
    write_outcome::{ClassifiedWriteOutcome, WriteFailure},
};

impl<T: Send + Sync + 'static> DeliveryTurn<'_, T> {
    pub(super) async fn attempt_delivery(
        &mut self,
        leased: &mut LeasedSealedBatch,
        index: u32,
    ) -> AttemptNextStep {
        if !self.check_attempt_deadline() {
            return AttemptNextStep::StopTurn;
        }
        let Ok(attempt) = self.build_write_attempt(leased) else {
            let quarantined = self
                .settle_leased(
                    leased,
                    SettleDisposition::Quarantine {
                        reason: QuarantineReason::PoisonReplayEnvelope,
                        completed_ids: Vec::new(),
                    },
                )
                .await
                .is_ok();
            self.report.batches_failed = self.report.batches_failed.saturating_add(1);
            return if quarantined {
                AttemptNextStep::Settled
            } else {
                AttemptNextStep::Unconfirmed
            };
        };
        self.engine
            .cfg
            .observer
            .observe(WriteEvent::FlushAttempted {
                operations: leased.pending_operation_ids.len(),
                retry_attempt: index,
            });
        let started = self.engine.cfg.clock.now_instant();
        let outcome = self
            .engine
            .complete_engine_operation(attempt.deadline(), || {
                self.engine.cfg.sink.flush_writes(attempt)
            })
            .await
            .unwrap_or_else(|| Err(SinkError::unknown_outcome("sink attempt deadline exceeded")));
        let has_more = index + 1 < self.engine.cfg.delivery_policy.max_attempts_per_turn;
        self.apply_attempt_outcome(leased, outcome, started, has_more)
            .await
    }

    fn build_write_attempt(
        &self,
        leased: &LeasedSealedBatch,
    ) -> Result<WriteAttempt<T>, PrepareError> {
        leased.batch.validate_compatibility(
            &self.engine.cfg.namespace,
            self.engine.cfg.codec.version(),
            self.engine.cfg.batch_strategy.strategy_version(),
        )?;
        leased
            .batch
            .validate_sink_limits(self.engine.cfg.sink.limits())?;
        let now = self.engine.cfg.clock.now_instant();
        let budget = self
            .deadline
            .remaining_at(now)
            .min(self.engine.cfg.delivery_policy.attempt_timeout);
        WriteAttempt::try_new(
            leased.batch.clone(),
            self.engine.cfg.codec.as_ref(),
            leased.pending_operation_ids.clone().into(),
            Deadline::from_anchor(now, budget),
        )
        .map_err(PrepareError::from)
    }

    async fn apply_attempt_outcome(
        &mut self,
        leased: &mut LeasedSealedBatch,
        outcome: Result<WriteOutcome, SinkError>,
        started: Instant,
        has_more: bool,
    ) -> AttemptNextStep {
        let elapsed = self
            .engine
            .cfg
            .clock
            .now_instant()
            .saturating_duration_since(started);
        match outcome.and_then(|outcome| outcome.classify(&leased.pending_operation_ids)) {
            Ok(ClassifiedWriteOutcome::Complete) => {
                if self
                    .settle_leased(leased, SettleDisposition::Delivered)
                    .await
                    .is_err()
                {
                    return AttemptNextStep::Unconfirmed;
                }
                self.report.batches_flushed = self.report.batches_flushed.saturating_add(1);
                self.report.items_settled = self
                    .report
                    .items_settled
                    .saturating_add(leased.unsettled_record_count);
                self.engine.record_sink_success();
                self.engine
                    .cfg
                    .observer
                    .observe(WriteEvent::FlushCompleted {
                        operations: leased.pending_operation_ids.len(),
                        elapsed,
                    });
                AttemptNextStep::Settled
            }
            Ok(ClassifiedWriteOutcome::Incomplete(failure)) => {
                self.handle_sink_error(leased, failure, has_more).await
            }
            Err(error) => self.handle_sink_error(leased, error.into(), has_more).await,
        }
    }

    async fn handle_sink_error(
        &mut self,
        leased: &mut LeasedSealedBatch,
        failure: WriteFailure,
        has_more: bool,
    ) -> AttemptNextStep {
        let WriteFailure {
            error,
            mut completed_ids,
        } = failure;
        if error.is_retryable()
            && !completed_ids.is_empty()
            && !self
                .checkpoint_partial_progress(leased, std::mem::take(&mut completed_ids))
                .await
        {
            return AttemptNextStep::Unconfirmed;
        }
        match error {
            SinkError::IdentityConflict | SinkError::Permanent { .. } => {
                self.quarantine_failed_writes(
                    leased,
                    WriteFailure {
                        error,
                        completed_ids,
                    },
                )
                .await
            }
            SinkError::InvalidOutcome { .. } => {
                self.report.batches_failed = self.report.batches_failed.saturating_add(1);
                self.report.last_error = Some(SinkFailureKind::InvalidOutcome);
                AttemptNextStep::StopTurn
            }
            SinkError::Retryable { .. } | SinkError::UnknownOutcome { .. } => {
                self.retry_failed_write(leased, error, has_more).await
            }
        }
    }

    async fn retry_failed_write(
        &mut self,
        leased: &LeasedSealedBatch,
        error: SinkError,
        has_more: bool,
    ) -> AttemptNextStep {
        let kind = if error.is_unknown_outcome() {
            SinkFailureKind::UnknownOutcome
        } else {
            SinkFailureKind::Retryable
        };
        self.report.last_error = Some(kind);
        let age = leased
            .batch
            .age_at_utc_ms(self.engine.cfg.clock.now_utc().timestamp_millis());
        self.engine.record_sink_failure(age);
        self.engine.cfg.observer.observe(WriteEvent::FlushFailed {
            kind,
            retrying: has_more,
        });
        if age >= self.engine.cfg.delivery_policy.fallback_age {
            self.engine.transition_mode(DeliveryMode::Synchronous);
            match self.try_handoff_leased(leased).await {
                HandoffOutcome::Transferred => return AttemptNextStep::Settled,
                HandoffOutcome::Unconfirmed => return AttemptNextStep::Unconfirmed,
                HandoffOutcome::Retained => {}
            }
        }
        if has_more && self.engine.mode_and_health().1 != SinkHealth::Open {
            AttemptNextStep::RetrySameBatch
        } else {
            self.report.batches_failed = self.report.batches_failed.saturating_add(1);
            AttemptNextStep::StopTurn
        }
    }
}
