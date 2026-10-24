use super::super::state::Engine;
use crate::{
    Deadline, DeliveryMode, FlushReport, LeasedSealedBatch, SettleDisposition, SinkFailureKind,
    SinkHealth,
};

/// One serialized delivery budget. All attempt and settlement operations share
/// this deadline and report; the engine's turn permit remains with its caller.
pub(in crate::engine) struct DeliveryTurn<'a, T> {
    pub(super) engine: &'a Engine<T>,
    pub(super) deadline: Deadline,
    pub(super) report: &'a mut FlushReport,
}

pub(super) enum AttemptNextStep {
    Settled,
    Unconfirmed,
    RetrySameBatch,
    StopTurn,
}

pub(super) enum HandoffOutcome {
    Retained,
    Transferred,
    Unconfirmed,
}

impl<'a, T: Send + Sync + 'static> DeliveryTurn<'a, T> {
    pub(in crate::engine) fn new(
        engine: &'a Engine<T>,
        deadline: Deadline,
        report: &'a mut FlushReport,
    ) -> Self {
        Self {
            engine,
            deadline,
            report,
        }
    }

    pub(in crate::engine) async fn deliver(
        &mut self,
        mut leased: LeasedSealedBatch,
        force_all_ages: bool,
    ) -> bool {
        let age = leased
            .batch
            .age_at_utc_ms(self.engine.cfg.clock.now_utc().timestamp_millis());
        if self.engine.mode_and_health().1 == SinkHealth::Open
            && age >= self.engine.cfg.delivery_policy.fallback_age
        {
            self.engine.transition_mode(DeliveryMode::Synchronous);
        }
        if !self.engine.acquire_sink_permission(self.deadline).await {
            return self.settle_unavailable_sink(&leased, force_all_ages).await;
        }
        for index in 0..self.engine.cfg.delivery_policy.max_attempts_per_turn {
            match self.attempt_delivery(&mut leased, index).await {
                AttemptNextStep::Settled => return true,
                AttemptNextStep::Unconfirmed => return false,
                AttemptNextStep::RetrySameBatch => {
                    if !self.wait_before_retry(index).await {
                        break;
                    }
                }
                AttemptNextStep::StopTurn => break,
            }
        }
        self.release_for_retry(&leased).await;
        false
    }

    async fn settle_unavailable_sink(
        &mut self,
        leased: &LeasedSealedBatch,
        force_all_ages: bool,
    ) -> bool {
        let age = leased
            .batch
            .age_at_utc_ms(self.engine.cfg.clock.now_utc().timestamp_millis());
        if force_all_ages || age >= self.engine.cfg.delivery_policy.fallback_age {
            match self.try_handoff_leased(leased).await {
                HandoffOutcome::Transferred => return true,
                HandoffOutcome::Unconfirmed => return false,
                HandoffOutcome::Retained => {}
            }
        }
        self.report.batches_failed = self.report.batches_failed.saturating_add(1);
        self.release_for_retry(leased).await;
        false
    }

    async fn wait_before_retry(&self, index: u32) -> bool {
        let remaining = self
            .deadline
            .remaining_at(self.engine.cfg.clock.now_instant());
        self.engine
            .complete_engine_operation(self.deadline, || {
                self.engine
                    .cfg
                    .clock
                    .sleep(self.engine.retry_delay(index).min(remaining))
            })
            .await
            .is_some()
    }

    async fn release_for_retry(&mut self, leased: &LeasedSealedBatch) {
        let retry_delay = self.engine.cfg.delivery_policy.retry_base_delay;
        let _ = self
            .settle_leased(leased, SettleDisposition::ReleaseForRetry { retry_delay })
            .await;
    }

    pub(super) fn check_attempt_deadline(&mut self) -> bool {
        if self
            .deadline
            .is_expired_at(self.engine.cfg.clock.now_instant())
        {
            self.report.last_error = Some(SinkFailureKind::DeadlineExceeded);
            return false;
        }
        true
    }
}
