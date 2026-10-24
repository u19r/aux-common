use super::{delivery::DeliveryTurn, state::Engine};
use crate::{
    buffer::{
        BufferClaimRequest, BufferInspectRequest, BufferSealAction, BufferSealRequest,
        BufferSnapshot, ClaimedWork, LeasedSealedBatch, OpenBatchCandidate,
    },
    configuration::Deadline,
    error::{BufferError, PrepareError},
    observer::{FlushReport, QuarantineReason, SinkHealth, WriteEvent},
};

impl<T: Send + Sync + 'static> Engine<T> {
    pub(crate) async fn after_response(&self) -> FlushReport {
        let force_capacity = self.flush_signal.take_capacity_request();
        let deadline = Deadline::from_anchor(
            self.cfg.clock.now_instant(),
            self.cfg.delivery_policy.flush_budget,
        );
        let snapshot = match self.inspect_now(deadline).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return FlushReport {
                    buffer_error: Some(error),
                    ..self.empty_report()
                };
            }
        };
        self.flush_turn(Some(snapshot.watermark), force_capacity, deadline)
            .await
    }

    #[cfg(feature = "tokio")]
    pub(crate) async fn flush_eligible_writes(&self) -> FlushReport {
        let force_capacity = self.flush_signal.take_capacity_request();
        let deadline = Deadline::from_anchor(
            self.cfg.clock.now_instant(),
            self.cfg.delivery_policy.flush_budget,
        );
        self.flush_turn(None, force_capacity, deadline).await
    }

    pub(crate) async fn flush_writes(&self) -> FlushReport {
        let deadline = Deadline::from_anchor(
            self.cfg.clock.now_instant(),
            self.cfg.delivery_policy.flush_budget,
        );
        self.flush_turn(None, true, deadline).await
    }

    pub(super) async fn complete_buffer_operation<F, R>(
        &self,
        deadline: Deadline,
        operation: impl FnOnce() -> F,
    ) -> Result<R, BufferError>
    where
        F: std::future::Future<Output = Result<R, BufferError>>,
    {
        self.complete_engine_operation(deadline, operation)
            .await
            .unwrap_or(Err(BufferError::DeadlineExceeded))
    }

    pub(crate) async fn inspect_now(
        &self,
        deadline: Deadline,
    ) -> Result<BufferSnapshot, BufferError> {
        let revision = self
            .inspection_revision
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .saturating_add(1);
        let observation = self
            .complete_buffer_operation(deadline, || {
                self.cfg.buffer.inspect(BufferInspectRequest {
                    operation_id: None,
                    now_utc_ms: self.cfg.clock.now_utc().timestamp_millis(),
                    now_instant: self.cfg.clock.now_instant(),
                    deadline,
                })
            })
            .await;
        self.cfg.observer.observe(match &observation {
            Ok(snapshot) => WriteEvent::BufferObserved {
                stats: snapshot.stats,
                revision,
            },
            Err(_) => WriteEvent::BufferInspectionFailed { revision },
        });
        observation
    }

    pub(super) async fn flush_turn(
        &self,
        max_watermark: Option<u64>,
        force_all_ages: bool,
        deadline: Deadline,
    ) -> FlushReport {
        let mut report = self.empty_report();
        let Some(_turn_guard) = self
            .complete_engine_operation(deadline, || self.turn_lock.lock())
            .await
        else {
            report.last_error = Some(crate::SinkFailureKind::DeadlineExceeded);
            return report;
        };
        while !deadline.is_expired_at(self.cfg.clock.now_instant()) {
            let snapshot = match self.inspect_flush_capacity(deadline, &mut report).await {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    report.buffer_error = Some(error);
                    break;
                }
            };
            if snapshot.unsettled_items == 0 {
                self.maybe_restore_buffered_mode(true);
                break;
            }
            let fallback_due = snapshot.stats.oldest_age() >= self.cfg.delivery_policy.fallback_age;
            let policy_eligible = force_all_ages
                || self.cfg.flush_policy.should_flush(&snapshot.stats)
                || (fallback_due && self.mode_and_health().1 != SinkHealth::Closed);
            if !policy_eligible && snapshot.claimable_sealed_batches == 0 {
                break;
            }
            let Some(leased) = self
                .claim_and_seal_next(
                    max_watermark,
                    policy_eligible,
                    force_all_ages,
                    deadline,
                    &mut report,
                )
                .await
            else {
                break;
            };
            if !DeliveryTurn::new(self, deadline, &mut report)
                .deliver(leased, force_all_ages)
                .await
            {
                break;
            }
        }
        match self.inspect_now(deadline).await {
            Err(error) => report.buffer_error = Some(error),
            Ok(snapshot) => {
                report.quarantined_items = snapshot.quarantined_items;
                report.unresolved_batches = snapshot.unresolved_batch_ids;
                let no_eligible = snapshot.unsettled_items == 0
                    || !self.cfg.flush_policy.should_flush(&snapshot.stats);
                self.maybe_restore_buffered_mode(no_eligible);
            }
        }
        let (mode, health) = self.mode_and_health();
        report.mode = mode;
        report.sink_health = health;
        report
    }

    async fn inspect_flush_capacity(
        &self,
        deadline: Deadline,
        report: &mut FlushReport,
    ) -> Result<BufferSnapshot, BufferError> {
        let snapshot = self.inspect_now(deadline).await?;
        report.quarantined_items = snapshot.quarantined_items;
        report
            .unresolved_batches
            .clone_from(&snapshot.unresolved_batch_ids);
        self.validate_retained_capacity(&snapshot)?;
        Ok(snapshot)
    }

    pub(super) async fn claim_and_seal_next(
        &self,
        max_watermark: Option<u64>,
        allow_open_claim: bool,
        force_all_ages: bool,
        deadline: Deadline,
        report: &mut FlushReport,
    ) -> Option<LeasedSealedBatch> {
        loop {
            let claimed = self
                .complete_buffer_operation(deadline, || {
                    self.cfg.buffer.claim(BufferClaimRequest {
                        max_watermark,
                        allow_open_claim,
                        force_all_ages,
                        max_items: self.cfg.preparation.input_items(),
                        max_bytes: self.cfg.preparation.input_bytes(),
                        lease_duration: self.cfg.delivery_policy.lease_duration,
                        now_utc_ms: self.cfg.clock.now_utc().timestamp_millis(),
                        now_instant: self.cfg.clock.now_instant(),
                        deadline,
                    })
                })
                .await
                .map_err(|error| report.buffer_error = Some(error))
                .ok()?;
            match claimed {
                ClaimedWork::None => return None,
                ClaimedWork::ExistingSealed(leased) => return Some(leased),
                ClaimedWork::OpenCandidate(candidate) => {
                    match self
                        .seal_candidate_with_splitting(candidate, deadline, report)
                        .await
                    {
                        Ok(Some(leased)) => return Some(leased),
                        Ok(None) => {}
                        Err(error) => {
                            report.buffer_error = Some(error);
                            return None;
                        }
                    }
                }
            }
        }
    }

    pub(super) async fn seal_candidate_with_splitting(
        &self,
        candidate: OpenBatchCandidate,
        deadline: Deadline,
        report: &mut FlushReport,
    ) -> Result<Option<LeasedSealedBatch>, BufferError> {
        if let Err(error) = self.validate_candidate_configuration(&candidate) {
            self.release_candidate(candidate.fencing_token, deadline)
                .await?;
            return Err(error);
        }
        let mut count = candidate.records.len();
        loop {
            let slice = &candidate.records[..count];
            let reserved = candidate.reserved_bytes[..count]
                .iter()
                .copied()
                .fold(0usize, usize::saturating_add);
            match self.prepare_candidate_slice(slice, reserved) {
                Ok(sealed) => {
                    return self
                        .install_prepared_batch(
                            sealed,
                            candidate.fencing_token,
                            deadline,
                            slice[0].admitted_at_mono,
                        )
                        .await
                        .map(Some);
                }
                Err(
                    PrepareError::CandidateTooLarge { .. } | PrepareError::TooManyOperations { .. },
                ) if count > 1 => count /= 2,
                Err(_) if count > 1 => count = 1,
                Err(err) => {
                    self.quarantine_candidate_singleton(&candidate, err, deadline, report)
                        .await?;
                    return Ok(None);
                }
            }
        }
    }

    async fn install_prepared_batch(
        &self,
        sealed: crate::batch::SealedBatch,
        fence: crate::FencingToken,
        deadline: Deadline,
        admitted_at: std::time::Instant,
    ) -> Result<LeasedSealedBatch, BufferError> {
        let leased = self
            .complete_buffer_operation(deadline, || {
                self.cfg.buffer.seal(BufferSealRequest {
                    fencing_token: fence,
                    action: BufferSealAction::InstallBatch(sealed),
                    capacity: self.cfg.capacity,
                    lease_duration: self.cfg.delivery_policy.lease_duration,
                    now_utc_ms: self.cfg.clock.now_utc().timestamp_millis(),
                    deadline,
                })
            })
            .await?
            .ok_or(BufferError::InvalidRequest {
                reason: "installed batch has no retained lease acknowledgement",
            })?;
        self.observe_sealed_batch(&leased.batch, admitted_at);
        Ok(leased)
    }

    async fn release_candidate(
        &self,
        fence: crate::FencingToken,
        deadline: Deadline,
    ) -> Result<(), BufferError> {
        self.complete_buffer_operation(deadline, || {
            self.cfg.buffer.seal(BufferSealRequest {
                fencing_token: fence,
                action: BufferSealAction::ReleaseCandidate,
                capacity: self.cfg.capacity,
                lease_duration: self.cfg.delivery_policy.lease_duration,
                now_utc_ms: self.cfg.clock.now_utc().timestamp_millis(),
                deadline,
            })
        })
        .await?;
        Ok(())
    }

    pub(super) async fn quarantine_candidate_singleton(
        &self,
        candidate: &OpenBatchCandidate,
        err: PrepareError,
        deadline: Deadline,
        report: &mut FlushReport,
    ) -> Result<(), BufferError> {
        let reason = match err {
            PrepareError::CandidateTooLarge { .. } | PrepareError::TooManyOperations { .. } => {
                QuarantineReason::OversizedSingleton
            }
            _ => QuarantineReason::PermanentPrepareError,
        };
        self.complete_buffer_operation(deadline, || {
            self.cfg.buffer.seal(BufferSealRequest {
                fencing_token: candidate.fencing_token,
                action: BufferSealAction::QuarantineSingleton {
                    operation_id: candidate.records[0].operation_id.clone(),
                    reason: "candidate preparation failed on singleton",
                },
                capacity: self.cfg.capacity,
                lease_duration: self.cfg.delivery_policy.lease_duration,
                now_utc_ms: self.cfg.clock.now_utc().timestamp_millis(),
                deadline,
            })
        })
        .await?;
        self.cfg
            .observer
            .observe(WriteEvent::Quarantined { reason });
        report.batches_failed = report.batches_failed.saturating_add(1);
        Ok(())
    }
    fn observe_sealed_batch(
        &self,
        batch: &crate::batch::SealedBatch,
        admitted_at: std::time::Instant,
    ) {
        self.cfg.observer.observe(WriteEvent::BatchSealed {
            operations: batch.operation_ids().len(),
            bytes: batch.accounted_bytes(),
            oldest_age: self
                .cfg
                .clock
                .now_instant()
                .saturating_duration_since(admitted_at),
        });
    }
}
