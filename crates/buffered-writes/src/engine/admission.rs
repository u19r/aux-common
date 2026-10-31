use super::state::Engine;
use crate::{
    batch::AdmittedRecord,
    buffer::BufferAppendRequest,
    configuration::{
        Admission, AdmissionStatus, BackpressurePolicy, Deadline, DurabilityClass, OperationId,
        WriteOptions,
    },
    constants::DEFAULT_SUBMIT_TIMEOUT,
    error::{BufferError, WriteError},
    observer::{AdmissionRejectReason, DeliveryMode, SinkFailureKind, SinkHealth, WriteEvent},
    write_sink::ReplayGuarantee,
};

impl<T: Send + Sync + 'static> Engine<T> {
    pub(crate) async fn admit_factory(
        &self,
        create: impl FnOnce() -> Result<T, crate::EncodeError> + Send,
        options: WriteOptions,
    ) -> Result<Admission, WriteError> {
        self.admit_with_factory(create, options)
            .await
            .inspect_err(|error| self.observe_admission_rejection(error))
    }

    async fn admit_with_factory(
        &self,
        create: impl FnOnce() -> Result<T, crate::EncodeError> + Send,
        options: WriteOptions,
    ) -> Result<Admission, WriteError> {
        let (_submission, mut admission) = self.admissions.begin(self.cfg.capacity.item_limit())?;
        let deadline = self.admission_deadline(&options)?;
        let mut reservation = self
            .reserve_staging(deadline, options.operation_id())
            .await?;
        if self.admissions.is_closed() {
            return Err(WriteError::Closed);
        }
        let record = self
            .prepare_staged_record(
                create().map_err(WriteError::Encode)?,
                options,
                deadline,
                &mut reservation,
            )
            .await?;
        let append_res = self
            .append_with_backpressure(&record, deadline, &mut admission)
            .await?;
        drop(reservation);
        drop(admission);
        self.finish_admission(record, append_res, deadline).await
    }

    fn admission_deadline(&self, options: &WriteOptions) -> Result<Deadline, WriteError> {
        let now_instant = self.cfg.clock.now_instant();
        let deadline = options
            .deadline()
            .unwrap_or_else(|| Deadline::from_anchor(now_instant, DEFAULT_SUBMIT_TIMEOUT));
        if deadline.is_expired_at(now_instant) {
            return Err(WriteError::DeadlineExceeded {
                operation_id: options.operation_id().cloned(),
                accepted: false,
            });
        }
        Ok(deadline)
    }

    pub(super) fn create_admission_record(
        &self,
        item: &T,
        mut options: WriteOptions,
    ) -> Result<AdmittedRecord, WriteError> {
        if options.scope().is_none()
            && let Some(extractor) = &self.cfg.scope_extractor
        {
            options = options.with_scope(extractor(item)?);
        }
        let operation_id = options
            .operation_id()
            .cloned()
            .unwrap_or_else(OperationId::generate_v7);
        let scope = options
            .scope()
            .cloned()
            .unwrap_or_else(|| self.default_scope.clone());
        Ok(AdmittedRecord {
            operation_id,
            scope,
            codec_version: self.cfg.codec.version().to_owned(),
            admitted_at_utc_ms: self.cfg.clock.now_utc().timestamp_millis(),
            admitted_at_mono: self.cfg.clock.now_instant(),
            payload: bytes::Bytes::new(),
        })
    }

    async fn finish_admission(
        &self,
        record: AdmittedRecord,
        append_res: crate::buffer::BufferAppendResult,
        deadline: Deadline,
    ) -> Result<Admission, WriteError> {
        let bytes = record.payload.len();
        let admission = if self.mode_and_health().0 == DeliveryMode::Synchronous {
            let fingerprint = record.admission_fingerprint();
            self.settle_synchronous_submission(
                record.operation_id,
                append_res.watermark,
                deadline,
                fingerprint,
            )
            .await?
        } else {
            self.flush_signal.notify();
            Admission::new(
                AdmissionStatus::Buffered,
                append_res.durability,
                record.operation_id,
            )
        };
        self.cfg.observer.observe(WriteEvent::Admitted {
            status: admission.status(),
            durability: admission.durability(),
            bytes,
        });
        Ok(admission)
    }

    fn observe_admission_rejection(&self, error: &WriteError) {
        if !error.is_definitely_rejected() {
            return;
        }
        let reason = match error {
            WriteError::Full => AdmissionRejectReason::Full,
            WriteError::Closed => AdmissionRejectReason::Closed,
            WriteError::OversizedItem { .. } => AdmissionRejectReason::Oversized,
            WriteError::IdentityConflict { .. } => AdmissionRejectReason::IdentityConflict,
            WriteError::DeadlineExceeded { .. } => AdmissionRejectReason::DeadlineExceeded,
            WriteError::Encode(_)
            | WriteError::Configuration(_)
            | WriteError::InvalidScope { .. }
            | WriteError::Rejected { .. } => AdmissionRejectReason::InvalidInput,
            WriteError::Unavailable { .. }
            | WriteError::Ambiguous { .. }
            | WriteError::CorruptBuffer { .. } => AdmissionRejectReason::Unavailable,
        };
        self.cfg
            .observer
            .observe(WriteEvent::AdmissionRejected { reason });
    }

    pub(super) async fn append_with_backpressure(
        &self,
        record: &AdmittedRecord,
        deadline: Deadline,
        admission: &mut super::admission_gate::AdmissionLease<'_>,
    ) -> Result<crate::buffer::BufferAppendResult, WriteError> {
        loop {
            match self.append_once(record, deadline, admission).await {
                Err(WriteError::Full)
                    if self.cfg.capacity.backpressure_policy()
                        == BackpressurePolicy::WaitUntilDeadline =>
                {
                    self.wait_for_capacity(deadline, Some(&record.operation_id))
                        .await?;
                }
                result => return result,
            }
        }
    }

    async fn append_once(
        &self,
        record: &AdmittedRecord,
        deadline: Deadline,
        admission: &mut super::admission_gate::AdmissionLease<'_>,
    ) -> Result<crate::buffer::BufferAppendResult, WriteError> {
        self.check_staging_deadline(deadline, Some(&record.operation_id))?;
        let fingerprint = record.admission_fingerprint();
        let result = self
            .complete_buffer_operation(deadline, || async {
                admission.dispatch(
                    &record.operation_id,
                    self.admission_byte_charge(record),
                    self.cfg.capacity.item_limit(),
                    fingerprint,
                )?;
                self.cfg
                    .buffer
                    .append(BufferAppendRequest {
                        record: record.clone(),
                        reserved_bytes: self.admission_reserved_bytes(record),
                        capacity: self.cfg.capacity,
                        deadline,
                    })
                    .await
            })
            .await;
        let uncertain = matches!(
            &result,
            Err(BufferError::DeadlineExceeded | BufferError::AmbiguousAdmission { .. })
        );
        if !uncertain {
            admission.finish(result.is_ok());
        }
        if matches!(result, Err(BufferError::DeadlineExceeded)) && !admission.was_dispatched() {
            return Err(WriteError::DeadlineExceeded {
                operation_id: Some(record.operation_id.clone()),
                accepted: false,
            });
        }
        result.map_err(|error| self.map_append_error(error, &record.operation_id))
    }

    pub(super) fn map_append_error(&self, err: BufferError, op_id: &OperationId) -> WriteError {
        match err {
            BufferError::Full => WriteError::Full,
            BufferError::Configuration(error) => WriteError::Configuration(error),
            BufferError::DuplicateIdentityConflict { .. } => WriteError::IdentityConflict {
                operation_id: op_id.clone(),
            },
            BufferError::DeadlineExceeded => WriteError::Ambiguous {
                operation_id: op_id.clone(),
            },
            BufferError::AmbiguousAdmission { .. } => WriteError::Ambiguous {
                operation_id: op_id.clone(),
            },
            BufferError::OversizedItem { size, limit } => WriteError::OversizedItem { size, limit },
            BufferError::CorruptStorage { reason } => WriteError::CorruptBuffer { reason },
            _ => WriteError::Unavailable {
                operation_id: Some(op_id.clone()),
                accepted: false,
            },
        }
    }

    pub(super) async fn settle_synchronous_submission(
        &self,
        operation_id: OperationId,
        watermark: u64,
        deadline: Deadline,
        expected: crate::batch::AdmissionFingerprint,
    ) -> Result<Admission, WriteError> {
        if deadline.is_expired_at(self.cfg.clock.now_instant()) {
            return Err(WriteError::DeadlineExceeded {
                operation_id: Some(operation_id),
                accepted: true,
            });
        }
        let report = self.flush_turn(Some(watermark), true, deadline).await;
        let status = self
            .inspect_admission(&operation_id, deadline)
            .await
            .filter(|receipt| receipt.fingerprint == expected)
            .map(|receipt| receipt.status);
        if status == Some(AdmissionStatus::Written) {
            let durability = match self.cfg.sink.replay_guarantee() {
                ReplayGuarantee::AtomicBatch => DurabilityClass::SinkCommittedAtomic,
                ReplayGuarantee::IndependentlyIdempotent | ReplayGuarantee::Unsupported => {
                    DurabilityClass::SinkCommittedIdempotent
                }
            };
            return Ok(Admission::new(
                AdmissionStatus::Written,
                durability,
                operation_id,
            ));
        }
        if self.cfg.delivery_policy.allow_queue_success && status == Some(AdmissionStatus::Queued) {
            return Ok(Admission::new(
                AdmissionStatus::Queued,
                DurabilityClass::QueueHandedOff,
                operation_id,
            ));
        }
        if report.last_error == Some(SinkFailureKind::UnknownOutcome)
            || report.queue_error == Some(crate::QueueError::AmbiguousPublish)
        {
            return Err(WriteError::Ambiguous { operation_id });
        }
        if deadline.is_expired_at(self.cfg.clock.now_instant()) {
            return Err(WriteError::DeadlineExceeded {
                operation_id: Some(operation_id),
                accepted: true,
            });
        }
        Err(WriteError::Unavailable {
            operation_id: Some(operation_id),
            accepted: true,
        })
    }

    pub(super) async fn inspect_admission(
        &self,
        operation_id: &OperationId,
        deadline: Deadline,
    ) -> Option<crate::buffer::AdmissionReceipt> {
        self.complete_buffer_operation(deadline, || {
            self.cfg.buffer.inspect(crate::BufferInspectRequest {
                operation_id: Some(operation_id.clone()),
                now_utc_ms: self.cfg.clock.now_utc().timestamp_millis(),
                now_instant: self.cfg.clock.now_instant(),
                deadline,
            })
        })
        .await
        .ok()
        .and_then(|snapshot| snapshot.admission)
    }

    pub(super) async fn acquire_sink_permission(&self, deadline: Deadline) -> bool {
        let now = self.cfg.clock.now_instant();
        let probe_due = {
            let guard = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match guard.health {
                SinkHealth::Closed => return true,
                SinkHealth::HalfOpen => return true,
                SinkHealth::Open => guard.next_probe_at.is_some_and(|t| now >= t),
            }
        };
        if !probe_due {
            return false;
        }
        let probe_deadline = Deadline::from_anchor(now, self.cfg.delivery_policy.attempt_timeout)
            .shorten_to(deadline, now);
        let probe_result = self
            .complete_engine_operation(probe_deadline, || async {
                match self.cfg.sink.probe(probe_deadline) {
                    Some(probe) => probe.await,
                    None => Ok(()),
                }
            })
            .await;
        if probe_result.is_none_or(|result| result.is_err()) {
            self.record_sink_failure(std::time::Duration::ZERO);
            return false;
        }
        self.transition_health(SinkHealth::HalfOpen);
        true
    }
}
