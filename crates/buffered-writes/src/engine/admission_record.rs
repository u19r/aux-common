use super::state::Engine;
use crate::{
    batch::AdmittedRecord,
    configuration::{BackpressurePolicy, Deadline, OperationId, WriteOptions},
    error::{EncodeError, WriteError},
    retention::RetentionState,
};

pub(super) struct StagingReservation<'a> {
    _turn: futures_util::lock::MutexGuard<'a, ()>,
    available_bytes: usize,
}

impl<'a> StagingReservation<'a> {
    pub(super) fn new(
        turn: futures_util::lock::MutexGuard<'a, ()>,
        available_bytes: usize,
    ) -> Self {
        Self {
            _turn: turn,
            available_bytes,
        }
    }
}

impl<T: Send + Sync + 'static> Engine<T> {
    pub(super) async fn prepare_staged_record(
        &self,
        item: T,
        options: WriteOptions,
        deadline: Deadline,
        staging: &mut StagingReservation<'_>,
    ) -> Result<AdmittedRecord, WriteError> {
        self.check_staging_deadline(deadline, options.operation_id())?;
        let mut record = self.create_admission_record(&item, options)?;
        loop {
            self.check_staging_deadline(deadline, Some(&record.operation_id))?;
            record.payload = bytes::Bytes::new();
            match self.encode_staged_record(&item, &mut record, staging.available_bytes) {
                Err(WriteError::Full)
                    if self.cfg.capacity.backpressure_policy()
                        == BackpressurePolicy::WaitUntilDeadline =>
                {
                    staging.available_bytes = self
                        .wait_for_staging_bytes(deadline, &record.operation_id)
                        .await?;
                }
                Err(error) => return Err(error),
                Ok(()) => return Ok(record),
            }
        }
    }

    pub(super) fn check_staging_deadline(
        &self,
        requested: Deadline,
        id: Option<&OperationId>,
    ) -> Result<(), WriteError> {
        let now = self.cfg.clock.now_instant();
        if self
            .drain_deadline
            .constrain(requested, now)
            .is_expired_at(now)
        {
            return Err(WriteError::DeadlineExceeded {
                operation_id: id.cloned(),
                accepted: false,
            });
        }
        Ok(())
    }

    pub(super) fn admission_reserved_bytes(&self, record: &AdmittedRecord) -> usize {
        let requested = self.cfg.preparation.retained_reservation(
            record,
            &self.cfg.namespace,
            self.cfg.batch_strategy.strategy_version(),
        );
        RetentionState::admission_reserved_bytes(record, requested)
    }

    pub(super) fn admission_byte_charge(&self, record: &AdmittedRecord) -> usize {
        self.admission_reserved_bytes(record)
            .saturating_add(RetentionState::admission_receipt_bytes(record))
    }

    fn encode_staged_record(
        &self,
        item: &T,
        record: &mut AdmittedRecord,
        available: usize,
    ) -> Result<(), WriteError> {
        let overhead = record
            .accounted_bytes()
            .saturating_add(RetentionState::admission_receipt_bytes(record));
        let single_limit = self
            .cfg
            .preparation
            .input_bytes()
            .min(self.cfg.capacity.byte_limit().saturating_sub(overhead));
        let limit = single_limit.min(available.saturating_sub(overhead));
        let payload = self.cfg.codec.encode(item, limit).and_then(|payload| {
            if payload.len() > limit {
                return Err(EncodeError::PayloadTooLarge {
                    size: payload.len(),
                    limit,
                });
            }
            Ok(payload)
        });
        record.payload = payload.map_err(|error| {
            if matches!(error, EncodeError::PayloadTooLarge { .. }) && limit < single_limit {
                return WriteError::Full;
            }
            self.cfg
                .preparation
                .admission_error(error, &self.cfg.effective_limits, limit)
        })?;
        let charge = self.admission_byte_charge(record);
        if charge > self.cfg.capacity.byte_limit() {
            return Err(WriteError::OversizedItem {
                size: charge,
                limit: self.cfg.capacity.byte_limit(),
            });
        }
        if charge > available {
            return Err(WriteError::Full);
        }
        Ok(())
    }

    async fn wait_for_staging_bytes(
        &self,
        deadline: Deadline,
        id: &OperationId,
    ) -> Result<usize, WriteError> {
        loop {
            self.wait_for_capacity(deadline, Some(id)).await?;
            match self.available_staging_bytes(deadline, Some(id)).await {
                Err(WriteError::Full) => {}
                result => return result,
            }
        }
    }
}
