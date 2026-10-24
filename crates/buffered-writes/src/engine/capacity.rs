use super::{admission_record::StagingReservation, state::Engine};
use crate::{
    buffer::{BufferInspectRequest, BufferSnapshot},
    configuration::{Deadline, OperationId},
    error::{BufferError, WriteError},
};

impl<T: Send + Sync + 'static> Engine<T> {
    pub(super) async fn reserve_staging(
        &self,
        deadline: Deadline,
        operation_id: Option<&OperationId>,
    ) -> Result<StagingReservation<'_>, WriteError> {
        let turn = self
            .complete_engine_operation(deadline, || self.admission_turn.lock())
            .await
            .ok_or(WriteError::DeadlineExceeded {
                operation_id: operation_id.cloned(),
                accepted: false,
            })?;
        loop {
            match self.available_staging_bytes(deadline, operation_id).await {
                Err(WriteError::Full)
                    if self.cfg.capacity.backpressure_policy()
                        == crate::BackpressurePolicy::WaitUntilDeadline =>
                {
                    self.wait_for_capacity(deadline, operation_id).await?;
                }
                Err(error) => return Err(error),
                Ok(available_bytes) => {
                    return Ok(StagingReservation::new(turn, available_bytes));
                }
            }
        }
    }

    pub(super) async fn wait_for_capacity(
        &self,
        deadline: Deadline,
        operation_id: Option<&OperationId>,
    ) -> Result<(), WriteError> {
        if self.admissions.is_closed() {
            return Err(WriteError::Closed);
        }
        let expired = || WriteError::DeadlineExceeded {
            operation_id: operation_id.cloned(),
            accepted: false,
        };
        if deadline.is_expired_at(self.cfg.clock.now_instant()) {
            return Err(expired());
        }
        self.flush_signal.request_capacity();
        self.complete_engine_operation(deadline, || {
            self.cfg
                .clock
                .sleep(self.cfg.delivery_policy.retry_base_delay)
        })
        .await
        .ok_or_else(expired)
    }

    pub(super) async fn available_staging_bytes(
        &self,
        deadline: Deadline,
        operation_id: Option<&OperationId>,
    ) -> Result<usize, WriteError> {
        if self.admissions.is_closed() {
            return Err(WriteError::Closed);
        }
        self.reconcile_uncertain_admissions(deadline).await;
        let snapshot = self
            .inspect_staging_capacity(deadline, operation_id)
            .await?;
        self.validate_retained_capacity(&snapshot)?;
        if snapshot.admission.is_some() {
            return Ok(self.cfg.capacity.byte_limit());
        }
        let (pending_items, pending_bytes) = self.admissions.pending_capacity(operation_id);
        if snapshot.stats.items().saturating_add(pending_items) >= self.cfg.capacity.item_limit() {
            return Err(WriteError::Full);
        }
        let protected = snapshot
            .stats
            .bytes()
            .saturating_sub(snapshot.reclaimable_bytes)
            .saturating_add(pending_bytes);
        let available = self.cfg.capacity.byte_limit().saturating_sub(protected);
        if available == 0 {
            return Err(WriteError::Full);
        }
        Ok(available)
    }

    async fn inspect_staging_capacity(
        &self,
        deadline: Deadline,
        operation_id: Option<&OperationId>,
    ) -> Result<BufferSnapshot, WriteError> {
        self.complete_buffer_operation(deadline, || {
            self.cfg.buffer.inspect(BufferInspectRequest {
                operation_id: operation_id.cloned(),
                now_utc_ms: self.cfg.clock.now_utc().timestamp_millis(),
                now_instant: self.cfg.clock.now_instant(),
                deadline,
            })
        })
        .await
        .map_err(|error| match error {
            BufferError::Configuration(error) => WriteError::Configuration(error),
            BufferError::DeadlineExceeded => WriteError::DeadlineExceeded {
                operation_id: operation_id.cloned(),
                accepted: false,
            },
            BufferError::Closed => WriteError::Closed,
            BufferError::CorruptStorage { reason } => WriteError::CorruptBuffer { reason },
            _ => WriteError::Unavailable {
                operation_id: operation_id.cloned(),
                accepted: false,
            },
        })
    }
}
