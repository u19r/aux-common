use super::state::Engine;
use crate::{
    batch::{
        AdmittedRecord, BatchItems, BatchItemsInput, PreparedWrites, SealedBatch, SealedBatchInput,
    },
    configuration::BatchId,
    error::PrepareError,
    retention::RetentionState,
};

impl<T: Send + Sync + 'static> Engine<T> {
    pub(super) fn prepare_candidate_slice(
        &self,
        records: &[AdmittedRecord],
        retained_budget: usize,
    ) -> Result<SealedBatch, PrepareError> {
        let mut items = Vec::with_capacity(records.len());
        let mut ids = Vec::with_capacity(records.len());
        let mut payloads = Vec::with_capacity(records.len());
        for record in records {
            items.push(record.decode(self.cfg.codec.as_ref())?);
            ids.push(record.operation_id.clone());
            payloads.push(record.payload.clone());
        }
        let first = records.first().ok_or(PrepareError::EmptyOperations)?;
        let base = RetentionState::preparation_base_bytes(
            records,
            &self.cfg.namespace,
            self.cfg.batch_strategy.strategy_version(),
        );
        let batch_id = BatchId::generate_v7();
        let prepared = self
            .cfg
            .batch_strategy
            .prepare(BatchItems::new(BatchItemsInput {
                batch_id,
                scope: &first.scope,
                items: &items,
                operation_ids: &ids,
                raw_payloads: &payloads,
                limits: &self.cfg.effective_limits,
                first_item_time_ms: records
                    .iter()
                    .map(|record| record.admitted_at_utc_ms)
                    .min()
                    .unwrap_or(0),
                max_prepared_bytes: retained_budget.saturating_sub(base),
            }))?;
        self.cfg.preparation.validate_prepared(&prepared)?;
        self.seal_prepared_candidate(batch_id, records, prepared, retained_budget)
    }

    fn seal_prepared_candidate(
        &self,
        batch_id: BatchId,
        records: &[AdmittedRecord],
        prepared: PreparedWrites,
        retained_budget: usize,
    ) -> Result<SealedBatch, PrepareError> {
        let first = records.first().ok_or(PrepareError::EmptyOperations)?;
        let batch = SealedBatch::try_new(SealedBatchInput {
            batch_id,
            namespace: self.cfg.namespace.clone(),
            scope: first.scope.clone(),
            codec_version: self.cfg.codec.version().to_owned(),
            strategy_version: self.cfg.batch_strategy.strategy_version().to_owned(),
            first_item_time_ms: records
                .iter()
                .map(|record| record.admitted_at_utc_ms)
                .min()
                .unwrap_or(0),
            records: records.iter().map(AdmittedRecord::to_persisted).collect(),
            prepared: prepared.payload,
            operation_ids: prepared.operation_ids,
        })?;
        let size = RetentionState::sealed_batch_bytes(&batch);
        if size > retained_budget {
            return Err(PrepareError::CandidateTooLarge {
                size,
                limit: retained_budget,
            });
        }
        Ok(batch)
    }
}
