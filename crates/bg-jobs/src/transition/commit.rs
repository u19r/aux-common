//! Checked transaction construction and durable lifecycle transitions.

use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::CommitOperationId,
    store::{
        Check, CommitOutcome, EffectReceiptGroup, JobStore, Mutation, StoreTransaction,
        StoreTransactionInput, TransactionLimits,
    },
};

#[derive(Clone, Copy)]
pub(crate) enum TransitionConflict {
    LeaseConflict,
    LeaseLost,
}

impl<S: JobStore> JobSystem<S> {
    pub(crate) fn build_transaction(
        &self,
        operation_id: CommitOperationId,
        checks: Vec<Check>,
        mutations: Vec<Mutation>,
    ) -> JobResult<StoreTransaction, S::Error> {
        let capabilities = self.store().capabilities();
        let transaction = StoreTransaction::try_from(StoreTransactionInput {
            operation_id,
            checks,
            mutations,
            limits: TransactionLimits {
                max_checks: capabilities.max_transaction_keys(),
                max_mutations: capabilities.max_transaction_keys(),
                max_bytes: capabilities.max_transaction_bytes(),
            },
        })?;
        capabilities.validate_transaction(&transaction)?;
        Ok(transaction)
    }

    pub(crate) async fn commit_terminal_transition(
        &self,
        transaction: StoreTransaction,
        conflict: TransitionConflict,
    ) -> JobResult<(), S::Error> {
        let transaction = if let Some(effect) = self.terminal_effect(&transaction)? {
            let mut draft = StoreTransactionInput::from(transaction);
            self.prepare_catalog_terminal_transition(&mut draft, &effect)
                .await?;
            self.prepare_fair_terminal_transition(&mut draft, &effect)
                .await?;
            if effect.kind().removes_job() && self.store().capabilities().effect_receipt_groups() {
                let record = effect.record();
                draft
                    .mutations
                    .push(Mutation::ClearEffectReceipts(EffectReceiptGroup::new(
                        self.namespace(),
                        record.job_id,
                        record.execution_id,
                    )?));
            }
            self.build_transaction(draft.operation_id, draft.checks, draft.mutations)?
        } else {
            transaction
        };
        self.commit_transition(transaction, conflict).await
    }

    pub(crate) async fn commit_transition(
        &self,
        transaction: StoreTransaction,
        conflict: TransitionConflict,
    ) -> JobResult<(), S::Error> {
        match self.commit_durable(transaction).await? {
            CommitOutcome::Committed => Ok(()),
            CommitOutcome::Conflict => Err(match conflict {
                TransitionConflict::LeaseConflict => JobSystemError::LeaseConflict,
                TransitionConflict::LeaseLost => JobSystemError::LeaseLost,
            }),
            CommitOutcome::Unknown => Err(JobSystemError::UnknownCommit),
        }
    }
}

pub(crate) fn checked_transaction<S: JobStore>(
    system: &JobSystem<S>,
    checks: Vec<Check>,
    mutations: Vec<Mutation>,
) -> JobResult<StoreTransaction, S::Error> {
    let identity = CommitOperationId::generate().map_err(|_| JobSystemError::EntropyUnavailable)?;
    system.build_transaction(identity, checks, mutations)
}
