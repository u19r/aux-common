//! Checked transaction construction, commits, and reconciliation.

use bytes::Bytes;

use crate::{
    codec::{DecodedOperation, decode_operation},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::{CommitOperationId, JobId, OperationId},
    keys,
    lifecycle::ClaimedJob,
    store::{
        Check, CommitOutcome, JobStore, Mutation, StoreKey, StoreTransaction, StoreTransactionInput,
    },
    transition::ReconciliationOutcome,
};

pub(crate) async fn commit_record<S: JobStore>(
    system: &JobSystem<S>,
    transaction: StoreTransaction,
    claim: &ClaimedJob,
    new_encoded: &Bytes,
) -> JobResult<(), S::Error> {
    commit_transition(
        system,
        transaction,
        keys::job_key(system.namespace(), &claim.record().job_id)?,
        Some(claim.encoded()),
        Some(new_encoded),
        TransitionConflict::LeaseLost,
    )
    .await
}

pub(crate) async fn commit_record_without_claim<S: JobStore>(
    system: &JobSystem<S>,
    transaction: StoreTransaction,
    job_id: &JobId,
    old_encoded: &Bytes,
    new_encoded: &Bytes,
) -> JobResult<(), S::Error> {
    commit_transition(
        system,
        transaction,
        keys::job_key(system.namespace(), job_id)?,
        Some(old_encoded),
        Some(new_encoded),
        TransitionConflict::LeaseLost,
    )
    .await
}

#[derive(Clone, Copy)]
pub(crate) enum TransitionConflict {
    LeaseConflict,
    LeaseLost,
}

impl TransitionConflict {
    fn error<E>(self) -> JobSystemError<E> {
        match self {
            Self::LeaseConflict => JobSystemError::LeaseConflict,
            Self::LeaseLost => JobSystemError::LeaseLost,
        }
    }
}

enum UnknownTransition {
    Reached,
    Retry,
    Unresolved,
}

struct TransitionProbe<'a> {
    key: StoreKey,
    expected_old: Option<&'a Bytes>,
    expected_new: Option<&'a Bytes>,
}

pub(crate) async fn commit_transition<S: JobStore>(
    system: &JobSystem<S>,
    transaction: StoreTransaction,
    probe_key: StoreKey,
    expected_old: Option<&Bytes>,
    expected_new: Option<&Bytes>,
    conflict: TransitionConflict,
) -> JobResult<(), S::Error> {
    let probe = TransitionProbe {
        key: probe_key,
        expected_old,
        expected_new,
    };
    if commit_reconciled(system, &transaction, &probe).await? {
        return Ok(());
    }
    // Only a known aborted transaction permits a new commit identity. Its
    // authoritative conditions remain in the replacement transaction.
    if let Some(refreshed) = super::wake::refresh_conflicted_wake(system, &transaction).await?
        && commit_reconciled(system, &refreshed, &probe).await?
    {
        return Ok(());
    }
    Err(conflict.error())
}

async fn commit_reconciled<S: JobStore>(
    system: &JobSystem<S>,
    transaction: &StoreTransaction,
    probe: &TransitionProbe<'_>,
) -> JobResult<bool, S::Error> {
    for attempt in 0..=1 {
        match commit_once(system, transaction).await? {
            CommitOutcome::Committed => return Ok(true),
            CommitOutcome::Conflict => return Ok(false),
            CommitOutcome::Unknown => {
                match reconcile_unknown(
                    system,
                    &probe.key,
                    probe.expected_old,
                    probe.expected_new,
                    attempt == 0,
                )
                .await?
                {
                    UnknownTransition::Reached => return Ok(true),
                    UnknownTransition::Retry => continue,
                    UnknownTransition::Unresolved => {
                        return Err(if attempt == 1 {
                            JobSystemError::UnknownCommit
                        } else {
                            JobSystemError::LeaseLost
                        });
                    }
                }
            }
        }
    }
    Err(JobSystemError::UnknownCommit)
}

async fn commit_once<S: JobStore>(
    system: &JobSystem<S>,
    transaction: &StoreTransaction,
) -> JobResult<CommitOutcome, S::Error> {
    system
        .store()
        .commit(transaction)
        .await
        .map_err(JobSystemError::Store)
}

async fn reconcile_unknown<S: JobStore>(
    system: &JobSystem<S>,
    probe_key: &StoreKey,
    expected_old: Option<&Bytes>,
    expected_new: Option<&Bytes>,
    retry_allowed: bool,
) -> JobResult<UnknownTransition, S::Error> {
    let visible = system
        .store()
        .get(probe_key.clone())
        .await
        .map_err(JobSystemError::Store)?;
    let reached = match expected_new {
        Some(expected) => visible.as_deref() == Some(expected.as_ref()),
        None => visible.is_none(),
    };
    if reached {
        return Ok(UnknownTransition::Reached);
    }
    let unchanged = match expected_old {
        Some(expected) => visible.as_deref() == Some(expected.as_ref()),
        None => visible.is_none(),
    };
    Ok(if unchanged && retry_allowed {
        UnknownTransition::Retry
    } else {
        UnknownTransition::Unresolved
    })
}

pub(crate) async fn commit_marker<S: JobStore>(
    system: &JobSystem<S>,
    transaction: StoreTransaction,
    marker: &StoreKey,
) -> JobResult<(), S::Error> {
    let marker_value = keys::cancellation_value()?;
    commit_transition(
        system,
        transaction,
        marker.clone(),
        None,
        Some(&marker_value),
        TransitionConflict::LeaseLost,
    )
    .await
}

pub(crate) fn checked_transaction<S: JobStore>(
    system: &JobSystem<S>,
    checks: Vec<Check>,
    mutations: Vec<Mutation>,
) -> JobResult<StoreTransaction, S::Error> {
    let capabilities = system.store().capabilities();
    let transaction = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::generate()
            .map_err(|_| JobSystemError::EntropyUnavailable)?,
        checks,
        mutations,
        limits: crate::store::TransactionLimits {
            max_checks: capabilities.max_transaction_keys(),
            max_mutations: capabilities.max_transaction_keys(),
            max_bytes: capabilities.max_transaction_bytes(),
        },
    })?;
    capabilities.validate_transaction(&transaction)?;
    Ok(transaction)
}

pub(crate) async fn reconcile<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    operation: OperationId,
) -> JobResult<ReconciliationOutcome, S::Error> {
    let Some((job, encoded)) = read_reconciliation_state(system, &job_id).await? else {
        return Ok(ReconciliationOutcome::Conflict);
    };
    let (current, is_receipt) = match decode_reconciliation_operation(&encoded, job_id) {
        Ok(operation) => operation,
        Err(outcome) => return Ok(outcome),
    };
    Ok(resolve_reconciliation(
        job.is_some(),
        current,
        is_receipt,
        operation,
    ))
}

async fn read_reconciliation_state<S: JobStore>(
    system: &JobSystem<S>,
    job_id: &JobId,
) -> JobResult<Option<(Option<Bytes>, Bytes)>, S::Error> {
    let keys = [
        keys::job_key(system.namespace(), job_id)?,
        keys::operation_key(system.namespace(), job_id)?,
    ];
    let values = system.read_many(&keys).await?;
    if values.len() != keys.len() {
        return Ok(None);
    }
    let mut values = values.into_iter();
    let job = values.next().flatten();
    let Some(operation) = values.next().flatten() else {
        return Ok(None);
    };
    Ok(Some((job, operation)))
}

fn decode_reconciliation_operation(
    encoded: &Bytes,
    job_id: JobId,
) -> Result<(Option<OperationId>, bool), ReconciliationOutcome> {
    let decoded = decode_operation(encoded).map_err(|_| ReconciliationOutcome::Conflict)?;
    match decoded {
        DecodedOperation::Live(authority) if authority.matches_job(job_id) => {
            Ok((authority.operation_id(), false))
        }
        DecodedOperation::Receipt(receipt) if receipt.job_id == job_id => {
            Ok((Some(receipt.operation_id), true))
        }
        DecodedOperation::Live(_) | DecodedOperation::Receipt(_) => {
            Err(ReconciliationOutcome::Conflict)
        }
    }
}

fn resolve_reconciliation(
    has_job: bool,
    current: Option<OperationId>,
    is_receipt: bool,
    expected: OperationId,
) -> ReconciliationOutcome {
    match (has_job, is_receipt, current == Some(expected)) {
        (false, true, true) => ReconciliationOutcome::AlreadyCommitted,
        (false, _, _) | (true, true, _) => ReconciliationOutcome::Conflict,
        (true, false, true) => ReconciliationOutcome::RetryCommit,
        (true, false, false) => ReconciliationOutcome::LeaseLost,
    }
}
