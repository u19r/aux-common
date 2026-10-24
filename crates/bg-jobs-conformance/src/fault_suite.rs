use bg_jobs::store::{CommitOutcome, JobStore, Mutation, StoreKey};

use super::{ConformanceConfig, ConformanceError, ConformanceReport};
use crate::{
    CommitFaultKind, FaultStore, FaultStoreError, ReadFaultKind,
    suite::{cleanup, put_transaction, transaction},
};

/// Exercises each deterministic commit fault and returns the resulting proof
/// counts. `UnknownAfterCommit` is checked by observing that the mutation is
/// visible despite the unresolved acknowledgement.
pub async fn run_faults<S: JobStore>(
    store: &FaultStore<S>,
    config: &ConformanceConfig,
) -> Result<ConformanceReport, ConformanceError<FaultStoreError<S::Error>>> {
    let key = config
        .key(b"faults/value")
        .map_err(ConformanceError::Invalid)?;
    let clean = transaction(store, vec![], vec![Mutation::Delete(key.clone())])?;
    let _ = store
        .commit(&clean)
        .await
        .map_err(ConformanceError::Store)?;
    let mut report = ConformanceReport {
        commits: 1,
        ..ConformanceReport::default()
    };
    report = transient_faults(store, &key, report).await?;
    report = injected_conflict(store, &key, report).await?;
    report = unknown_before(store, &key, report).await?;
    report = unknown_after(store, &key, report).await?;
    cleanup(store, std::slice::from_ref(&key)).await?;
    Ok(report)
}

async fn transient_faults<S: JobStore>(
    store: &FaultStore<S>,
    key: &StoreKey,
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<FaultStoreError<S::Error>>> {
    for kind in [ReadFaultKind::Unavailable, ReadFaultKind::Timeout] {
        store
            .queue_commit_fault(CommitFaultKind::Transient(kind))
            .map_err(ConformanceError::Store)?;
        let transaction = put_transaction(store, key, b"transient")?;
        let result = store.commit(&transaction).await;
        report.commits += 1;
        report.assertions += 1;
        let matches_kind = matches!(
            (&result, kind),
            (
                Err(FaultStoreError::Unavailable),
                ReadFaultKind::Unavailable
            ) | (Err(FaultStoreError::Timeout), ReadFaultKind::Timeout)
        );
        if !matches_kind {
            return Err(ConformanceError::Invalid(
                "transient fault was not surfaced",
            ));
        }
    }
    Ok(report)
}

async fn injected_conflict<S: JobStore>(
    store: &FaultStore<S>,
    key: &StoreKey,
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<FaultStoreError<S::Error>>> {
    store
        .queue_commit_fault(CommitFaultKind::Conflict)
        .map_err(ConformanceError::Store)?;
    report.commits += 1;
    report.conflicts += 1;
    report.assertions += 1;
    let transaction = put_transaction(store, key, b"conflict")?;
    if store
        .commit(&transaction)
        .await
        .map_err(ConformanceError::Store)?
        != CommitOutcome::Conflict
    {
        return Err(ConformanceError::Invalid("injected conflict committed"));
    }
    Ok(report)
}

async fn unknown_before<S: JobStore>(
    store: &FaultStore<S>,
    key: &StoreKey,
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<FaultStoreError<S::Error>>> {
    store
        .queue_commit_fault(CommitFaultKind::UnknownBeforeCommit)
        .map_err(ConformanceError::Store)?;
    report.commits += 1;
    report.unknowns += 1;
    report.assertions += 1;
    let transaction = put_transaction(store, key, b"before")?;
    if store
        .commit(&transaction)
        .await
        .map_err(ConformanceError::Store)?
        != CommitOutcome::Unknown
        || store
            .get(key.clone())
            .await
            .map_err(ConformanceError::Store)?
            .is_some()
    {
        return Err(ConformanceError::Invalid(
            "before-commit unknown was applied",
        ));
    }
    Ok(report)
}

async fn unknown_after<S: JobStore>(
    store: &FaultStore<S>,
    key: &StoreKey,
    mut report: ConformanceReport,
) -> Result<ConformanceReport, ConformanceError<FaultStoreError<S::Error>>> {
    store
        .queue_commit_fault(CommitFaultKind::UnknownAfterCommit)
        .map_err(ConformanceError::Store)?;
    report.commits += 1;
    report.unknowns += 1;
    report.assertions += 1;
    let transaction = put_transaction(store, key, b"after")?;
    if store
        .commit(&transaction)
        .await
        .map_err(ConformanceError::Store)?
        != CommitOutcome::Unknown
        || store
            .get(key.clone())
            .await
            .map_err(ConformanceError::Store)?
            .as_deref()
            != Some(&b"after"[..])
    {
        return Err(ConformanceError::Invalid(
            "after-commit unknown was not applied",
        ));
    }
    Ok(report)
}
