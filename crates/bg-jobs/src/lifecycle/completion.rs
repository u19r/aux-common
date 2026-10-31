//! Completion receipts and terminal completion transactions.

use crate::{
    budget::CompletionDetails,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    lifecycle::claim::ClaimedJob,
    model::{JobOutcome, JobState, OperationReceipt, TerminalDisposition},
    store::{Check, JobStore, Mutation, StoreTransaction},
    time::Timestamp,
};

pub(crate) async fn complete<S: JobStore>(
    system: &JobSystem<S>,
    claim: ClaimedJob,
    outcome: JobOutcome,
    completed_at: Timestamp,
) -> JobResult<CompletionDetails, S::Error> {
    let (receipt, transaction) = prepare_completion(system, &claim, outcome, completed_at).await?;
    let operation_key = keys::operation_key(system.namespace(), &claim.record().job_id)?;
    let previous_operation = keys::operation_value(
        &claim.record().job_id,
        &claim.operation_id(),
        claim.fence_high_water(),
    )?;
    let receipt_value = keys::operation_receipt_value(&receipt)?;
    crate::transition::commit_transition(
        system,
        transaction,
        operation_key,
        Some(&previous_operation),
        Some(&receipt_value),
        crate::transition::TransitionConflict::LeaseLost,
    )
    .await?;
    system.observe(crate::observer::JobEvent::Completed {
        queue: claim.record().queue.clone(),
        effect_mode: claim.record().policy.effect_mode,
    });
    Ok(completion_details(receipt))
}

async fn prepare_completion<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    outcome: JobOutcome,
    completed_at: Timestamp,
) -> JobResult<(OperationReceipt, StoreTransaction), S::Error> {
    let code = match outcome {
        JobOutcome::Complete(code) => code,
        other => {
            other.validate()?;
            return Err(JobSystemError::UnsupportedOutcome);
        }
    };
    crate::transition::current_lease(system, claim, completed_at)?;
    let receipt = completion_receipt(claim, code, completed_at)?;
    let transaction = completion_transaction(system, claim, &receipt).await?;
    Ok((receipt, transaction))
}

fn completion_receipt<E>(
    claim: &ClaimedJob,
    outcome: crate::policy::OutcomeCode,
    completed_at: Timestamp,
) -> JobResult<OperationReceipt, E> {
    let lease = match &claim.record().state {
        JobState::Leased(lease) => lease,
        _ => return Err(JobSystemError::LeaseLost),
    };
    let attempts = claim
        .record()
        .attempts
        .as_ref()
        .ok_or(JobSystemError::LeaseLost)?
        .attempts;
    let revision = claim
        .record()
        .revision
        .checked_add(1)
        .ok_or(JobSystemError::LeaseConflict)?;
    Ok(OperationReceipt {
        definition_digest: Some(crate::codec::job_definition_digest(
            &crate::model::JobDefinition::from(claim.record()),
        )?),
        operation_id: claim.operation_id(),
        job_id: claim.record().job_id,
        generation: claim.record().generation,
        revision,
        execution_id: claim.record().execution_id,
        attempt_id: claim.attempt_id(),
        attempts,
        kind: claim.record().kind.clone(),
        queue: claim.record().queue.clone(),
        effect_mode: claim.record().policy.effect_mode,
        created_at: claim.record().created_at,
        completed_at,
        owner: lease.owner,
        token: lease.token,
        fence: lease.fence,
        terminal: TerminalDisposition::Completed,
        outcome,
    })
}

fn completion_details(receipt: OperationReceipt) -> CompletionDetails {
    CompletionDetails {
        job_id: receipt.job_id,
        execution_id: receipt.execution_id,
        generation: receipt.generation,
        kind: receipt.kind,
        queue: receipt.queue,
        effect_mode: receipt.effect_mode,
        created_at: receipt.created_at,
        completed_at: receipt.completed_at,
        attempts: receipt.attempts,
        outcome: receipt.outcome,
    }
}

async fn completion_transaction<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    receipt: &OperationReceipt,
) -> JobResult<StoreTransaction, S::Error> {
    let job_key = keys::job_key(system.namespace(), &claim.record().job_id)?;
    let lease_value = keys::lease_value(&claim.record().job_id)?;
    let mut checks = Vec::with_capacity(5);
    checks.push(Check::Value(job_key.clone(), claim.encoded().clone()));
    checks.push(Check::Value(claim.lease_key().clone(), lease_value));
    checks.push(Check::Value(
        keys::operation_key(system.namespace(), &claim.record().job_id)?,
        keys::operation_value(
            &claim.record().job_id,
            &claim.operation_id(),
            claim.fence_high_water(),
        )?,
    ));
    checks.push(Check::Absent(keys::cancellation_key(
        system.namespace(),
        &claim.record().job_id,
    )?));
    let mut mutations = completion_mutations(system, claim, receipt)?;
    let wake_check = crate::transition::wake_mutation(
        system,
        &claim.record().queue,
        claim.due_key(),
        None,
        &mut mutations,
    )
    .await?;
    if let Some(check) = wake_check {
        checks.push(check);
    }
    mutations.insert(0, crate::store::Mutation::Delete(job_key));
    crate::transition::checked_transaction(system, checks, mutations)
}

pub(super) fn completion_mutations<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    receipt: &OperationReceipt,
) -> JobResult<Vec<Mutation>, S::Error> {
    let mut mutations = Vec::new();
    for key in &claim.record().payload.chunk_keys {
        mutations.push(Mutation::Delete(key.clone()));
    }
    if let Some(due_key) = claim.due_key() {
        mutations.push(Mutation::Delete(due_key.clone()));
    }
    mutations.push(Mutation::Delete(claim.fair_key().clone()));
    mutations.push(Mutation::Delete(claim.lease_key().clone()));
    for permit_key in claim.permit_keys() {
        mutations.push(Mutation::Delete(permit_key.clone()));
    }
    mutations.push(Mutation::Put(
        keys::operation_key(system.namespace(), &claim.record().job_id)?,
        keys::operation_receipt_value(receipt)?,
    ));
    Ok(mutations)
}
