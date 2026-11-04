//! Successful completion and terminal transactions.

use crate::{
    budget::CompletionDetails,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    lifecycle::claim::ClaimedJob,
    model::JobOutcome,
    store::{Check, JobStore, Mutation, StoreTransaction},
    time::Timestamp,
};

pub(crate) async fn complete<S: JobStore>(
    system: &JobSystem<S>,
    claim: ClaimedJob,
    outcome: JobOutcome,
    completed_at: Timestamp,
) -> JobResult<CompletionDetails, S::Error> {
    let (details, transaction) = prepare_completion(system, &claim, outcome, completed_at).await?;
    system
        .commit_terminal_transition(
            transaction,
            crate::transition::TransitionConflict::LeaseLost,
        )
        .await?;
    system.observe(crate::observer::JobEvent::Completed {
        queue: claim.record().queue.clone(),
        effect_mode: claim.record().policy.effect_mode,
    });
    Ok(details)
}

async fn prepare_completion<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    outcome: JobOutcome,
    completed_at: Timestamp,
) -> JobResult<(CompletionDetails, StoreTransaction), S::Error> {
    let code = match outcome {
        JobOutcome::Complete(code) => code,
        other => {
            other.validate()?;
            return Err(JobSystemError::UnsupportedOutcome);
        }
    };
    crate::transition::current_lease(system, claim, completed_at)?;
    let attempts = claim
        .record()
        .attempts
        .as_ref()
        .ok_or(JobSystemError::LeaseLost)?
        .attempts;
    let details = CompletionDetails {
        job_id: claim.record().job_id,
        execution_id: claim.record().execution_id,
        generation: claim.record().generation,
        kind: claim.record().kind.clone(),
        queue: claim.record().queue.clone(),
        effect_mode: claim.record().policy.effect_mode,
        created_at: claim.record().created_at,
        completed_at,
        attempts,
        outcome: code,
    };
    let transaction = completion_transaction(system, claim).await?;
    Ok((details, transaction))
}

async fn completion_transaction<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
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
    let mut mutations = completion_mutations(system, claim)?;
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

fn completion_mutations<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
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
    mutations.push(Mutation::Delete(keys::operation_key(
        system.namespace(),
        &claim.record().job_id,
    )?));
    Ok(mutations)
}
