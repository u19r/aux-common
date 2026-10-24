use bytes::Bytes;

use crate::{
    admin::{decode_lease_markers, load_job, load_lease_marker_values},
    codec::encode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    failure::{CancellationResult, OutcomeResult},
    ids::{JobId, OperationId},
    keys,
    lifecycle::ClaimedJob,
    model::{JobRecordV1, JobState},
    policy::OutcomeCode,
    store::{Check, JobStore, Mutation},
    time::Timestamp,
    transition::{
        TerminalTransition, checked_transaction, code, commit_record, commit_record_without_claim,
        current_lease, fresh_operation, next_revision, terminal_transaction, wake_mutation,
    },
};

/// Quarantines a claimed record whose immutable payload cannot be decoded.
pub(crate) async fn dead_letter_by_id<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
) -> JobResult<(), S::Error> {
    let mut authority = load_payload_authority(system, job_id).await?;
    let outcome = code("payload_corrupt")?;
    if let Some(attempts) = &mut authority.record.attempts {
        attempts.last_attempt_at = now;
        attempts.last_outcome = Some(outcome);
    }
    authority.record.state = JobState::DeadLettered;
    authority.record.revision = next_revision(system, &authority.record)?;
    let new_operation = fresh_operation(system)?;
    let new_encoded = encode_job_record(&authority.record)?;
    let dlq_key = keys::dead_letter_key(system.namespace(), &authority.record.queue, &job_id)?;
    let transaction = payload_corrupt_transaction(
        system,
        &authority,
        &authority.record,
        &new_encoded,
        new_operation,
        dlq_key,
    )
    .await?;
    commit_record_without_claim(
        system,
        transaction,
        &job_id,
        &authority.encoded,
        &new_encoded,
    )
    .await
}

struct PayloadAuthority {
    job_key: crate::store::StoreKey,
    encoded: Bytes,
    record: JobRecordV1,
    markers: crate::admin::LeaseMarkers,
    permit_keys: Vec<crate::store::StoreKey>,
    permit_value: Bytes,
}

async fn load_payload_authority<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<PayloadAuthority, S::Error> {
    let (job_key, encoded, record) = load_job(system, job_id).await?;
    let marker_values = load_lease_marker_values(system, &record.queue, job_id).await?;
    if !matches!(&record.state, JobState::Leased(_)) {
        return Err(JobSystemError::LeaseLost);
    }
    let permit_value = keys::permit_value_for_record(&record)?;
    let permit_keys = crate::fairness::find_owned_permit_keys(system, &record).await?;
    let markers = decode_lease_markers(marker_values, job_id)?;
    Ok(PayloadAuthority {
        job_key,
        encoded,
        record,
        markers,
        permit_keys,
        permit_value,
    })
}

async fn payload_corrupt_transaction<S: JobStore>(
    system: &JobSystem<S>,
    authority: &PayloadAuthority,
    record: &JobRecordV1,
    encoded: &Bytes,
    operation: OperationId,
    dlq_key: crate::store::StoreKey,
) -> JobResult<crate::store::StoreTransaction, S::Error> {
    let mut mutations = vec![
        Mutation::Put(authority.job_key.clone(), encoded.clone()),
        Mutation::Delete(authority.markers.lease_key.clone()),
        Mutation::Delete(keys::fair_key(
            system.namespace(),
            &record.queue,
            &record.job_id,
        )?),
        Mutation::Delete(keys::cancellation_key(system.namespace(), &record.job_id)?),
        Mutation::Put(dlq_key, keys::dead_letter_value(&record.job_id)?),
        Mutation::Put(
            authority.markers.operation_key.clone(),
            keys::operation_value(
                &record.job_id,
                &operation,
                authority.markers.fence_high_water,
            )?,
        ),
    ];
    for permit_key in &authority.permit_keys {
        mutations.push(Mutation::Delete(permit_key.clone()));
    }
    let wake_check = wake_mutation(system, &record.queue, None, None, &mut mutations).await?;
    let mut checks = payload_corrupt_checks::<S::Error>(authority)?;
    if let Some(check) = wake_check {
        checks.push(check);
    }
    checked_transaction(system, checks, mutations)
}

fn payload_corrupt_checks<E>(
    authority: &PayloadAuthority,
) -> Result<Vec<Check>, JobSystemError<E>> {
    let mut checks = vec![
        Check::Value(authority.job_key.clone(), authority.encoded.clone()),
        Check::Value(
            authority.markers.lease_key.clone(),
            authority.markers.lease_value.clone(),
        ),
        Check::Value(
            authority.markers.operation_key.clone(),
            keys::operation_value(
                &authority.record.job_id,
                &authority.markers.operation,
                authority.markers.fence_high_water,
            )?,
        ),
    ];
    checks.extend(
        authority
            .permit_keys
            .iter()
            .cloned()
            .map(|key| Check::Value(key, authority.permit_value.clone())),
    );
    Ok(checks)
}

pub(crate) async fn cancel_claim_commit<S: JobStore>(
    system: &JobSystem<S>,
    mut claim: ClaimedJob,
    now: Timestamp,
) -> JobResult<OutcomeResult, S::Error> {
    claim.lease_at(now).ok_or(JobSystemError::LeaseLost)?;
    let cancellation_requested = has_cancellation_request(system, claim.record().job_id).await?;
    if system.is_shutdown() && !cancellation_requested {
        let checkpoint = claim.record().checkpoint.clone().unwrap_or_default();
        return super::continue_claim(system, claim, now, checkpoint, now).await;
    }
    if !cancellation_requested {
        current_lease(system, &claim, now)?;
    }
    {
        let record = claim.record_mut();
        record.state = JobState::Cancelled;
        record.revision = next_revision(system, record)?;
    }
    let operation_id = fresh_operation(system)?;
    let new_encoded = encode_job_record(claim.record())?;
    let transaction = terminal_transaction(
        system,
        &claim,
        claim.record(),
        &new_encoded,
        operation_id,
        if cancellation_requested {
            TerminalTransition::CancellationAcknowledgement
        } else {
            TerminalTransition::WorkerCancellation
        },
    )
    .await?;
    commit_record(system, transaction, &claim, &new_encoded).await?;
    claim.lose_authority();
    system.observe(crate::observer::JobEvent::Cancelled {
        queue: claim.record().queue.clone(),
    });
    Ok(OutcomeResult::Cancelled)
}

async fn has_cancellation_request<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<bool, S::Error> {
    let key = keys::cancellation_key(system.namespace(), &job_id)?;
    let Some(value) = system
        .store()
        .get(key)
        .await
        .map_err(JobSystemError::Store)?
    else {
        return Ok(false);
    };
    keys::validate_empty_marker(&value, crate::codec::ValueTag::Cancellation)
        .map_err(|_| JobSystemError::PayloadCorrupt)?;
    Ok(true)
}

pub(crate) async fn cancel_claim<S: JobStore>(
    system: &JobSystem<S>,
    mut claim: ClaimedJob,
    now: Timestamp,
) -> JobResult<CancellationResult, S::Error> {
    claim.lease_at(now).ok_or(JobSystemError::LeaseLost)?;
    let cancellation_key = keys::cancellation_key(system.namespace(), &claim.record().job_id)?;
    let cancellation = system
        .store()
        .get(cancellation_key.clone())
        .await
        .map_err(JobSystemError::Store)?
        .ok_or(JobSystemError::LeaseConflict)?;
    keys::validate_empty_marker(&cancellation, crate::codec::ValueTag::Cancellation)
        .map_err(|_| JobSystemError::PayloadCorrupt)?;

    claim.record_mut().state = JobState::Cancelled;
    let revision = next_revision(system, claim.record())?;
    claim.record_mut().revision = revision;
    let operation_id = fresh_operation(system)?;
    let new_encoded = encode_job_record(claim.record())?;
    let transaction = terminal_transaction(
        system,
        &claim,
        claim.record(),
        &new_encoded,
        operation_id,
        TerminalTransition::CancellationAcknowledgement,
    )
    .await?;
    commit_record(system, transaction, &claim, &new_encoded).await?;
    system.observe(crate::observer::JobEvent::Cancelled {
        queue: claim.record().queue.clone(),
    });
    Ok(CancellationResult::Cancelled)
}

pub(crate) async fn dead_letter_claim<S: JobStore>(
    system: &JobSystem<S>,
    mut claim: ClaimedJob,
    code: OutcomeCode,
    now: Timestamp,
) -> JobResult<OutcomeResult, S::Error> {
    current_lease(system, &claim, now)?;
    {
        let record = claim.record_mut();
        if let Some(attempts) = &mut record.attempts {
            attempts.last_attempt_at = now;
            attempts.last_outcome = Some(code.clone());
        }
        record.state = JobState::DeadLettered;
        record.revision = next_revision(system, record)?;
    }
    let operation_id = fresh_operation(system)?;
    let new_encoded = encode_job_record(claim.record())?;
    let dlq_key = keys::dead_letter_key(
        system.namespace(),
        &claim.record().queue,
        &claim.record().job_id,
    )?;
    let transaction = terminal_transaction(
        system,
        &claim,
        claim.record(),
        &new_encoded,
        operation_id,
        TerminalTransition::DeadLetter(dlq_key),
    )
    .await?;
    commit_record(system, transaction, &claim, &new_encoded).await?;
    system.observe(crate::observer::JobEvent::DeadLettered {
        queue: claim.record().queue.clone(),
        outcome: code.clone(),
    });
    Ok(OutcomeResult::DeadLettered { code })
}
