use bytes::Bytes;

use super::operation::ValidatedEnqueue;
use crate::{
    codec::decode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::JobId,
    keys,
    model::{EnqueueDisposition, EnqueueResult, NewJob},
    store::{JobStore, StoreKey},
    time::Timestamp,
};

pub(super) struct PriorFenceAuthority {
    pub(super) encoded: Bytes,
    pub(super) fence_high_water: u64,
}

#[derive(Clone, Copy)]
pub(super) enum ExistingJobMatch {
    ExactRequest,
    StableSeed,
}

pub(super) enum EnqueueAuthority {
    Existing(Bytes),
    Deduplicated {
        job_id: JobId,
    },
    Missing {
        expected_dedupe: Option<Bytes>,
        prior_fence: Option<PriorFenceAuthority>,
    },
}

pub(super) async fn read_enqueue_authority<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    job_key: &StoreKey,
    now: Timestamp,
) -> JobResult<EnqueueAuthority, S::Error> {
    let (read_keys, has_dedupe) = enqueue_read_keys(system, job, job_key)?;
    let values = system.read_many(&read_keys).await?;
    if values.len() != read_keys.len() {
        return Err(JobSystemError::PayloadCorrupt);
    }
    classify_enqueue_values(values, has_dedupe, job, now)
}

fn enqueue_read_keys<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    job_key: &StoreKey,
) -> JobResult<(Vec<StoreKey>, bool), S::Error> {
    let mut read_keys = vec![job_key.clone()];
    let has_dedupe = if let Some(deduplication) = &job.deduplication {
        read_keys.push(keys::dedupe_key(system.namespace(), deduplication.key())?);
        true
    } else {
        false
    };
    read_keys.push(keys::operation_key(system.namespace(), &job.job_id)?);
    Ok((read_keys, has_dedupe))
}

fn classify_enqueue_values<E>(
    values: Vec<Option<Bytes>>,
    has_dedupe: bool,
    job: &NewJob,
    now: Timestamp,
) -> JobResult<EnqueueAuthority, E> {
    let mut values = values.into_iter();
    if let Some(existing) = values.next().flatten() {
        return Ok(EnqueueAuthority::Existing(existing));
    }
    let expected_dedupe = match has_dedupe {
        true => match values.next().flatten() {
            Some(encoded) => {
                let (dedupe_job_id, retain_until) = keys::decode_dedupe_value(&encoded)?;
                if retain_until > now {
                    return Ok(EnqueueAuthority::Deduplicated {
                        job_id: dedupe_job_id,
                    });
                }
                Some(encoded)
            }
            None => None,
        },
        false => None,
    };
    let prior_fence = values
        .next()
        .flatten()
        .map(|encoded| decode_prior_fence(encoded, &job.job_id))
        .transpose()?;
    Ok(EnqueueAuthority::Missing {
        expected_dedupe,
        prior_fence,
    })
}

fn decode_prior_fence<E>(encoded: Bytes, job_id: &JobId) -> JobResult<PriorFenceAuthority, E> {
    let fence_high_water = keys::decode_operation_fence_high_water(&encoded, job_id)?;
    Ok(PriorFenceAuthority {
        encoded,
        fence_high_water,
    })
}

pub(super) fn reconcile_record<S: JobStore>(
    system: &JobSystem<S>,
    request: &ValidatedEnqueue<'_>,
    encoded: &[u8],
    disposition: EnqueueDisposition,
) -> JobResult<EnqueueResult, S::Error> {
    let record = decode_job_record(encoded)?;
    crate::lifecycle::validate_persisted_identity(system, request.job.job_id, &record).map_err(
        |error| match error {
            JobSystemError::LeaseConflict | JobSystemError::PayloadCorrupt => {
                JobSystemError::JobIdConflict
            }
            other => other,
        },
    )?;
    let matches_schedule = match request.existing_match {
        ExistingJobMatch::ExactRequest => record.scheduled_at == request.job.scheduled_at,
        ExistingJobMatch::StableSeed => true,
    };
    if !matches_schedule
        || crate::model::JobDefinition::from(&record) != request.definition(system.namespace())?
    {
        return Err(JobSystemError::JobIdConflict);
    }
    Ok(enqueue_result_at(
        request.job.job_id,
        disposition,
        record.scheduled_at,
        request.now,
    ))
}

pub(super) async fn reconcile_after_commit<S: JobStore>(
    system: &JobSystem<S>,
    request: &ValidatedEnqueue<'_>,
    disposition: EnqueueDisposition,
) -> JobResult<EnqueueResult, S::Error> {
    let keys = [
        keys::job_key(system.namespace(), &request.job.job_id)?,
        keys::operation_key(system.namespace(), &request.job.job_id)?,
    ];
    let values = system.read_many(&keys).await?;
    if values.len() != keys.len() {
        return Err(JobSystemError::PayloadCorrupt);
    }
    let mut values = values.into_iter();
    if let Some(encoded) = values.next().flatten() {
        return reconcile_record(system, request, &encoded, disposition);
    }
    if let Some(encoded) = values.next().flatten() {
        let prior = decode_prior_fence(encoded, &request.job.job_id)?;
        if let Some(result) =
            reconcile_completed_seed(request, system.namespace(), &prior, disposition)?
        {
            return Ok(result);
        }
    }
    Err(JobSystemError::UnknownCommit)
}

fn enqueue_result_at(
    job_id: JobId,
    disposition: EnqueueDisposition,
    scheduled_at: Timestamp,
    now: Timestamp,
) -> EnqueueResult {
    EnqueueResult {
        job_id,
        disposition,
        wake: crate::time::WakeHint::from_timestamp(scheduled_at, now),
    }
}

/// A terminal receipt reserves a completed seed identity. Startup must not
/// recreate executable work when its live row has already been removed.
pub(super) fn reconcile_completed_seed<E>(
    request: &ValidatedEnqueue<'_>,
    namespace: &crate::ids::Namespace,
    prior: &PriorFenceAuthority,
    disposition: EnqueueDisposition,
) -> JobResult<Option<EnqueueResult>, E> {
    if !matches!(request.existing_match, ExistingJobMatch::StableSeed) {
        return Ok(None);
    }
    let crate::codec::DecodedOperation::Receipt(receipt) =
        crate::codec::decode_operation(&prior.encoded)?
    else {
        return Ok(None);
    };
    if receipt.kind != request.job.kind
        || receipt.queue != *request.registration.queue()
        || receipt.effect_mode != request.registration.effect_mode()
        || receipt.definition_digest
            != Some(crate::codec::job_definition_digest(
                &request.definition(namespace)?,
            )?)
    {
        return Err(JobSystemError::JobIdConflict);
    }
    Ok(Some(EnqueueResult {
        job_id: receipt.job_id,
        disposition,
        wake: crate::time::WakeHint::None,
    }))
}
