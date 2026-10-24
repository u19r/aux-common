use bytes::Bytes;

use crate::{
    codec::decode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::{JobId, OperationId, QueueName},
    keys,
    lifecycle::validate_persisted_identity,
    model::JobRecordV1,
    store::{JobStore, StoreKey},
};

pub(crate) async fn load_job<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<(StoreKey, Bytes, JobRecordV1), S::Error> {
    let job_key = keys::job_key(system.namespace(), &job_id)?;
    let encoded = system
        .store()
        .get(job_key.clone())
        .await
        .map_err(JobSystemError::Store)?
        .ok_or(JobSystemError::NotFound)?;
    let record = decode_job_record(&encoded)?;
    validate_persisted_identity(system, job_id, &record)?;
    Ok((job_key, encoded, record))
}

pub(super) struct JobOperation {
    pub(super) job_key: StoreKey,
    pub(super) encoded: Bytes,
    pub(super) record: JobRecordV1,
    pub(super) operation_key: StoreKey,
    pub(super) operation_value: Option<Bytes>,
}

impl JobOperation {
    pub(super) fn active_operation<E>(
        &self,
    ) -> Result<(&Bytes, OperationId, u64), JobSystemError<E>> {
        let value = self
            .operation_value
            .as_ref()
            .ok_or(JobSystemError::PayloadCorrupt)?;
        let (operation, fence) = keys::decode_active_operation(value, &self.record.job_id)
            .map_err(|_| JobSystemError::PayloadCorrupt)?;
        Ok((value, operation, fence))
    }
}

pub(super) async fn load_job_operation<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<JobOperation, S::Error> {
    let job_key = keys::job_key(system.namespace(), &job_id)?;
    let operation_key = keys::operation_key(system.namespace(), &job_id)?;
    let values = system
        .read_many(&[job_key.clone(), operation_key.clone()])
        .await?;
    if values.len() != 2 {
        return Err(JobSystemError::PayloadCorrupt);
    }
    let mut values = values.into_iter();
    let encoded = values.next().flatten().ok_or(JobSystemError::NotFound)?;
    let operation_value = values.next().flatten();
    let record = decode_job_record(&encoded)?;
    validate_persisted_identity(system, job_id, &record)?;
    Ok(JobOperation {
        job_key,
        encoded,
        record,
        operation_key,
        operation_value,
    })
}

pub(crate) struct LeaseMarkerValues {
    lease_key: StoreKey,
    lease_value: Option<Bytes>,
    operation_key: StoreKey,
    operation_value: Option<Bytes>,
}

pub(crate) struct LeaseMarkers {
    pub(crate) lease_key: StoreKey,
    pub(crate) lease_value: Bytes,
    pub(crate) operation_key: StoreKey,
    pub(crate) operation_value: Bytes,
    pub(crate) operation: OperationId,
    pub(crate) fence_high_water: u64,
}

pub(super) async fn load_lease_markers<S: JobStore>(
    system: &JobSystem<S>,
    queue: &QueueName,
    job_id: JobId,
) -> JobResult<LeaseMarkers, S::Error> {
    let values = load_lease_marker_values(system, queue, job_id).await?;
    decode_lease_markers(values, job_id)
}

pub(crate) async fn load_lease_marker_values<S: JobStore>(
    system: &JobSystem<S>,
    queue: &QueueName,
    job_id: JobId,
) -> JobResult<LeaseMarkerValues, S::Error> {
    let lease_key = keys::lease_key(system.namespace(), queue, &job_id)?;
    let operation_key = keys::operation_key(system.namespace(), &job_id)?;
    let values = system
        .read_many(&[lease_key.clone(), operation_key.clone()])
        .await?;
    if values.len() != 2 {
        return Err(JobSystemError::PayloadCorrupt);
    }
    let mut values = values.into_iter();
    Ok(LeaseMarkerValues {
        lease_key,
        lease_value: values.next().flatten(),
        operation_key,
        operation_value: values.next().flatten(),
    })
}

pub(crate) fn decode_lease_markers<E>(
    values: LeaseMarkerValues,
    job_id: JobId,
) -> Result<LeaseMarkers, JobSystemError<E>> {
    let lease_value = values.lease_value.ok_or(JobSystemError::LeaseLost)?;
    let operation_value = values.operation_value.ok_or(JobSystemError::LeaseLost)?;
    keys::validate_job_marker(&lease_value, crate::codec::ValueTag::Lease, &job_id)
        .map_err(|_| JobSystemError::PayloadCorrupt)?;
    let (operation, fence_high_water) = keys::decode_active_operation(&operation_value, &job_id)
        .map_err(|_| JobSystemError::PayloadCorrupt)?;
    Ok(LeaseMarkers {
        lease_key: values.lease_key,
        lease_value,
        operation_key: values.operation_key,
        operation_value,
        operation,
        fence_high_water,
    })
}

pub(super) struct ScheduledMarkers {
    pub(super) due_value: Bytes,
    pub(super) fair_value: Bytes,
    pub(super) operation_value: Option<Bytes>,
    pub(super) fence_high_water: u64,
}

pub(super) async fn load_scheduled_markers<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
) -> JobResult<(StoreKey, StoreKey, ScheduledMarkers), S::Error> {
    let due_key = keys::due_key(
        system.namespace(),
        &record.queue,
        record.scheduled_at,
        &record.job_id,
    )?;
    let fair_key = keys::fair_key(system.namespace(), &record.queue, &record.job_id)?;
    let operation_key = keys::operation_key(system.namespace(), &record.job_id)?;
    let values = system
        .read_many(&[due_key.clone(), fair_key.clone(), operation_key])
        .await?;
    if values.len() != 3 {
        return Err(JobSystemError::PayloadCorrupt);
    }
    let markers = decode_scheduled_markers(values, record)?;
    Ok((due_key, fair_key, markers))
}

fn decode_scheduled_markers<E>(
    values: Vec<Option<Bytes>>,
    record: &JobRecordV1,
) -> Result<ScheduledMarkers, JobSystemError<E>> {
    let mut values = values.into_iter();
    let due_value = values
        .next()
        .flatten()
        .ok_or(JobSystemError::LeaseConflict)?;
    if keys::decode_timestamp_value(&due_value, crate::codec::ValueTag::Due)? != record.scheduled_at
    {
        return Err(JobSystemError::LeaseConflict);
    }
    let fair_value = values
        .next()
        .flatten()
        .ok_or(JobSystemError::LeaseConflict)?;
    keys::validate_job_marker(
        &fair_value,
        crate::codec::ValueTag::FairReady,
        &record.job_id,
    )
    .map_err(|_| JobSystemError::PayloadCorrupt)?;
    let operation_value = values.next().flatten();
    let fence_high_water = match &operation_value {
        Some(encoded) => {
            keys::decode_active_operation(encoded, &record.job_id)
                .map_err(|_| JobSystemError::PayloadCorrupt)?
                .1
        }
        None => 0,
    };
    Ok(ScheduledMarkers {
        due_value,
        fair_value,
        operation_value,
        fence_high_water,
    })
}
