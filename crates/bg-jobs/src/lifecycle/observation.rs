//! Durable lifecycle observations backed by the caller-owned store.

use bytes::Bytes;

use crate::{
    codec::{DecodedOperation, decode_job_record},
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreDataError},
    ids::{JobId, OperationId},
    lifecycle::{scan_payload, validate_persisted_identity},
    model::{
        JobRecordV1, LifecycleObservation, LifecyclePayload, LifecycleRecord,
        LifecycleRecordStatus, LifecycleRoutes, PayloadManifest,
    },
    store::{JobStore, StoreKey},
};

pub(crate) async fn observe<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<LifecycleObservation, S::Error> {
    let job_key = crate::keys::job_key(system.namespace(), &job_id)?;
    let operation_key = crate::keys::operation_key(system.namespace(), &job_id)?;
    let values = system.read_many(&[job_key, operation_key]).await?;
    if values.len() != 2 {
        return Err(JobSystemError::PayloadCorrupt);
    }
    let mut values = values.into_iter();
    let job = values.next().flatten();
    let operation = values.next().flatten();
    observe_values(system, job_id, job, operation).await
}

async fn observe_values<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    encoded_job: Option<Bytes>,
    encoded_operation: Option<Bytes>,
) -> JobResult<LifecycleObservation, S::Error> {
    match (encoded_job, encoded_operation) {
        (None, None) => Ok(LifecycleObservation::Missing),
        (Some(encoded), operation) => observe_current(system, job_id, encoded, operation).await,
        (None, Some(encoded)) => observe_terminal(job_id, encoded),
    }
}

async fn observe_current<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    encoded: Bytes,
    encoded_operation: Option<Bytes>,
) -> JobResult<LifecycleObservation, S::Error> {
    let record = match decode_current_record(&encoded) {
        Ok(record) => record,
        Err(error) => {
            return Ok(invalid_observation(
                record_status(&error),
                LifecycleRoutes::default(),
                None,
            ));
        }
    };
    if !persisted_identity_is_valid(system, job_id, &record) {
        return Ok(invalid_observation(
            LifecycleRecordStatus::Corrupt,
            LifecycleRoutes::default(),
            Some(project_record(record, false)),
        ));
    }

    let evidence = read_current_evidence(system, &record).await?;
    let operation_id = match decode_operation_id(encoded_operation, &job_id) {
        Ok(operation_id) => operation_id,
        Err(error) => {
            return Ok(invalid_observation(
                record_status(&error),
                evidence.routes,
                Some(project_record(record, evidence.payload_complete)),
            ));
        }
    };
    let projected_record = project_record(record, evidence.payload_complete);
    Ok(LifecycleObservation::Current {
        record: projected_record,
        operation_id,
        routes: evidence.routes,
        cancellation_requested: evidence.cancellation_requested,
        status: LifecycleRecordStatus::Valid,
    })
}

struct CurrentEvidence {
    routes: LifecycleRoutes,
    payload_complete: bool,
    cancellation_requested: bool,
}

fn decode_current_record(encoded: &Bytes) -> Result<JobRecordV1, StoreDataError> {
    decode_job_record(encoded)
}

fn persisted_identity_is_valid<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    record: &JobRecordV1,
) -> bool {
    validate_persisted_identity(system, job_id, record).is_ok()
}

fn decode_operation_id(
    encoded: Option<Bytes>,
    job_id: &JobId,
) -> Result<Option<OperationId>, StoreDataError> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    Ok(crate::keys::decode_operation_authority(&encoded, job_id)?.operation_id())
}

async fn read_current_evidence<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
) -> JobResult<CurrentEvidence, S::Error> {
    let keys = current_evidence_keys(system, record)?;
    let values = read_current_values(system, &keys).await?;
    decode_current_evidence(record, values)
}

fn current_evidence_keys<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
) -> JobResult<Vec<StoreKey>, S::Error> {
    let mut keys = vec![
        crate::keys::due_key(
            system.namespace(),
            &record.queue,
            record.scheduled_at,
            &record.job_id,
        )?,
        crate::keys::fair_key(system.namespace(), &record.queue, &record.job_id)?,
        crate::keys::lease_key(system.namespace(), &record.queue, &record.job_id)?,
        crate::keys::wake_key(system.namespace(), &record.queue)?,
    ];
    keys.extend(record.payload.chunk_keys.iter().cloned());
    keys.push(crate::keys::cancellation_key(
        system.namespace(),
        &record.job_id,
    )?);
    Ok(keys)
}

async fn read_current_values<S: JobStore>(
    system: &JobSystem<S>,
    keys: &[StoreKey],
) -> JobResult<Vec<Option<Bytes>>, S::Error> {
    let values = system.read_many(keys).await?;
    if values.len() != keys.len() {
        return Err(JobSystemError::PayloadCorrupt);
    }
    Ok(values)
}

fn decode_current_evidence<E>(
    record: &JobRecordV1,
    values: Vec<Option<Bytes>>,
) -> JobResult<CurrentEvidence, E> {
    let mut values = values.into_iter();
    let routes = decode_routes(&mut values);
    let payload_complete = payload_complete::<E, _>(
        &record.payload,
        values.by_ref().take(record.payload.chunk_keys.len()),
    );
    let cancellation_requested = values
        .next()
        .ok_or(JobSystemError::PayloadCorrupt)?
        .is_some();
    if values.next().is_some() {
        return Err(JobSystemError::PayloadCorrupt);
    }
    Ok(CurrentEvidence {
        routes,
        payload_complete,
        cancellation_requested,
    })
}

fn decode_routes<I>(values: &mut I) -> LifecycleRoutes
where I: Iterator<Item = Option<Bytes>> {
    let due = values.next().flatten().is_some();
    let fair = values.next().flatten().is_some();
    let lease = values.next().flatten().is_some();
    let wake = values.next().flatten().is_some();
    LifecycleRoutes {
        due,
        fair,
        lease,
        wake: (due || fair) && wake,
    }
}

fn payload_complete<E, I>(manifest: &PayloadManifest, encoded_chunks: I) -> bool
where I: IntoIterator<Item = Option<Bytes>> {
    scan_payload::<E, _, _>(manifest, encoded_chunks, |_| {}).is_ok()
}

fn project_record(record: JobRecordV1, payload_complete: bool) -> LifecycleRecord {
    let lifecycle_payload = project_payload(&record.payload, payload_complete);
    let checkpoint_bytes = record.checkpoint.as_ref().map_or(0, Bytes::len);
    LifecycleRecord {
        job_id: record.job_id,
        queue: record.queue,
        kind: record.kind,
        schema_version: record.schema_version,
        generation: record.generation,
        execution_id: record.execution_id,
        payload: lifecycle_payload,
        fairness: record.fairness,
        ordering_key: record.ordering_key,
        priority: record.priority,
        created_at: record.created_at,
        scheduled_at: record.scheduled_at,
        expires_at: record.expires_at,
        policy: record.policy,
        attempts: record.attempts,
        state: record.state,
        checkpoint_bytes,
        retention_deadline: record.retention_deadline,
        deduplication: record.deduplication,
        revision: record.revision,
    }
}

fn project_payload(payload: &PayloadManifest, complete: bool) -> LifecyclePayload {
    LifecyclePayload {
        total_length: payload.total_length,
        digest: payload.digest,
        chunk_count: payload.chunk_keys.len(),
        complete,
    }
}

fn invalid_observation(
    status: LifecycleRecordStatus,
    routes: LifecycleRoutes,
    record: Option<LifecycleRecord>,
) -> LifecycleObservation {
    LifecycleObservation::Invalid {
        status,
        routes,
        record,
    }
}

fn record_status(error: &StoreDataError) -> LifecycleRecordStatus {
    match error {
        StoreDataError::UnknownVersion(_) => LifecycleRecordStatus::UnknownVersion,
        StoreDataError::UnknownTag(_)
        | StoreDataError::Truncated
        | StoreDataError::Malformed(_)
        | StoreDataError::InvalidLength { .. }
        | StoreDataError::LengthOverflow
        | StoreDataError::TrailingBytes => LifecycleRecordStatus::Corrupt,
    }
}

fn observe_terminal<E>(job_id: JobId, encoded: Bytes) -> JobResult<LifecycleObservation, E>
where E: std::error::Error + Send + Sync + 'static {
    let receipt = match crate::codec::decode_operation(&encoded) {
        Ok(DecodedOperation::Receipt(receipt)) => receipt,
        Ok(DecodedOperation::Live(_)) => {
            return Ok(LifecycleObservation::Invalid {
                status: LifecycleRecordStatus::Corrupt,
                routes: LifecycleRoutes::default(),
                record: None,
            });
        }
        Err(error) => {
            return Ok(LifecycleObservation::Invalid {
                status: record_status(&error),
                routes: LifecycleRoutes::default(),
                record: None,
            });
        }
    };
    if receipt.job_id != job_id {
        return Ok(LifecycleObservation::Invalid {
            status: LifecycleRecordStatus::Corrupt,
            routes: LifecycleRoutes::default(),
            record: None,
        });
    }
    Ok(LifecycleObservation::Terminal(receipt))
}
