//! Validation of storage records at the lifecycle boundary.

use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::JobId,
    keys,
    model::JobRecordV1,
    store::JobStore,
};

pub(crate) fn validate_persisted_identity<S: JobStore>(
    system: &JobSystem<S>,
    requested_job_id: JobId,
    record: &JobRecordV1,
) -> JobResult<(), S::Error> {
    if record.job_id != requested_job_id
        || record.namespace.as_bytes() != system.namespace().as_bytes()
    {
        return Err(JobSystemError::LeaseConflict);
    }
    for (index, key) in record.payload.chunk_keys.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| JobSystemError::PayloadCorrupt)?;
        let expected = keys::payload_key(system.namespace(), &record.job_id, index)?;
        if key != &expected {
            return Err(JobSystemError::PayloadCorrupt);
        }
    }
    Ok(())
}
