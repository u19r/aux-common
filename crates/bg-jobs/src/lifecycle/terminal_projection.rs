use crate::{
    codec::decode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::JobId,
    keys,
    lifecycle::validate_persisted_identity,
    model::{JobState, JobTerminalAuthority},
    store::JobStore,
};

impl<S: JobStore> JobSystem<S> {
    /// Issues a native-checked witness for a cancelled or dead-lettered job.
    /// Active, suspended, missing, and successfully completed jobs return None.
    /// Reading a terminal state alone never grants live effect authority.
    pub async fn terminal_authority(
        &self,
        job_id: JobId,
    ) -> JobResult<Option<JobTerminalAuthority>, S::Error> {
        let observation_keys = [
            keys::job_key(self.namespace(), &job_id)?,
            keys::cancellation_key(self.namespace(), &job_id)?,
        ];
        let values = self.read_many(&observation_keys).await?;
        let [encoded_job, _] = values.as_slice() else {
            return Err(JobSystemError::PayloadCorrupt);
        };
        let Some(encoded_job) = encoded_job else {
            return Ok(None);
        };
        let record = decode_job_record(encoded_job)?;
        validate_persisted_identity(self, job_id, &record)?;
        match record.state {
            JobState::DeadLettered => Ok(Some(JobTerminalAuthority::from_terminal_record(
                observation_keys,
                encoded_job.clone(),
                JobState::DeadLettered,
                record.attempts.and_then(|attempts| attempts.last_outcome),
            ))),
            JobState::Cancelled => Ok(Some(JobTerminalAuthority::from_terminal_record(
                observation_keys,
                encoded_job.clone(),
                JobState::Cancelled,
                None,
            ))),
            JobState::Scheduled | JobState::Leased(_) | JobState::Suspended => Ok(None),
        }
    }
}
