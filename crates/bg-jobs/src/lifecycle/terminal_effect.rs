use crate::{
    codec::{KeyCodec, KeyTag, decode_job_record},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    model::{JobRecordV1, JobState},
    store::{Check, JobStore, Mutation, StoreTransaction},
};

#[derive(Clone, Copy)]
pub(crate) enum TerminalEffectKind {
    Completed,
    Cancelled,
    DeadLettered,
    Retired,
}

impl TerminalEffectKind {
    pub(crate) fn removes_job(self) -> bool {
        matches!(self, Self::Completed | Self::Retired)
    }
}

/// Decoded lifecycle authority shared by terminal bookkeeping owners. It is
/// derived from the exact job check and mutation retained in recovery input.
pub(crate) struct TerminalEffect {
    record: JobRecordV1,
    kind: TerminalEffectKind,
}

impl TerminalEffect {
    pub(crate) fn record(&self) -> &JobRecordV1 {
        &self.record
    }
    pub(crate) fn kind(&self) -> TerminalEffectKind {
        self.kind
    }
}

impl<S: JobStore> JobSystem<S> {
    pub(crate) fn terminal_effect(
        &self,
        input: &StoreTransaction,
    ) -> JobResult<Option<TerminalEffect>, S::Error> {
        let prefix = KeyCodec::encode(self.namespace(), KeyTag::Job, &[])?;
        for mutation in input.mutations() {
            if !mutation.key().as_bytes().starts_with(prefix.as_bytes()) {
                continue;
            }
            let kind = match mutation {
                Mutation::ClearEffectReceipts(_) => continue,
                Mutation::Delete(_) => TerminalEffectKind::Completed,
                Mutation::Put(_, value) => match decode_job_record(value)?.state {
                    JobState::Cancelled => TerminalEffectKind::Cancelled,
                    JobState::DeadLettered => TerminalEffectKind::DeadLettered,
                    JobState::Scheduled | JobState::Leased(_) | JobState::Suspended => continue,
                },
            };
            let Some(Check::Value(_, encoded)) = input
                .checks()
                .iter()
                .find(|check| check.key() == mutation.key())
            else {
                return Err(JobSystemError::PayloadCorrupt);
            };
            let record = decode_job_record(encoded)?;
            super::validate_persisted_identity(self, record.job_id, &record)?;
            if KeyCodec::job(self.namespace(), &record.job_id)? != *mutation.key() {
                return Err(JobSystemError::PayloadCorrupt);
            }
            let kind = match (&record.state, kind) {
                (JobState::DeadLettered | JobState::Cancelled, TerminalEffectKind::Completed) => {
                    TerminalEffectKind::Retired
                }
                (_, kind) => kind,
            };
            return Ok(Some(TerminalEffect { record, kind }));
        }
        Ok(None)
    }
}
