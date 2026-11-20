//! Rebase expired identity observations without discarding accepted enqueues.

use super::deduplication::DedupeAdmission;
use crate::{
    codec::{KeyCodec, KeyTag, decode_job_record},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    model::JobRecordV1,
    store::{
        Check, CommitOutcome, JobStore, Mutation, StoreKey, StoreTransaction, StoreTransactionInput,
    },
};

struct DedupeTransition {
    record: JobRecordV1,
    key: StoreKey,
}

impl DedupeTransition {
    fn from_input<S: JobStore>(
        system: &JobSystem<S>,
        input: &StoreTransaction,
    ) -> JobResult<Option<Self>, S::Error> {
        let prefix = KeyCodec::encode(system.namespace(), KeyTag::Dedupe, &[])?;
        let Some((key, value)) = input
            .mutations()
            .iter()
            .find_map(|mutation| match mutation {
                Mutation::Put(key, value) if key.as_bytes().starts_with(prefix.as_bytes()) => {
                    Some((key, value))
                }
                _ => None,
            })
        else {
            return Ok(None);
        };
        let (job_id, until) = keys::decode_dedupe_value(value)?;
        let job_key = keys::job_key(system.namespace(), &job_id)?;
        if !input.checks().contains(&Check::Absent(job_key.clone())) {
            return Ok(None);
        }
        let Some(Mutation::Put(_, encoded)) = input
            .mutations()
            .iter()
            .find(|mutation| mutation.key() == &job_key)
        else {
            return Err(JobSystemError::PayloadCorrupt);
        };
        let record = decode_job_record(encoded)?;
        crate::lifecycle::validate_persisted_identity(system, job_id, &record)?;
        let transition = Self {
            record,
            key: key.clone(),
        };
        transition.validate_identity(system, input, until)?;
        Ok(Some(transition))
    }

    fn validate_identity<S: JobStore>(
        &self,
        system: &JobSystem<S>,
        input: &StoreTransaction,
        until: crate::time::Timestamp,
    ) -> JobResult<(), S::Error> {
        let deduplication = self
            .record
            .deduplication
            .as_ref()
            .ok_or(JobSystemError::PayloadCorrupt)?;
        if deduplication.retain_until() != until
            || keys::dedupe_key(
                system.namespace(),
                keys::DedupeIdentity::new(
                    &self.record.kind,
                    &self.record.fairness,
                    deduplication.key(),
                ),
            )? != self.key
            || !input.checks().iter().any(|check| check.key() == &self.key)
        {
            return Err(JobSystemError::PayloadCorrupt);
        }
        Ok(())
    }

    fn rebuild<S: JobStore>(
        &self,
        system: &JobSystem<S>,
        input: &mut StoreTransactionInput,
        current: Option<bytes::Bytes>,
    ) -> JobResult<(), S::Error> {
        let admission = DedupeAdmission::try_new(system.namespace(), &self.record, current)?
            .ok_or(JobSystemError::PayloadCorrupt)?;
        input.remove_key(&self.key);
        let mut mutations = Vec::new();
        let expiry_prefix = KeyCodec::encode(system.namespace(), KeyTag::DedupeExpiry, &[])?;
        let identity = self
            .record
            .deduplication
            .as_ref()
            .ok_or(JobSystemError::PayloadCorrupt)?
            .key();
        for mutation in std::mem::take(&mut input.mutations) {
            if mutation
                .key()
                .as_bytes()
                .starts_with(expiry_prefix.as_bytes())
            {
                let decoded = KeyCodec::decode_borrowed(system.namespace(), mutation.key())?;
                if decoded.components.last().copied() == Some(identity.as_bytes()) {
                    continue;
                }
            }
            mutations.push(mutation);
        }
        input.mutations = mutations;
        admission.append(&mut input.checks, &mut input.mutations);
        Ok(())
    }
}

impl<S: JobStore> JobSystem<S> {
    pub(crate) fn deduplication_enqueue_check<'a>(
        &self,
        input: &'a StoreTransaction,
    ) -> JobResult<Option<&'a Check>, S::Error> {
        let Some(transition) = DedupeTransition::from_input(self, input)? else {
            return Ok(None);
        };
        Ok(input
            .checks()
            .iter()
            .find(|check| check.key() == &transition.key))
    }

    pub(crate) async fn refresh_deduplication_transition(
        &self,
        input: &StoreTransaction,
        draft: &mut StoreTransactionInput,
        command: &Check,
    ) -> JobResult<bool, S::Error> {
        let Some(transition) = DedupeTransition::from_input(self, input)? else {
            return Ok(true);
        };
        let current = self
            .store()
            .get(transition.key.clone())
            .await
            .map_err(JobSystemError::Store)?;
        if let Some(value) = &current {
            let (_, until) = keys::decode_dedupe_value(value)?;
            if until > transition.record.created_at {
                // Point reads can regress. Only native confirmation of this
                // competing unexpired identity can reject accepted work.
                let proof = crate::transition::checked_transaction(
                    self,
                    vec![
                        command.clone(),
                        Check::Value(transition.key.clone(), value.clone()),
                    ],
                    Vec::new(),
                )?;
                return match self
                    .store()
                    .transact(&proof)
                    .await
                    .map_err(JobSystemError::Store)?
                {
                    CommitOutcome::Committed => Ok(false),
                    CommitOutcome::Conflict | CommitOutcome::Unknown => {
                        Err(JobSystemError::UnknownCommit)
                    }
                };
            }
        }
        transition.rebuild(self, draft, current)?;
        Ok(true)
    }
}
