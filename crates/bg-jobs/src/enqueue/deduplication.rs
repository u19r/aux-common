//! Admission and expiry share ownership of the promised deduplication window.

use std::num::{NonZeroU32, NonZeroUsize};

use bytes::Bytes;

use super::constants::{
    EXPIRED_DEDUPE_PAGE_ITEMS, EXPIRED_DEDUPE_RETIRE_STORE_OPERATIONS, MAX_DEDUPE_RANGE_BYTES,
};
use crate::{
    budget::OperationBudget,
    codec::{KeyCodec, KeyTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreDataError},
    ids::{DeduplicationKey, Namespace},
    keys,
    model::JobRecordV1,
    store::{
        Check, CommitOutcome, JobStore, Mutation, RangeDirection, RangeEntry, RangeRequest,
        RangeRequestInput,
    },
    time::{Timestamp, WakeHint},
};

pub(super) struct DedupeAdmission {
    check: Check,
    mutations: Vec<Mutation>,
}

impl DedupeAdmission {
    pub(super) fn try_new(
        namespace: &Namespace,
        job: &JobRecordV1,
        expected: Option<Bytes>,
    ) -> Result<Option<Self>, StoreDataError> {
        let Some(dedupe) = &job.deduplication else {
            return Ok(None);
        };
        let key = keys::dedupe_key(namespace, dedupe.key())?;
        let expiry = keys::dedupe_expiry_key(namespace, dedupe.key(), dedupe.retain_until())?;
        let value = keys::dedupe_value(&job.job_id, dedupe.retain_until())?;
        let mut mutations = vec![
            Mutation::Put(key.clone(), value.clone()),
            Mutation::Put(expiry.clone(), value),
        ];
        let check = match expected {
            Some(value) => {
                let (_, previous_until) = keys::decode_dedupe_value(&value)?;
                let previous_expiry =
                    keys::dedupe_expiry_key(namespace, dedupe.key(), previous_until)?;
                if previous_expiry != expiry {
                    mutations.push(Mutation::Delete(previous_expiry));
                }
                Check::Value(key, value)
            }
            None => Check::Absent(key),
        };
        Ok(Some(Self { check, mutations }))
    }

    pub(super) fn append(self, checks: &mut Vec<Check>, mutations: &mut Vec<Mutation>) {
        checks.push(self.check);
        mutations.extend(self.mutations);
    }
}

impl<S: JobStore> JobSystem<S> {
    pub(crate) async fn retire_expired_deduplication(
        &self,
        now: Timestamp,
        budget: &mut OperationBudget,
        mut should_stop: impl FnMut() -> bool,
    ) -> JobResult<WakeHint, S::Error> {
        if should_stop() {
            return Ok(WakeHint::None);
        }
        if !budget.reserve(1) {
            return Ok(WakeHint::Now);
        }
        let request = self.deduplication_expiry_page()?;
        let page = self
            .store()
            .read_range(request)
            .await
            .map_err(JobSystemError::Store)?;
        for entry in page.entries {
            let (identity, until) = self.deduplication_expiry_identity(&entry)?;
            if until > now {
                return Ok(WakeHint::At(until));
            }
            if should_stop() || !budget.reserve(EXPIRED_DEDUPE_RETIRE_STORE_OPERATIONS) {
                return Ok(WakeHint::Now);
            }
            if !self.retire_deduplication_entry(entry, identity).await? {
                return Ok(WakeHint::Now);
            }
        }
        Ok(if page.continuation.is_some() {
            WakeHint::Now
        } else {
            WakeHint::None
        })
    }

    fn deduplication_expiry_page(&self) -> JobResult<RangeRequest, S::Error> {
        let start = KeyCodec::encode(self.namespace(), KeyTag::DedupeExpiry, &[])?;
        let end = KeyCodec::prefix_end(&start);
        let capabilities = self.store().capabilities();
        let item_limit = NonZeroU32::new(EXPIRED_DEDUPE_PAGE_ITEMS)
            .ok_or(JobSystemError::PayloadCorrupt)?
            .min(capabilities.max_range_items());
        let byte_limit = NonZeroUsize::new(MAX_DEDUPE_RANGE_BYTES)
            .ok_or(JobSystemError::PayloadCorrupt)?
            .min(capabilities.max_range_bytes());
        RangeRequest::try_from(RangeRequestInput {
            start: Some(start),
            end,
            direction: RangeDirection::Forward,
            item_limit,
            byte_limit,
            continuation: None,
        })
        .map_err(Into::into)
    }

    async fn retire_deduplication_entry(
        &self,
        entry: RangeEntry,
        identity: crate::store::StoreKey,
    ) -> JobResult<bool, S::Error> {
        let current = self
            .store()
            .get(identity.clone())
            .await
            .map_err(JobSystemError::Store)?;
        let mut checks = vec![Check::Value(entry.key.clone(), entry.value.clone())];
        let mut mutations = vec![Mutation::Delete(entry.key)];
        if current.as_ref() == Some(&entry.value) {
            mutations.push(Mutation::Delete(identity.clone()));
        }
        checks.push(match current {
            Some(value) => Check::Value(identity, value),
            None => Check::Absent(identity),
        });
        // The expiry index itself is durable retry input. A lost producer
        // leaves the entry present, or completes this exact guarded deletion;
        // no command journal reservation or retirement is needed.
        let input = crate::transition::checked_transaction(self, checks, mutations)?;
        match self
            .store()
            .transact(&input)
            .await
            .map_err(JobSystemError::Store)?
        {
            CommitOutcome::Committed => Ok(true),
            CommitOutcome::Conflict => Ok(false),
            CommitOutcome::Unknown => Err(JobSystemError::UnknownCommit),
        }
    }

    fn deduplication_expiry_identity(
        &self,
        entry: &RangeEntry,
    ) -> JobResult<(crate::store::StoreKey, Timestamp), S::Error> {
        let decoded = KeyCodec::decode_borrowed(self.namespace(), &entry.key)?;
        let [_, identity] = decoded.components.as_slice() else {
            return Err(JobSystemError::PayloadCorrupt);
        };
        let key =
            DeduplicationKey::try_new(identity).map_err(|_| JobSystemError::PayloadCorrupt)?;
        let (_, until) = keys::decode_dedupe_value(&entry.value)?;
        if decoded.tag != KeyTag::DedupeExpiry
            || entry.key != keys::dedupe_expiry_key(self.namespace(), &key, until)?
        {
            return Err(JobSystemError::PayloadCorrupt);
        }
        Ok((keys::dedupe_key(self.namespace(), &key)?, until))
    }
}
