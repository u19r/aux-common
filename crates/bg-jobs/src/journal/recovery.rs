use std::num::{NonZeroU32, NonZeroUsize};

use super::{
    codec::slot_key,
    constants::{COMMIT_WORST_CASE_STORE_OPERATIONS, HEAD_SCAN_BYTES, SLOT_COUNT},
    state::{Head, Phase, Slot},
};
use crate::{
    budget::OperationBudget,
    codec::{KeyCodec, KeyTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreDataError},
    ids::LeaseToken,
    store::{
        CommitOutcome, JobStore, RangeDirection, RangeEntry, RangeRequest, RangeRequestInput,
        StoreKey,
    },
};

pub(crate) struct RecoveryProgress {
    pub(crate) recovered: u32,
    pub(crate) pending: bool,
}

impl<S: JobStore> JobSystem<S> {
    /// Finishes accepted native commands after producer death. It never needs
    /// the original producer or a second execution of its handler.
    /// Recovery hydrates at most one native-bounded command at a time.
    /// Encoded input and decoded values can coexist during hydration. This
    /// memory is separate from handler in-flight payloads; automatic recovery
    /// runs before handlers and is bounded by native transaction limits.
    pub async fn recover_commits(&self) -> JobResult<u32, S::Error> {
        let maximum = COMMIT_WORST_CASE_STORE_OPERATIONS
            .saturating_mul(SLOT_COUNT as u32)
            .saturating_add(SLOT_COUNT as u32);
        let mut budget = OperationBudget::new(maximum, self.clone_observer());
        self.recover_pending_commits(&mut budget, || false)
            .await
            .map(|progress| progress.recovered)
    }

    pub(crate) async fn recover_pending_commits(
        &self,
        budget: &mut OperationBudget,
        mut should_stop: impl FnMut() -> bool + Send,
    ) -> JobResult<RecoveryProgress, S::Error> {
        let mut scan = RecoveryScan::new();
        let mut cursor = None;
        loop {
            if should_stop() || !budget.reserve(1) {
                scan.record(Ok(RecoveryStep::Exhausted));
                break;
            }
            let page = self
                .store()
                .read_range(self.commit_head_range(cursor)?)
                .await
                .map_err(JobSystemError::Store)?;
            for entry in page.entries {
                let result = self
                    .recover_commit_entry(entry, budget, &mut should_stop)
                    .await;
                if !scan.record(result) {
                    break;
                }
            }
            cursor = page.continuation;
            if cursor.is_none() || scan.exhausted {
                break;
            }
        }
        scan.first_error.map_or(Ok(scan.progress), Err)
    }

    async fn recover_commit_entry(
        &self,
        entry: RangeEntry,
        budget: &mut OperationBudget,
        should_stop: &mut (impl FnMut() -> bool + Send),
    ) -> JobResult<RecoveryStep, S::Error> {
        let slot = self.decode_commit_entry(entry.key, entry.value)?;
        let Head::Active(head) = slot.head else {
            return Ok(RecoveryStep::Skipped);
        };
        if self.journal.is_active(head.token)? || self.journal.is_reconciled(&slot)? {
            return Ok(RecoveryStep::Skipped);
        }
        head.validate_manifest(self.store().capabilities())?;
        let operations = if head.phase == Phase::Committed && head.chunks == 0 {
            0
        } else {
            COMMIT_WORST_CASE_STORE_OPERATIONS
        };
        if should_stop() || !budget.reserve(operations) {
            return Ok(RecoveryStep::Exhausted);
        }
        self.recover_commit_slot(&slot)
            .await
            .map(|outcome| match outcome {
                Some(_) => RecoveryStep::Recovered,
                None => RecoveryStep::Pending,
            })
    }

    fn commit_head_range(&self, cursor: Option<StoreKey>) -> JobResult<RangeRequest, S::Error> {
        let capabilities = self.store().capabilities();
        let prefix = KeyCodec::encode(self.namespace(), KeyTag::Commit, &[])?;
        let end = KeyCodec::encode(self.namespace(), KeyTag::Cancellation, &[])?;
        RangeRequest::try_from(RangeRequestInput {
            start: Some(prefix),
            end: Some(end),
            direction: RangeDirection::Forward,
            continuation: cursor,
            item_limit: NonZeroU32::new(
                capabilities.max_range_items().get().min(SLOT_COUNT as u32),
            )
            .ok_or(JobSystemError::PayloadCorrupt)?,
            byte_limit: NonZeroUsize::new(
                capabilities.max_range_bytes().get().min(HEAD_SCAN_BYTES),
            )
            .ok_or(JobSystemError::PayloadCorrupt)?,
        })
        .map_err(Into::into)
    }

    fn decode_commit_entry(
        &self,
        key: StoreKey,
        encoded: bytes::Bytes,
    ) -> JobResult<Slot, S::Error> {
        let decoded = KeyCodec::decode_borrowed(self.namespace(), &key)?;
        let [component] = decoded.components.as_slice() else {
            return Err(StoreDataError::Malformed("command slot key").into());
        };
        let [index] = *component else {
            return Err(StoreDataError::Malformed("command slot ordinal").into());
        };
        let index = *index;
        let head = Head::decode(&encoded)?;
        if key != slot_key(self.namespace(), index)? {
            return Err(StoreDataError::Malformed("command slot identity").into());
        }
        Ok(Slot {
            index,
            key,
            encoded: Some(encoded),
            head,
        })
    }

    async fn recover_commit_slot(&self, slot: &Slot) -> JobResult<Option<CommitOutcome>, S::Error> {
        let mut head = slot.active()?;
        // Committed work needs no new application authority. Exact-head
        // settlement can acknowledge the witness or delete pending chunks.
        if head.phase == Phase::Committed {
            return self
                .settle_commit(slot, CommitOutcome::Committed)
                .await
                .map(Some);
        }
        head.token = LeaseToken::generate().map_err(|_| JobSystemError::EntropyUnavailable)?;
        let _active = self.journal.register(head.token)?;
        let claimed = slot.replace(Head::Active(head));
        if !self
            .write_commit_control(slot, &claimed, Vec::new())
            .await?
        {
            return Ok(None);
        }
        self.resume_commit(claimed, None).await.map(Some)
    }
}

/// One bounded scan retains errors while allowing unrelated accepted commands
/// to finish. Capacity exhaustion alone stops further native work.
struct RecoveryScan<E> {
    progress: RecoveryProgress,
    first_error: Option<JobSystemError<E>>,
    exhausted: bool,
}

enum RecoveryStep {
    Skipped,
    Recovered,
    Pending,
    Exhausted,
}

impl<E> RecoveryScan<E> {
    fn new() -> Self {
        Self {
            progress: RecoveryProgress {
                recovered: 0,
                pending: false,
            },
            first_error: None,
            exhausted: false,
        }
    }

    fn record(&mut self, result: JobResult<RecoveryStep, E>) -> bool {
        match result {
            Ok(RecoveryStep::Skipped) => {}
            Ok(RecoveryStep::Recovered) => self.progress.recovered += 1,
            Ok(RecoveryStep::Pending) => self.progress.pending = true,
            Ok(RecoveryStep::Exhausted) => {
                self.progress.pending = true;
                self.exhausted = true;
            }
            Err(error) => {
                self.first_error.get_or_insert(error);
                self.progress.pending = true;
            }
        }
        !self.exhausted
    }
}
