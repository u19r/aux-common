use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::{Arc, Mutex},
};

use bytes::Bytes;

use super::constants::{
    DEFAULT_MAX_GET_MANY_KEY_BYTES, DEFAULT_MAX_GET_MANY_KEYS, DEFAULT_MAX_KEY_BYTES,
    DEFAULT_MAX_RANGE_BYTES, DEFAULT_MAX_RANGE_ITEMS, DEFAULT_MAX_TRANSACTION_BYTES,
    DEFAULT_MAX_TRANSACTION_KEYS, DEFAULT_MAX_VALUE_BYTES,
};
use crate::{
    error::StoreContractError,
    ids::CommitOperationId,
    store::{
        Check, CommitOutcome, JobStore, Mutation, RangeDirection, RangePage, RangeRequest,
        StoreCapabilities, StoreCapabilitiesInput, StoreKey, StoreLevel,
    },
};

/// Errors emitted by the reusable in-memory store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeStoreError {
    Contract(StoreContractError),
    KeyTooLarge,
    RangeItemTooLarge,
    CommitOperationReused,
    Poisoned,
}

impl fmt::Display for FakeStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => error.fmt(formatter),
            Self::KeyTooLarge => formatter.write_str("fake store key exceeds capability"),
            Self::RangeItemTooLarge => formatter.write_str("fake store range item exceeds limit"),
            Self::CommitOperationReused => {
                formatter.write_str("commit operation ID was reused with different content")
            }
            Self::Poisoned => formatter.write_str("fake store lock is poisoned"),
        }
    }
}

impl std::error::Error for FakeStoreError {}

impl From<StoreContractError> for FakeStoreError {
    fn from(error: StoreContractError) -> Self {
        Self::Contract(error)
    }
}

#[derive(Clone, Copy)]
struct QueuedCommit {
    outcome: CommitOutcome,
    apply: bool,
}

struct FakeState {
    entries: BTreeMap<StoreKey, Bytes>,
    commits: BTreeMap<CommitOperationId, RecordedCommit>,
    queued_commits: VecDeque<QueuedCommit>,
}

struct RecordedCommit {
    transaction: crate::store::StoreTransaction,
    outcome: CommitOutcome,
}

/// A deliberately fake, deterministic, checked, atomic ordered key/value store
/// for library tests and conformance runs.
///
/// `FakeStore` is test infrastructure in aux-common, not production
/// persistence. It implements only the public [`JobStore`] contract, has no
/// product schema or cloud assumptions, and can be configured as local or
/// distributed for conformance tests. Consumers must provide their own
/// production [`JobStore`] implementation and backend adapter. A queued
/// `Unknown` outcome applies the transaction by default, modelling an
/// acknowledgement lost after commit.
#[derive(Clone)]
pub struct FakeStore {
    capabilities: StoreCapabilities,
    state: Arc<Mutex<FakeState>>,
}

impl Default for FakeStore {
    fn default() -> Self {
        Self::with_level(StoreLevel::Local)
    }
}

impl FakeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn local() -> Self {
        Self::with_level(StoreLevel::Local)
    }

    pub fn distributed() -> Self {
        Self::with_level(StoreLevel::Distributed)
    }

    pub fn with_level(level: StoreLevel) -> Self {
        let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
            level,
            max_key_bytes: nonzero_usize(DEFAULT_MAX_KEY_BYTES),
            max_value_bytes: nonzero_usize(DEFAULT_MAX_VALUE_BYTES),
            max_get_many_keys: nonzero_u32(DEFAULT_MAX_GET_MANY_KEYS),
            max_get_many_key_bytes: nonzero_usize(DEFAULT_MAX_GET_MANY_KEY_BYTES),
            max_transaction_bytes: nonzero_usize(DEFAULT_MAX_TRANSACTION_BYTES),
            max_transaction_keys: nonzero_u32(DEFAULT_MAX_TRANSACTION_KEYS),
            max_range_items: nonzero_u32(DEFAULT_MAX_RANGE_ITEMS),
            max_range_bytes: nonzero_usize(DEFAULT_MAX_RANGE_BYTES),
            max_transaction_duration: std::time::Duration::from_secs(5),
        });
        match capabilities {
            Ok(value) => Self::with_capabilities(value),
            Err(_) => unreachable!("default fake-store capabilities are valid"),
        }
    }

    pub fn with_capabilities(capabilities: StoreCapabilities) -> Self {
        Self {
            capabilities,
            state: Arc::new(Mutex::new(FakeState {
                entries: BTreeMap::new(),
                commits: BTreeMap::new(),
                queued_commits: VecDeque::new(),
            })),
        }
    }

    pub fn capabilities(&self) -> StoreCapabilities {
        self.capabilities
    }

    /// Queue a deterministic result for the next commit. Unknown applies the
    /// transaction.
    pub fn queue_commit_outcome(&self, outcome: CommitOutcome) -> Result<(), FakeStoreError> {
        self.queue_commit(outcome, outcome != CommitOutcome::Conflict)
    }

    /// Queue an acknowledgement lost before the transaction is applied.
    pub fn queue_unknown_before_commit(&self) -> Result<(), FakeStoreError> {
        self.queue_commit(CommitOutcome::Unknown, false)
    }

    /// Queue an acknowledgement that is lost after the checked mutation
    /// applies.
    pub fn queue_unknown_after_commit(&self) -> Result<(), FakeStoreError> {
        self.queue_commit(CommitOutcome::Unknown, true)
    }

    pub fn put_raw(&self, key: StoreKey, value: Bytes) -> Result<(), FakeStoreError> {
        self.validate_key(&key)?;
        if value.len() > self.capabilities.max_value_bytes().get() {
            return Err(FakeStoreError::Contract(
                StoreContractError::CapabilityExceeded("value bytes"),
            ));
        }
        let mut state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        state.entries.insert(key, value);
        Ok(())
    }

    /// Removes one explicitly named fixture key without going through a
    /// transaction.  This is restricted to the fake store's conformance
    /// surface so corruption/quarantine connectors can exercise recovery
    /// against the same persisted keyspace as production code.
    pub fn delete_raw(&self, key: &StoreKey) -> Result<bool, FakeStoreError> {
        self.validate_key(key)?;
        let mut state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        Ok(state.entries.remove(key).is_some())
    }

    pub fn snapshot(&self) -> Result<Vec<(StoreKey, Bytes)>, FakeStoreError> {
        let state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        Ok(state
            .entries
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect())
    }

    pub fn contains(&self, key: &StoreKey) -> Result<bool, FakeStoreError> {
        let state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        Ok(state.entries.contains_key(key))
    }

    fn queue_commit(&self, outcome: CommitOutcome, apply: bool) -> Result<(), FakeStoreError> {
        let mut state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        state
            .queued_commits
            .push_back(QueuedCommit { outcome, apply });
        Ok(())
    }

    fn validate_key(&self, key: &StoreKey) -> Result<(), FakeStoreError> {
        if key.as_bytes().len() > self.capabilities.max_key_bytes().get() {
            return Err(FakeStoreError::KeyTooLarge);
        }
        Ok(())
    }

    fn read_page(&self, request: RangeRequest) -> Result<RangePage, FakeStoreError> {
        self.capabilities.validate_range(&request)?;
        self.validate_range_keys(&request)?;
        let state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        let mut has_more = false;
        let iter: Box<dyn Iterator<Item = (&StoreKey, &Bytes)>> = match request.direction() {
            RangeDirection::Forward => Box::new(state.entries.iter()),
            RangeDirection::Reverse => Box::new(state.entries.iter().rev()),
        };
        for (key, value) in iter {
            if !within_range(key, &request) || !after_continuation(key, &request) {
                continue;
            }
            if entries.len() >= request.item_limit().get() as usize {
                has_more = true;
                break;
            }
            let entry_bytes = key.as_bytes().len().saturating_add(value.len());
            if entry_bytes > request.byte_limit().get() && entries.is_empty() {
                return Err(FakeStoreError::RangeItemTooLarge);
            }
            if bytes.saturating_add(entry_bytes) > request.byte_limit().get() {
                has_more = true;
                break;
            }
            bytes = bytes.saturating_add(entry_bytes);
            entries.push(crate::store::RangeEntry {
                key: key.clone(),
                value: value.clone(),
            });
        }
        let continuation = has_more
            .then(|| entries.last().map(|entry| entry.key.clone()))
            .flatten();
        RangePage::new(entries, continuation).map_err(FakeStoreError::from)
    }

    fn validate_range_keys(&self, request: &RangeRequest) -> Result<(), FakeStoreError> {
        if request
            .start()
            .is_some_and(|key| key.as_bytes().len() > self.capabilities.max_key_bytes().get())
            || request
                .end()
                .is_some_and(|key| key.as_bytes().len() > self.capabilities.max_key_bytes().get())
        {
            return Err(FakeStoreError::KeyTooLarge);
        }
        Ok(())
    }

    fn commit_transaction(
        &self,
        transaction: &crate::store::StoreTransaction,
    ) -> Result<CommitOutcome, FakeStoreError> {
        self.capabilities.validate_transaction(transaction)?;
        for check in transaction.checks() {
            self.validate_key(check.key())?;
        }
        for mutation in transaction.mutations() {
            self.validate_key(mutation.key())?;
        }
        let mut state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        if let Some(recorded) = state.commits.get(&transaction.operation_id()) {
            return if recorded.transaction == *transaction {
                Ok(recorded.outcome)
            } else {
                Err(FakeStoreError::CommitOperationReused)
            };
        }
        if !checks_match(&state.entries, transaction.checks()) {
            record_commit(&mut state, transaction, CommitOutcome::Conflict);
            return Ok(CommitOutcome::Conflict);
        }
        let queued = state.queued_commits.pop_front();
        let (outcome, apply) = queued
            .map(|value| (value.outcome, value.apply))
            .unwrap_or((CommitOutcome::Committed, true));
        if outcome == CommitOutcome::Conflict || !apply {
            if outcome == CommitOutcome::Conflict {
                record_commit(&mut state, transaction, CommitOutcome::Conflict);
            }
            return Ok(outcome);
        }
        apply_mutations(&mut state.entries, transaction.mutations());
        record_commit(&mut state, transaction, CommitOutcome::Committed);
        Ok(outcome)
    }
}

fn record_commit(
    state: &mut FakeState,
    transaction: &crate::store::StoreTransaction,
    outcome: CommitOutcome,
) {
    state.commits.insert(
        transaction.operation_id(),
        RecordedCommit {
            transaction: transaction.clone(),
            outcome,
        },
    );
}

impl JobStore for FakeStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.capabilities
    }

    async fn get(&self, key: StoreKey) -> Result<Option<Bytes>, Self::Error> {
        self.validate_key(&key)?;
        let state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        Ok(state.entries.get(&key).cloned())
    }

    async fn get_many(&self, keys: &[StoreKey]) -> Result<Vec<Option<Bytes>>, Self::Error> {
        // This is the fake's one native batch operation: validate the complete
        // request, take one snapshot lock, and preserve input order/cardinality
        // without routing through the point-read method.
        self.capabilities.validate_get_many(keys)?;
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let state = self.state.lock().map_err(|_| FakeStoreError::Poisoned)?;
        Ok(keys
            .iter()
            .map(|key| state.entries.get(key).cloned())
            .collect())
    }

    async fn read_range(&self, request: RangeRequest) -> Result<RangePage, Self::Error> {
        self.read_page(request)
    }

    async fn commit(
        &self,
        transaction: &crate::store::StoreTransaction,
    ) -> Result<CommitOutcome, Self::Error> {
        self.commit_transaction(transaction)
    }
}

fn checks_match(entries: &BTreeMap<StoreKey, Bytes>, checks: &[Check]) -> bool {
    checks.iter().all(|check| match check {
        Check::Absent(key) => !entries.contains_key(key),
        Check::Value(key, expected) => entries.get(key) == Some(expected),
    })
}

fn apply_mutations(entries: &mut BTreeMap<StoreKey, Bytes>, mutations: &[Mutation]) {
    for mutation in mutations {
        match mutation {
            Mutation::Put(key, value) => {
                entries.insert(key.clone(), value.clone());
            }
            Mutation::Delete(key) => {
                entries.remove(key);
            }
        }
    }
}

fn within_range(key: &StoreKey, request: &RangeRequest) -> bool {
    request.start().is_none_or(|start| key >= start) && request.end().is_none_or(|end| key < end)
}

fn after_continuation(key: &StoreKey, request: &RangeRequest) -> bool {
    request
        .continuation()
        .is_none_or(|cursor| match request.direction() {
            RangeDirection::Forward => key > cursor,
            RangeDirection::Reverse => key < cursor,
        })
}

fn nonzero_usize(value: usize) -> std::num::NonZeroUsize {
    match std::num::NonZeroUsize::new(value) {
        Some(value) => value,
        None => unreachable!("fixed fake-store capability is non-zero"),
    }
}

fn nonzero_u32(value: u32) -> std::num::NonZeroU32 {
    match std::num::NonZeroU32::new(value) {
        Some(value) => value,
        None => unreachable!("fixed fake-store capability is non-zero"),
    }
}
