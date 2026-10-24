use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    future::Future,
    sync::{Arc, Mutex},
};

use bg_jobs::store::{
    CommitOperationId, CommitOutcome, JobStore, RangePage, RangeRequest, StoreCapabilities,
    StoreKey, StoreTransaction,
};
use bytes::Bytes;

/// Store operation at which a deterministic fault should be injected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultOperation {
    Get,
    GetMany,
    Range,
}

/// Read faults supported by the reusable harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadFaultKind {
    Unavailable,
    Timeout,
}

/// Commit faults supported by the reusable harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommitFaultKind {
    Transient(ReadFaultKind),
    Conflict,
    UnknownBeforeCommit,
    UnknownAfterCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueuedFault {
    Read(FaultOperation, ReadFaultKind),
    Commit(CommitFaultKind),
}

/// Error returned by [`FaultStore`] when an injected or wrapped operation
/// fails. The inner error remains available to the consumer's conformance
/// assertions without exposing it through job telemetry.
#[derive(Debug)]
pub enum FaultStoreError<E> {
    Inner(E),
    Unavailable,
    Timeout,
    CommitOperationReused,
    Poisoned,
}

impl<E: fmt::Display> fmt::Display for FaultStoreError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(error) => error.fmt(formatter),
            Self::Unavailable => formatter.write_str("injected store unavailability"),
            Self::Timeout => formatter.write_str("injected store timeout"),
            Self::CommitOperationReused => {
                formatter.write_str("commit operation ID was reused with different content")
            }
            Self::Poisoned => formatter.write_str("fault store state is poisoned"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display + 'static> std::error::Error for FaultStoreError<E> {}

/// A cloneable test/conformance-only `JobStore` decorator that injects
/// one-shot, deterministic failures at the owning store boundary.
///
/// `UnknownAfterCommit` invokes the wrapped transaction and changes only its
/// acknowledgement. `UnknownBeforeCommit` does not invoke it. This lets a
/// consumer prove reconciliation without adding a second persistence path.
/// It is not a production persistence adapter; consumers wrap their own
/// production `JobStore` only while running conformance proof.
pub struct FaultStore<S: JobStore> {
    inner: Arc<S>,
    state: Arc<Mutex<FaultState>>,
}

#[derive(Default)]
struct FaultState {
    queued: VecDeque<QueuedFault>,
    commits: BTreeMap<CommitOperationId, StoreTransaction>,
}

impl<S: JobStore> Clone for FaultStore<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            state: Arc::clone(&self.state),
        }
    }
}

impl<S: JobStore> FaultStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner: Arc::new(inner),
            state: Arc::new(Mutex::new(FaultState::default())),
        }
    }

    pub fn queue_read_fault(
        &self,
        operation: FaultOperation,
        kind: ReadFaultKind,
    ) -> Result<(), FaultStoreError<S::Error>> {
        let mut state = self.state.lock().map_err(|_| FaultStoreError::Poisoned)?;
        state.queued.push_back(QueuedFault::Read(operation, kind));
        Ok(())
    }

    pub fn queue_commit_fault(
        &self,
        kind: CommitFaultKind,
    ) -> Result<(), FaultStoreError<S::Error>> {
        let mut state = self.state.lock().map_err(|_| FaultStoreError::Poisoned)?;
        state.queued.push_back(QueuedFault::Commit(kind));
        Ok(())
    }

    pub fn clear_faults(&self) -> Result<(), FaultStoreError<S::Error>> {
        let mut state = self.state.lock().map_err(|_| FaultStoreError::Poisoned)?;
        state.queued.clear();
        Ok(())
    }

    pub fn pending_faults(&self) -> Result<usize, FaultStoreError<S::Error>> {
        let state = self.state.lock().map_err(|_| FaultStoreError::Poisoned)?;
        Ok(state.queued.len())
    }

    fn take_fault(
        &self,
        operation: Option<FaultOperation>,
    ) -> Result<Option<QueuedFault>, FaultStoreError<S::Error>> {
        let mut state = self.state.lock().map_err(|_| FaultStoreError::Poisoned)?;
        let index = state
            .queued
            .iter()
            .position(|fault| match (operation, fault) {
                (Some(operation), QueuedFault::Read(queued_operation, _)) => {
                    *queued_operation == operation
                }
                (None, QueuedFault::Commit(_)) => true,
                _ => false,
            });
        Ok(index.and_then(|index| state.queued.remove(index)))
    }

    fn replay_injected_conflict(
        &self,
        transaction: &StoreTransaction,
    ) -> Result<bool, FaultStoreError<S::Error>> {
        let state = self.state.lock().map_err(|_| FaultStoreError::Poisoned)?;
        match state.commits.get(&transaction.operation_id()) {
            Some(recorded) if recorded == transaction => Ok(true),
            Some(_) => Err(FaultStoreError::CommitOperationReused),
            None => Ok(false),
        }
    }

    fn record_injected_conflict(
        &self,
        transaction: &StoreTransaction,
    ) -> Result<(), FaultStoreError<S::Error>> {
        let mut state = self.state.lock().map_err(|_| FaultStoreError::Poisoned)?;
        state
            .commits
            .insert(transaction.operation_id(), transaction.clone());
        Ok(())
    }
}

impl<S: JobStore> JobStore for FaultStore<S> {
    type Error = FaultStoreError<S::Error>;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    fn get(
        &self,
        key: StoreKey,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_ {
        let store = self.clone();
        async move {
            if let Some(QueuedFault::Read(_, kind)) = store.take_fault(Some(FaultOperation::Get))? {
                return Err(read_fault(kind));
            }
            store.inner.get(key).await.map_err(FaultStoreError::Inner)
        }
    }

    fn get_many<'a>(
        &'a self,
        keys: &'a [StoreKey],
    ) -> impl Future<Output = Result<Vec<Option<Bytes>>, Self::Error>> + Send + 'a {
        let store = self.clone();
        async move {
            if let Some(QueuedFault::Read(_, kind)) =
                store.take_fault(Some(FaultOperation::GetMany))?
            {
                return Err(read_fault(kind));
            }
            store
                .inner
                .get_many(keys)
                .await
                .map_err(FaultStoreError::Inner)
        }
    }

    fn read_range(
        &self,
        request: RangeRequest,
    ) -> impl Future<Output = Result<RangePage, Self::Error>> + Send + '_ {
        let store = self.clone();
        async move {
            if let Some(QueuedFault::Read(_, kind)) =
                store.take_fault(Some(FaultOperation::Range))?
            {
                return Err(read_fault(kind));
            }
            store
                .inner
                .read_range(request)
                .await
                .map_err(FaultStoreError::Inner)
        }
    }

    fn commit<'a>(
        &'a self,
        transaction: &'a StoreTransaction,
    ) -> impl Future<Output = Result<CommitOutcome, Self::Error>> + Send + 'a {
        let store = self.clone();
        async move {
            if store.replay_injected_conflict(transaction)? {
                return Ok(CommitOutcome::Conflict);
            }
            match store.take_fault(None)? {
                Some(QueuedFault::Commit(kind)) => match kind {
                    CommitFaultKind::Transient(kind) => Err(read_fault(kind)),
                    CommitFaultKind::Conflict => {
                        store.record_injected_conflict(transaction)?;
                        Ok(CommitOutcome::Conflict)
                    }
                    CommitFaultKind::UnknownBeforeCommit => Ok(CommitOutcome::Unknown),
                    CommitFaultKind::UnknownAfterCommit => {
                        let result = store
                            .inner
                            .commit(transaction)
                            .await
                            .map_err(FaultStoreError::Inner)?;
                        Ok(if result == CommitOutcome::Committed {
                            CommitOutcome::Unknown
                        } else {
                            result
                        })
                    }
                },
                Some(QueuedFault::Read(..)) => {
                    unreachable!("commit selector returned a read fault")
                }
                None => store
                    .inner
                    .commit(transaction)
                    .await
                    .map_err(FaultStoreError::Inner),
            }
        }
    }
}

fn read_fault<E>(kind: ReadFaultKind) -> FaultStoreError<E> {
    match kind {
        ReadFaultKind::Unavailable => FaultStoreError::Unavailable,
        ReadFaultKind::Timeout => FaultStoreError::Timeout,
    }
}

/// Exact store-operation counters for debug performance and budget tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OperationCounts {
    pub gets: u64,
    pub get_many: u64,
    pub get_many_keys: u64,
    pub ranges: u64,
    pub commits: u64,
    pub get_key_bytes: u64,
    pub get_many_key_bytes: u64,
    pub range_request_key_bytes: u64,
    pub range_result_bytes: u64,
    pub transaction_bytes: u64,
    pub transaction_checks: u64,
    pub transaction_mutations: u64,
}

#[derive(Default)]
struct CountState {
    counts: OperationCounts,
}

/// A cloneable operation-counting decorator for representative debug
/// workloads. It records calls and encoded bytes, not wall-clock timing.
pub struct CountingStore<S: JobStore> {
    inner: Arc<S>,
    state: Arc<Mutex<CountState>>,
}

impl<S: JobStore> Clone for CountingStore<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            state: Arc::clone(&self.state),
        }
    }
}

impl<S: JobStore> CountingStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner: Arc::new(inner),
            state: Arc::new(Mutex::new(CountState::default())),
        }
    }

    pub fn snapshot(&self) -> OperationCounts {
        match self.state.lock() {
            Ok(state) => state.counts,
            Err(poisoned) => poisoned.into_inner().counts,
        }
    }

    pub fn reset(&self) {
        match self.state.lock() {
            Ok(mut state) => state.counts = OperationCounts::default(),
            Err(poisoned) => poisoned.into_inner().counts = OperationCounts::default(),
        }
    }

    fn record(&self, update: impl FnOnce(&mut OperationCounts)) {
        match self.state.lock() {
            Ok(mut state) => update(&mut state.counts),
            Err(poisoned) => update(&mut poisoned.into_inner().counts),
        }
    }
}

impl<S: JobStore> JobStore for CountingStore<S> {
    type Error = S::Error;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    fn get(
        &self,
        key: StoreKey,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_ {
        let store = self.clone();
        async move {
            let key_bytes = key.as_bytes().len() as u64;
            store.record(|counts| {
                counts.gets += 1;
                counts.get_key_bytes += key_bytes;
            });
            store.inner.get(key).await
        }
    }

    fn get_many<'a>(
        &'a self,
        keys: &'a [StoreKey],
    ) -> impl Future<Output = Result<Vec<Option<Bytes>>, Self::Error>> + Send + 'a {
        let store = self.clone();
        async move {
            let key_count = keys.len() as u64;
            let key_bytes = keys
                .iter()
                .map(|key| key.as_bytes().len() as u64)
                .sum::<u64>();
            store.record(|counts| {
                counts.get_many += 1;
                counts.get_many_keys += key_count;
                counts.get_many_key_bytes += key_bytes;
            });
            store.inner.get_many(keys).await
        }
    }

    fn read_range(
        &self,
        request: RangeRequest,
    ) -> impl Future<Output = Result<RangePage, Self::Error>> + Send + '_ {
        let store = self.clone();
        async move {
            let request_bytes = range_request_key_bytes(&request);
            store.record(|counts| {
                counts.ranges += 1;
                counts.range_request_key_bytes += request_bytes;
            });
            let page = store.inner.read_range(request).await?;
            let result_bytes = page.total_bytes() as u64;
            store.record(|counts| counts.range_result_bytes += result_bytes);
            Ok(page)
        }
    }

    fn commit<'a>(
        &'a self,
        transaction: &'a StoreTransaction,
    ) -> impl Future<Output = Result<CommitOutcome, Self::Error>> + Send + 'a {
        let store = self.clone();
        async move {
            let transaction_bytes = transaction.encoded_bytes() as u64;
            let checks = transaction.checks().len() as u64;
            let mutations = transaction.mutations().len() as u64;
            store.record(|counts| {
                counts.commits += 1;
                counts.transaction_bytes += transaction_bytes;
                counts.transaction_checks += checks;
                counts.transaction_mutations += mutations;
            });
            store.inner.commit(transaction).await
        }
    }
}

fn range_request_key_bytes(request: &RangeRequest) -> u64 {
    request
        .start()
        .iter()
        .chain(request.end().iter())
        .chain(request.continuation().iter())
        .map(|key| key.as_bytes().len() as u64)
        .sum()
}
