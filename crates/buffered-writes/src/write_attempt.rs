use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Deref,
    sync::Arc,
};

use serde::de::DeserializeOwned;

use crate::{
    batch::{PreparedOperation, PreparedPayload, RecordCodec, SealedBatch},
    configuration::{BatchId, Deadline, Namespace, OperationId, TenantScope},
    error::{EncodeError, SinkError},
    write_outcome::{OperationStatus, WriteOutcome},
};

/// One pending item and its stable [`OperationId`] inside a [`WriteAttempt`].
pub struct PendingItem<T> {
    operation_id: OperationId,
    items: Arc<[T]>,
    index: usize,
}

impl<T> Clone for PendingItem<T> {
    fn clone(&self) -> Self {
        Self {
            operation_id: self.operation_id.clone(),
            items: self.items.clone(),
            index: self.index,
        }
    }
}

impl<T> PendingItem<T> {
    #[must_use]
    pub fn new(operation_id: OperationId, item: T) -> Self {
        Self {
            operation_id,
            items: Arc::from([item]),
            index: 0,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub fn item(&self) -> &T {
        &self.items[self.index]
    }
}

impl<T: PartialEq> PartialEq for PendingItem<T> {
    fn eq(&self, other: &Self) -> bool {
        self.operation_id == other.operation_id && self.item() == other.item()
    }
}

impl<T: Eq> Eq for PendingItem<T> {}

impl<T> Deref for PendingItem<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.item()
    }
}

impl<T> AsRef<T> for PendingItem<T> {
    fn as_ref(&self) -> &T {
        self.item()
    }
}

/// Owned attempt view passed to [`crate::WriteSink::flush_writes`].
pub struct WriteAttempt<T> {
    batch: SealedBatch,
    items: Arc<[T]>,
    pending_items: Arc<[PendingItem<T>]>,
    pending_operations: Arc<[PreparedOperation]>,
    pending_operation_ids: Arc<[OperationId]>,
    deadline: Deadline,
}

impl<T> Clone for WriteAttempt<T> {
    fn clone(&self) -> Self {
        Self {
            batch: self.batch.clone(),
            items: self.items.clone(),
            pending_items: self.pending_items.clone(),
            pending_operations: self.pending_operations.clone(),
            pending_operation_ids: self.pending_operation_ids.clone(),
            deadline: self.deadline,
        }
    }
}

impl<T> WriteAttempt<T> {
    pub(crate) fn try_new(
        batch: SealedBatch,
        codec: &dyn RecordCodec<T>,
        pending_operation_ids: Arc<[OperationId]>,
        deadline: Deadline,
    ) -> Result<Self, EncodeError>
    where
        T: 'static,
    {
        let items: Arc<[T]> = batch
            .records()
            .iter()
            .map(|record| codec.decode(&record.payload))
            .collect::<Result<Vec<_>, _>>()?
            .into();
        let pending_set: BTreeSet<&OperationId> = pending_operation_ids.iter().collect();
        let pending_items = batch
            .records()
            .iter()
            .enumerate()
            .filter(|(_, record)| pending_set.contains(&record.operation_id))
            .map(|(index, record)| PendingItem {
                operation_id: record.operation_id.clone(),
                items: items.clone(),
                index,
            })
            .collect::<Vec<_>>()
            .into();
        let pending_operations = batch.pending_operations(&pending_set);
        Ok(Self {
            batch,
            items,
            pending_items,
            pending_operations,
            pending_operation_ids,
            deadline,
        })
    }

    #[must_use]
    pub const fn batch_id(&self) -> BatchId {
        self.batch.batch_id()
    }

    #[must_use]
    pub const fn namespace(&self) -> &Namespace {
        self.batch.namespace()
    }

    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        self.batch.scope()
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        self.batch.digest()
    }

    #[must_use]
    pub const fn first_item_time_ms(&self) -> i64 {
        self.batch.first_item_time_ms()
    }

    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }

    #[must_use]
    pub const fn sealed_batch(&self) -> &SealedBatch {
        &self.batch
    }

    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    #[must_use]
    pub fn pending_items(&self) -> &[PendingItem<T>] {
        &self.pending_items
    }

    #[must_use]
    pub fn pending_operations(&self) -> &[PreparedOperation] {
        &self.pending_operations
    }

    #[must_use]
    pub fn operation_ids(&self) -> &[OperationId] {
        self.batch.operation_ids()
    }

    #[must_use]
    pub fn pending_operation_ids(&self) -> &[OperationId] {
        &self.pending_operation_ids
    }

    #[must_use]
    pub fn packed_payload(&self) -> Option<&[u8]> {
        match self.batch.prepared() {
            PreparedPayload::CustomOperations(ops) if ops.len() == 1 => {
                Some(ops[0].payload.as_ref())
            }
            PreparedPayload::SharedRecords | PreparedPayload::CustomOperations(_) => None,
        }
    }

    pub fn decode_packed<P: DeserializeOwned>(&self) -> Result<P, EncodeError> {
        let bytes = self
            .packed_payload()
            .ok_or(EncodeError::DeserializationFailed)?;
        serde_json::from_slice(bytes).map_err(|_| EncodeError::DeserializationFailed)
    }

    pub const fn complete(&self) -> Result<WriteOutcome, SinkError> {
        Ok(WriteOutcome::Complete)
    }

    /// Marks every pending operation complete except the supplied `unprocessed`
    /// IDs. Rejects duplicate or foreign operation IDs.
    pub fn complete_except<I>(&self, unprocessed: I) -> Result<WriteOutcome, SinkError>
    where I: IntoIterator<Item = OperationId> {
        let pending_set: BTreeSet<&OperationId> = self.pending_operation_ids.iter().collect();
        let mut unprocessed_set = BTreeSet::new();
        for op_id in unprocessed {
            if !pending_set.contains(&op_id) {
                return Err(SinkError::invalid_outcome(
                    "unprocessed operation id does not belong to pending attempt",
                ));
            }
            if !unprocessed_set.insert(op_id) {
                return Err(SinkError::invalid_outcome(
                    "duplicate operation id in unprocessed response",
                ));
            }
        }
        if unprocessed_set.is_empty() {
            return Ok(WriteOutcome::Complete);
        }
        let mut outcomes = BTreeMap::new();
        for op_id in self.pending_operation_ids.iter() {
            let status = if unprocessed_set.contains(op_id) {
                OperationStatus::Retryable {
                    reason: "unprocessed_item",
                }
            } else {
                OperationStatus::Completed
            };
            outcomes.insert(op_id.clone(), status);
        }
        Ok(WriteOutcome::Partial(outcomes))
    }

    pub fn partial(
        &self,
        outcomes: BTreeMap<OperationId, OperationStatus>,
    ) -> Result<WriteOutcome, SinkError> {
        let pending_set: BTreeSet<&OperationId> = self.pending_operation_ids.iter().collect();
        for op_id in outcomes.keys() {
            if !pending_set.contains(op_id) {
                return Err(SinkError::invalid_outcome(
                    "partial outcome contains foreign operation id",
                ));
            }
        }
        Ok(WriteOutcome::Partial(outcomes))
    }
}

impl SealedBatch {
    fn pending_operations(&self, pending: &BTreeSet<&OperationId>) -> Arc<[PreparedOperation]> {
        match self.prepared() {
            PreparedPayload::SharedRecords => self
                .records()
                .iter()
                .filter(|record| pending.contains(&record.operation_id))
                .map(|record| PreparedOperation {
                    operation_id: record.operation_id.clone(),
                    payload: record.payload.clone(),
                })
                .collect::<Vec<_>>()
                .into(),
            PreparedPayload::CustomOperations(operations) => operations
                .iter()
                .filter(|operation| pending.contains(&operation.operation_id))
                .cloned()
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl<T> std::fmt::Debug for PendingItem<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingItem")
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}
impl<T> std::fmt::Debug for WriteAttempt<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WriteAttempt")
            .field("batch_id", &self.batch_id())
            .field("items", &self.items.len())
            .field("pending_operations", &self.pending_operation_ids.len())
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}
