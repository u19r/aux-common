use std::{fmt, sync::Arc};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::{operation_builder::OperationBuilder, preparation_limits::PreparationLayout};
use crate::{
    configuration::{BatchId, OperationId, SinkLimits, TenantScope, validate_version},
    constants::DEFAULT_GROUPING_STRATEGY_VERSION,
    error::{ConfigurationError, PrepareError},
};

pub(crate) struct BatchItemsInput<'a, T> {
    pub batch_id: BatchId,
    pub scope: &'a TenantScope,
    pub items: &'a [T],
    pub operation_ids: &'a [OperationId],
    pub raw_payloads: &'a [Bytes],
    pub limits: &'a SinkLimits,
    pub first_item_time_ms: i64,
    pub max_prepared_bytes: usize,
}

/// Immutable candidate view supplied to [`WriteBatch::prepare`].
pub struct BatchItems<'a, T> {
    input: BatchItemsInput<'a, T>,
}

impl<'a, T> BatchItems<'a, T> {
    #[must_use]
    pub(crate) const fn new(input: BatchItemsInput<'a, T>) -> Self {
        Self { input }
    }

    #[must_use]
    pub const fn batch_id(&self) -> BatchId {
        self.input.batch_id
    }

    #[must_use]
    pub const fn scope(&self) -> &'a TenantScope {
        self.input.scope
    }

    #[must_use]
    pub const fn items(&self) -> &'a [T] {
        self.input.items
    }

    #[must_use]
    pub const fn operation_ids(&self) -> &'a [OperationId] {
        self.input.operation_ids
    }

    #[must_use]
    pub const fn limits(&self) -> &'a SinkLimits {
        self.input.limits
    }

    /// Modeled budget for command data, identity arrays, and completion
    /// tracking. Canonical input and batch headers have separate retention
    /// charges.
    #[must_use]
    pub const fn max_prepared_bytes(&self) -> usize {
        self.input.max_prepared_bytes
    }

    #[must_use]
    pub const fn first_item_time_ms(&self) -> i64 {
        self.input.first_item_time_ms
    }

    #[must_use]
    pub(crate) const fn raw_payloads(&self) -> &'a [Bytes] {
        self.input.raw_payloads
    }
}

/// Single prepared operation with a stable operation ID and encoded command
/// payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedOperation {
    pub operation_id: OperationId,
    pub payload: Bytes,
}

impl fmt::Debug for PreparedOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedOperation")
            .field("operation_id", &self.operation_id)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Prepared payload representation inside a [`SealedBatch`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreparedPayload {
    SharedRecords,
    CustomOperations(Arc<[PreparedOperation]>),
}

/// Validated output of [`WriteBatch::prepare`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedWrites {
    pub(crate) payload: PreparedPayload,
    pub(crate) operation_ids: Arc<[OperationId]>,
}

impl PreparedWrites {
    pub fn default_items<T>(batch: &BatchItems<'_, T>) -> Result<Self, PrepareError> {
        let count = batch.operation_ids().len();
        let payload_bytes = batch
            .raw_payloads()
            .iter()
            .map(Bytes::len)
            .fold(0, usize::saturating_add);
        batch
            .limits()
            .validate_prepared_size(count, payload_bytes)?;
        Ok(Self {
            payload: PreparedPayload::SharedRecords,
            operation_ids: Arc::from(batch.operation_ids().to_vec()),
        })
    }

    pub fn packed<T, P: Serialize>(
        batch: &BatchItems<'_, T>,
        packed: &P,
    ) -> Result<Self, PrepareError> {
        if batch.items().is_empty() {
            return Err(PrepareError::EmptyOperations);
        }
        let mut operations = OperationBuilder::new(batch.limits(), batch.max_prepared_bytes());
        let op_id = OperationId::try_new(format!("packed-{}", batch.batch_id()))
            .map_err(|_| PrepareError::InvalidOperationId)?;
        operations.push(op_id, packed)?;
        operations.finish()
    }

    pub fn operations<T, C, I>(batch: &BatchItems<'_, T>, commands: I) -> Result<Self, PrepareError>
    where
        C: Serialize,
        I: IntoIterator<Item = C>,
    {
        let mut operations = OperationBuilder::new(batch.limits(), batch.max_prepared_bytes());
        for (index, command) in commands.into_iter().enumerate() {
            let op_id = OperationId::try_new(format!("{}-op-{index}", batch.batch_id()))
                .map_err(|_| PrepareError::InvalidOperationId)?;
            operations.push(op_id, &command)?;
        }
        operations.finish()
    }
}

/// Pluggable pure batch preparation strategy.
pub trait WriteBatch<T>: Send + Sync + 'static {
    /// Custom preparation uses retention limits for canonical input. Override
    /// only when every prepared operation is an unchanged canonical record.
    fn layout(&self) -> PreparationLayout {
        PreparationLayout::Custom
    }

    fn strategy_version(&self) -> &str;
    fn prepare(&self, batch: BatchItems<'_, T>) -> Result<PreparedWrites, PrepareError>;
}

/// Default item-grouping batch strategy (`default-items/v1`).
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultItemGrouping;

impl<T> WriteBatch<T> for DefaultItemGrouping {
    fn layout(&self) -> PreparationLayout {
        PreparationLayout::Records
    }

    fn strategy_version(&self) -> &str {
        DEFAULT_GROUPING_STRATEGY_VERSION
    }

    fn prepare(&self, batch: BatchItems<'_, T>) -> Result<PreparedWrites, PrepareError> {
        PreparedWrites::default_items(&batch)
    }
}

/// Closure adapter for `.prepare_with(version, closure)`.
pub struct ClosureWriteBatch<F> {
    version: String,
    prepare_fn: F,
}

impl<F> ClosureWriteBatch<F> {
    pub fn try_new(version: impl Into<String>, prepare_fn: F) -> Result<Self, ConfigurationError> {
        let version = version.into();
        validate_version(&version)?;
        Ok(Self {
            version,
            prepare_fn,
        })
    }
}

impl<T, F> WriteBatch<T> for ClosureWriteBatch<F>
where F: Fn(BatchItems<'_, T>) -> Result<PreparedWrites, PrepareError> + Send + Sync + 'static
{
    fn strategy_version(&self) -> &str {
        &self.version
    }

    fn prepare(&self, batch: BatchItems<'_, T>) -> Result<PreparedWrites, PrepareError> {
        (self.prepare_fn)(batch)
    }
}
