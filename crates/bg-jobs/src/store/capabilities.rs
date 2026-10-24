use std::{
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

use crate::{
    error::{StoreContractError, ValidationError},
    store::{RangeRequest, StoreKey, StoreTransaction},
};

/// Whether a store can safely be used by one process or multiple nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreLevel {
    Local,
    Distributed,
}

/// Backend limits used to validate portable payload and transaction guarantees.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreCapabilities {
    level: StoreLevel,
    max_key_bytes: NonZeroUsize,
    max_value_bytes: NonZeroUsize,
    max_get_many_keys: NonZeroU32,
    max_get_many_key_bytes: NonZeroUsize,
    max_transaction_bytes: NonZeroUsize,
    max_transaction_keys: NonZeroU32,
    max_range_items: NonZeroU32,
    max_range_bytes: NonZeroUsize,
    max_transaction_duration: Duration,
}

/// Inputs for constructing backend capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreCapabilitiesInput {
    pub level: StoreLevel,
    pub max_key_bytes: NonZeroUsize,
    pub max_value_bytes: NonZeroUsize,
    pub max_get_many_keys: NonZeroU32,
    pub max_get_many_key_bytes: NonZeroUsize,
    pub max_transaction_bytes: NonZeroUsize,
    pub max_transaction_keys: NonZeroU32,
    pub max_range_items: NonZeroU32,
    pub max_range_bytes: NonZeroUsize,
    pub max_transaction_duration: Duration,
}

impl TryFrom<StoreCapabilitiesInput> for StoreCapabilities {
    type Error = StoreContractError;

    fn try_from(input: StoreCapabilitiesInput) -> Result<Self, Self::Error> {
        if input.max_transaction_duration.is_zero() {
            return Err(StoreContractError::Validation(
                ValidationError::InvalidValue {
                    field: "transaction duration",
                },
            ));
        }
        if input.max_transaction_bytes.get() < input.max_key_bytes.get() {
            return Err(StoreContractError::Validation(ValidationError::Ordering {
                field: "transaction/key bytes",
            }));
        }
        if input.max_get_many_key_bytes.get() < input.max_key_bytes.get() {
            return Err(StoreContractError::Validation(ValidationError::Ordering {
                field: "get-many/key bytes",
            }));
        }
        Ok(Self {
            level: input.level,
            max_key_bytes: input.max_key_bytes,
            max_value_bytes: input.max_value_bytes,
            max_get_many_keys: input.max_get_many_keys,
            max_get_many_key_bytes: input.max_get_many_key_bytes,
            max_transaction_bytes: input.max_transaction_bytes,
            max_transaction_keys: input.max_transaction_keys,
            max_range_items: input.max_range_items,
            max_range_bytes: input.max_range_bytes,
            max_transaction_duration: input.max_transaction_duration,
        })
    }
}

impl StoreCapabilities {
    pub fn validate_transaction(
        &self,
        transaction: &StoreTransaction,
    ) -> Result<(), StoreContractError> {
        if transaction.checks().len() + transaction.mutations().len()
            > self.max_transaction_keys.get() as usize
        {
            return Err(StoreContractError::CapabilityExceeded("transaction keys"));
        }
        if transaction.encoded_bytes() > self.max_transaction_bytes.get() {
            return Err(StoreContractError::CapabilityExceeded("transaction bytes"));
        }
        if transaction.max_key_bytes() > self.max_key_bytes.get() {
            return Err(StoreContractError::CapabilityExceeded("key bytes"));
        }
        if transaction.max_value_bytes() > self.max_value_bytes.get() {
            return Err(StoreContractError::CapabilityExceeded("value bytes"));
        }
        Ok(())
    }

    /// Validates one ordered native batch/read-plan request.
    ///
    /// An empty request is valid and has an empty result. Byte limits cover
    /// the input keys; returned values remain individually bounded by
    /// [`Self::max_value_bytes`].
    pub fn validate_get_many(&self, keys: &[StoreKey]) -> Result<(), StoreContractError> {
        if keys.len() > self.max_get_many_keys.get() as usize {
            return Err(StoreContractError::CapabilityExceeded("get-many keys"));
        }
        if keys
            .iter()
            .any(|key| key.as_bytes().len() > self.max_key_bytes.get())
        {
            return Err(StoreContractError::CapabilityExceeded("get-many key bytes"));
        }
        let key_bytes = keys
            .iter()
            .try_fold(0usize, |total, key| total.checked_add(key.as_bytes().len()));
        if key_bytes.is_none_or(|bytes| bytes > self.max_get_many_key_bytes.get()) {
            return Err(StoreContractError::CapabilityExceeded("get-many key bytes"));
        }
        Ok(())
    }

    pub fn validate_range(&self, request: &RangeRequest) -> Result<(), StoreContractError> {
        if request.item_limit().get() > self.max_range_items.get() {
            return Err(StoreContractError::CapabilityExceeded("range items"));
        }
        if request.byte_limit().get() > self.max_range_bytes.get() {
            return Err(StoreContractError::CapabilityExceeded("range bytes"));
        }
        if request
            .start()
            .is_some_and(|key| key.as_bytes().len() > self.max_key_bytes.get())
            || request
                .end()
                .is_some_and(|key| key.as_bytes().len() > self.max_key_bytes.get())
            || request
                .continuation()
                .is_some_and(|key| key.as_bytes().len() > self.max_key_bytes.get())
        {
            return Err(StoreContractError::CapabilityExceeded("range key bytes"));
        }
        Ok(())
    }

    pub const fn is_distributed(self) -> bool {
        matches!(self.level, StoreLevel::Distributed)
    }

    pub const fn level(self) -> StoreLevel {
        self.level
    }

    pub const fn max_key_bytes(self) -> NonZeroUsize {
        self.max_key_bytes
    }

    pub const fn max_value_bytes(self) -> NonZeroUsize {
        self.max_value_bytes
    }

    pub const fn max_get_many_keys(self) -> NonZeroU32 {
        self.max_get_many_keys
    }

    pub const fn max_get_many_key_bytes(self) -> NonZeroUsize {
        self.max_get_many_key_bytes
    }

    pub const fn max_transaction_bytes(self) -> NonZeroUsize {
        self.max_transaction_bytes
    }

    pub const fn max_transaction_keys(self) -> NonZeroU32 {
        self.max_transaction_keys
    }

    pub const fn max_range_items(self) -> NonZeroU32 {
        self.max_range_items
    }

    pub const fn max_range_bytes(self) -> NonZeroUsize {
        self.max_range_bytes
    }

    pub const fn max_transaction_duration(self) -> Duration {
        self.max_transaction_duration
    }
}
