use std::{error::Error, fmt};

use crate::constants::{
    DEFAULT_REFRESH_BATCH_BYTES, DEFAULT_REFRESH_BATCH_KEYS, DEFAULT_REFRESH_BATCHES,
    DEFAULT_REFRESH_BYTES, MAX_LOAD_KEYS,
};

/// Declared payload budget. Charge peak owned bytes across queued/active keys
/// and batch copies (clones may share allocations). Key/batch limits bound
/// container overhead; provider responses and subscribers need separate bounds.
#[derive(Clone, Copy)]
pub struct RefreshBudget {
    pub(super) keys: usize,
    pub(super) bytes: usize,
}

impl RefreshBudget {
    pub fn try_new(keys: usize, bytes: usize) -> Result<Self, RefreshQueueConfigError> {
        if keys == 0 || bytes == 0 {
            return Err(RefreshQueueConfigError);
        }
        Ok(Self { keys, bytes })
    }
    pub(super) fn can_reserve(
        &self,
        keys: usize,
        bytes: usize,
        additional_keys: usize,
        additional_bytes: usize,
    ) -> bool {
        keys.checked_add(additional_keys)
            .is_some_and(|total| total <= self.keys)
            && bytes
                .checked_add(additional_bytes)
                .is_some_and(|total| total <= self.bytes)
    }
}

#[derive(Clone, Copy)]
pub struct RefreshQueueLimits {
    pub(super) total: RefreshBudget,
    pub(super) background: RefreshBudget,
    pub(super) batch: RefreshBudget,
    pub(super) active_batches: usize,
}

impl RefreshQueueLimits {
    pub fn try_new(
        total: RefreshBudget,
        background: RefreshBudget,
        batch: RefreshBudget,
        active_batches: usize,
    ) -> Result<Self, RefreshQueueConfigError> {
        if background.keys >= total.keys
            || background.bytes >= total.bytes
            || batch.keys > total.keys
            || batch.bytes > total.bytes
            || active_batches < 2
        {
            return Err(RefreshQueueConfigError);
        }
        Ok(Self {
            total,
            background,
            batch,
            active_batches,
        })
    }
}

impl Default for RefreshQueueLimits {
    fn default() -> Self {
        Self {
            total: RefreshBudget {
                keys: MAX_LOAD_KEYS,
                bytes: DEFAULT_REFRESH_BYTES,
            },
            background: RefreshBudget {
                keys: MAX_LOAD_KEYS / 2,
                bytes: DEFAULT_REFRESH_BYTES / 2,
            },
            batch: RefreshBudget {
                keys: DEFAULT_REFRESH_BATCH_KEYS,
                bytes: DEFAULT_REFRESH_BATCH_BYTES,
            },
            active_batches: DEFAULT_REFRESH_BATCHES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshQueueConfigError;

impl fmt::Display for RefreshQueueConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("refresh queue limits must be positive and reserve cold capacity")
    }
}

impl Error for RefreshQueueConfigError {}
