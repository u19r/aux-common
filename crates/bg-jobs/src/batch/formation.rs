//! Bounded batch formation and admission limits.

use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroUsize},
    time::Duration,
};

use super::compatibility::BatchItem;
use crate::{error::ValidationError, time::Timestamp};

/// Count, byte, formation-delay, and deadline bounds for one batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchLimits {
    max_items: NonZeroU16,
    max_payload_bytes: NonZeroUsize,
    max_formation_delay: Duration,
}

/// Inputs for constructing a bounded batch policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchLimitsInput {
    pub max_items: NonZeroU16,
    pub max_payload_bytes: NonZeroUsize,
    pub max_formation_delay: Duration,
}

impl BatchLimits {
    pub fn try_new(input: BatchLimitsInput) -> Result<Self, ValidationError> {
        if input.max_formation_delay.is_zero() {
            return Err(ValidationError::InvalidValue {
                field: "batch formation delay",
            });
        }
        if input.max_formation_delay.as_millis() > i64::MAX as u128 {
            return Err(ValidationError::Overflow {
                field: "batch formation delay",
            });
        }
        Ok(Self {
            max_items: input.max_items,
            max_payload_bytes: input.max_payload_bytes,
            max_formation_delay: input.max_formation_delay,
        })
    }
}

/// A reason an item could not join the current batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BatchRejection {
    Full,
    Incompatible,
    DuplicateAttemptId,
    DuplicateOrderingGroup,
    PayloadCapacity,
    FormationDeadline,
    FormationWindow,
    FormationClock,
}

/// A batch after bounded formation. Payloads are owned only until result
/// application and are dropped when this value is dropped or cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub(super) items: Vec<BatchItem>,
    pub(super) formed_at: Timestamp,
    pub(super) deadline: Timestamp,
    pub(super) payload_bytes: usize,
}

impl Batch {
    #[cfg(feature = "test-support")]
    pub fn items(&self) -> &[BatchItem] {
        &self.items
    }

    pub const fn formed_at(&self) -> Timestamp {
        self.formed_at
    }

    pub const fn deadline(&self) -> Timestamp {
        self.deadline
    }

    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
}

/// Builder that never waits beyond the configured formation window.
#[derive(Clone, Debug)]
pub struct BatchBuilder {
    limits: BatchLimits,
    items: Vec<BatchItem>,
    ordering_hashes: HashMap<u64, usize>,
    ordering_collisions: HashMap<u64, Vec<usize>>,
    formed_at: Timestamp,
    payload_bytes: usize,
    deadline: Timestamp,
}

impl BatchBuilder {
    pub fn try_new(
        first: BatchItem,
        limits: BatchLimits,
        formed_at: Timestamp,
    ) -> Result<Self, BatchRejection> {
        let mut builder = Self {
            limits,
            items: Vec::with_capacity(limits.max_items.get() as usize),
            ordering_hashes: HashMap::with_capacity(limits.max_items.get() as usize),
            ordering_collisions: HashMap::new(),
            formed_at,
            payload_bytes: 0,
            deadline: first.batch_deadline,
        };
        builder.try_add(first, formed_at)?;
        Ok(builder)
    }

    pub fn try_add(&mut self, item: BatchItem, at: Timestamp) -> Result<(), BatchRejection> {
        let ordering_hash = self.check_admission(&item, at)?;
        let bytes = self.checked_payload_bytes(&item)?;
        self.deadline = self.deadline.min(item.batch_deadline);
        self.payload_bytes = bytes;
        let item_index = self.items.len();
        self.items.push(item);
        self.record_ordering(ordering_hash, item_index);
        Ok(())
    }

    pub fn finish(self) -> Batch {
        Batch {
            items: self.items,
            formed_at: self.formed_at,
            deadline: self.deadline,
            payload_bytes: self.payload_bytes,
        }
    }

    fn checked_payload_bytes(&self, item: &BatchItem) -> Result<usize, BatchRejection> {
        let bytes = self
            .payload_bytes
            .checked_add(item.payload.len())
            .ok_or(BatchRejection::PayloadCapacity)?;
        if bytes > self.limits.max_payload_bytes.get() {
            return Err(BatchRejection::PayloadCapacity);
        }
        Ok(bytes)
    }

    fn record_ordering(&mut self, ordering_hash: Option<u64>, item_index: usize) {
        let Some(ordering_hash) = ordering_hash else {
            return;
        };
        let Some(&primary_index) = self.ordering_hashes.get(&ordering_hash) else {
            self.ordering_hashes.insert(ordering_hash, item_index);
            return;
        };
        if self.items[primary_index].ordering_key == self.items[item_index].ordering_key {
            return;
        }
        let collisions = self.ordering_collisions.entry(ordering_hash).or_default();
        if collisions.is_empty() {
            collisions.push(primary_index);
        }
        collisions.push(item_index);
    }

    fn check_admission(
        &self,
        item: &BatchItem,
        at: Timestamp,
    ) -> Result<Option<u64>, BatchRejection> {
        self.check_basic_admission(item)?;
        let ordering_hash = self.check_ordering(item)?;
        self.check_timing(item, at)?;
        Ok(ordering_hash)
    }

    fn check_basic_admission(&self, item: &BatchItem) -> Result<(), BatchRejection> {
        if self.items.len() >= self.limits.max_items.get() as usize {
            return Err(BatchRejection::Full);
        }
        if self
            .items
            .iter()
            .any(|current| current.attempt_id == item.attempt_id)
        {
            return Err(BatchRejection::DuplicateAttemptId);
        }
        if self
            .items
            .first()
            .is_some_and(|current| current.compatibility != item.compatibility)
        {
            return Err(BatchRejection::Incompatible);
        }
        Ok(())
    }

    fn check_ordering(&self, item: &BatchItem) -> Result<Option<u64>, BatchRejection> {
        let ordering_hash = item
            .ordering_key
            .as_ref()
            .map(|key| ordering_hash(key.as_bytes()));
        if ordering_hash.is_some_and(|hash| self.has_ordering(hash, item)) {
            return Err(BatchRejection::DuplicateOrderingGroup);
        }
        Ok(ordering_hash)
    }

    fn has_ordering(&self, hash: u64, item: &BatchItem) -> bool {
        self.ordering_hashes
            .get(&hash)
            .is_some_and(|&primary_index| {
                self.items[primary_index].ordering_key.as_ref() == item.ordering_key.as_ref()
                    || self.ordering_collisions.get(&hash).is_some_and(|indices| {
                        indices.iter().any(|&index| {
                            self.items[index].ordering_key.as_ref() == item.ordering_key.as_ref()
                        })
                    })
            })
    }

    fn check_timing(&self, item: &BatchItem, at: Timestamp) -> Result<(), BatchRejection> {
        if at < item.enqueued_at || at < self.formed_at {
            return Err(BatchRejection::FormationClock);
        }
        let delay = at
            .duration_since(self.formed_at)
            .map_err(|_| BatchRejection::FormationClock)?;
        if delay > self.limits.max_formation_delay {
            return Err(BatchRejection::FormationWindow);
        }
        if at > item.batch_deadline || at > self.deadline {
            return Err(BatchRejection::FormationDeadline);
        }
        Ok(())
    }
}

fn ordering_hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}
