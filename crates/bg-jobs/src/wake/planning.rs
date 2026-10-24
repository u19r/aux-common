//! Advisory wake-watermark planning.

#[cfg(any(test, feature = "test-support"))]
use std::num::NonZeroU32;

use bytes::Bytes;

#[cfg(any(test, feature = "test-support"))]
use crate::time::WakeHint;
use crate::{
    codec::ValueTag,
    error::JobResult,
    keys,
    store::{Check, Mutation, StoreKey},
    time::Timestamp,
};

/// One bounded advisory lower-bound record. It is never execution authority.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WakeWatermark {
    value: Option<Timestamp>,
    revision: u64,
}

#[cfg(any(test, feature = "test-support"))]
impl WakeWatermark {
    pub const fn new() -> Self {
        Self {
            value: None,
            revision: 0,
        }
    }

    pub const fn from_hint(hint: WakeHint) -> Self {
        match hint {
            WakeHint::At(value) => Self {
                value: Some(value),
                revision: 0,
            },
            WakeHint::Now | WakeHint::None => Self::new(),
        }
    }

    pub const fn hint(self) -> WakeHint {
        match self.value {
            Some(value) => WakeHint::At(value),
            None => WakeHint::None,
        }
    }

    pub const fn value(self) -> Option<Timestamp> {
        self.value
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }

    /// Atomically lowers the watermark in a local candidate record.
    pub fn lower(&mut self, candidate: Timestamp) -> bool {
        if self.value.is_some_and(|current| current <= candidate) {
            return false;
        }
        self.value = Some(candidate);
        self.revision = self.revision.saturating_add(1);
        true
    }

    /// Lazily raises or clears a stale early watermark after bounded discovery.
    pub fn raise_stale(&mut self, next: Option<Timestamp>) -> bool {
        if self.value == next
            || matches!((self.value, next), (Some(current), Some(next)) if next < current)
        {
            return false;
        }
        self.value = next;
        self.revision = self.revision.saturating_add(1);
        true
    }

    /// Applies a lower/raise mutation only when the presented revision is
    /// current.
    pub fn compare_and_set(&mut self, expected_revision: u64, next: Option<Timestamp>) -> bool {
        if self.revision != expected_revision {
            return false;
        }
        self.raise_stale(next)
    }
}

pub(crate) enum WakeUpdate {
    Lower(Timestamp),
    Reconcile(Option<Timestamp>),
}

pub(crate) fn apply<E>(
    wake_key: StoreKey,
    current: Option<Bytes>,
    update: WakeUpdate,
    mutations: &mut Vec<Mutation>,
) -> JobResult<Option<Check>, E> {
    let current_time = current
        .as_deref()
        .map(|encoded| keys::decode_timestamp_value(encoded, ValueTag::Wake))
        .transpose()?;
    let next = match update {
        WakeUpdate::Lower(candidate) => {
            if current_time.is_some_and(|current| current <= candidate) {
                return Ok(None);
            }
            Some(candidate)
        }
        WakeUpdate::Reconcile(next) => next,
    };
    match (current, next) {
        (Some(encoded), Some(next)) => {
            if current_time == Some(next) {
                return Ok(None);
            }
            mutations.push(Mutation::Put(wake_key.clone(), keys::wake_value(next)?));
            Ok(Some(Check::Value(wake_key, encoded)))
        }
        (Some(encoded), None) => {
            mutations.push(Mutation::Delete(wake_key.clone()));
            Ok(Some(Check::Value(wake_key, encoded)))
        }
        (None, Some(next)) => {
            mutations.push(Mutation::Put(wake_key.clone(), keys::wake_value(next)?));
            Ok(Some(Check::Absent(wake_key)))
        }
        (None, None) => Ok(None),
    }
}

/// A bounded set of wake candidates collected by an external adapter.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WakeCandidates {
    pub watermarks: Vec<WakeHint>,
    pub due_heads: Vec<WakeHint>,
    pub schedule_heads: Vec<WakeHint>,
}

#[cfg(any(test, feature = "test-support"))]
impl WakeCandidates {
    pub fn merge(&self, maximum: NonZeroU32) -> WakeHint {
        let mut merged = WakeHint::None;
        let mut remaining = maximum.get() as usize;
        for hints in [&self.watermarks, &self.due_heads, &self.schedule_heads] {
            for hint in hints.iter().take(remaining) {
                merged = merged.earliest(*hint);
                remaining = remaining.saturating_sub(1);
                if merged.is_now() {
                    return merged;
                }
            }
            if remaining == 0 {
                break;
            }
        }
        merged
    }
}
