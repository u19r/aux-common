use std::num::{NonZeroU32, NonZeroUsize};

use bytes::Bytes;

use crate::{error::ValidationError, store::StoreKey};

/// Direction of an ordered range page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RangeDirection {
    Forward,
    Reverse,
}

/// Validated bounded range-read request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeRequest {
    start: Option<StoreKey>,
    end: Option<StoreKey>,
    direction: RangeDirection,
    item_limit: NonZeroU32,
    byte_limit: NonZeroUsize,
    continuation: Option<StoreKey>,
}

/// Inputs for constructing a range request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeRequestInput {
    pub start: Option<StoreKey>,
    pub end: Option<StoreKey>,
    pub direction: RangeDirection,
    pub item_limit: NonZeroU32,
    pub byte_limit: NonZeroUsize,
    pub continuation: Option<StoreKey>,
}

impl TryFrom<RangeRequestInput> for RangeRequest {
    type Error = ValidationError;

    fn try_from(input: RangeRequestInput) -> Result<Self, Self::Error> {
        if let (Some(start), Some(end)) = (&input.start, &input.end)
            && start >= end
        {
            return Err(ValidationError::Ordering {
                field: "range bounds",
            });
        }
        if let Some(cursor) = &input.continuation
            && !within_bounds(cursor, input.start.as_ref(), input.end.as_ref())
        {
            return Err(ValidationError::Ordering {
                field: "range continuation",
            });
        }
        Ok(Self {
            start: input.start,
            end: input.end,
            direction: input.direction,
            item_limit: input.item_limit,
            byte_limit: input.byte_limit,
            continuation: input.continuation,
        })
    }
}

impl RangeRequest {
    pub fn start(&self) -> Option<&StoreKey> {
        self.start.as_ref()
    }

    pub fn end(&self) -> Option<&StoreKey> {
        self.end.as_ref()
    }

    pub const fn direction(&self) -> RangeDirection {
        self.direction
    }

    pub const fn item_limit(&self) -> NonZeroU32 {
        self.item_limit
    }

    pub const fn byte_limit(&self) -> NonZeroUsize {
        self.byte_limit
    }

    pub fn continuation(&self) -> Option<&StoreKey> {
        self.continuation.as_ref()
    }
}

fn within_bounds(cursor: &StoreKey, start: Option<&StoreKey>, end: Option<&StoreKey>) -> bool {
    start.is_none_or(|value| cursor >= value) && end.is_none_or(|value| cursor < value)
}

/// One ordered key/value returned by a range read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeEntry {
    pub key: StoreKey,
    pub value: Bytes,
}

/// A bounded page and optional exclusive continuation cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangePage {
    pub entries: Vec<RangeEntry>,
    pub continuation: Option<StoreKey>,
}

impl RangePage {
    pub fn new(
        entries: Vec<RangeEntry>,
        continuation: Option<StoreKey>,
    ) -> Result<Self, crate::error::StoreContractError> {
        if entries.is_empty() && continuation.is_some() {
            return Err(crate::error::StoreContractError::Validation(
                ValidationError::InvalidValue {
                    field: "range continuation",
                },
            ));
        }
        Ok(Self {
            entries,
            continuation,
        })
    }

    pub fn total_bytes(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| entry.key.as_bytes().len() + entry.value.len())
            .sum()
    }
}
