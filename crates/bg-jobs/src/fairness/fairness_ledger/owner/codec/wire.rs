//! Primitive fields and enum mappings for the fair-owner wire format.

use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::Duration,
};

use super::super::state::FairBatchItemState;
use crate::{
    error::StoreDataError,
    fairness::{CandidateBlock, FairCandidateState, FairScope, FairVolumeMode},
    ids::FairnessKey,
    policy::{BackoffMultiplier, Priority, RetryPolicy, RetryPolicyInput},
};

pub(super) fn write_count(writer: &mut Writer, count: usize) -> Result<(), StoreDataError> {
    let count = u32::try_from(count).map_err(|_| StoreDataError::LengthOverflow)?;
    if usize::try_from(count).unwrap_or(usize::MAX) > super::constants::MAX_OWNER_ENTRIES {
        return Err(StoreDataError::InvalidLength {
            field: "fair owner entries",
            actual: usize::try_from(count).unwrap_or(usize::MAX),
            maximum: super::constants::MAX_OWNER_ENTRIES,
        });
    }
    writer.u32(count);
    Ok(())
}

pub(super) fn read_count(reader: &mut Reader<'_>) -> Result<usize, StoreDataError> {
    let count = usize::try_from(reader.u32()?).map_err(|_| StoreDataError::LengthOverflow)?;
    if count > super::constants::MAX_OWNER_ENTRIES {
        return Err(StoreDataError::InvalidLength {
            field: "fair owner entries",
            actual: count,
            maximum: super::constants::MAX_OWNER_ENTRIES,
        });
    }
    Ok(count)
}

pub(in crate::fairness::fairness_ledger::owner) fn write_scope(
    writer: &mut Writer,
    scope: &FairScope,
) -> Result<(), StoreDataError> {
    match scope {
        FairScope::LowVolume => writer.u8(0),
        FairScope::Scoped { primary, secondary } => {
            writer.u8(1);
            writer.bytes(primary.as_bytes())?;
            write_optional_bytes(writer, secondary.as_ref().map(FairnessKey::as_bytes))?;
        }
    }
    Ok(())
}

pub(in crate::fairness::fairness_ledger::owner) fn read_scope(
    reader: &mut Reader<'_>,
) -> Result<FairScope, StoreDataError> {
    match reader.u8()? {
        0 => Ok(FairScope::LowVolume),
        1 => {
            let primary = FairnessKey::try_new(reader.bytes()?)?;
            let secondary = reader
                .optional_bytes()?
                .map(FairnessKey::try_new)
                .transpose()?;
            Ok(FairScope::Scoped { primary, secondary })
        }
        _ => Err(StoreDataError::Malformed("fair owner scope")),
    }
}

pub(in crate::fairness::fairness_ledger::owner) fn write_optional_bytes(
    writer: &mut Writer,
    value: Option<&[u8]>,
) -> Result<(), StoreDataError> {
    match value {
        None => writer.u8(0),
        Some(value) => {
            writer.u8(1);
            writer.bytes(value)?;
        }
    }
    Ok(())
}

pub(in crate::fairness::fairness_ledger::owner) fn write_block(
    writer: &mut Writer,
    block: Option<CandidateBlock>,
) {
    writer.u8(match block {
        None => 0,
        Some(CandidateBlock::Leased) => 1,
        Some(CandidateBlock::Missing) => 2,
        Some(CandidateBlock::Corrupt) => 3,
        Some(CandidateBlock::Oversized) => 4,
        Some(CandidateBlock::Poison) => 5,
        Some(CandidateBlock::RateLimited) => 6,
        Some(CandidateBlock::Capacity) => 7,
    });
}

pub(in crate::fairness::fairness_ledger::owner) fn read_block(
    reader: &mut Reader<'_>,
) -> Result<Option<CandidateBlock>, StoreDataError> {
    Ok(match reader.u8()? {
        0 => None,
        1 => Some(CandidateBlock::Leased),
        2 => Some(CandidateBlock::Missing),
        3 => Some(CandidateBlock::Corrupt),
        4 => Some(CandidateBlock::Oversized),
        5 => Some(CandidateBlock::Poison),
        6 => Some(CandidateBlock::RateLimited),
        7 => Some(CandidateBlock::Capacity),
        _ => return Err(StoreDataError::Malformed("fair owner block")),
    })
}

pub(super) fn volume_mode_byte(mode: FairVolumeMode) -> u8 {
    match mode {
        FairVolumeMode::Scoped => 0,
        FairVolumeMode::LowVolume => 1,
    }
}

pub(super) fn volume_mode_from_byte(byte: u8) -> Result<FairVolumeMode, StoreDataError> {
    match byte {
        0 => Ok(FairVolumeMode::Scoped),
        1 => Ok(FairVolumeMode::LowVolume),
        _ => Err(StoreDataError::Malformed("fair owner volume mode")),
    }
}

pub(super) fn priority_byte(priority: Priority) -> u8 {
    match priority {
        Priority::Critical => 0,
        Priority::Default => 1,
        Priority::Bulk => 2,
    }
}

pub(super) fn priority_from_byte(byte: u8) -> Result<Priority, StoreDataError> {
    match byte {
        0 => Ok(Priority::Critical),
        1 => Ok(Priority::Default),
        2 => Ok(Priority::Bulk),
        _ => Err(StoreDataError::Malformed("fair owner priority")),
    }
}

pub(super) fn candidate_state_byte(state: FairCandidateState) -> u8 {
    match state {
        FairCandidateState::Absent => 0,
        FairCandidateState::Scheduled => 1,
        FairCandidateState::Leased => 2,
        FairCandidateState::RetryWaiting => 3,
        FairCandidateState::DeadLettered => 4,
        FairCandidateState::Cancelled => 5,
    }
}

pub(super) fn candidate_state_from_byte(byte: u8) -> Result<FairCandidateState, StoreDataError> {
    match byte {
        0 => Ok(FairCandidateState::Absent),
        1 => Ok(FairCandidateState::Scheduled),
        2 => Ok(FairCandidateState::Leased),
        3 => Ok(FairCandidateState::RetryWaiting),
        4 => Ok(FairCandidateState::DeadLettered),
        5 => Ok(FairCandidateState::Cancelled),
        _ => Err(StoreDataError::Malformed("fair owner candidate state")),
    }
}

pub(super) fn batch_result_state_byte(state: FairBatchItemState) -> u8 {
    match state {
        FairBatchItemState::Missing => 0,
        FairBatchItemState::Success => 1,
        FairBatchItemState::Retry => 2,
        FairBatchItemState::DeadLetter => 3,
        FairBatchItemState::Duplicate => 4,
    }
}

pub(super) fn batch_result_state_from_byte(byte: u8) -> Result<FairBatchItemState, StoreDataError> {
    match byte {
        0 => Ok(FairBatchItemState::Missing),
        1 => Ok(FairBatchItemState::Success),
        2 => Ok(FairBatchItemState::Retry),
        3 => Ok(FairBatchItemState::DeadLetter),
        4 => Ok(FairBatchItemState::Duplicate),
        _ => Err(StoreDataError::Malformed("fair owner batch result")),
    }
}

pub(super) fn write_retry(writer: &mut Writer, policy: RetryPolicy) -> Result<(), StoreDataError> {
    writer.u16(policy.maximum_attempts().get());
    writer.u64(
        u64::try_from(policy.maximum_age().as_nanos())
            .map_err(|_| StoreDataError::LengthOverflow)?,
    );
    writer.u64(
        u64::try_from(policy.minimum_backoff().as_nanos())
            .map_err(|_| StoreDataError::LengthOverflow)?,
    );
    writer.u64(
        u64::try_from(policy.maximum_backoff().as_nanos())
            .map_err(|_| StoreDataError::LengthOverflow)?,
    );
    writer.u32(policy.multiplier().get());
    Ok(())
}

pub(super) fn read_retry(reader: &mut Reader<'_>) -> Result<RetryPolicy, StoreDataError> {
    let maximum_attempts = nonzero_u16(reader.u16()?, "retry attempts")?;
    let maximum_age = Duration::from_nanos(reader.u64()?);
    let minimum_backoff = Duration::from_nanos(reader.u64()?);
    let maximum_backoff = Duration::from_nanos(reader.u64()?);
    let multiplier = BackoffMultiplier::try_from(reader.u32()?)
        .map_err(|_| StoreDataError::Malformed("fair owner retry multiplier"))?;
    RetryPolicy::try_from(RetryPolicyInput {
        maximum_attempts,
        maximum_age,
        minimum_backoff,
        maximum_backoff,
        multiplier,
    })
    .map_err(|_| StoreDataError::Malformed("fair owner retry policy"))
}

pub(super) fn nonzero_u16(value: u16, field: &'static str) -> Result<NonZeroU16, StoreDataError> {
    NonZeroU16::new(value).ok_or(StoreDataError::Malformed(field))
}

pub(super) fn nonzero_u32(value: u32, field: &'static str) -> Result<NonZeroU32, StoreDataError> {
    NonZeroU32::new(value).ok_or(StoreDataError::Malformed(field))
}

pub(super) fn nonzero_usize(
    value: u64,
    field: &'static str,
) -> Result<NonZeroUsize, StoreDataError> {
    let value = usize::try_from(value).map_err(|_| StoreDataError::LengthOverflow)?;
    NonZeroUsize::new(value).ok_or(StoreDataError::Malformed(field))
}

#[derive(Default)]
pub(super) struct Writer {
    pub(super) bytes: Vec<u8>,
}

impl Writer {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub(super) fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(super) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn u128(&mut self, value: u128) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), StoreDataError> {
        self.u32(u32::try_from(value.len()).map_err(|_| StoreDataError::LengthOverflow)?);
        self.fixed(value);
        Ok(())
    }

    pub(super) fn text(&mut self, value: &str) -> Result<(), StoreDataError> {
        self.bytes(value.as_bytes())
    }
}

pub(in crate::fairness::fairness_ledger::owner) struct Reader<'a> {
    pub(in crate::fairness::fairness_ledger::owner) bytes: &'a [u8],
    pub(in crate::fairness::fairness_ledger::owner) offset: usize,
}

impl<'a> Reader<'a> {
    pub(in crate::fairness::fairness_ledger::owner) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(in crate::fairness::fairness_ledger::owner) fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], StoreDataError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StoreDataError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(StoreDataError::Truncated);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    pub(in crate::fairness::fairness_ledger::owner) fn fixed_array<const N: usize>(
        &mut self,
    ) -> Result<&'a [u8; N], StoreDataError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StoreDataError::Truncated)
    }

    pub(in crate::fairness::fairness_ledger::owner) fn u8(&mut self) -> Result<u8, StoreDataError> {
        Ok(self.take(1)?[0])
    }

    pub(in crate::fairness::fairness_ledger::owner) fn u16(
        &mut self,
    ) -> Result<u16, StoreDataError> {
        Ok(u16::from_be_bytes(*self.fixed_array()?))
    }

    pub(in crate::fairness::fairness_ledger::owner) fn u32(
        &mut self,
    ) -> Result<u32, StoreDataError> {
        Ok(u32::from_be_bytes(*self.fixed_array()?))
    }

    pub(in crate::fairness::fairness_ledger::owner) fn u64(
        &mut self,
    ) -> Result<u64, StoreDataError> {
        Ok(u64::from_be_bytes(*self.fixed_array()?))
    }

    pub(in crate::fairness::fairness_ledger::owner) fn u128(
        &mut self,
    ) -> Result<u128, StoreDataError> {
        Ok(u128::from_be_bytes(*self.fixed_array()?))
    }

    pub(in crate::fairness::fairness_ledger::owner) fn i64(
        &mut self,
    ) -> Result<i64, StoreDataError> {
        Ok(i64::from_be_bytes(*self.fixed_array()?))
    }

    pub(in crate::fairness::fairness_ledger::owner) fn bytes(
        &mut self,
    ) -> Result<&'a [u8], StoreDataError> {
        let length = usize::try_from(self.u32()?).map_err(|_| StoreDataError::LengthOverflow)?;
        self.take(length)
    }

    pub(in crate::fairness::fairness_ledger::owner) fn text(
        &mut self,
    ) -> Result<&'a str, StoreDataError> {
        core::str::from_utf8(self.bytes()?)
            .map_err(|_| StoreDataError::Malformed("fair owner text"))
    }

    pub(in crate::fairness::fairness_ledger::owner) fn optional_bytes(
        &mut self,
    ) -> Result<Option<&'a [u8]>, StoreDataError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.bytes()?)),
            _ => Err(StoreDataError::Malformed("fair owner optional bytes")),
        }
    }

    pub(in crate::fairness::fairness_ledger::owner) fn finish(&self) -> Result<(), StoreDataError> {
        (self.offset == self.bytes.len())
            .then_some(())
            .ok_or(StoreDataError::TrailingBytes)
    }
}
