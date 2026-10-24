use bytes::Bytes;

use crate::{
    codec::value::constants::{MAX_VALUE_BODY_BYTES, VALUE_HEADER_BYTES, VALUE_VERSION},
    error::StoreDataError,
    policy::EffectMode,
    time::Timestamp,
};

pub(crate) fn encode_effect_mode(mode: EffectMode) -> u8 {
    match mode {
        EffectMode::ReadOnly => 0,
        EffectMode::Idempotent => 1,
        EffectMode::AtLeastOnce => 2,
        EffectMode::Fenced => 3,
    }
}

pub(crate) fn decode_effect_mode(value: u8) -> Result<EffectMode, StoreDataError> {
    match value {
        0 => Ok(EffectMode::ReadOnly),
        1 => Ok(EffectMode::Idempotent),
        2 => Ok(EffectMode::AtLeastOnce),
        3 => Ok(EffectMode::Fenced),
        _ => Err(StoreDataError::Malformed("effect mode")),
    }
}

/// Fixed v1 value tags. Values are independently versioned from keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ValueTag {
    Job = b'J',
    PayloadChunk = b'P',
    Due = b'D',
    FairReady = b'F',
    Lease = b'L',
    DeadLetter = b'X',
    Schedule = b'S',
    Dedupe = b'U',
    Wake = b'W',
    Permit = b'R',
    Operation = b'O',
    Cancellation = b'C',
}

impl ValueTag {
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn try_from_byte(byte: u8) -> Result<Self, StoreDataError> {
        let tag = match byte {
            b'J' => Self::Job,
            b'P' => Self::PayloadChunk,
            b'D' => Self::Due,
            b'F' => Self::FairReady,
            b'L' => Self::Lease,
            b'X' => Self::DeadLetter,
            b'S' => Self::Schedule,
            b'U' => Self::Dedupe,
            b'W' => Self::Wake,
            b'R' => Self::Permit,
            b'O' => Self::Operation,
            b'C' => Self::Cancellation,
            other => return Err(StoreDataError::UnknownTag(other)),
        };
        Ok(tag)
    }
}

/// A decoded, fail-closed v1 value envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedValue {
    pub tag: ValueTag,
    pub body: Bytes,
}

/// Deterministic versioned value envelope codec.
pub struct ValueCodec;

impl ValueCodec {
    pub fn encode(tag: ValueTag, body: &[u8]) -> Result<Bytes, StoreDataError> {
        if body.len() > MAX_VALUE_BODY_BYTES {
            return Err(StoreDataError::InvalidLength {
                field: "value body",
                actual: body.len(),
                maximum: MAX_VALUE_BODY_BYTES,
            });
        }
        let length = u32::try_from(body.len()).map_err(|_| StoreDataError::LengthOverflow)?;
        let mut encoded = Vec::with_capacity(VALUE_HEADER_BYTES + body.len());
        encoded.push(VALUE_VERSION);
        encoded.push(tag.as_byte());
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(body);
        Ok(Bytes::from(encoded))
    }

    pub fn decode(encoded: &[u8]) -> Result<DecodedValue, StoreDataError> {
        let (tag, body) = Self::decode_envelope(encoded)?;
        Ok(DecodedValue {
            tag,
            body: Bytes::copy_from_slice(body),
        })
    }

    pub(crate) fn decode_body(encoded: &[u8]) -> Result<(ValueTag, &[u8]), StoreDataError> {
        Self::decode_envelope(encoded)
    }

    fn decode_envelope(encoded: &[u8]) -> Result<(ValueTag, &[u8]), StoreDataError> {
        if encoded.is_empty() {
            return Err(StoreDataError::Truncated);
        }
        if encoded[0] != VALUE_VERSION {
            return Err(StoreDataError::UnknownVersion(encoded[0]));
        }
        if encoded.len() < VALUE_HEADER_BYTES {
            return Err(StoreDataError::Truncated);
        }
        let tag = ValueTag::try_from_byte(encoded[1])?;
        let length = u32::from_be_bytes(
            encoded[2..VALUE_HEADER_BYTES]
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        ) as usize;
        if length > MAX_VALUE_BODY_BYTES {
            return Err(StoreDataError::InvalidLength {
                field: "value body",
                actual: length,
                maximum: MAX_VALUE_BODY_BYTES,
            });
        }
        let end = VALUE_HEADER_BYTES
            .checked_add(length)
            .ok_or(StoreDataError::LengthOverflow)?;
        if end > encoded.len() {
            return Err(StoreDataError::Truncated);
        }
        if end != encoded.len() {
            return Err(StoreDataError::TrailingBytes);
        }
        Ok((tag, &encoded[VALUE_HEADER_BYTES..end]))
    }

    pub(crate) fn decode_timestamp(
        encoded: &[u8],
        expected: ValueTag,
    ) -> Result<Timestamp, StoreDataError> {
        let (tag, body) = Self::decode_envelope(encoded)?;
        if tag != expected || body.len() != 8 {
            return Err(StoreDataError::Malformed("timestamp index"));
        }
        let millis = i64::from_be_bytes(body.try_into().map_err(|_| StoreDataError::Truncated)?);
        Ok(Timestamp::from_millis(millis))
    }
}
