use bytes::Bytes;

use super::{
    constants::{ACTIVE_HEAD_BYTES, HEAD_VERSION, VACANT_HEAD_BYTES},
    state::{ActiveHead, Head, Phase},
};
use crate::{
    codec::{KeyCodec, KeyTag},
    error::StoreDataError,
    ids::{CommitOperationId, LeaseToken, Namespace},
    store::StoreKey,
};

impl Head {
    pub(super) fn encode(self) -> Bytes {
        let mut bytes = Vec::with_capacity(ACTIVE_HEAD_BYTES);
        bytes.push(HEAD_VERSION);
        match self {
            Self::Vacant(generation) => {
                bytes.push(0);
                bytes.extend_from_slice(&generation.to_be_bytes());
            }
            Self::Active(head) => {
                bytes.push(1);
                head.write_fields(&mut bytes);
            }
        }
        Bytes::from(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, StoreDataError> {
        let Some(&version) = bytes.first() else {
            return Err(StoreDataError::Truncated);
        };
        if version != HEAD_VERSION {
            return Err(StoreDataError::UnknownVersion(version));
        }
        if bytes.len() != VACANT_HEAD_BYTES && bytes.len() != ACTIVE_HEAD_BYTES {
            return Err(StoreDataError::Malformed("command head length"));
        }
        let generation = u64::from_be_bytes(
            bytes[2..10]
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        );
        if bytes.len() == VACANT_HEAD_BYTES && bytes[1] == 0 {
            return Ok(Self::Vacant(generation));
        }
        if bytes.len() != ACTIVE_HEAD_BYTES || bytes[1] != 1 {
            return Err(StoreDataError::Malformed("command head kind"));
        }
        Self::decode_active(generation, bytes)
    }

    fn decode_active(generation: u64, bytes: &[u8]) -> Result<Self, StoreDataError> {
        let phase = match bytes[82] {
            0 => Phase::Prepared,
            1 => Phase::Committed,
            2 => Phase::Conflict,
            _ => return Err(StoreDataError::Malformed("command phase")),
        };
        let chunks = u32::from_be_bytes(
            bytes[42..46]
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        );
        let input_bytes = u32::from_be_bytes(
            bytes[46..50]
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        );
        let has_input = chunks > 0 && input_bytes > 0;
        let is_completed = phase == Phase::Committed && chunks == 0 && input_bytes == 0;
        if generation == 0 || !(has_input || is_completed) {
            return Err(StoreDataError::Malformed("command manifest"));
        }
        Ok(Self::Active(ActiveHead {
            generation,
            command_id: CommitOperationId::try_from_slice(&bytes[10..26])?,
            token: LeaseToken::try_from_slice(&bytes[26..42])?,
            chunks,
            input_bytes,
            binding: bytes[50..82]
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
            phase,
        }))
    }
}

impl ActiveHead {
    fn write_fields(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(self.command_id.as_bytes());
        bytes.extend_from_slice(self.token.as_bytes());
        bytes.extend_from_slice(&self.chunks.to_be_bytes());
        bytes.extend_from_slice(&self.input_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.binding);
        bytes.push(match self.phase {
            Phase::Prepared => 0,
            Phase::Committed => 1,
            Phase::Conflict => 2,
        });
    }
}

pub(super) fn slot_key(namespace: &Namespace, slot: u8) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Commit, &[&[slot]])
}

pub(super) fn input_key(
    namespace: &Namespace,
    slot: u8,
    chunk: u32,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(
        namespace,
        KeyTag::CommitInput,
        &[&[slot], &chunk.to_be_bytes()],
    )
}
