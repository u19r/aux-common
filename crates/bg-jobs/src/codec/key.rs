use crate::{
    codec::constants::{KEY_VERSION, MAX_COMPONENTS, NAMESPACE_LENGTH_BYTES},
    error::StoreDataError,
    ids::{JobId, Namespace},
    store::StoreKey,
};

/// The fixed v1 key tags used by the persisted queue records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyTag {
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

impl KeyTag {
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

/// Decoded v1 tag and length-delimited tuple components.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedKey {
    pub tag: KeyTag,
    pub components: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedKeyRef<'a> {
    pub tag: KeyTag,
    pub components: Vec<&'a [u8]>,
}

/// Canonical collision-free key codec.
pub struct KeyCodec;

impl KeyCodec {
    pub fn encode(
        namespace: &Namespace,
        tag: KeyTag,
        components: &[&[u8]],
    ) -> Result<StoreKey, StoreDataError> {
        if components.len() > MAX_COMPONENTS {
            return Err(StoreDataError::Malformed("too many key components"));
        }
        let component_bytes = components.iter().try_fold(0usize, |total, component| {
            if component.len() > u32::MAX as usize {
                return Err(StoreDataError::LengthOverflow);
            }
            total
                .checked_add(4)
                .and_then(|total| total.checked_add(component.len()))
                .ok_or(StoreDataError::LengthOverflow)
        })?;
        let namespace_length = u32::try_from(namespace.as_bytes().len())
            .map_err(|_| StoreDataError::LengthOverflow)?;
        let capacity = NAMESPACE_LENGTH_BYTES
            .checked_add(1)
            .and_then(|total| total.checked_add(namespace.as_bytes().len()))
            .and_then(|total| total.checked_add(1))
            .and_then(|total| total.checked_add(component_bytes))
            .ok_or(StoreDataError::LengthOverflow)?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.push(KEY_VERSION);
        encoded.extend_from_slice(&namespace_length.to_be_bytes());
        encoded.extend_from_slice(namespace.as_bytes());
        encoded.push(tag.as_byte());
        for component in components {
            let length = component.len() as u32;
            encoded.extend_from_slice(&length.to_be_bytes());
            encoded.extend_from_slice(component);
        }
        StoreKey::try_from(encoded).map_err(|_| StoreDataError::Malformed("empty key"))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn decode(namespace: &Namespace, key: &StoreKey) -> Result<DecodedKey, StoreDataError> {
        let (tag, components_start) = decode_header(namespace, key.as_bytes())?;
        let components = decode_components(&key.as_bytes()[components_start..])?;
        Ok(DecodedKey { tag, components })
    }

    pub fn decode_borrowed<'a>(
        namespace: &Namespace,
        key: &'a StoreKey,
    ) -> Result<DecodedKeyRef<'a>, StoreDataError> {
        let (tag, components_start) = decode_header(namespace, key.as_bytes())?;
        let components = decode_component_slices(&key.as_bytes()[components_start..])?;
        Ok(DecodedKeyRef { tag, components })
    }

    #[cfg(feature = "test-support")]
    pub fn decode_single_component<'a>(
        namespace: &Namespace,
        key: &'a StoreKey,
    ) -> Result<(KeyTag, &'a [u8]), StoreDataError> {
        let (tag, components_start) = decode_header(namespace, key.as_bytes())?;
        let component_bytes = &key.as_bytes()[components_start..];
        let end = 4usize;
        if end > component_bytes.len() {
            return Err(StoreDataError::Truncated);
        }
        let length = u32::from_be_bytes(
            component_bytes[..end]
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        ) as usize;
        let component_end = end
            .checked_add(length)
            .ok_or(StoreDataError::LengthOverflow)?;
        if component_end > component_bytes.len() {
            return Err(StoreDataError::Truncated);
        }
        if component_end != component_bytes.len() {
            return Err(StoreDataError::Malformed("expected one key component"));
        }
        Ok((tag, &component_bytes[end..component_end]))
    }

    pub fn job(namespace: &Namespace, job_id: &JobId) -> Result<StoreKey, StoreDataError> {
        Self::encode(namespace, KeyTag::Job, &[job_id.as_bytes()])
    }

    pub fn prefix_end(prefix: &StoreKey) -> Option<StoreKey> {
        let mut bytes = prefix.as_bytes().to_vec();
        for index in (0..bytes.len()).rev() {
            if bytes[index] != u8::MAX {
                bytes[index] += 1;
                bytes.truncate(index + 1);
                return StoreKey::try_from(bytes).ok();
            }
        }
        None
    }
}

fn decode_header(namespace: &Namespace, bytes: &[u8]) -> Result<(KeyTag, usize), StoreDataError> {
    let namespace_length_end = 1usize
        .checked_add(NAMESPACE_LENGTH_BYTES)
        .ok_or(StoreDataError::LengthOverflow)?;
    if bytes.len() < namespace_length_end {
        return Err(StoreDataError::Truncated);
    }
    if bytes[0] != KEY_VERSION {
        return Err(StoreDataError::UnknownVersion(bytes[0]));
    }
    let namespace_length = u32::from_be_bytes(
        bytes[1..namespace_length_end]
            .try_into()
            .map_err(|_| StoreDataError::Truncated)?,
    ) as usize;
    if namespace_length != namespace.as_bytes().len() {
        return Err(StoreDataError::Malformed("key prefix"));
    }
    let namespace_end = namespace_length_end
        .checked_add(namespace_length)
        .ok_or(StoreDataError::LengthOverflow)?;
    let tag_end = namespace_end
        .checked_add(1)
        .ok_or(StoreDataError::LengthOverflow)?;
    if bytes.len() < tag_end || &bytes[namespace_length_end..namespace_end] != namespace.as_bytes()
    {
        return Err(StoreDataError::Malformed("key prefix"));
    }
    let tag = KeyTag::try_from_byte(bytes[namespace_end])?;
    Ok((tag, tag_end))
}

#[cfg(any(test, feature = "test-support"))]
fn decode_components(bytes: &[u8]) -> Result<Vec<Vec<u8>>, StoreDataError> {
    let mut offset = 0;
    let mut components = Vec::new();
    while offset < bytes.len() {
        if components.len() == MAX_COMPONENTS {
            return Err(StoreDataError::Malformed("too many key components"));
        }
        let end = offset
            .checked_add(4)
            .ok_or(StoreDataError::LengthOverflow)?;
        if end > bytes.len() {
            return Err(StoreDataError::Truncated);
        }
        let length = u32::from_be_bytes(
            bytes[offset..end]
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        ) as usize;
        offset = end;
        let component_end = offset
            .checked_add(length)
            .ok_or(StoreDataError::LengthOverflow)?;
        if component_end > bytes.len() {
            return Err(StoreDataError::Truncated);
        }
        components.push(bytes[offset..component_end].to_vec());
        offset = component_end;
    }
    Ok(components)
}

fn decode_component_slices(bytes: &[u8]) -> Result<Vec<&[u8]>, StoreDataError> {
    let mut offset = 0;
    let mut components = Vec::new();
    while offset < bytes.len() {
        if components.len() == MAX_COMPONENTS {
            return Err(StoreDataError::Malformed("too many key components"));
        }
        let end = offset
            .checked_add(4)
            .ok_or(StoreDataError::LengthOverflow)?;
        if end > bytes.len() {
            return Err(StoreDataError::Truncated);
        }
        let length = u32::from_be_bytes(
            bytes[offset..end]
                .try_into()
                .map_err(|_| StoreDataError::Truncated)?,
        ) as usize;
        offset = end;
        let component_end = offset
            .checked_add(length)
            .ok_or(StoreDataError::LengthOverflow)?;
        if component_end > bytes.len() {
            return Err(StoreDataError::Truncated);
        }
        components.push(&bytes[offset..component_end]);
        offset = component_end;
    }
    Ok(components)
}
