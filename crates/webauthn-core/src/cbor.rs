use std::io::Cursor;

use ciborium::value::Value;
use p256::PublicKey;

use crate::{WebAuthnError, types::CosePublicKey};

pub type CoseKey = CosePublicKey;

pub(crate) const MAX_COSE_KEY_BYTES: usize = 1024;
// These limits run before ciborium recursively allocates a Value tree.
pub(crate) const MAX_CBOR_DEPTH: usize = 16;
pub(crate) const MAX_CBOR_ITEMS: usize = 256;

pub fn parse_cose_key(bytes: &[u8]) -> Result<CosePublicKey, WebAuthnError> {
    let value = decode_bounded_cbor(bytes, MAX_COSE_KEY_BYTES)?;
    ensure_canonical_cbor(&value, bytes)?;
    let Value::Map(entries) = value else {
        return Err(WebAuthnError::UnsupportedCoseKey);
    };
    validate_canonical_map_order(&entries)?;
    let mut seen = std::collections::HashSet::new();
    let mut kty = None;
    let mut alg = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;
    for (key, value) in entries {
        let key = integer(&key).ok_or(WebAuthnError::UnsupportedCoseKey)?;
        if !seen.insert(key) {
            return Err(WebAuthnError::Malformed);
        }
        match key {
            1 => kty = Some(integer(&value).ok_or(WebAuthnError::UnsupportedCoseKey)?),
            3 => alg = Some(integer(&value).ok_or(WebAuthnError::UnsupportedCoseKey)?),
            -1 => curve = Some(integer(&value).ok_or(WebAuthnError::UnsupportedCoseKey)?),
            -2 => x = Some(bytes_value(&value)?),
            -3 => y = Some(bytes_value(&value)?),
            _ => return Err(WebAuthnError::UnsupportedCoseKey),
        }
    }
    if kty != Some(2) || alg != Some(-7) || curve != Some(1) {
        return Err(WebAuthnError::UnsupportedCoseKey);
    }
    let x = exact_coordinate(x.ok_or(WebAuthnError::UnsupportedCoseKey)?)?;
    let y = exact_coordinate(y.ok_or(WebAuthnError::UnsupportedCoseKey)?)?;
    let mut encoded = [0_u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(&x);
    encoded[33..].copy_from_slice(&y);
    PublicKey::from_sec1_bytes(&encoded).map_err(|_| WebAuthnError::UnsupportedCoseKey)?;
    Ok(CosePublicKey {
        algorithm: -7,
        curve: 1,
        x,
        y,
    })
}

pub(crate) fn validate_cbor_structure(bytes: &[u8], max_bytes: usize) -> Result<(), WebAuthnError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(WebAuthnError::Malformed);
    }
    CborScanner::new(bytes).scan()
}

pub(crate) fn decode_bounded_cbor(bytes: &[u8], max_bytes: usize) -> Result<Value, WebAuthnError> {
    validate_cbor_structure(bytes, max_bytes)?;
    let mut cursor = Cursor::new(bytes);
    let value: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|_| WebAuthnError::Malformed)?;
    if cursor.position() as usize != bytes.len() {
        return Err(WebAuthnError::Malformed);
    }
    Ok(value)
}

struct CborScanner<'a> {
    bytes: &'a [u8],
    position: usize,
    items: usize,
    pending_items: Vec<usize>,
}

impl<'a> CborScanner<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            items: 0,
            pending_items: vec![1],
        }
    }

    fn scan(mut self) -> Result<(), WebAuthnError> {
        while let Some(remaining) = self.pending_items.last_mut() {
            if *remaining == 0 {
                self.pending_items.pop();
                continue;
            }
            *remaining -= 1;
            self.items = self.items.checked_add(1).ok_or(WebAuthnError::Malformed)?;
            if self.items > MAX_CBOR_ITEMS {
                return Err(WebAuthnError::Malformed);
            }

            let (major, additional) = self.read_initial()?;
            match major {
                0 | 1 => {
                    self.read_argument(additional)?;
                }
                2 | 3 => {
                    let length = self.read_length(additional)?;
                    self.skip(length)?;
                }
                4 => {
                    let length = self.read_length(additional)?;
                    self.push_children(length)?;
                }
                5 => {
                    let length = self.read_length(additional)?;
                    let children = length.checked_mul(2).ok_or(WebAuthnError::Malformed)?;
                    self.push_children(children)?;
                }
                6 => {
                    self.read_argument(additional)?;
                    self.push_children(1)?;
                }
                7 => {
                    self.read_simple(additional)?;
                }
                _ => return Err(WebAuthnError::Malformed),
            }
        }
        (self.position == self.bytes.len())
            .then_some(())
            .ok_or(WebAuthnError::Malformed)
    }

    fn push_children(&mut self, count: usize) -> Result<(), WebAuthnError> {
        if self.pending_items.len().saturating_sub(1) >= MAX_CBOR_DEPTH || count > MAX_CBOR_ITEMS {
            return Err(WebAuthnError::Malformed);
        }
        self.pending_items.push(count);
        Ok(())
    }

    fn read_initial(&mut self) -> Result<(u8, u8), WebAuthnError> {
        let byte = self.read_byte()?;
        Ok((byte >> 5, byte & 0x1f))
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, WebAuthnError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => Ok(u64::from(self.read_byte()?)),
            25 => self.read_unsigned(2),
            26 => self.read_unsigned(4),
            27 => self.read_unsigned(8),
            _ => Err(WebAuthnError::Malformed),
        }
    }

    fn read_length(&mut self, additional: u8) -> Result<usize, WebAuthnError> {
        self.read_argument(additional)?
            .try_into()
            .map_err(|_| WebAuthnError::Malformed)
    }

    fn read_simple(&mut self, additional: u8) -> Result<(), WebAuthnError> {
        match additional {
            0..=23 => Ok(()),
            24 => {
                self.read_byte()?;
                Ok(())
            }
            25 => self.skip(2),
            26 => self.skip(4),
            27 => self.skip(8),
            _ => Err(WebAuthnError::Malformed),
        }
    }

    fn read_unsigned(&mut self, length: usize) -> Result<u64, WebAuthnError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(WebAuthnError::Malformed)?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(WebAuthnError::Malformed)?;
        self.position = end;
        let mut value = 0_u64;
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    fn read_byte(&mut self) -> Result<u8, WebAuthnError> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or(WebAuthnError::Malformed)?;
        self.position += 1;
        Ok(byte)
    }

    fn skip(&mut self, length: usize) -> Result<(), WebAuthnError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(WebAuthnError::Malformed)?;
        if end > self.bytes.len() {
            return Err(WebAuthnError::Malformed);
        }
        self.position = end;
        Ok(())
    }
}

pub(crate) fn ensure_canonical_cbor(value: &Value, encoded: &[u8]) -> Result<(), WebAuthnError> {
    let mut canonical = Vec::new();
    ciborium::ser::into_writer(value, &mut canonical).map_err(|_| WebAuthnError::Malformed)?;
    if canonical != encoded {
        return Err(WebAuthnError::Malformed);
    }
    Ok(())
}

pub(crate) fn validate_canonical_map_order(
    entries: &[(Value, Value)],
) -> Result<(), WebAuthnError> {
    let mut previous = None;
    for (key, _) in entries {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(key, &mut encoded).map_err(|_| WebAuthnError::Malformed)?;
        if let Some(previous) = previous.as_deref()
            && canonical_key_cmp(previous, encoded.as_slice()).is_ge()
        {
            return Err(WebAuthnError::Malformed);
        }
        previous = Some(encoded);
    }
    Ok(())
}

fn canonical_key_cmp(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    let left_major = left.first().map_or(0, |byte| byte >> 5);
    let right_major = right.first().map_or(0, |byte| byte >> 5);
    left_major
        .cmp(&right_major)
        .then_with(|| left.len().cmp(&right.len()))
        .then_with(|| left.cmp(right))
}

fn integer(value: &Value) -> Option<i64> {
    let Value::Integer(value) = value else {
        return None;
    };
    let value: i128 = (*value).into();
    i64::try_from(value).ok()
}

fn bytes_value(value: &Value) -> Result<Vec<u8>, WebAuthnError> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(WebAuthnError::UnsupportedCoseKey),
    }
}

fn exact_coordinate(bytes: Vec<u8>) -> Result<[u8; 32], WebAuthnError> {
    bytes
        .try_into()
        .map_err(|_| WebAuthnError::UnsupportedCoseKey)
}
