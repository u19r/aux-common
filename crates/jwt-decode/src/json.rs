use std::{collections::HashSet, fmt};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserializer,
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
};

use crate::{ClaimErrorKind, JwtDecodeError, JwtDecodeErrorKind, Result};

pub(crate) const DEFAULT_MAX_TOKEN_BYTES: usize = 16 * 1024;

pub(crate) struct CompactToken<'a> {
    pub(crate) header: &'a str,
    pub(crate) payload: &'a str,
}

impl<'a> TryFrom<&'a str> for CompactToken<'a> {
    type Error = JwtDecodeError;

    fn try_from(token: &'a str) -> Result<Self> {
        if token.len() > DEFAULT_MAX_TOKEN_BYTES {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        }

        let mut parts = token.split('.');
        let Some(header) = parts.next() else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        };
        let Some(payload) = parts.next() else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        };
        let Some(signature) = parts.next() else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        };

        if parts.next().is_some() || header.is_empty() || payload.is_empty() || signature.is_empty()
        {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        }

        Ok(Self { header, payload })
    }
}

impl CompactToken<'_> {
    pub(crate) fn reject_duplicate_json_members(&self) -> Result<()> {
        for encoded in [self.header, self.payload] {
            let decoded = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken))?;
            JsonDocument::reject_duplicate_members(&decoded).map_err(|_| {
                JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(
                    ClaimErrorKind::DuplicateJsonMember,
                ))
            })?;
        }
        Ok(())
    }
}

pub(crate) struct JsonDocument;

impl JsonDocument {
    pub(crate) fn reject_duplicate_members(bytes: &[u8]) -> std::result::Result<(), ()> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        deserializer
            .deserialize_any(DuplicateRejectingVisitor)
            .map_err(|_| ())
    }
}

struct DuplicateRejectingVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON without duplicate object members")
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where A: SeqAccess<'de> {
        while seq.next_element_seed(DuplicateRejectingSeed)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where A: MapAccess<'de> {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            map.next_value_seed(DuplicateRejectingSeed)?;
        }
        Ok(())
    }
}

struct DuplicateRejectingSeed;

impl<'de> DeserializeSeed<'de> for DuplicateRejectingSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_any(DuplicateRejectingVisitor)
    }
}
