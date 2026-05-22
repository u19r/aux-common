use std::{borrow::Cow, fmt};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserializer,
    de::{DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};

use crate::{ClaimErrorKind, JwtDecodeError, JwtDecodeErrorKind, Result};

pub(crate) const DEFAULT_MAX_TOKEN_BYTES: usize = 16 * 1024;

pub(crate) struct CompactToken<'a> {
    pub(crate) message: &'a str,
    pub(crate) header: &'a str,
    pub(crate) payload: &'a str,
    pub(crate) signature: &'a str,
}

impl<'a> TryFrom<&'a str> for CompactToken<'a> {
    type Error = JwtDecodeError;

    fn try_from(token: &'a str) -> Result<Self> {
        if token.len() > DEFAULT_MAX_TOKEN_BYTES {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        }

        let Some((message, signature)) = token.rsplit_once('.') else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        };
        let Some((header, payload)) = message.split_once('.') else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        };
        if payload.contains('.') || header.is_empty() || payload.is_empty() || signature.is_empty()
        {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken));
        }

        Ok(Self {
            message,
            header,
            payload,
            signature,
        })
    }
}

impl CompactToken<'_> {
    pub(crate) fn reject_duplicate_header_members(&self) -> Result<()> {
        Self::reject_duplicate_members_in_encoded_part(self.header)
    }

    pub(crate) fn payload_value_rejecting_duplicates(&self) -> Result<Value> {
        Self::decoded_part_rejecting_duplicates(self.payload)
    }

    pub(crate) fn reject_duplicate_json_members(&self) -> Result<()> {
        for encoded in [self.header, self.payload] {
            Self::reject_duplicate_members_in_encoded_part(encoded)?;
        }
        Ok(())
    }

    fn reject_duplicate_members_in_encoded_part(encoded: &str) -> Result<()> {
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken))?;
        JsonDocument::reject_duplicate_members(&decoded).map_err(|_| {
            JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(
                ClaimErrorKind::DuplicateJsonMember,
            ))
        })
    }

    fn decoded_part_rejecting_duplicates(encoded: &str) -> Result<Value> {
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::MalformedToken))?;
        JsonDocument::value_rejecting_duplicate_members(&decoded).map_err(|_| {
            JwtDecodeError::new(JwtDecodeErrorKind::ClaimsInvalid(
                ClaimErrorKind::DuplicateJsonMember,
            ))
        })
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

    pub(crate) fn value_rejecting_duplicate_members(
        bytes: &[u8],
    ) -> std::result::Result<Value, ()> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        deserializer
            .deserialize_any(DuplicateRejectingValueVisitor)
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
        let mut inline_names: [Option<Cow<'de, str>>; 16] = std::array::from_fn(|_| None);
        let mut inline_len = 0;
        let mut overflow_names: Vec<Cow<'de, str>> = Vec::new();
        while let Some(name) = map.next_key::<Cow<'de, str>>()? {
            let inline_duplicate = inline_names[..inline_len]
                .iter()
                .flatten()
                .any(|existing| existing == &name);
            let overflow_duplicate = overflow_names.iter().any(|existing| existing == &name);
            if inline_duplicate || overflow_duplicate {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            if inline_len < inline_names.len() {
                inline_names[inline_len] = Some(name);
                inline_len += 1;
            } else {
                overflow_names.push(name);
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

struct DuplicateRejectingValueVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("valid JSON value without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where E: serde::de::Error {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where A: SeqAccess<'de> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(DuplicateRejectingValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where A: MapAccess<'de> {
        let mut value = Map::new();
        while let Some(name) = map.next_key::<Cow<'de, str>>()? {
            if value.contains_key(name.as_ref()) {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            value.insert(
                name.into_owned(),
                map.next_value_seed(DuplicateRejectingValueSeed)?,
            );
        }
        Ok(Value::Object(value))
    }
}

struct DuplicateRejectingValueSeed;

impl<'de> DeserializeSeed<'de> for DuplicateRejectingValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_any(DuplicateRejectingValueVisitor)
    }
}
