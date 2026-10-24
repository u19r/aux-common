use std::fmt;

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::{
    JoseError,
    constants::{
        MAX_JSON_DEPTH, MAX_JSON_MEMBERS, MAX_JSON_STRING_BYTES, MAX_PROOF_JSON_BYTES,
        MAX_TARGET_URI_BYTES,
    },
};

/// Duplicate-safe JSON with fixed allocation, collection, string, and nesting
/// bounds. Only the root `htu` member has the larger URI string bound.
pub struct BoundedJson(Value);

impl BoundedJson {
    pub fn parse(bytes: &[u8]) -> Result<Self, JoseError> {
        if bytes.len() > MAX_PROOF_JSON_BYTES {
            return Err(JoseError::InvalidProtectedHeader);
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let value = JsonSeed {
            depth: 0,
            string_limit: MAX_JSON_STRING_BYTES,
        }
        .deserialize(&mut deserializer)
        .map_err(|_| JoseError::InvalidProtectedHeader)?;
        deserializer
            .end()
            .map_err(|_| JoseError::InvalidProtectedHeader)?;
        Ok(Self(value))
    }

    pub fn into_value(self) -> Value {
        self.0
    }
}

struct JsonSeed {
    depth: usize,
    string_limit: usize,
}

impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonSeed {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > self.string_limit {
            return Err(E::custom("JSON string limit"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(A::Error::custom("JSON depth limit"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonSeed {
            depth: self.depth + 1,
            string_limit: MAX_JSON_STRING_BYTES,
        })? {
            if values.len() == MAX_JSON_MEMBERS {
                return Err(A::Error::custom("JSON array limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(A::Error::custom("JSON depth limit"));
        }
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_JSON_STRING_BYTES
                || values.len() == MAX_JSON_MEMBERS
                || values.contains_key(&key)
            {
                return Err(A::Error::custom("JSON member limit or duplicate"));
            }
            let string_limit = if self.depth == 0 && key == "htu" {
                MAX_TARGET_URI_BYTES
            } else {
                MAX_JSON_STRING_BYTES
            };
            let value = map.next_value_seed(JsonSeed {
                depth: self.depth + 1,
                string_limit,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
