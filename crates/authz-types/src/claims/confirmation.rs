use std::fmt;

use oauth_dpop::{AccessTokenConfirmation, JwkThumbprint};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error, MapAccess, Visitor},
};
use serde_json::{Map, Value};

/// Bounded wire confirmation; an unsupported present value remains distinct
/// from absence.
#[derive(Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ConfirmationClaim(Map<String, Value>);

impl ConfirmationClaim {
    pub fn from_thumbprint(jkt: &JwkThumbprint) -> Self {
        Self(Map::from_iter([(
            "jkt".to_owned(),
            Value::String(jkt.as_str().to_owned()),
        )]))
    }

    pub fn normalize(&self) -> AccessTokenConfirmation {
        // Construction and deserialization already establish the bounded
        // confirmation invariant.
        match AccessTokenConfirmation::parse(Some(&Value::Object(self.0.clone()))) {
            Ok(value) => value,
            Err(_) => AccessTokenConfirmation::Unsupported,
        }
    }
}

impl fmt::Debug for ConfirmationClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfirmationClaim([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for ConfirmationClaim {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(ConfirmationVisitor)
    }
}

struct ConfirmationVisitor;

impl<'de> Visitor<'de> for ConfirmationVisitor {
    type Value = ConfirmationClaim;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded token confirmation")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
        let mut members = Map::new();
        while let Some(name) = input.next_key::<String>()? {
            if members.len() == 16 || members.contains_key(&name) || name.len() > 256 {
                return Err(A::Error::custom("invalid token confirmation"));
            }
            let value = input.next_value::<Value>()?;
            members.insert(name, value);
        }
        let value = Value::Object(members.clone());
        if serde_json::to_vec(&value).map_err(A::Error::custom)?.len() > 2048 {
            return Err(A::Error::custom("invalid token confirmation"));
        }
        AccessTokenConfirmation::parse(Some(&value)).map_err(A::Error::custom)?;
        Ok(ConfirmationClaim(members))
    }
}

pub(super) fn deserialize_present_confirmation<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ConfirmationClaim>, D::Error> {
    ConfirmationClaim::deserialize(deserializer).map(Some)
}
