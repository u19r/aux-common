use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{ClaimBoundsError, claim_bounds::validate_string};

/// Normalized JWT audience values.
///
/// JWT permits `aud` to be either one string or an array of strings. This
/// type accepts both wire forms and exposes one ordered representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedAudience {
    pub values: Vec<String>,
}

impl NormalizedAudience {
    pub fn try_new(values: Vec<String>) -> Result<Self, ClaimBoundsError> {
        if values.is_empty() || values.iter().any(String::is_empty) {
            return Err(ClaimBoundsError::InvalidAudience);
        }
        for value in &values {
            validate_string("aud", value)?;
        }
        Ok(Self { values })
    }

    #[must_use]
    pub fn contains(&self, audience: &str) -> bool {
        self.values.iter().any(|value| value == audience)
    }
}

impl Serialize for NormalizedAudience {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match self.values.as_slice() {
            [value] => value.serialize(serializer),
            values => values.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for NormalizedAudience {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum WireAudience {
            Single(String),
            Multiple(Vec<String>),
        }

        let values = match WireAudience::deserialize(deserializer)? {
            WireAudience::Single(value) => vec![value],
            WireAudience::Multiple(values) => values,
        };
        Self::try_new(values).map_err(D::Error::custom)
    }
}
