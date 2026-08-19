use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;

use crate::{ClaimBoundsError, claim_bounds::validate_claim_value};

/// A lossless, validated JSON tree copied from verified JWT claims.
///
/// This type intentionally retains JSON nulls, object insertion order, array
/// order, and `serde_json::Number` distinctions. It does not reinterpret
/// tenant-defined claims as platform authorization fields.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedClaimTree {
    pub value: Value,
}

impl VerifiedClaimTree {
    pub fn try_new(value: Value) -> Result<Self, ClaimBoundsError> {
        validate_claim_value(&value, 0)?;
        Ok(Self { value })
    }
}

impl Serialize for VerifiedClaimTree {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        self.value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VerifiedClaimTree {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        Self::try_new(Value::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
