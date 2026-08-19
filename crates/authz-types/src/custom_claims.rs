use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::{Map, Value};

use crate::{
    ClaimBoundsError, MAX_CUSTOM_CLAIM_JSON_BYTES, MAX_CUSTOM_CLAIMS, MAX_CUSTOM_CLAIMS_JSON_BYTES,
    VerifiedClaimTree,
    claim_bounds::{canonical_json, validate_claim_value, validate_string},
    oauth_claims::is_structural_claim,
};

/// Bounded non-structural access-token claims.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomClaims {
    pub claims: Map<String, Value>,
}

impl CustomClaims {
    pub fn try_new(claims: Map<String, Value>) -> Result<Self, ClaimBoundsError> {
        if claims.len() > MAX_CUSTOM_CLAIMS {
            return Err(ClaimBoundsError::CustomClaimsExceeded {
                limit: MAX_CUSTOM_CLAIMS,
                actual: claims.len(),
            });
        }

        let mut total_bytes = 0;
        for (name, value) in &claims {
            validate_string("custom claim name", name)?;
            if is_structural_claim(name) {
                return Err(ClaimBoundsError::ProtectedClaim(name.clone()));
            }
            validate_claim_value(value, 1)?;
            let bytes = canonical_json(value).len();
            if bytes > MAX_CUSTOM_CLAIM_JSON_BYTES {
                return Err(ClaimBoundsError::CustomClaimTooLarge {
                    name: name.clone(),
                    limit: MAX_CUSTOM_CLAIM_JSON_BYTES,
                    actual: bytes,
                });
            }
            total_bytes += bytes;
        }
        if total_bytes > MAX_CUSTOM_CLAIMS_JSON_BYTES {
            return Err(ClaimBoundsError::CustomClaimsTooLarge {
                limit: MAX_CUSTOM_CLAIMS_JSON_BYTES,
                actual: total_bytes,
            });
        }

        VerifiedClaimTree::try_new(Value::Object(claims.clone()))?;
        Ok(Self { claims })
    }
}

impl Default for CustomClaims {
    fn default() -> Self {
        Self { claims: Map::new() }
    }
}

impl Serialize for CustomClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        self.claims.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CustomClaims {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        Self::try_new(Map::<String, Value>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
