use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize};

use crate::JoseError;

/// Canonical SHA-256 RFC 7638 thumbprint. Debug is redacted.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct JwkThumbprint(String);

impl TryFrom<String> for JwkThumbprint {
    type Error = JoseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 43 {
            return Err(JoseError::InvalidJwk);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&value)
            .map_err(|_| JoseError::InvalidJwk)?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes) != value {
            return Err(JoseError::InvalidJwk);
        }
        Ok(Self(value))
    }
}

impl JwkThumbprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for JwkThumbprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for JwkThumbprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JwkThumbprint([REDACTED])")
    }
}
