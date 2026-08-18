use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::JoseError;

const MAX_PROTECTED_HEADER_B64_BYTES: usize = 8 * 1024;
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_TYP_BYTES: usize = 64;

/// The asymmetric JWS algorithms supported by the public profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum JwsAlgorithm {
    #[serde(rename = "RS256")]
    Rs256,
    #[serde(rename = "RS384")]
    Rs384,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
    #[serde(rename = "EdDSA")]
    EdDsa,
}

impl JwsAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDsa => "EdDSA",
        }
    }

    #[must_use]
    pub fn as_jwt(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::Rs256 => jsonwebtoken::Algorithm::RS256,
            Self::Rs384 => jsonwebtoken::Algorithm::RS384,
            Self::Es256 => jsonwebtoken::Algorithm::ES256,
            Self::Es384 => jsonwebtoken::Algorithm::ES384,
            Self::EdDsa => jsonwebtoken::Algorithm::EdDSA,
        }
    }
}

impl TryFrom<&str> for JwsAlgorithm {
    type Error = JoseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "RS256" => Ok(Self::Rs256),
            "RS384" => Ok(Self::Rs384),
            "ES256" => Ok(Self::Es256),
            "ES384" => Ok(Self::Es384),
            "EdDSA" => Ok(Self::EdDsa),
            _ => Err(JoseError::UnsupportedAlgorithm),
        }
    }
}

impl std::fmt::Display for JwsAlgorithm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProtectedHeaderWire<'a> {
    alg: &'a str,
    kid: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedHeader {
    algorithm: JwsAlgorithm,
    key_id: String,
    typ: Option<String>,
}

impl ProtectedHeader {
    pub fn new(
        algorithm: JwsAlgorithm,
        key_id: impl Into<String>,
        typ: Option<impl Into<String>>,
    ) -> Result<Self, JoseError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > MAX_KEY_ID_BYTES {
            return Err(JoseError::EmptyKeyId);
        }
        let typ = typ.map(Into::into);
        if typ
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_TYP_BYTES)
        {
            return Err(JoseError::InvalidProtectedHeader);
        }
        Ok(Self {
            algorithm,
            key_id,
            typ,
        })
    }

    #[must_use]
    pub const fn algorithm(&self) -> JwsAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    pub fn encode(&self) -> Result<String, JoseError> {
        let wire = ProtectedHeaderWire {
            alg: self.algorithm.as_str(),
            kid: &self.key_id,
            typ: self.typ.as_deref(),
        };
        let json = serde_json::to_vec(&wire).map_err(|_| JoseError::InvalidProtectedHeader)?;
        Ok(URL_SAFE_NO_PAD.encode(json))
    }

    pub fn decode(encoded: &str) -> Result<Self, JoseError> {
        if encoded.len() > MAX_PROTECTED_HEADER_B64_BYTES {
            return Err(JoseError::InvalidProtectedHeader);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| JoseError::InvalidBase64)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err(JoseError::InvalidBase64);
        }
        let wire: ProtectedHeaderWire<'_> =
            serde_json::from_slice(&decoded).map_err(|_| JoseError::InvalidProtectedHeader)?;
        let algorithm = JwsAlgorithm::try_from(wire.alg)?;
        let header = Self::new(algorithm, wire.kid, wire.typ)?;
        let canonical = serde_json::to_vec(&ProtectedHeaderWire {
            alg: header.algorithm.as_str(),
            kid: header.key_id(),
            typ: header.typ(),
        })
        .map_err(|_| JoseError::InvalidProtectedHeader)?;
        if canonical != decoded {
            return Err(JoseError::InvalidProtectedHeader);
        }
        Ok(header)
    }
}
