use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    JoseError, JwkThumbprint,
    constants::{MAX_EMBEDDED_JWK_BYTES, MAX_EMBEDDED_JWK_MEMBERS},
    lossless_jws::decode_part,
};

/// Public P-256 verification material, imported without network or key-id
/// resolution.
pub struct EmbeddedEs256Key {
    verifier: VerifyingKey,
    thumbprint: JwkThumbprint,
}

impl TryFrom<&Value> for EmbeddedEs256Key {
    type Error = JoseError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let object = value.as_object().ok_or(JoseError::InvalidJwk)?;
        if object.len() > MAX_EMBEDDED_JWK_MEMBERS
            || serde_json::to_vec(value)
                .map_err(|_| JoseError::InvalidJwk)?
                .len()
                > MAX_EMBEDDED_JWK_BYTES
        {
            return Err(JoseError::InvalidJwk);
        }
        validate_metadata(value)?;
        let x = value["x"].as_str().ok_or(JoseError::InvalidJwk)?;
        let y = value["y"].as_str().ok_or(JoseError::InvalidJwk)?;
        let x_bytes = decode_part(x, 32)?;
        let y_bytes = decode_part(y, 32)?;
        if x_bytes.len() != 32 || y_bytes.len() != 32 {
            return Err(JoseError::InvalidJwk);
        }
        let point = [vec![4], x_bytes, y_bytes].concat();
        let verifier = VerifyingKey::from_sec1_bytes(&point).map_err(|_| JoseError::InvalidJwk)?;
        let projection = serde_json::json!({"crv":"P-256", "kty":"EC", "x":x, "y":y});
        let canonical = serde_json::to_vec(&projection).map_err(|_| JoseError::InvalidJwk)?;
        let thumbprint =
            JwkThumbprint::try_from(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)))?;
        Ok(Self {
            verifier,
            thumbprint,
        })
    }
}

impl EmbeddedEs256Key {
    pub fn parse_json(bytes: &[u8]) -> Result<Self, JoseError> {
        if bytes.len() > MAX_EMBEDDED_JWK_BYTES {
            return Err(JoseError::InvalidJwk);
        }
        let value = crate::BoundedJson::parse(bytes)?.into_value();
        Self::try_from(&value)
    }

    pub fn thumbprint(&self) -> &JwkThumbprint {
        &self.thumbprint
    }

    pub fn verify(&self, signing_input: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        let signature =
            Signature::from_slice(signature).map_err(|_| JoseError::InvalidSignature)?;
        self.verifier
            .verify(signing_input, &signature)
            .map_err(|_| JoseError::InvalidSignature)
    }
}

fn validate_metadata(value: &Value) -> Result<(), JoseError> {
    if value["kty"] != "EC"
        || value["crv"] != "P-256"
        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "n", "e"]
            .iter()
            .any(|name| value.get(name).is_some())
    {
        return Err(JoseError::InvalidJwk);
    }
    if value
        .get("alg")
        .is_some_and(|algorithm| algorithm != "ES256")
        || value.get("use").is_some_and(|usage| usage != "sig")
    {
        return Err(JoseError::InvalidJwk);
    }
    if let Some(operations) = value.get("key_ops") {
        let operations = operations.as_array().ok_or(JoseError::InvalidJwk)?;
        if !operations.iter().all(Value::is_string)
            || !operations.iter().any(|operation| operation == "verify")
            || operations
                .iter()
                .enumerate()
                .any(|(index, operation)| operations[..index].contains(operation))
        {
            return Err(JoseError::InvalidJwk);
        }
    }
    Ok(())
}
