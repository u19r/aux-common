use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PublicEncryptingKey};

use super::{encryption::encrypt_nested_jwt, protected_header::encode_protected_header};
use crate::{
    JoseError,
    constants::{
        JWE_MAX_KEY_ID_BYTES, JWE_MAX_PUBLIC_KEY_DER_BYTES, JWE_MAX_RSA_CIPHERTEXT_BYTES,
        JWE_MAX_SIGNED_JWT_BYTES, JWE_MIN_RSA_CIPHERTEXT_BYTES,
    },
};

/// Validated RSA recipient for the RSA-OAEP-256/A256GCM compact profile.
/// Callers own recipient authorization, key lifecycle and tenant boundaries.
pub struct JweRecipient {
    key_id: String,
    key: OaepPublicEncryptingKey,
}

impl JweRecipient {
    pub fn try_new(key_id: impl Into<String>, public_key_spki: &[u8]) -> Result<Self, JoseError> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > JWE_MAX_KEY_ID_BYTES {
            return Err(JoseError::EmptyKeyId);
        }
        if public_key_spki.len() > JWE_MAX_PUBLIC_KEY_DER_BYTES {
            return Err(JoseError::InvalidPublicKey);
        }
        let key = PublicEncryptingKey::from_der(public_key_spki)
            .map_err(|_| JoseError::InvalidPublicKey)?;
        let key = OaepPublicEncryptingKey::new(key).map_err(|_| JoseError::InvalidPublicKey)?;
        if !(JWE_MIN_RSA_CIPHERTEXT_BYTES..=JWE_MAX_RSA_CIPHERTEXT_BYTES)
            .contains(&key.ciphertext_size())
        {
            return Err(JoseError::InvalidPublicKey);
        }
        Ok(Self { key_id, key })
    }

    /// Encrypt an already signed compact JWT with a fresh CEK and nonce.
    /// Signing and signature authority remain the caller's responsibility.
    pub fn encrypt_nested_jwt(&self, signed_jwt: &str) -> Result<String, JoseError> {
        if signed_jwt.is_empty() || signed_jwt.len() > JWE_MAX_SIGNED_JWT_BYTES {
            return Err(JoseError::InvalidCompactShape);
        }
        let segments: Vec<_> = signed_jwt.split('.').collect();
        if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
            return Err(JoseError::InvalidCompactShape);
        }
        let header = encode_protected_header(&self.key_id)?;
        encrypt_nested_jwt(&self.key, &header, signed_jwt.as_bytes())
    }
}
