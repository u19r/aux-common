use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use data_encoding::BASE32_NOPAD;
use rand::{RngExt as _, rng};
use sha3::{Digest as _, Sha3_512};
use subtle::ConstantTimeEq;

use crate::HashError;

pub const API_KEY_HASH_ALGO: &str = "sha3-512";
const API_KEY_SALT_BYTES: usize = 16;
const API_KEY_SALT_B64_BYTES: usize = 22;
const API_KEY_DIGEST_BYTES: usize = 64;
const API_KEY_DIGEST_B64_BYTES: usize = 86;

/// Neutral serialized components for a salted API-key secret hash.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKeySecretHash {
    algo: &'static str,
    salt_b64: String,
    hash_b64: String,
}

impl std::fmt::Debug for ApiKeySecretHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApiKeySecretHash")
            .field("algo", &self.algo)
            .field("salt_b64", &"<redacted>")
            .field("hash_b64", &"<redacted>")
            .finish()
    }
}

impl ApiKeySecretHash {
    #[must_use]
    pub const fn algo(&self) -> &'static str {
        self.algo
    }

    #[must_use]
    pub fn salt_b64(&self) -> &str {
        &self.salt_b64
    }

    #[must_use]
    pub fn hash_b64(&self) -> &str {
        &self.hash_b64
    }
}

/// Hash an API-key secret with a fresh random salt.
#[must_use]
pub fn hash_api_key_secret(secret: &[u8]) -> ApiKeySecretHash {
    let mut salt = [0_u8; API_KEY_SALT_BYTES];
    rng().fill(&mut salt);
    let mut hasher = Sha3_512::new();
    hasher.update(salt);
    hasher.update(secret);
    ApiKeySecretHash {
        algo: API_KEY_HASH_ALGO,
        salt_b64: URL_SAFE_NO_PAD.encode(salt),
        hash_b64: URL_SAFE_NO_PAD.encode(hasher.finalize()),
    }
}

/// Verify an API-key secret using the stored algorithm, salt, and digest.
#[must_use]
pub fn verify_api_key_secret(
    secret: &[u8],
    algo: &str,
    salt_b64: &str,
    expected_b64: &str,
) -> bool {
    if algo != API_KEY_HASH_ALGO {
        return false;
    }
    if salt_b64.len() != API_KEY_SALT_B64_BYTES || expected_b64.len() != API_KEY_DIGEST_B64_BYTES {
        return false;
    }
    let Ok(salt) = URL_SAFE_NO_PAD.decode(salt_b64) else {
        return false;
    };
    let Ok(expected) = URL_SAFE_NO_PAD.decode(expected_b64) else {
        return false;
    };
    if salt.len() != API_KEY_SALT_BYTES || expected.len() != API_KEY_DIGEST_BYTES {
        return false;
    }
    if URL_SAFE_NO_PAD.encode(&salt) != salt_b64
        || URL_SAFE_NO_PAD.encode(&expected) != expected_b64
    {
        return false;
    }
    let mut hasher = Sha3_512::new();
    hasher.update(&salt);
    hasher.update(secret);
    let calculated = hasher.finalize();
    calculated[..].ct_eq(&expected).into()
}

/// Derive a stable, truncated public identifier with a caller-owned HMAC key.
pub fn try_derive_api_key_public_id(
    secret: &[u8],
    hmac_key: &[u8],
    truncate_len: usize,
) -> Result<String, HashError> {
    if truncate_len == 0 || truncate_len > 52 {
        return Err(HashError::InvalidApiKeyEncoding);
    }
    let tag = crate::sha256::hmac_sha256(hmac_key, secret);
    let encoded = BASE32_NOPAD.encode(&tag).to_ascii_lowercase();
    encoded
        .get(..truncate_len)
        .map(ToOwned::to_owned)
        .ok_or(HashError::InvalidApiKeyEncoding)
}
