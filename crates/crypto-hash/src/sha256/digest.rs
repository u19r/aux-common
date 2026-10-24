//! SHA-256 and HMAC-SHA256 encodings used by protocol callers.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest as _, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 digest bytes.
#[must_use]
pub fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 digest encoded with the standard padded Base64 alphabet.
#[must_use]
pub fn digest_base64(data: &[u8]) -> String {
    STANDARD.encode(digest(data))
}

/// RFC 9530 `Content-Digest` value for SHA-256.
#[must_use]
pub fn content_digest_header_value(body: &[u8]) -> String {
    format!("sha-256=:{}:", digest_base64(body))
}

/// Compute an HMAC-SHA256 tag.
///
/// Delegates key normalization and pad construction to the audited `hmac` crate
/// (RFC 2104). The `hmac` constructor accepts keys of any length, so the error
/// arms below are unreachable; they fall back deterministically instead of
/// panicking.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        debug_assert!(false, "HMAC accepts keys of any length");
        let derived = Sha256::digest(key);
        let Ok(mut fallback) = HmacSha256::new_from_slice(&derived) else {
            debug_assert!(false, "derived HMAC key must be accepted");
            return Sha256::digest(data).into();
        };
        fallback.update(data);
        return fallback.finalize().into_bytes().into();
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}
