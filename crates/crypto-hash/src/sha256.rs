//! SHA-256 and HMAC-SHA256 encodings used by protocol callers.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};

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
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut normalized_key = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        normalized_key[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = normalized_key;
    let mut outer_pad = normalized_key;
    for byte in &mut inner_pad {
        *byte ^= 0x36;
    }
    for byte in &mut outer_pad {
        *byte ^= 0x5c;
    }
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner_pad);
    inner_hasher.update(data);
    let inner = inner_hasher.finalize();
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer_pad);
    outer_hasher.update(inner);
    outer_hasher.finalize().into()
}
