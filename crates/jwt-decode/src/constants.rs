pub(crate) const DEFAULT_LEEWAY: std::time::Duration = std::time::Duration::from_secs(30);

/// OAuth access-token token-type claim conventions recognized as DPoP-eligible
/// access-token policies for the DPoP leeway ceiling. `access` is the preset
/// value from `TokenKind::Access.default_claim_value()`; `access_token` is the
/// explicit override convention documented by RFC 9449 deployments.
pub(crate) const DPOP_ACCESS_TOKEN_TYPE_VALUES: &[&str] = &["access", "access_token"];

pub(crate) const DEFAULT_MAX_TOKEN_BYTES: usize = 16 * 1024;
pub(crate) const MAX_JWKS_DOCUMENT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_JWKS_KEYS: usize = 1024;

pub(crate) const MIN_RSA_MODULUS_BITS: usize = 2048;
pub(crate) const MAX_RSA_MODULUS_BYTES: usize = 1024;
pub(crate) const MIN_HMAC_KEY_BYTES: usize = 32;
pub(crate) const MAX_HMAC_KEY_BYTES: usize = 64;
pub(crate) const MAX_ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// The P-256 group order `n` halves to this value: a signature is low-S
/// (non-malleable) only when its `s` component, read as a big-endian
/// 256-bit integer, is at most this constant. Signatures with `s` above
/// the half-order are the `n - s` mirror of a low-S signature.
pub(crate) const P256_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, //
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, //
    0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// The P-256 group order `n`.
pub(crate) const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, //
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Normalizes a raw 64-byte `r || s` P-256 signature to low-S form.
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) fn normalize_low_s_raw(raw_signature: &[u8; 64]) -> [u8; 64] {
    let mut normalized = *raw_signature;
    if normalized[32..64] <= P256_HALF_ORDER[..] {
        return normalized;
    }
    let s = &mut normalized[32..64];
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let difference = u16::from(P256_ORDER[index]).checked_sub(u16::from(s[index]) + borrow);
        match difference {
            Some(value) => {
                s[index] = u8::try_from(value).expect("in-range byte");
                borrow = 0;
            }
            None => {
                s[index] = u8::try_from(
                    u16::from(P256_ORDER[index]) + 0x100 - u16::from(s[index]) - borrow,
                )
                .expect("wrapped byte");
                borrow = 1;
            }
        }
    }
    normalized
}

/// Normalizes a base64url-encoded ES256 signature to low-S form and
/// re-encodes it, so both the low-S and high-S encodings of one logical
/// signature produce identical verification results downstream.
///
/// Returns `None` when the signature is not valid base64url or not exactly
/// 64 bytes after decoding.
pub(crate) fn normalize_low_s_encoded(encoded_signature: &str) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let raw = URL_SAFE_NO_PAD.decode(encoded_signature).ok()?;
    if raw.len() != 64 {
        return None;
    }
    let mut normalized = [0_u8; 64];
    normalized.copy_from_slice(&raw);
    if normalized[32..64] <= P256_HALF_ORDER[..] {
        return Some(encoded_signature.to_owned());
    }
    let s = &mut normalized[32..64];
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let difference = u16::from(P256_ORDER[index]).checked_sub(u16::from(s[index]) + borrow);
        match difference {
            Some(value) => {
                s[index] = u8::try_from(value).ok()?;
                borrow = 0;
            }
            None => {
                s[index] = u8::try_from(
                    u16::from(P256_ORDER[index]) + 0x100 - u16::from(s[index]) - borrow,
                )
                .ok()?;
                borrow = 1;
            }
        }
    }
    Some(URL_SAFE_NO_PAD.encode(normalized))
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) const UNKNOWN_KID_REFRESH_COOLDOWN: std::time::Duration =
    std::time::Duration::from_secs(1);
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const MAX_UNKNOWN_KID_REFRESH_COOLDOWNS: usize = 256;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const MAX_INVALIDATION_GENERATIONS: usize = 256;
