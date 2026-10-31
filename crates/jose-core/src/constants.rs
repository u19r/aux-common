#[cfg(feature = "native")]
pub(crate) const JWE_MAX_KEY_ID_BYTES: usize = 128;
#[cfg(feature = "native")]
pub(crate) const JWE_MAX_PUBLIC_KEY_DER_BYTES: usize = 8192;
#[cfg(feature = "native")]
pub(crate) const JWE_MIN_RSA_CIPHERTEXT_BYTES: usize = 256;
#[cfg(feature = "native")]
pub(crate) const JWE_MAX_RSA_CIPHERTEXT_BYTES: usize = 512;
#[cfg(feature = "native")]
pub(crate) const JWE_MAX_SIGNED_JWT_BYTES: usize = 65_536;
#[cfg(feature = "native")]
pub(crate) const JWE_CONTENT_KEY_BYTES: usize = 32;
#[cfg(feature = "native")]
pub(crate) const JWE_IV_BYTES: usize = 12;

// TODO: this is repeated in other constants.rs files, combine if possible and
// it makes sense
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
///
/// ECDSA signatures are malleable: for a signature `(r, s)`, the pair
/// `(r, n - s)` also verifies for the same message under the same key.
/// Without normalization, the two byte-encodings of one logical signature
/// can produce distinct observable outcomes (replay dedupe, forensic
/// identification, and signature-hash rate limiting all see two different
/// inputs). Normalizing `s` to the lower half of the order ensures both
/// forms produce identical verification results.
///
/// Returns the normalized 64-byte signature. When `s` is already in the
/// lower half, the input is returned unchanged.
pub(crate) fn normalize_low_s(raw_signature: &[u8]) -> Option<[u8; 64]> {
    if raw_signature.len() != 64 {
        return None;
    }
    let mut normalized = [0_u8; 64];
    normalized[..64].copy_from_slice(raw_signature);
    if normalized[32..64] <= P256_HALF_ORDER[..] {
        return Some(normalized);
    }
    // s' = n - s: the mirror form, which is in the lower half because the
    // input s was in the upper half.
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
    Some(normalized)
}

// Fixed security bounds for embedded proof material.
pub(crate) const MAX_PROOF_BYTES: usize = 24 * 1024;
pub(crate) const MAX_ENCODED_PROOF_PART_BYTES: usize = 12 * 1024;
pub(crate) const MAX_PROOF_JSON_BYTES: usize = 8 * 1024;
pub(crate) const MAX_PROOF_SIGNATURE_BYTES: usize = 1024;
pub(crate) const MAX_JSON_DEPTH: usize = 8;
pub(crate) const MAX_JSON_MEMBERS: usize = 32;
pub(crate) const MAX_JSON_STRING_BYTES: usize = 2048;
pub(crate) const MAX_TARGET_URI_BYTES: usize = 8192;
pub(crate) const MAX_EMBEDDED_JWK_BYTES: usize = 4096;
pub(crate) const MAX_EMBEDDED_JWK_MEMBERS: usize = 16;
