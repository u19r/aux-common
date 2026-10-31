pub(crate) const MIN_CHALLENGE_BYTES: usize = 16;
pub(crate) const MAX_CHALLENGE_BYTES: usize = 128;
pub(crate) const MAX_AUTHENTICATOR_DATA_BYTES: usize = 16 * 1024;
pub(crate) const MAX_SIGNATURE_BYTES: usize = 256;
pub(crate) const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
pub(crate) const MAX_ATTESTATION_OBJECT_BYTES: usize = 32 * 1024;
pub(crate) const MAX_COSE_KEY_BYTES: usize = 1024;
pub(crate) const MAX_CBOR_DEPTH: usize = 16;
pub(crate) const MAX_CBOR_ITEMS: usize = 256;
pub(crate) const MAX_CLIENT_DATA_BYTES: usize = 16 * 1024;
pub(crate) const MAX_USER_HANDLE_BYTES: usize = 64;

/// The P-256 group order `n` halves to this value: a signature is low-S
/// (non-malleable) only when its `s` component, read as a big-endian
/// 256-bit integer, is at most this constant.
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

/// Normalizes a raw 64-byte `r || s` P-256 signature to low-S form so both
/// the low-S and high-S encodings of one logical signature produce identical
/// verification results.
pub(crate) fn normalize_low_s_webauthn(raw_signature: &[u8; 64]) -> [u8; 64] {
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

/// Normalizes a decoded P-256 signature to low-S form, returning the
/// normalized `Signature` for verification.
pub(crate) fn normalize_low_s_signature(
    signature: &p256::ecdsa::Signature,
) -> p256::ecdsa::Signature {
    let raw: [u8; 64] = signature.to_bytes().into();
    let normalized = crate::constants::normalize_low_s_webauthn(&raw);
    p256::ecdsa::Signature::from_slice(&normalized).expect("normalized signature is valid")
}
