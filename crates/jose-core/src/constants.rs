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
