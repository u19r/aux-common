pub(crate) const DEFAULT_LEEWAY: std::time::Duration = std::time::Duration::from_secs(30);
pub(crate) const DEFAULT_MAX_TOKEN_BYTES: usize = 16 * 1024;
pub(crate) const MAX_JWKS_DOCUMENT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_JWKS_KEYS: usize = 1024;

pub(crate) const MIN_RSA_MODULUS_BITS: usize = 2048;
pub(crate) const MAX_RSA_MODULUS_BYTES: usize = 1024;
pub(crate) const MIN_HMAC_KEY_BYTES: usize = 32;
pub(crate) const MAX_HMAC_KEY_BYTES: usize = 64;
pub(crate) const MAX_ED25519_PUBLIC_KEY_BYTES: usize = 32;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) const UNKNOWN_KID_REFRESH_COOLDOWN: std::time::Duration =
    std::time::Duration::from_secs(1);
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const MAX_UNKNOWN_KID_REFRESH_COOLDOWNS: usize = 256;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const MAX_INVALIDATION_GENERATIONS: usize = 256;
