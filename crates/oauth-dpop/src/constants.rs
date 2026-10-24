pub(crate) const MAX_JTI_BYTES: usize = 256;
pub(crate) const MAX_METHOD_BYTES: usize = 32;
pub(crate) const MAX_URI_BYTES: usize = 8192;
pub const MAX_ACCESS_TOKEN_BYTES: usize = 256 * 1024;
pub(crate) const MAX_PROOF_AGE_SECONDS: i64 = 60;
pub(crate) const MAX_FUTURE_SKEW_SECONDS: i64 = 5;
pub(crate) const MAX_NUMERIC_DATE_SECONDS: i64 = 253_402_300_799;

/// Maximum verifier expiry grace used to bound required-policy transition.
pub const MAX_ACCESS_TOKEN_EXPIRY_LEEWAY_SECONDS: u64 = 60;
