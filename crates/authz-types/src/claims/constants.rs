/// Maximum nesting depth accepted in a verified claim tree.
pub const MAX_CLAIM_DEPTH: usize = 8;
/// Maximum members allowed in any claim object or array.
pub const MAX_CLAIM_MEMBERS: usize = 128;
/// Maximum custom top-level claims in one access token.
pub const MAX_CUSTOM_CLAIMS: usize = 64;
/// Maximum UTF-8 bytes in a custom property name or string value.
pub const MAX_CLAIM_STRING_BYTES: usize = 1_024;
/// Maximum canonical JSON bytes occupied by one custom claim.
pub const MAX_CUSTOM_CLAIM_JSON_BYTES: usize = 4 * 1_024;
/// Maximum aggregate canonical JSON bytes occupied by custom claims.
pub const MAX_CUSTOM_CLAIMS_JSON_BYTES: usize = 8 * 1_024;
/// Maximum bytes in the final compact JWT.
pub const MAX_COMPACT_JWT_BYTES: usize = 16 * 1_024;

/// Claim names owned by the signed access-token protocol or reserved by a
/// removed protocol contract so they cannot be reintroduced as custom claims.
pub const STRUCTURAL_CLAIM_NAMES: &[&str] = &[
    "cnf",
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "client_id",
    "scope",
    "tenant",
    "token_type",
    "principal_type",
    "auth_time",
    "acr",
    "amr",
    "nonce",
    "azp",
    "at_hash",
    "c_hash",
    "access_profile_session_reference",
    "permission_set_id",
    "permission_set_revision",
];

pub const MAX_CLAIM_MAPPINGS: usize = 64;
pub const MAX_CLAIM_MAPPING_PATH_BYTES: usize = 1_024;
pub const MAX_CLAIM_MAPPING_PATTERN_BYTES: usize = 1_024;
pub const MAX_CLAIM_MAPPING_TEMPLATE_NODES: usize = 128;
pub(crate) const MAX_CLAIM_MAPPING_REGEX_GROUP_DEPTH: usize = 32;
pub(crate) const MAX_CLAIM_MAPPING_REGEX_QUANTIFIERS: usize = 64;
pub(crate) const MAX_CLAIM_MAPPING_REGEX_REPEAT: u64 = 128;
