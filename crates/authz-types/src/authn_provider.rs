use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// External authentication provider used solely for JWT verification in authz
/// flows.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "issuer": "https://issuer.example.com",
    "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
    "algorithms": ["RS256"],
    "audiences": ["auxfn-api"],
    "subject_claim": "sub",
    "org_claim": "org_id",
    "cache_ttl_seconds": 300
}))]
pub struct AuthnProviderConfig {
    /// Expected issuer (`iss`) claim.
    #[schema(
        min_length = 8,
        max_length = 2048,
        pattern = "^https://.+",
        example = "https://issuer.example.com"
    )]
    pub issuer: String,
    /// JWKS URI for signature verification.
    #[schema(
        min_length = 8,
        max_length = 2048,
        pattern = "^https://.+",
        example = "https://issuer.example.com/.well-known/jwks.json"
    )]
    pub jwks_uri: String,
    /// Allowed algorithms (e.g., ["RS256","ES256","HS256"]). Defaults to
    /// RS/ES256 if empty.
    #[serde(default)]
    #[schema(nullable = true, max_items = 6, example = json!(["RS256", "ES256"]))]
    pub algorithms: Option<Vec<String>>,
    /// Allowed audiences. If None, audience is not enforced.
    #[serde(default)]
    #[schema(nullable = true, min_items = 1, max_items = 25, example = json!(["auxfn-api"]))]
    pub audiences: Option<Vec<String>>,
    /// Claim name to use for subject id (defaults to "sub").
    #[serde(default = "default_subject_claim")]
    #[schema(min_length = 1, max_length = 58, default = "sub", example = "sub")]
    pub subject_claim: String,
    /// Claim name to use for org id (optional, copied into subject properties).
    #[serde(default)]
    #[schema(nullable = true, min_length = 1, max_length = 58, example = "org_id")]
    pub org_claim: Option<String>,
    /// JWKS cache TTL seconds.
    #[serde(default = "default_cache_ttl")]
    #[schema(minimum = 1, maximum = 86400, default = 300, example = 300)]
    pub cache_ttl_seconds: u64,
}

fn default_subject_claim() -> String {
    "sub".to_string()
}

fn default_cache_ttl() -> u64 {
    300
}
