//! Token context supplied during authorization evaluation for API key requests.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{TokenScopeConfig, TokenScopeType};

/// API token context included in evaluation requests.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "token_id": "tok_public_123",
    "owner_id": "user_123",
    "scopes": {
        "scope_type": "scope_strings",
        "scope_strings": ["doc:read"]
    },
    "expires_at": 1739697600
}))]
pub struct TokenContext {
    /// Public token identifier (never the secret).
    #[schema(min_length = 1, max_length = 58, example = "tok_public_123")]
    pub token_id: String,

    /// Owner of the token (UserId serialized as string to avoid cross-crate
    /// dep).
    #[schema(min_length = 1, max_length = 58, example = "user_123")]
    pub owner_id: String,

    /// Scoping configuration that restricts permissions.
    pub scopes: TokenScopeConfig,

    /// Optional expiration timestamp (seconds since epoch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, minimum = 0, example = 1739697600)]
    pub expires_at: Option<i64>,
}

impl TokenContext {
    pub fn new(token_id: String, owner_id: String, scopes: TokenScopeConfig) -> Self {
        Self {
            token_id,
            owner_id,
            scopes,
            expires_at: None,
        }
    }

    pub fn is_full_access(&self) -> bool {
        matches!(self.scopes.scope_type, TokenScopeType::FullAccess)
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|exp| exp < Utc::now().timestamp())
    }
}
