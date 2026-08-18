//! Token context supplied during authorization evaluation for API key requests.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{TokenScopeConfig, TokenScopeType};

/// Relationship between a validated token owner and the evaluated subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenSubjectBinding {
    /// A user token may authorize only its owner.
    Subject,
    /// A service token authorizes a runtime caller evaluating another subject.
    Delegated,
}

/// Validated token context included in evaluation requests.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "token_id": "tok_public_123",
    "owner_id": "user_123",
    "subject_binding": "subject",
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

    /// Whether the token is bound to its owner as the evaluated subject or
    /// delegates evaluation to a trusted runtime caller.
    pub subject_binding: TokenSubjectBinding,

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
            subject_binding: TokenSubjectBinding::Subject,
            scopes,
            expires_at: None,
        }
    }

    /// Construct a validated service credential used to evaluate other
    /// subjects while retaining the credential's own permission ceiling.
    pub fn delegated(token_id: String, owner_id: String, scopes: TokenScopeConfig) -> Self {
        Self {
            token_id,
            owner_id,
            subject_binding: TokenSubjectBinding::Delegated,
            scopes,
            expires_at: None,
        }
    }

    #[must_use]
    pub fn with_expiration(mut self, expires_at: Option<i64>) -> Self {
        self.expires_at = expires_at;
        self
    }

    pub fn is_full_access(&self) -> bool {
        matches!(self.scopes.scope_type, TokenScopeType::FullAccess)
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now().timestamp())
    }

    pub(crate) fn is_expired_at(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiration_at_exact_second_is_expired() {
        let token = TokenContext {
            token_id: "token".to_string(),
            owner_id: "owner".to_string(),
            subject_binding: TokenSubjectBinding::Subject,
            scopes: TokenScopeConfig::default(),
            expires_at: Some(1_000),
        };

        assert!(token.is_expired_at(1_000));
        assert!(!token.is_expired_at(999));
    }
}
