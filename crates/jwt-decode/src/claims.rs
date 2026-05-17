use serde::{Deserialize, Serialize};

use crate::SignatureAlgorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Access,
    Id,
    Refresh,
}

impl TokenKind {
    pub(crate) fn default_claim_value(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Id => "id",
            Self::Refresh => "refresh",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisteredClaims {
    pub iss: String,
    #[serde(default)]
    pub sub: Option<String>,
    pub aud: Audience,
    pub exp: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    pub iat: i64,
    #[serde(default)]
    pub jti: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    pub(crate) fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(value) => value == expected,
            Self::Multiple(values) => values.iter().any(|value| value == expected),
        }
    }

    pub(crate) fn count(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Multiple(values) => values.len(),
        }
    }

    pub(crate) fn is_valid(&self) -> bool {
        match self {
            Self::Single(value) => !value.is_empty(),
            Self::Multiple(values) => {
                !values.is_empty() && values.iter().all(|value| !value.is_empty())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedJwt<T> {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub registered: RegisteredClaims,
    pub claims: T,
}
