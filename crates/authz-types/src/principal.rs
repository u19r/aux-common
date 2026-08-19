use serde::{Deserialize, Serialize};

/// Principal kind represented by a signed access token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    #[default]
    User,
    ServicePrincipal,
}

/// The verified principal represented by an access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Principal {
    User { id: String },
    ServicePrincipal { id: String },
}
