use serde::{Deserialize, Serialize};

/// Signed token-type discriminator for OAuth access tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenType {
    AccessToken,
}
