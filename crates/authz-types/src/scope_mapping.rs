//! Coarse-grained scope string mappings used for API token scoping.
//!
//! Tenants define mappings from scope strings (e.g., "repo:read") to the
//! permission identifiers declared in their authorization configuration. Scope
//! strings may expand hierarchically using `includes`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Maps a scope string to permission identifiers and optional child scopes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "scope": "doc:read",
    "permissions": ["doc:read"],
    "includes": ["doc:list"]
}))]
pub struct ScopeMappingEntry {
    /// The scope string (e.g., "repo:read", "admin:org").
    /// Must match a permission id in the configuration.
    #[schema(min_length = 1, max_length = 128, example = "repo:read")]
    pub scope: String,

    /// Permission identifiers this scope allows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500, example = json!(["repo:read"]))]
    pub permissions: Vec<String>,

    /// Additional scope strings this scope expands to (hierarchical scopes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 200, example = json!(["repo:read", "repo:triage"]))]
    pub includes: Vec<String>,
}

impl ScopeMappingEntry {
    /// Returns true when the entry does not allow anything directly.
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty() && self.includes.is_empty()
    }
}
