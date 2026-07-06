//! Token scoping types for API key permission ceilings.
//!
//! Effective permissions are always the intersection of user claims and
//! token scopes. Tokens can only restrict, never expand, what the user can do.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Defines how an API token restricts the user's permissions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "scope_type": "scope_strings",
    "scope_strings": ["doc:read", "doc:write"],
    "fine_grained": null,
    "org_id": null
}))]
pub struct TokenScopeConfig {
    /// Scoping model used by the token.
    #[serde(default)]
    #[schema(
        value_type = String,
        default = "full_access",
        example = "scope_strings"
    )]
    pub scope_type: TokenScopeType,

    /// OAuth-style scope strings (coarse-grained scopes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 200, example = json!(["doc:read", "doc:write"]))]
    pub scope_strings: Vec<String>,

    /// Fine-grained per-resource permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub fine_grained: Option<FineGrainedScopes>,

    /// Optional organization binding for the token (org-scoped tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, min_length = 1, max_length = 58, example = "org_123")]
    pub org_id: Option<String>,
}

impl Default for TokenScopeConfig {
    fn default() -> Self {
        Self {
            scope_type: TokenScopeType::FullAccess,
            scope_strings: Vec::new(),
            fine_grained: None,
            org_id: None,
        }
    }
}

impl TokenScopeConfig {
    /// Create an unrestricted token scope (default behavior).
    pub fn full_access() -> Self {
        Self::default()
    }

    /// Create a coarse-grained scope configuration.
    pub fn with_scopes(scopes: Vec<String>) -> Self {
        Self {
            scope_type: TokenScopeType::ScopeStrings,
            scope_strings: scopes,
            fine_grained: None,
            org_id: None,
        }
    }

    /// Create a fine-grained scope configuration.
    pub fn fine_grained(config: FineGrainedScopes) -> Self {
        Self {
            scope_type: TokenScopeType::FineGrained,
            scope_strings: Vec::new(),
            fine_grained: Some(config),
            org_id: None,
        }
    }

    /// Attach an org binding to the token.
    pub fn with_org(mut self, org_id: String) -> Self {
        self.org_id = Some(org_id);
        self
    }
}

/// Scoping model used by a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenScopeType {
    /// No additional restriction; token inherits all user permissions.
    #[default]
    FullAccess,

    /// Coarse-grained OAuth-style scope strings.
    ScopeStrings,

    /// Fine-grained per-resource permission allow-lists.
    FineGrained,
}

/// Fine-grained permission allow-lists per resource type.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "resource_selection": "selected",
    "selected_resources": ["doc_1", "doc_2"],
    "resource_permissions": { "document": ["doc:read"] },
    "org_permissions": { "org_123": ["org:manage"] }
}))]
pub struct FineGrainedScopes {
    /// Which resources the token can access.
    #[serde(default)]
    #[schema(value_type = String, default = "all", example = "selected")]
    pub resource_selection: ResourceSelection,

    /// Explicit resource identifiers when `resource_selection` is `Selected`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 1000, example = json!(["doc_1", "doc_2"]))]
    pub selected_resources: Vec<String>,

    /// Allowed permission ids per resource type identifier.
    ///
    /// Example:
    /// `{"repo": ["repo:read", "repo:write"]}`
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[schema(example = json!({ "document": ["doc:read", "doc:write"] }))]
    pub resource_permissions: HashMap<String, Vec<String>>,

    /// Optional org-level allowed permission ids.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[schema(example = json!({ "org_123": ["org:manage"] }))]
    pub org_permissions: HashMap<String, Vec<String>>,
}

/// Resource selection strategy for fine-grained tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceSelection {
    /// All resources the user can access.
    #[default]
    All,

    /// Only explicitly selected resources.
    Selected,
}
