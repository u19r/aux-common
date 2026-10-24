use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Default scoping configuration applied before policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DefaultScopingConfig {
    /// Global scoping pattern for resources.
    pub pattern: ScopingPattern,
    #[serde(default)]
    /// Field configuration for standard scoping patterns.
    pub config: ScopingPatternConfig,
    #[serde(default)]
    /// Per-resource-type overrides.
    pub resource_scoping: HashMap<String, ResourceScopingConfig>,
}

impl Default for DefaultScopingConfig {
    fn default() -> Self {
        Self {
            pattern: ScopingPattern::OrgScoped,
            config: ScopingPatternConfig::default(),
            resource_scoping: HashMap::new(),
        }
    }
}

/// Standard scoping patterns.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopingPattern {
    /// All resources belong to an org. Users must be org members.
    #[default]
    OrgScoped,
    /// Resources belong to groups. Users must be group members.
    GroupScoped,
    /// Resources have an owner user. Only owner (or admins) can access.
    UserOwned,
    /// Different resource types have different scoping rules.
    Mixed,
    /// No default scoping. Tenant handles all scoping in policies.
    None,
}

/// Configuration for a scoping pattern.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScopingPatternConfig {
    /// Field on resource that contains the org ID.
    #[serde(default = "default_org_field")]
    pub resource_org_field: String,
    /// Field on resource that contains the group ID.
    #[serde(default = "default_group_field")]
    pub resource_group_field: String,
    /// Field on resource that contains the owner user ID.
    #[serde(default = "default_owner_field")]
    pub resource_owner_field: String,
    /// Whether to implicitly check org membership before other checks.
    #[serde(default = "default_true")]
    pub implicit_org_check: bool,
    /// Whether owner has full access to their resources.
    #[serde(default = "default_true")]
    pub owner_has_full_access: bool,
    /// Whether admin role overrides all resource-level permissions.
    #[serde(default)]
    pub admin_role_overrides: bool,
}

impl Default for ScopingPatternConfig {
    fn default() -> Self {
        Self {
            resource_org_field: default_org_field(),
            resource_group_field: default_group_field(),
            resource_owner_field: default_owner_field(),
            implicit_org_check: true,
            owner_has_full_access: true,
            admin_role_overrides: false,
        }
    }
}

/// Per-resource-type scoping configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResourceScopingConfig {
    pub pattern: ScopingPattern,
    #[serde(default)]
    pub org_field: Option<String>,
    #[serde(default)]
    pub group_field: Option<String>,
    #[serde(default)]
    pub owner_field: Option<String>,
}

fn default_org_field() -> String {
    "owner_org_id".to_string()
}

fn default_group_field() -> String {
    "owner_group_id".to_string()
}

fn default_owner_field() -> String {
    "owner_user_id".to_string()
}

fn default_true() -> bool {
    true
}
