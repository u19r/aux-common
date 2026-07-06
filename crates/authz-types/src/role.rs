use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{PermissionId, Scope, ValidationError};

/// Validated role identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[schema(
    value_type = String,
    example = "repo_admin"
)]
pub struct RoleId(String);

impl RoleId {
    pub const MAX_LENGTH: usize = 58;

    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ValidationError::InvalidFormat {
                field: "role_id",
                message: "cannot be empty".to_string(),
            });
        }
        if s.len() > Self::MAX_LENGTH {
            return Err(ValidationError::OutOfRange {
                field: "role_id",
                message: format!("max length is {}", Self::MAX_LENGTH),
            });
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A permission entry with scope restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RolePermission {
    /// Permission identifier attached to this role.
    #[schema(value_type = String, example = "repo:read")]
    pub permission_id: PermissionId,
    /// Scope restrictions for this permission grant.
    #[schema(max_items = 100)]
    pub scopes: Vec<Scope>,
}

/// A direct action entry with scope restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RoleActionRef {
    /// Resource type referenced by this role action.
    #[schema(example = "document", min_length = 1, max_length = 58)]
    pub resource_type: String,
    /// Action name referenced by this role action.
    #[schema(example = "read", min_length = 1, max_length = 58)]
    pub action_name: String,
    #[schema(max_items = 100)]
    pub scopes: Vec<Scope>,
}

/// A role groups permissions with optional scope restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Role {
    /// Role identifier.
    #[schema(example = "repo:admin", min_length = 1, max_length = 58)]
    pub id: String,
    /// Customer-supplied stable role name.
    #[schema(example = "repo_admin", min_length = 1, max_length = 58)]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional human-readable role description.
    #[schema(
        min_length = 1,
        max_length = 250,
        nullable = true,
        example = "Full administrative access to repositories"
    )]
    pub description: Option<String>,
    #[schema(max_items = 1024)] // Keep in sync with MAX_PERMISSIONS.
    pub permissions: Vec<RolePermission>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500)]
    pub actions: Vec<RoleActionRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500)]
    pub not_actions: Vec<RoleActionRef>,
}
