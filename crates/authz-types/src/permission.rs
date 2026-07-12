use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::ValidationError;

/// Validated permission identifier (format: {resource_type}:{name}).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, ToSchema)]
#[schema(
    value_type = String,
    pattern = "^[^:]+:[^:]+$",
    example = "repo:read"
)]
pub struct PermissionId(String);

impl PermissionId {
    pub const MAX_LENGTH: usize = 128;

    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s = s.into();
        if s.len() > Self::MAX_LENGTH {
            return Err(ValidationError::OutOfRange {
                field: "permission_id",
                message: format!("max length is {}", Self::MAX_LENGTH),
            });
        }
        let Some((resource_type, name)) = s.split_once(':') else {
            return Err(ValidationError::InvalidFormat {
                field: "permission_id",
                message: "must be {resource_type}:{name}".to_string(),
            });
        };
        if resource_type.is_empty() || name.is_empty() || name.contains(':') {
            return Err(ValidationError::InvalidFormat {
                field: "permission_id",
                message: "must contain exactly one ':' with non-empty components".to_string(),
            });
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn resource_type(&self) -> &str {
        self.0
            .split_once(':')
            .map(|(resource_type, _)| resource_type)
            .unwrap_or_default()
    }
    pub fn name(&self) -> &str {
        self.0
            .split_once(':')
            .map(|(_, name)| name)
            .unwrap_or_default()
    }
}

impl<'de> Deserialize<'de> for PermissionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct PermissionActionRef {
    /// Resource type referenced by this action.
    #[schema(example = "document", min_length = 1, max_length = 58)]
    pub resource_type: String,
    /// Action name referenced by this action.
    #[schema(example = "read", min_length = 1, max_length = 58)]
    pub action_name: String,
}

/// A permission bundles one or more actions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Permission {
    /// Permission identifier `{resource_type}:{name}`.
    #[schema(
        example = "repo:read",
        min_length = 3,
        max_length = 128,
        pattern = "^[^:]+:[^:]+$"
    )]
    pub id: String,
    /// Customer-supplied stable permission name.
    #[schema(example = "repo_read", min_length = 1, max_length = 58)]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional human-readable permission description.
    #[schema(
        min_length = 1,
        max_length = 250,
        nullable = true,
        example = "Allows viewing repository metadata and files"
    )]
    pub description: Option<String>,
    /// Actions allowed by this permission.
    #[schema(max_items = 500)]
    pub actions: Vec<PermissionActionRef>,
    /// Explicitly denied actions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500)]
    pub not_actions: Vec<PermissionActionRef>,
}
