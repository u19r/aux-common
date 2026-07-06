use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::ValidationError;

/// Validated resource type identifier (lowercase alphanumeric + underscore).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[schema(
    value_type = String,
    pattern = "^[a-z0-9_]+$",
    example = "repository"
)]
pub struct ResourceTypeId(String);

impl ResourceTypeId {
    pub const MAX_LENGTH: usize = 58;

    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ValidationError::InvalidFormat {
                field: "resource_type_id",
                message: "cannot be empty".to_string(),
            });
        }
        if s.len() > Self::MAX_LENGTH {
            return Err(ValidationError::OutOfRange {
                field: "resource_type_id",
                message: format!("max length is {}", Self::MAX_LENGTH),
            });
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(ValidationError::InvalidFormat {
                field: "resource_type_id",
                message: "must be lowercase alphanumeric with underscores".to_string(),
            });
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Action definition within a resource type.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ActionDefinition {
    /// Action identifier within the resource type.
    #[schema(example = "read", min_length = 1, max_length = 58)]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional human-readable action description.
    #[schema(
        min_length = 1,
        max_length = 250,
        nullable = true,
        example = "Allows reading repository contents"
    )]
    pub description: Option<String>,
}

/// A resource type defines a category of objects that can be protected.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResourceType {
    /// Resource type identifier.
    #[schema(example = "repository", min_length = 1, max_length = 58)]
    pub id: String,
    /// Human-readable resource type name.
    #[schema(example = "repository", min_length = 1, max_length = 58)]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional human-readable resource type description.
    #[schema(
        min_length = 1,
        max_length = 250,
        nullable = true,
        example = "Source code repositories managed by the tenant"
    )]
    pub description: Option<String>,
    #[schema(max_items = 256)] // Keep in sync with MAX_ACTIONS_PER_RESOURCE_TYPE.
    pub actions: Vec<ActionDefinition>,
    /// JSON Schema for context properties expected on this resource type
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = serde_json::Value, max_length = 10_000, nullable = true)]
    pub context_schema: Option<serde_json::Value>,
}
