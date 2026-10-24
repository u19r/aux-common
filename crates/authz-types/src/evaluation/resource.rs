use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::EvaluationProperties;

/// Evaluation resource, the object being accessed.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
        "type": "document",
        "id": "doc_456",
        "properties": { "owner_org_id": "org_123", "owner_user_id": "user_123" }
    }))]
pub struct Resource {
    /// Resource type (e.g., "document", "project", "org")
    #[serde(rename = "type")]
    #[schema(min_length = 1, max_length = 58)]
    pub resource_type: String,

    /// Unique identifier scoped to type
    #[schema(min_length = 1, max_length = 58)]
    pub id: String,

    /// Attributes needed for policy evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = EvaluationProperties, max_length = 10_000, nullable = true)]
    pub properties: Option<serde_json::Value>,
}

impl Resource {
    pub fn new(resource_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            id: id.into(),
            properties: None,
        }
    }

    pub fn with_properties(mut self, properties: serde_json::Value) -> Self {
        self.properties = Some(properties);
        self
    }

    pub fn with_evaluation_properties(
        self,
        properties: crate::EvaluationProperties,
    ) -> Result<Self, serde_json::Error> {
        serde_json::to_value(properties).map(|properties| self.with_properties(properties))
    }
}
