use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Evaluation action, the operation being performed.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "name": "read",
    "properties": { "source": "api" }
}))]
pub struct Action {
    /// Action name (e.g., "read", "write", "delete")
    #[schema(min_length = 1, max_length = 58)]
    pub name: String,

    /// Additional action attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = serde_json::Value, max_length = 10_000, nullable = true)]
    pub properties: Option<serde_json::Value>,
}

impl Action {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            properties: None,
        }
    }
}
