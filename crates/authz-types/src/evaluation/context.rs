use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request-scoped attributes used in policy evaluation.
///
/// Context should be a JSON object and SHOULD be constrained by the resource
/// type's `context_schema` when one is defined. Use it for environmental
/// signals (risk score, request origin, flags) that are not part of the subject
/// or resource models. Avoid secrets or large blobs. Reserved keys
/// `subject_parents`, `resource_parents`, and `_authz` are populated by Authz
/// enrichment/internal enforcement and API requests that include them are
/// rejected.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "ip_country": "US",
    "risk_score": 42,
    "request_origin": "api_key"
}))]
pub struct Context {
    /// Allow-listed context attributes (flattened under `context` in the
    /// request).
    #[serde(flatten)]
    #[schema(
        value_type = std::collections::BTreeMap<String, serde_json::Value>,
        max_length = 10_000
    )]
    pub attributes: serde_json::Value,
}

impl Context {
    pub fn new(attributes: serde_json::Value) -> Self {
        Self { attributes }
    }

    pub fn empty() -> Self {
        Self {
            attributes: serde_json::Value::Object(Default::default()),
        }
    }
}
