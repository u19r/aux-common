use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{Action, Context, JwtContext, Resource, SessionContext, Subject, TokenContext};

/// Single authorization evaluation request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "subject": { "type": "user", "id": "user_123" },
    "resource": { "type": "document", "id": "doc_456" },
    "action": { "name": "read" }
}))]
pub struct EvaluationRequest {
    /// Principal requesting access. Use a stable identifier scoped to the
    /// subject type.
    #[schema(example = json!({ "type": "user", "id": "user_123" }))]
    pub subject: Subject,
    /// Target resource for the decision. Include properties needed for scoping
    /// or policy checks.
    #[schema(example = json!({ "type": "document", "id": "doc_456" }))]
    pub resource: Resource,
    /// Operation being evaluated. Must be defined for the resource type in the
    /// tenant config.
    #[schema(example = json!({ "name": "read" }))]
    pub action: Action,
    /// Request-scoped context used during policy evaluation.
    ///
    /// This must be a JSON object and SHOULD match the resource type's
    /// `context_schema` (if configured). Keep it allow-listed and small; do
    /// not pass secrets or full resource payloads. Reserved keys
    /// `subject_parents`, `resource_parents`, and `_authz` are populated by
    /// Authz enrichment/internal enforcement; the API rejects requests that
    /// include them.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub context: Option<Context>,
    /// JWT-derived identity context (orgs/groups/roles) used for stateless
    /// evaluation. Only supply when the caller is trusted or the JWT is
    /// validated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub jwt_context: Option<JwtContext>,

    /// Authentication session context for step-up evaluation
    /// (acr/amr/timestamps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub session_context: Option<SessionContext>,

    /// API token context for API key requests; restricts permissions to token
    /// scopes. Never include the token secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub token_context: Option<TokenContext>,
}

/// Batch authorization evaluation request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "evaluations": [{
        "subject": { "type": "user", "id": "user_123" },
        "resource": { "type": "document", "id": "doc_456" },
        "action": { "name": "read" }
    }]
}))]
pub struct BatchEvaluationRequest {
    #[schema(max_items = 100, example = json!([{
        "subject": { "type": "user", "id": "user_123" },
        "resource": { "type": "document", "id": "doc_456" },
        "action": { "name": "read" }
    }]))]
    pub evaluations: Vec<EvaluationRequest>,
    /// Optional shared subject applied to every evaluation in this batch.
    ///
    /// When present, this replaces per-item `subject` values at manager
    /// evaluation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub subject_override: Option<Subject>,
    /// Optional shared token context applied to every evaluation in this batch.
    ///
    /// When present, this replaces per-item `token_context` values at manager
    /// evaluation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub token_context_override: Option<TokenContext>,
}
