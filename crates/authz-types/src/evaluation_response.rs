use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::AuthzChallenge;

/// Decision context with debugging information.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecisionContext {
    /// Human-readable reason for the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 1,
        max_length = 500,
        example = "Denied by role deny rule"
    )]
    pub reason: Option<String>,
    /// Effective permission evaluated (for debugging)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 1,
        max_length = 128,
        example = "doc:read"
    )]
    pub effective_permission: Option<String>,

    /// Policy version used for evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, minimum = 1, example = 42)]
    pub policy_version: Option<u64>,

    /// Roles that were checked
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, max_items = 200, example = json!(["role_reader", "role_editor"]))]
    pub checked_roles: Option<Vec<String>>,

    /// For step-up authentication scenarios
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 1,
        max_length = 128,
        example = "urn:acr:2"
    )]
    pub acr_values: Option<String>,
}

/// Single authorization evaluation response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "decision": true,
    "challenge": null,
    "context": {
        "reason": "Allowed by role permission",
        "effective_permission": "doc:read",
        "policy_version": 42,
        "checked_roles": ["role_reader"],
        "acr_values": null
    }
}))]
pub struct EvaluationResponse {
    /// true = allow, false = deny
    #[schema(example = true)]
    pub decision: bool,

    /// Optional challenge indicating step-up is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub challenge: Option<AuthzChallenge>,

    /// Additional decision context
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub context: Option<DecisionContext>,
}

impl EvaluationResponse {
    pub fn allow() -> Self {
        Self {
            decision: true,
            challenge: None,
            context: None,
        }
    }

    pub fn deny() -> Self {
        Self {
            decision: false,
            challenge: None,
            context: None,
        }
    }

    pub fn deny_with_reason(reason: impl Into<String>) -> Self {
        Self {
            decision: false,
            challenge: None,
            context: Some(DecisionContext {
                reason: Some(reason.into()),
                effective_permission: None,
                policy_version: None,
                checked_roles: None,
                acr_values: None,
            }),
        }
    }

    pub fn deny_with_challenge(reason: impl Into<String>, challenge: AuthzChallenge) -> Self {
        Self {
            decision: false,
            challenge: Some(challenge),
            context: Some(DecisionContext {
                reason: Some(reason.into()),
                effective_permission: None,
                policy_version: None,
                checked_roles: None,
                acr_values: None,
            }),
        }
    }

    pub fn requires_step_up(&self) -> bool {
        !self.decision && self.challenge.is_some()
    }
}

/// Batch authorization evaluation response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchEvaluationResponse {
    #[schema(max_items = 100)]
    pub evaluations: Vec<EvaluationResponse>,
}
