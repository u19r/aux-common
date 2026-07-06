use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    Action, AuthzChallenge, BatchEvaluationRequest, Context, EvaluationRequest, EvaluationResponse,
    JwtContext, SessionContext, Subject, SubjectType, TokenContext,
};

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiEvaluationRequest {
    pub subject: ApiSubject,
    pub resource: ApiResource,
    pub action: ApiAction,
    #[serde(default)]
    pub context: Option<ApiContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_context: Option<JwtContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context: Option<SessionContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_context: Option<TokenContext>,
}

impl From<ApiEvaluationRequest> for EvaluationRequest {
    fn from(req: ApiEvaluationRequest) -> Self {
        Self {
            subject: Subject {
                subject_type: req.subject.subject_type,
                id: req.subject.id,
                properties: req.subject.properties,
            },
            resource: crate::Resource {
                resource_type: req.resource.resource_type,
                id: req.resource.id,
                properties: req.resource.properties,
            },
            action: Action {
                name: req.action.name,
                properties: req.action.properties,
            },
            context: req.context.map(|context| Context {
                attributes: context.attributes,
            }),
            jwt_context: req.jwt_context,
            session_context: req.session_context,
            token_context: req.token_context,
        }
    }
}

impl From<EvaluationRequest> for ApiEvaluationRequest {
    fn from(req: EvaluationRequest) -> Self {
        Self {
            subject: ApiSubject {
                subject_type: req.subject.subject_type,
                id: req.subject.id,
                properties: req.subject.properties,
            },
            resource: ApiResource {
                resource_type: req.resource.resource_type,
                id: req.resource.id,
                properties: req.resource.properties,
            },
            action: ApiAction {
                name: req.action.name,
                properties: req.action.properties,
            },
            context: req.context.map(|context| ApiContext {
                attributes: context.attributes,
            }),
            jwt_context: req.jwt_context,
            session_context: req.session_context,
            token_context: req.token_context,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiSubject {
    #[serde(rename = "type")]
    #[schema(value_type = String, example = "user")]
    pub subject_type: SubjectType,
    #[schema(min_length = 1, max_length = 58, example = "u_2BCDEFGHJKMNPQRSTVWXYZ1")]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = serde_json::Value, max_length = 10_000)]
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiResource {
    #[serde(rename = "type")]
    #[schema(min_length = 1, max_length = 58, example = "document")]
    pub resource_type: String,
    #[schema(min_length = 1, max_length = 58, example = "doc_123")]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = serde_json::Value, max_length = 10_000)]
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiAction {
    #[schema(min_length = 1, max_length = 58, example = "read")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = serde_json::Value, max_length = 10_000)]
    pub properties: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(transparent)]
pub struct ApiContext {
    pub attributes: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiResponseContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = "Permission matched via role repo_admin")]
    pub reason_admin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = "repo:read")]
    pub effective_permission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = 42)]
    pub policy_version: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiEvaluationResponse {
    pub decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<AuthzChallenge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ApiResponseContext>,
}

impl From<EvaluationResponse> for ApiEvaluationResponse {
    fn from(response: EvaluationResponse) -> Self {
        Self {
            decision: response.decision,
            challenge: response.challenge,
            context: response.context.map(|context| ApiResponseContext {
                reason_admin: context.reason,
                effective_permission: context.effective_permission,
                policy_version: context.policy_version.map(|value| value as u32),
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiBatchEvaluationRequest {
    #[schema(min_items = 1, max_items = 100)]
    pub evaluations: Vec<ApiEvaluationRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_override: Option<ApiSubject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_context_override: Option<TokenContext>,
}

impl From<ApiBatchEvaluationRequest> for BatchEvaluationRequest {
    fn from(req: ApiBatchEvaluationRequest) -> Self {
        Self {
            evaluations: req
                .evaluations
                .into_iter()
                .map(EvaluationRequest::from)
                .collect(),
            subject_override: req.subject_override.map(|subject| Subject {
                subject_type: subject.subject_type,
                id: subject.id,
                properties: subject.properties,
            }),
            token_context_override: req.token_context_override,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct ApiBatchEvaluationResponse {
    pub results: Vec<ApiEvaluationResponse>,
}
