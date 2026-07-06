use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Evaluation subject, the entity requesting access.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "type": "user",
    "id": "user_123",
    "properties": { "org_id": "org_123" }
}))]
pub struct Subject {
    /// Entity type (e.g., "user", "service", "api_key")
    #[serde(rename = "type")]
    pub subject_type: SubjectType,

    /// Unique identifier scoped to type
    #[schema(min_length = 1, max_length = 58)]
    pub id: String,

    /// Additional attributes for policy evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = serde_json::Value, max_length = 10_000, nullable = true)]
    pub properties: Option<serde_json::Value>,
}

impl Subject {
    pub fn user(id: impl Into<String>) -> Self {
        Self {
            subject_type: SubjectType::User,
            id: id.into(),
            properties: None,
        }
    }

    pub fn service_account(id: impl Into<String>) -> Self {
        Self {
            subject_type: SubjectType::Machine,
            id: id.into(),
            properties: None,
        }
    }

    pub fn machine(id: impl Into<String>) -> Self {
        Self {
            subject_type: SubjectType::Machine,
            id: id.into(),
            properties: None,
        }
    }

    pub fn protocol(id: impl Into<String>) -> Self {
        Self {
            subject_type: SubjectType::Protocol,
            id: id.into(),
            properties: None,
        }
    }

    pub fn api_key(id: impl Into<String>) -> Self {
        Self {
            subject_type: SubjectType::ApiKey,
            id: id.into(),
            properties: None,
        }
    }

    pub fn role(id: impl Into<String>) -> Self {
        Self {
            subject_type: SubjectType::Role,
            id: id.into(),
            properties: None,
        }
    }

    pub fn group(id: impl Into<String>) -> Self {
        Self {
            subject_type: SubjectType::Group,
            id: id.into(),
            properties: None,
        }
    }

    pub fn with_properties(mut self, properties: serde_json::Value) -> Self {
        self.properties = Some(properties);
        self
    }
}

/// Subject types accepted by the Authz API.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    User,
    Group,
    Role,
    ApiKey,
    #[serde(alias = "service_account")]
    Machine,
    Protocol,
}

impl SubjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
            Self::Role => "role",
            Self::ApiKey => "api_key",
            Self::Machine => "machine",
            Self::Protocol => "protocol",
        }
    }
}
