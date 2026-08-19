use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
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
#[derive(Debug, Clone, ToSchema, PartialEq, Eq, Hash)]
pub enum SubjectType {
    User,
    Group,
    Role,
    ApiKey,
    #[serde(alias = "service_account")]
    Machine,
    Protocol,
    /// AuthZEN permits arbitrary subject type strings. Unknown values are
    /// retained so the PDP can return a normal negative decision instead of
    /// rejecting an otherwise syntactically valid request.
    Custom(String),
}

impl SubjectType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::User => "user",
            Self::Group => "group",
            Self::Role => "role",
            Self::ApiKey => "api_key",
            Self::Machine => "machine",
            Self::Protocol => "protocol",
            Self::Custom(value) => value,
        }
    }
}

impl Serialize for SubjectType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SubjectType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let value = String::deserialize(deserializer)?;
        if value.trim().is_empty() {
            return Err(de::Error::custom("subject type must not be empty"));
        }
        Ok(match value.as_str() {
            "user" => Self::User,
            "group" => Self::Group,
            "role" => Self::Role,
            "api_key" => Self::ApiKey,
            "machine" | "service_account" => Self::Machine,
            "protocol" => Self::Protocol,
            _ => Self::Custom(value),
        })
    }
}
