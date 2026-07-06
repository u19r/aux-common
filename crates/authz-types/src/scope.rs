use std::{fmt, str::FromStr};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::schema::{ObjectBuilder, Type},
};

use crate::ValidationError;

/// Scope for role permissions and role assignments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Access to all resources in the tenant
    Tenant,
    /// Access to resources in the user's organization
    Org,
    /// Access to resources in the user's groups
    Group,
    /// Access to resources the user owns
    Own,
    /// Access to resources explicitly shared with user
    Shared,
    /// Access to resources marked as public
    Public,
    /// Access when principal has relationship to org parent chain
    OrgRelationship,
    /// Access when principal has relationship to group parent chain
    GroupRelationship,
    /// Access to a specific resource type (resource id stored separately).
    Resource { resource_type: Option<String> },
}

impl PartialSchema for Scope {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        ObjectBuilder::new().schema_type(Type::String).into()
    }
}

impl ToSchema for Scope {}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Org => "org",
            Self::Group => "group",
            Self::Own => "own",
            Self::Shared => "shared",
            Self::Public => "public",
            Self::OrgRelationship => "org_relationship",
            Self::GroupRelationship => "group_relationship",
            Self::Resource { .. } => "resource",
        }
    }

    pub fn storage_key(&self) -> String {
        match self {
            Self::Resource {
                resource_type: Some(resource_type),
            } => format!("resource:{resource_type}"),
            _ => self.as_str().to_string(),
        }
    }

    pub fn resource(resource_type: impl Into<String>) -> Self {
        Self::Resource {
            resource_type: Some(resource_type.into()),
        }
    }

    pub fn resource_type(&self) -> Option<&str> {
        match self {
            Self::Resource { resource_type } => resource_type.as_deref(),
            _ => None,
        }
    }
}

impl FromStr for Scope {
    type Err = ValidationError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let trimmed = raw.trim();
        let normalized = trimmed.to_ascii_lowercase();
        if let Some(resource_type) = normalized.strip_prefix("resource:") {
            if resource_type.is_empty() {
                return Err(ValidationError::InvalidFormat {
                    field: "scope",
                    message: "resource scope requires resource type".to_string(),
                });
            }
            return Ok(Self::Resource {
                resource_type: Some(resource_type.to_string()),
            });
        }

        match normalized.as_str() {
            "tenant" => Ok(Self::Tenant),
            "org" => Ok(Self::Org),
            "group" => Ok(Self::Group),
            "own" => Ok(Self::Own),
            "shared" => Ok(Self::Shared),
            "public" => Ok(Self::Public),
            "org_relationship" => Ok(Self::OrgRelationship),
            "group_relationship" => Ok(Self::GroupRelationship),
            "resource" => Ok(Self::Resource {
                resource_type: None,
            }),
            _ => Err(ValidationError::InvalidFormat {
                field: "scope",
                message: format!("unknown scope '{trimmed}'"),
            }),
        }
    }
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&self.storage_key())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct ScopeVisitor;

        impl<'de> Visitor<'de> for ScopeVisitor {
            type Value = Scope;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a scope string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where E: de::Error {
                Scope::from_str(v).map_err(E::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where E: de::Error {
                Scope::from_str(&v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ScopeVisitor)
    }
}
