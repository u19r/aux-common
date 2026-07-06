use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::Scope;

/// Known resource properties used by authorization scope evaluation.
///
/// The HTTP API still accepts this as an object under `resource.properties`,
/// but known fields are documented explicitly so SDKs and customers do not
/// need to infer the shape from arbitrary JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default)]
#[schema(example = json!({
    "owner_org_id": "org_123",
    "owner_group_id": "group_456",
    "owner_user_id": "user_789",
    "resource_org_id": "org_123",
    "resource_group_id": "group_456",
    "resource_owner_id": "user_789"
}))]
pub struct EvaluationProperties {
    /// Organization that owns the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = "org_123")]
    pub owner_org_id: Option<String>,

    /// Group that owns the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = "group_456")]
    pub owner_group_id: Option<String>,

    /// User that owns the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = "user_789")]
    pub owner_user_id: Option<String>,

    /// Organization associated with the concrete resource instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = "org_123")]
    pub resource_org_id: Option<String>,

    /// Group associated with the concrete resource instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = "group_456")]
    pub resource_group_id: Option<String>,

    /// User associated with the concrete resource instance.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true, example = "user_789")]
    pub resource_owner_id: Option<String>,
}

impl EvaluationProperties {
    #[must_use]
    pub fn has_org_scope_property(&self) -> bool {
        self.owner_org_id.is_some() || self.resource_org_id.is_some()
    }

    #[must_use]
    pub fn has_group_scope_property(&self) -> bool {
        self.owner_group_id.is_some() || self.resource_group_id.is_some()
    }

    #[must_use]
    pub fn has_owner_scope_property(&self) -> bool {
        self.owner_user_id.is_some() || self.resource_owner_id.is_some()
    }

    #[must_use]
    pub fn satisfies_scope(&self, scope: &Scope) -> bool {
        match scope {
            Scope::Org | Scope::OrgRelationship => self.has_org_scope_property(),
            Scope::Group | Scope::GroupRelationship => self.has_group_scope_property(),
            Scope::Own => self.has_owner_scope_property(),
            Scope::Tenant | Scope::Shared | Scope::Public | Scope::Resource { .. } => true,
        }
    }

    #[must_use]
    pub fn missing_scope_field_code(scope: &Scope) -> Option<&'static str> {
        match scope {
            Scope::Org | Scope::OrgRelationship => Some("authz_owner_org_id_missing"),
            Scope::Group | Scope::GroupRelationship => Some("authz_owner_group_id_missing"),
            Scope::Own => Some("authz_owner_user_id_missing"),
            Scope::Tenant | Scope::Shared | Scope::Public | Scope::Resource { .. } => None,
        }
    }
}
