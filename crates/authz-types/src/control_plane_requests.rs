use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::Scope;

fn deserialize_optional_string_non_null<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where D: Deserializer<'de> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNull {
        String(String),
        Null(()),
    }

    match StringOrNull::deserialize(deserializer)? {
        StringOrNull::String(value) => Ok(Some(value)),
        StringOrNull::Null(()) => Err(serde::de::Error::custom(
            "field must be omitted when unset; null is not allowed",
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "resource_type": {
        "name": "document",
        "description": "Document resources",
        "actions": [{ "name": "read", "description": "Read documents" }]
    }
}))]
pub struct CreateResourceTypeRequest {
    pub resource_type: ResourceTypeByNameInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceTypeByNameInput {
    /// Resource type name.
    #[schema(min_length = 1, max_length = 58, example = "document")]
    pub name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_string_non_null"
    )]
    /// Optional resource type description.
    #[schema(value_type = String, min_length = 1, max_length = 250, example = "Document resources")]
    pub description: Option<String>,
    #[schema(min_items = 1, max_items = 100)]
    pub actions: Vec<ResourceTypeActionByNameInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResourceTypeActionByNameInput {
    /// Action name under the resource type.
    #[schema(min_length = 1, max_length = 58, example = "read")]
    pub name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_string_non_null"
    )]
    /// Optional action description.
    #[schema(value_type = String, min_length = 1, max_length = 250, example = "Read documents")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "role": {
        "name": "document_admin",
        "description": "Administrators for documents",
        "permissions": [{ "permission_name": "document_read", "scopes": ["tenant"] }]
    },
    "description": "Create role document_admin"
}))]
pub struct CreateRoleRequest {
    pub role: RoleByNameInput,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_string_non_null"
    )]
    /// Optional audit/change description for this operation.
    #[schema(value_type = String, min_length = 1, max_length = 250, example = "Create role document_admin")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "role": {
        "name": "document_admin",
        "description": "Updated description",
        "permissions": [{ "permission_name": "document_read", "scopes": ["tenant"] }]
    },
    "description": "Update role document_admin"
}))]
pub struct UpdateRoleRequest {
    pub role: RoleByNameInput,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_string_non_null"
    )]
    /// Optional audit/change description for this operation.
    #[schema(value_type = String, min_length = 1, max_length = 250, example = "Update role document_admin")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleByNameInput {
    /// Role name.
    #[schema(min_length = 1, max_length = 58, example = "document_admin")]
    pub name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_string_non_null"
    )]
    /// Optional role description.
    #[schema(value_type = String, min_length = 1, max_length = 250, example = "Administrators for documents")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 100)]
    pub permissions: Vec<RolePermissionByNameInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500)]
    pub actions: Vec<RoleActionByNameInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500)]
    pub not_actions: Vec<RoleActionByNameInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RolePermissionByNameInput {
    /// Permission name included in this role.
    #[schema(min_length = 1, max_length = 58, example = "document_read")]
    pub permission_name: String,
    #[schema(max_items = 100, example = json!(["tenant"]))]
    pub scopes: Vec<Scope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleActionByNameInput {
    /// Resource type referenced by this action rule.
    #[schema(min_length = 1, max_length = 58, example = "document")]
    pub resource_type: String,
    /// Action name referenced by this action rule.
    #[schema(min_length = 1, max_length = 58, example = "read")]
    pub action_name: String,
    #[schema(max_items = 100, example = json!(["tenant"]))]
    pub scopes: Vec<Scope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "permission": {
        "name": "document_read",
        "description": "Read document resources",
        "actions": [{ "resource_type": "document", "action_name": "read" }]
    },
    "description": "Create permission document_read"
}))]
pub struct CreatePermissionRequest {
    pub permission: PermissionByNameInput,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_string_non_null"
    )]
    /// Optional audit/change description for this operation.
    #[schema(value_type = String, min_length = 1, max_length = 250, example = "Create permission document_read")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PermissionByNameInput {
    /// Permission name.
    #[schema(min_length = 1, max_length = 58, example = "document_read")]
    pub name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_string_non_null"
    )]
    /// Optional permission description.
    #[schema(value_type = String, min_length = 1, max_length = 250, example = "Read document resources")]
    pub description: Option<String>,
    #[schema(min_items = 1, max_items = 500)]
    pub actions: Vec<PermissionActionByNameInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500)]
    pub not_actions: Vec<PermissionActionByNameInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PermissionActionByNameInput {
    /// Resource type referenced by this permission action.
    #[schema(min_length = 1, max_length = 58, example = "document")]
    pub resource_type: String,
    /// Action name referenced by this permission action.
    #[schema(min_length = 1, max_length = 58, example = "read")]
    pub action_name: String,
}
