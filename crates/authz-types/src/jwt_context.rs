use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::json;
use utoipa::ToSchema;

/// JWT-provided entity context populated from claims or UserInfo.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "orgs": [{ "org_id": "org_123" }],
    "groups": [{ "group_id": "group_456", "org_id": "org_123", "role": "member" }],
    "roles": [{ "role_id": "role_reader", "scope": { "org": { "org_id": "org_123" } } }],
    "orgs_complete": true,
    "groups_complete": true,
    "roles_complete": true,
    "claims_complete": true
}))]
pub struct JwtContext {
    /// Organizations the user belongs to.
    #[serde(default)]
    #[schema(max_items = 500)]
    pub orgs: Vec<OrgMembership>,
    /// Groups the user belongs to.
    #[serde(default)]
    #[schema(max_items = 1000)]
    pub groups: Vec<GroupMembership>,
    /// Role assignments for the user.
    #[serde(default)]
    #[schema(max_items = 500)]
    pub roles: Vec<RoleAssignment>,
    /// Whether organization memberships are complete (not omitted or
    /// truncated).
    #[serde(default = "default_true")]
    #[schema(default = true, example = true)]
    pub orgs_complete: bool,
    /// Whether group memberships are complete (not omitted or truncated).
    #[serde(default = "default_true")]
    #[schema(default = true, example = true)]
    pub groups_complete: bool,
    /// Whether role assignments are complete (not omitted or truncated).
    #[serde(default = "default_true")]
    #[schema(default = true, example = true)]
    pub roles_complete: bool,
    /// Whether this context is complete (not truncated).
    #[serde(default = "default_true")]
    #[schema(default = true, example = true)]
    pub claims_complete: bool,
}

impl Default for JwtContext {
    fn default() -> Self {
        Self {
            orgs: Vec::new(),
            groups: Vec::new(),
            roles: Vec::new(),
            orgs_complete: true,
            groups_complete: true,
            roles_complete: true,
            claims_complete: true,
        }
    }
}

/// User's membership in an organization.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct OrgMembership {
    /// Organization identifier the user belongs to.
    #[schema(min_length = 1, max_length = 58, example = "org_123")]
    pub org_id: String,
}

/// User's membership in a group.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct GroupMembership {
    /// Group identifier the user belongs to.
    #[schema(min_length = 1, max_length = 58, example = "group_456")]
    pub group_id: String,
    /// Organization that owns the group.
    #[schema(min_length = 1, max_length = 58, example = "org_123")]
    pub org_id: String,
    /// Group role is tenant-defined free-form string.
    #[schema(min_length = 1, max_length = 58, example = "member")]
    pub role: String,
}

/// Role assignment for a user.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RoleAssignment {
    /// Role identifier assigned to the subject.
    #[schema(min_length = 1, max_length = 58, example = "role_reader")]
    pub role_id: String,
    /// Scope attached to the role assignment.
    #[schema(example = json!({ "org": { "org_id": "org_123" } }))]
    pub scope: RoleScope,
}

/// Scope of a role assignment.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RoleScope {
    Global,
    Org {
        #[schema(min_length = 1, max_length = 58, example = "org_123")]
        org_id: String,
    },
    Group {
        #[schema(min_length = 1, max_length = 58, example = "group_456")]
        group_id: String,
    },
    Resource {
        #[schema(min_length = 1, max_length = 58, example = "document")]
        resource_type: String,
        #[schema(min_length = 1, max_length = 58, example = "doc_789")]
        resource_id: String,
    },
}

impl JwtContext {
    /// Returns true only when every JWT-derived claim family is complete.
    pub fn is_complete(&self) -> bool {
        self.claims_complete && self.orgs_complete && self.groups_complete && self.roles_complete
    }

    pub fn refresh_claims_complete(&mut self) {
        self.claims_complete = self.orgs_complete && self.groups_complete && self.roles_complete;
    }

    /// Check if user is a member of the specified org.
    pub fn is_org_member(&self, org_id: &str) -> bool {
        self.orgs.iter().any(|m| m.org_id == org_id)
    }

    /// Check if user is a member of the specified group.
    pub fn is_group_member(&self, group_id: &str) -> bool {
        self.groups.iter().any(|m| m.group_id == group_id)
    }

    /// Get all org ids the user belongs to.
    pub fn org_ids(&self) -> Vec<&str> {
        self.orgs.iter().map(|m| m.org_id.as_str()).collect()
    }

    /// Get all group ids the user belongs to.
    pub fn group_ids(&self) -> Vec<&str> {
        self.groups.iter().map(|m| m.group_id.as_str()).collect()
    }
}

fn default_true() -> bool {
    true
}
