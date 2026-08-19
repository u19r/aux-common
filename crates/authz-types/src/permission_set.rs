//! Tenant-owned Permission Set contracts shared by interactive and service
//! authentication.  The set is an authority ceiling; protocol adapters decide
//! how the bounded permission/claim output is rendered.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{PrincipalType, ValidationError, is_structural_claim};

pub const MAX_PERMISSION_SET_ID_BYTES: usize = 128;
pub const MAX_PERMISSION_SET_PERMISSIONS: usize = 256;
pub const MAX_PERMISSION_SET_CLAIMS: usize = 64;
pub const MAX_PERMISSION_SET_CLAIM_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionSetProtocol {
    OAuth,
    Oidc,
    Saml,
    Native,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionSet {
    pub id: String,
    pub revision: u64,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocols: BTreeSet<PermissionSetProtocol>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub claims: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSetAssignment {
    pub application_id: String,
    pub principal_id: String,
    pub principal_type: PrincipalType,
    pub permission_set_id: String,
    pub revision: u64,
    #[serde(default = "default_assignment_active")]
    pub active: bool,
}

/// Errors returned when a protocol adapter resolves a principal's active
/// Permission Set.  Selection is deliberately a pure operation: storage and
/// protocol managers own loading records, while this contract owns the
/// zero/one/many and revision invariants shared by every protocol.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermissionSetSelectionError {
    #[error("no eligible permission set is configured")]
    NoEligibleSet,
    #[error("more than one eligible permission set requires an explicit selection")]
    SelectionRequired,
    #[error("requested permission set is not eligible")]
    IneligibleSelection,
    #[error("permission set assignment is missing or inactive")]
    AssignmentMissing,
    #[error("permission set assignment revision is stale")]
    StaleAssignment,
}

/// Return enabled sets that support the requested principal protocol.
#[must_use]
pub fn eligible_permission_sets(
    sets: &[PermissionSet],
    protocol: PermissionSetProtocol,
) -> Vec<&PermissionSet> {
    sets.iter()
        .filter(|set| set.enabled && set.protocols.contains(&protocol))
        .collect()
}

/// Resolve an interactive selection using the common zero/one/many rule.
pub fn select_interactive_permission_set<'a>(
    sets: &'a [PermissionSet],
    protocol: PermissionSetProtocol,
    requested_id: Option<&str>,
) -> Result<Option<&'a PermissionSet>, PermissionSetSelectionError> {
    let eligible = eligible_permission_sets(sets, protocol);
    if eligible.is_empty() {
        return Err(PermissionSetSelectionError::NoEligibleSet);
    }
    if let Some(requested_id) = requested_id {
        return eligible
            .into_iter()
            .find(|set| set.id == requested_id)
            .map(Some)
            .ok_or(PermissionSetSelectionError::IneligibleSelection);
    }
    match eligible.as_slice() {
        [only] => Ok(Some(*only)),
        _ => Err(PermissionSetSelectionError::SelectionRequired),
    }
}

/// Resolve the one administratively assigned set allowed by a non-interactive
/// client-credentials flow.  The assignment must point at the current set
/// revision; stale assignments fail closed rather than silently broadening
/// service authority.
pub fn select_service_permission_set<'a>(
    sets: &'a [PermissionSet],
    assignment: Option<&PermissionSetAssignment>,
    protocol: PermissionSetProtocol,
    principal_id: &str,
) -> Result<&'a PermissionSet, PermissionSetSelectionError> {
    let assignment = assignment.filter(|assignment| {
        assignment.active
            && assignment.principal_type == PrincipalType::ServicePrincipal
            && assignment.principal_id == principal_id
    });
    let assignment = assignment.ok_or(PermissionSetSelectionError::AssignmentMissing)?;
    let set = sets
        .iter()
        .find(|set| set.id == assignment.permission_set_id && set.enabled)
        .ok_or(PermissionSetSelectionError::IneligibleSelection)?;
    if !set.protocols.contains(&protocol) {
        return Err(PermissionSetSelectionError::IneligibleSelection);
    }
    if set.revision != assignment.revision {
        return Err(PermissionSetSelectionError::StaleAssignment);
    }
    Ok(set)
}

fn default_assignment_active() -> bool {
    true
}

impl PermissionSet {
    /// Render the bounded output owned by this set for one protocol.
    ///
    /// Permission identifiers are emitted as a deterministic `permissions`
    /// array.  Protocol adapters may translate that array into their native
    /// representation (for example SAML multivalue attributes), but they all
    /// start from the same validated claim ownership boundary.
    pub fn render_claims(
        &self,
        protocol: PermissionSetProtocol,
    ) -> Result<BTreeMap<String, Value>, ValidationError> {
        self.validate()?;
        if !self.protocols.contains(&protocol) {
            return Err(ValidationError::InvalidFormat {
                field: "protocol",
                message: format!("permission set does not support {protocol:?}"),
            });
        }

        if let Some(name) = self.claims.keys().find(|name| is_structural_claim(name)) {
            return Err(ValidationError::InvalidFormat {
                field: "claim_name",
                message: format!("{name} is a protected protocol claim"),
            });
        }

        let mut rendered = self.claims.clone();
        if !self.permissions.is_empty() {
            if rendered.contains_key("permissions") {
                return Err(ValidationError::InvalidFormat {
                    field: "permissions",
                    message: "permissions is reserved for the permission identifiers".to_string(),
                });
            }
            rendered.insert(
                "permissions".to_string(),
                Value::Array(
                    self.permissions
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }

        if protocol == PermissionSetProtocol::Saml
            && rendered.values().any(|value| !is_saml_value(value))
        {
            return Err(ValidationError::InvalidFormat {
                field: "claims",
                message: "SAML Permission Set claims must be strings or arrays of strings"
                    .to_string(),
            });
        }
        Ok(rendered)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_identifier(&self.id, "permission_set_id")?;
        if self.revision == 0 {
            return Err(ValidationError::OutOfRange {
                field: "revision",
                message: "must be positive".to_string(),
            });
        }
        if self.permissions.len() > MAX_PERMISSION_SET_PERMISSIONS {
            return Err(ValidationError::LimitExceeded {
                resource: "permission_set_permissions",
                limit: MAX_PERMISSION_SET_PERMISSIONS,
                actual: self.permissions.len(),
            });
        }
        let mut permissions = BTreeSet::new();
        for permission in &self.permissions {
            validate_identifier(permission, "permission")?;
            if !permissions.insert(permission) {
                return Err(ValidationError::DuplicateId(permission.clone()));
            }
        }
        if self.claims.len() > MAX_PERMISSION_SET_CLAIMS {
            return Err(ValidationError::LimitExceeded {
                resource: "permission_set_claims",
                limit: MAX_PERMISSION_SET_CLAIMS,
                actual: self.claims.len(),
            });
        }
        for (name, value) in &self.claims {
            validate_identifier(name, "claim_name")?;
            let bytes = serde_json::to_vec(value).map_err(|_| ValidationError::InvalidFormat {
                field: "claim",
                message: "claim value could not be serialized".to_string(),
            })?;
            if bytes.len() > MAX_PERMISSION_SET_CLAIM_BYTES {
                return Err(ValidationError::OutOfRange {
                    field: "claim",
                    message: format!("value exceeds {MAX_PERMISSION_SET_CLAIM_BYTES} bytes"),
                });
            }
        }
        if self.protocols.is_empty() {
            return Err(ValidationError::RequiredFieldMissing("protocols"));
        }
        Ok(())
    }
}

fn is_saml_value(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(values) => values.iter().all(Value::is_string),
        _ => false,
    }
}

impl PermissionSetAssignment {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_identifier(&self.application_id, "application_id")?;
        validate_identifier(&self.principal_id, "principal_id")?;
        validate_identifier(&self.permission_set_id, "permission_set_id")?;
        if self.revision == 0 {
            return Err(ValidationError::OutOfRange {
                field: "revision",
                message: "must be positive".to_string(),
            });
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.trim().is_empty() || value.len() > MAX_PERMISSION_SET_ID_BYTES {
        return Err(ValidationError::InvalidFormat {
            field,
            message: format!("must be 1..={MAX_PERMISSION_SET_ID_BYTES} bytes"),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidFormat {
            field,
            message: "must not contain control characters".to_string(),
        });
    }
    Ok(())
}
