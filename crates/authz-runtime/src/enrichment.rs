use std::collections::{HashMap, HashSet};

use authz_types::{EvaluationRequest, JwtContext, RoleScope, Subject};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    AuthzRuntimeError, AuthzRuntimeResult, EffectiveRoleAssignment, ScopeKind, classify_scope,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentRef {
    pub ref_type: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectAccessSnapshot {
    pub subject: Subject,
    pub assignments: Vec<EffectiveRoleAssignment>,
    pub subject_parents: Vec<ParentRef>,
    pub resource_scopes: HashMap<String, HashSet<String>>,
    pub fetched_at_ms: i64,
}

impl SubjectAccessSnapshot {
    pub fn active_assignments_at(&self, now: DateTime<Utc>) -> Vec<EffectiveRoleAssignment> {
        self.assignments
            .iter()
            .filter(|assignment| assignment.is_active_at(now))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAccessSnapshot {
    pub resource_type: String,
    pub resource_id: String,
    pub resource_parents: Vec<ParentRef>,
    pub fetched_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct EnrichedCedarRequest {
    pub request: EvaluationRequest,
    pub subject_parents: Vec<ParentRef>,
    pub resource_parents: Vec<ParentRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectParentTemplate {
    pub parents: Vec<ParentRef>,
    pub resource_scopes: HashMap<String, HashSet<String>>,
}

pub fn build_subject_parent_template(
    assignments: &[EffectiveRoleAssignment],
    relationship_parents: &[ParentRef],
    tenant_id: &str,
) -> SubjectParentTemplate {
    let mut parents = Vec::with_capacity(
        assignments
            .len()
            .saturating_mul(2)
            .saturating_add(relationship_parents.len()),
    );
    let mut resource_scopes: HashMap<String, HashSet<String>> = HashMap::new();

    for assignment in assignments {
        parents.push(ParentRef {
            ref_type: "role".to_string(),
            id: assignment.role_id.clone(),
        });
        if let Some(scope_type) = assignment.scope_type.as_deref() {
            match classify_scope(scope_type) {
                ScopeKind::Resource {
                    resource_type: Some(scope_resource_type),
                } => {
                    if let Some(scope_id) = assignment.scope_id.as_deref() {
                        resource_scopes
                            .entry(scope_resource_type.to_string())
                            .or_default()
                            .insert(scope_id.to_string());
                    }
                }
                ScopeKind::Org => {
                    if let Some(scope_id) = assignment.scope_id.as_deref() {
                        parents.push(ParentRef {
                            ref_type: "org".to_string(),
                            id: scope_id.to_string(),
                        });
                    }
                }
                ScopeKind::Group => {
                    if let Some(scope_id) = assignment.scope_id.as_deref() {
                        parents.push(ParentRef {
                            ref_type: "group".to_string(),
                            id: scope_id.to_string(),
                        });
                    }
                }
                ScopeKind::Tenant => {
                    parents.push(ParentRef {
                        ref_type: "tenant".to_string(),
                        id: tenant_id.to_string(),
                    });
                }
                ScopeKind::Resource {
                    resource_type: None,
                }
                | ScopeKind::Other => {}
            }
        }
    }

    parents.extend(relationship_parents.iter().cloned());
    dedupe_parents(&mut parents);
    SubjectParentTemplate {
        parents,
        resource_scopes,
    }
}

pub fn enrich_request_with_snapshots(
    tenant_id: &str,
    mut request: EvaluationRequest,
    subject_access: &SubjectAccessSnapshot,
    resource_access: &ResourceAccessSnapshot,
) -> AuthzRuntimeResult<EnrichedCedarRequest> {
    if request.subject.subject_type != subject_access.subject.subject_type
        || request.subject.id != subject_access.subject.id
    {
        return Err(AuthzRuntimeError::SubjectSnapshotMismatch);
    }
    if request.resource.resource_type != resource_access.resource_type
        || request.resource.id != resource_access.resource_id
    {
        return Err(AuthzRuntimeError::ResourceSnapshotMismatch);
    }

    let mut subject_parents = subject_access.subject_parents.clone();
    let mut resource_parents = resource_access.resource_parents.clone();
    let mut has_resource_scoped_assignment = subject_access
        .resource_scopes
        .get(request.resource.resource_type.as_str())
        .is_some_and(|resource_ids| resource_ids.contains(request.resource.id.as_str()));

    if let Some(jwt_ctx) = request.jwt_context.as_ref() {
        add_jwt_role_parents(
            jwt_ctx,
            &request,
            tenant_id,
            &mut subject_parents,
            &mut has_resource_scoped_assignment,
        );
    }

    dedupe_parents(&mut subject_parents);
    dedupe_parents(&mut resource_parents);

    let enriched_context = request
        .context
        .take()
        .map(|context| context.attributes)
        .unwrap_or_else(|| Value::Object(Map::new()));
    let mut subject_props = request
        .subject
        .properties
        .take()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let mut resource_props = request
        .resource
        .properties
        .take()
        .unwrap_or_else(|| Value::Object(Map::new()));

    inject_org_parent_property(&subject_parents, &mut subject_props);
    inject_org_parent_property(&resource_parents, &mut resource_props);

    if has_resource_scoped_assignment
        && let (Value::Object(subject_map), Value::Object(resource_map)) =
            (&mut subject_props, &resource_props)
        && !subject_map.contains_key("org_id")
        && let Some(org_value) = resource_map.get("org_id").cloned()
    {
        subject_map.insert("org_id".to_string(), org_value);
    }

    request.subject.properties = Some(subject_props);
    request.resource.properties = Some(resource_props);
    request.context = Some(authz_types::Context {
        attributes: enriched_context,
    });

    Ok(EnrichedCedarRequest {
        request,
        subject_parents,
        resource_parents,
    })
}

fn add_jwt_role_parents(
    jwt_ctx: &JwtContext,
    request: &EvaluationRequest,
    tenant_id: &str,
    subject_parents: &mut Vec<ParentRef>,
    has_resource_scoped_assignment: &mut bool,
) {
    for role in &jwt_ctx.roles {
        subject_parents.push(ParentRef {
            ref_type: "role".to_string(),
            id: role.role_id.clone(),
        });

        match &role.scope {
            RoleScope::Global => {
                subject_parents.push(ParentRef {
                    ref_type: "tenant".to_string(),
                    id: tenant_id.to_string(),
                });
            }
            RoleScope::Org { org_id } => {
                subject_parents.push(ParentRef {
                    ref_type: "org".to_string(),
                    id: org_id.clone(),
                });
            }
            RoleScope::Resource {
                resource_type,
                resource_id,
            } => {
                if resource_type == &request.resource.resource_type
                    && resource_id == &request.resource.id
                {
                    *has_resource_scoped_assignment = true;
                }
            }
            RoleScope::Group { .. } => {}
        }
    }
}

fn inject_org_parent_property(parents: &[ParentRef], properties: &mut Value) {
    let Some(org_parent) = parents
        .iter()
        .find(|parent| parent.ref_type.eq_ignore_ascii_case("org"))
    else {
        return;
    };
    if let Value::Object(map) = properties {
        map.entry("org_id".to_string())
            .or_insert(Value::String(org_parent.id.clone()));
    }
}

fn dedupe_parents(parents: &mut Vec<ParentRef>) {
    if parents.len() < 2 {
        return;
    }

    parents.sort_unstable_by(|left, right| {
        left.ref_type
            .cmp(&right.ref_type)
            .then(left.id.cmp(&right.id))
    });
    parents.dedup_by(|left, right| left.ref_type == right.ref_type && left.id == right.id);
}
