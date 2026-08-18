use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use authz_types::{EvaluationRequest, JwtContext, RoleScope, Subject};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    AuthzRuntimeError, AuthzRuntimeResult, EffectiveRoleAssignment, ScopeKind,
    TrustedAuthorizationContext, classify_scope,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentRef {
    pub ref_type: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectAccessSnapshot {
    /// Tenant that owns every identity, assignment, relationship, and scope in
    /// this snapshot.
    pub tenant_id: String,
    /// Trusted subject identity and attributes loaded with the access snapshot.
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
    /// Tenant that owns this resource and its relationship snapshot.
    pub tenant_id: String,
    pub resource_type: String,
    pub resource_id: String,
    /// Trusted resource attributes used for authorization and policy
    /// evaluation.
    ///
    /// Request-supplied resource properties are discarded during enrichment.
    /// Callers must put every resource attribute needed by a policy in this
    /// snapshot rather than relying on the lower-trust evaluation request.
    pub properties: Value,
    pub resource_parents: Vec<ParentRef>,
    pub fetched_at_ms: i64,
}

/// Bounds the age and clock skew accepted for authorization snapshots.
///
/// Snapshots contain identity, relationship, and resource attributes that are
/// security decisions. A caller must not be able to replay an old snapshot
/// indefinitely, nor make a future-dated snapshot look fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotFreshnessPolicy {
    max_age: Duration,
    max_future_skew: Duration,
}

impl SnapshotFreshnessPolicy {
    #[must_use]
    pub const fn new(max_age: Duration, max_future_skew: Duration) -> Self {
        Self {
            max_age,
            max_future_skew,
        }
    }

    #[must_use]
    pub const fn max_age(self) -> Duration {
        self.max_age
    }

    #[must_use]
    pub const fn max_future_skew(self) -> Duration {
        self.max_future_skew
    }

    #[cfg(test)]
    pub(crate) const fn for_tests() -> Self {
        Self::new(Duration::from_secs(u64::MAX), Duration::from_secs(u64::MAX))
    }

    fn validate(
        self,
        snapshot: &'static str,
        fetched_at_ms: i64,
        now_ms: i64,
    ) -> AuthzRuntimeResult<()> {
        if fetched_at_ms <= 0 {
            return Err(AuthzRuntimeError::SnapshotTimestampInvalid { snapshot });
        }
        let now_ms = u128::try_from(now_ms).unwrap_or_default();
        let fetched_at_ms = u128::try_from(fetched_at_ms).unwrap_or_default();
        let future_skew_ms = self.max_future_skew.as_millis();
        if fetched_at_ms > now_ms.saturating_add(future_skew_ms) {
            return Err(AuthzRuntimeError::SnapshotTimestampInvalid { snapshot });
        }
        let age_ms = now_ms.saturating_sub(fetched_at_ms);
        if age_ms > self.max_age.as_millis() {
            return Err(AuthzRuntimeError::SnapshotStale { snapshot });
        }
        Ok(())
    }
}

impl Default for SnapshotFreshnessPolicy {
    fn default() -> Self {
        Self::new(Duration::from_secs(300), Duration::from_secs(30))
    }
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
    request: EvaluationRequest,
    trusted_context: &TrustedAuthorizationContext,
    subject_access: &SubjectAccessSnapshot,
    resource_access: &ResourceAccessSnapshot,
) -> AuthzRuntimeResult<EnrichedCedarRequest> {
    enrich_request_with_snapshots_at(
        tenant_id,
        request,
        trusted_context,
        subject_access,
        resource_access,
        Utc::now(),
        SnapshotFreshnessPolicy::default(),
    )
}

pub fn enrich_request_with_snapshots_at(
    tenant_id: &str,
    mut request: EvaluationRequest,
    trusted_context: &TrustedAuthorizationContext,
    subject_access: &SubjectAccessSnapshot,
    resource_access: &ResourceAccessSnapshot,
    now: DateTime<Utc>,
    freshness: SnapshotFreshnessPolicy,
) -> AuthzRuntimeResult<EnrichedCedarRequest> {
    if !trusted_context.matches_subject(&request.subject) {
        return Err(AuthzRuntimeError::TrustedContextSubjectMismatch);
    }
    // The wire-shaped request is not an authentication boundary. Replace all
    // credential-bearing fields before any role, session, or token-derived
    // enrichment so this helper is safe for direct callers as well as the
    // local evaluator.
    request.jwt_context = trusted_context.jwt_context().cloned();
    request.session_context = trusted_context.session_context().cloned();
    request.token_context = trusted_context.token_context().cloned();

    if subject_access.tenant_id != tenant_id || resource_access.tenant_id != tenant_id {
        return Err(AuthzRuntimeError::TenantSnapshotMismatch);
    }
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
    let now_ms = now.timestamp_millis();
    freshness.validate("subject", subject_access.fetched_at_ms, now_ms)?;
    freshness.validate("resource", resource_access.fetched_at_ms, now_ms)?;

    let mut subject_parents = subject_access.subject_parents.clone();
    let mut resource_parents = resource_access.resource_parents.clone();
    let mut has_resource_scoped_assignment = subject_access
        .resource_scopes
        .get(request.resource.resource_type.as_str())
        .is_some_and(|resource_ids| resource_ids.contains(request.resource.id.as_str()));

    if let Some(jwt_ctx) = request.jwt_context.as_ref()
        && jwt_ctx.is_complete()
    {
        add_jwt_role_parents(
            jwt_ctx,
            &request,
            &resource_access.properties,
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
    // The request carries the caller's presentation of the subject/resource.
    // Snapshot attributes are the authority for policy and scope decisions;
    // retaining request properties here would let a caller forge org,
    // ownership, sharing, group, or public-read state.
    let mut subject_props = subject_access
        .subject
        .properties
        .clone()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let mut resource_props = resource_access.properties.clone();

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
    resource_properties: &Value,
    tenant_id: &str,
    subject_parents: &mut Vec<ParentRef>,
    has_resource_scoped_assignment: &mut bool,
) {
    for role in &jwt_ctx.roles {
        if !jwt_role_scope_applies(&role.scope, request, resource_properties) {
            continue;
        }
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

fn jwt_role_scope_applies(
    scope: &RoleScope,
    request: &EvaluationRequest,
    resource_properties: &Value,
) -> bool {
    match scope {
        RoleScope::Global => true,
        RoleScope::Org { org_id } => {
            resource_properties
                .as_object()
                .and_then(|properties| properties.get("org_id"))
                .and_then(Value::as_str)
                == Some(org_id.as_str())
        }
        RoleScope::Resource {
            resource_type,
            resource_id,
        } => {
            resource_type == &request.resource.resource_type && resource_id == &request.resource.id
        }
        RoleScope::Group { .. } => false,
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
        map.insert("org_id".to_string(), Value::String(org_parent.id.clone()));
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
