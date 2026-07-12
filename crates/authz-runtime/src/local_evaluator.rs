use std::{collections::BTreeSet, sync::Arc};

use authz_cedar::{
    CedarEvaluationErrorCategory, EntityParentRef as CedarEntityParentRef,
    evaluate_prepared_with_policy_sets_diagnostics as cedar_evaluate_prepared_with_policy_sets_diagnostics,
    prepare_evaluation_owned_with_parents as cedar_prepare_evaluation_owned_with_parents,
};
use authz_types::{
    CONTEXT_INTERNAL_KEY, DecisionContext, EvaluationRequest, EvaluationResponse,
    ResourceSelection, RoleScope, SessionContext, TokenContext, TokenScopeType,
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use crate::{
    AuthzRuntimeError, AuthzRuntimeResult, EffectiveRoleAssignment, EvaluationRuntime, ParentRef,
    PermissionBits, RoleBits, ScopedPermissionBits, StepUpEvaluator, StepUpResult,
    SubjectAccessSnapshot, enrich_request_with_snapshots, role_assignment_covers_resource,
};

#[derive(Debug, Clone)]
pub struct LocalAuthzEvaluator {
    runtime: Arc<EvaluationRuntime>,
}

impl LocalAuthzEvaluator {
    pub fn new(runtime: EvaluationRuntime) -> Self {
        Self {
            runtime: Arc::new(runtime),
        }
    }

    pub fn from_arc(runtime: Arc<EvaluationRuntime>) -> Self {
        Self { runtime }
    }

    pub fn runtime(&self) -> &EvaluationRuntime {
        &self.runtime
    }

    pub fn evaluate(&self, input: LocalEvaluationInput) -> AuthzRuntimeResult<EvaluationResponse> {
        self.evaluate_at(input, Utc::now())
    }

    pub fn evaluate_at(
        &self,
        input: LocalEvaluationInput,
        now: DateTime<Utc>,
    ) -> AuthzRuntimeResult<EvaluationResponse> {
        let token_ctx = input.request.token_context.as_ref();
        let session_ctx = input.request.session_context.as_ref();
        let assignments = input.subject_access.active_assignments_at(now);
        let scoped = permissions_for_request_bits(
            &self.runtime,
            &assignments,
            &input.request,
            &input.request.subject,
        );
        let checked_roles = self.runtime.role_ids_sorted(&scoped.checked_roles);

        let effective_permissions = if let Some(token_ctx) = token_ctx {
            let resolved =
                self.runtime
                    .resolve_token_permissions_at(&scoped.permissions, token_ctx, now);
            if !resolved.is_valid {
                let reason = resolved
                    .invalid_reason
                    .as_deref()
                    .unwrap_or("Token invalid");
                return Ok(with_checked_roles(
                    EvaluationResponse::deny_with_reason(reason),
                    &checked_roles,
                ));
            }

            if token_selected_resource_mismatch(token_ctx, &input.request) {
                return Ok(with_checked_roles(
                    EvaluationResponse::deny_with_reason("token_resource_scope"),
                    &checked_roles,
                ));
            }

            let token_decision = action_policy_decision_bits(
                &self.runtime,
                &input.request.resource.resource_type,
                &input.request.action.name,
                &resolved.permissions,
                &scoped.checked_roles,
                false,
            );
            if !matches!(token_decision, ActionPolicyDecision::AllowMatched) {
                return Ok(with_checked_roles(
                    EvaluationResponse::deny_with_reason("token_permission_ceiling"),
                    &checked_roles,
                ));
            }

            resolved.permissions
        } else {
            scoped.permissions
        };

        if let Some(token_ctx) = token_ctx
            && let Some(org_id) = token_ctx.scopes.org_id.as_deref()
        {
            let resource_org = resource_org(&input.request).unwrap_or_default();
            if resource_org != org_id
                || !token_owner_has_org(&assignments, &token_ctx.owner_id, org_id)
            {
                return Ok(with_checked_roles(
                    EvaluationResponse::deny_with_reason("token_org_mismatch"),
                    &checked_roles,
                ));
            }
        }

        let action_policy_decision = action_policy_decision_bits(
            &self.runtime,
            &input.request.resource.resource_type,
            &input.request.action.name,
            &effective_permissions,
            &scoped.checked_roles,
            token_ctx.is_none(),
        );

        if token_ctx.is_some()
            && !matches!(action_policy_decision, ActionPolicyDecision::AllowMatched)
        {
            return Ok(with_checked_roles(
                EvaluationResponse::deny_with_reason("token_permission_ceiling"),
                &checked_roles,
            ));
        }

        if !matches!(action_policy_decision, ActionPolicyDecision::AllowMatched)
            && !public_read_is_declared(&self.runtime, &input.request)
        {
            let reason = if matches!(action_policy_decision, ActionPolicyDecision::DenyMatched) {
                "deny_matched"
            } else {
                "no_policy_allow"
            };
            return Ok(with_checked_roles(
                EvaluationResponse::deny_with_reason(reason),
                &checked_roles,
            ));
        }

        if let Some(step_up_response) = step_up_response_for_allowed_request(
            &self.runtime,
            &input.request.resource.resource_type,
            &input.request.action.name,
            session_ctx,
            token_ctx.is_some(),
            now,
        ) {
            return Ok(step_up_response);
        }

        let internal_ctx = build_internal_context_at(
            &self.runtime,
            &input.request,
            &effective_permissions,
            token_ctx,
            &assignments,
            session_ctx,
            now,
        );
        let mut enriched = enrich_request_with_snapshots(
            &input.tenant_id,
            input.request,
            &input.subject_access,
            &input.resource_access,
        )?;
        inject_internal_context(&mut enriched.request, internal_ctx);

        let resource_type = enriched.request.resource.resource_type.clone();
        let action_name = enriched.request.action.name.clone();
        let subject_parents = to_cedar_parent_refs(&enriched.subject_parents);
        let resource_parents = to_cedar_parent_refs(&enriched.resource_parents);
        let prepared = cedar_prepare_evaluation_owned_with_parents(
            enriched.request,
            &subject_parents,
            &resource_parents,
        )
        .map_err(AuthzRuntimeError::cedar)?;
        let diagnostic_result = cedar_evaluate_prepared_with_policy_sets_diagnostics(
            &self.runtime.policy_sets,
            prepared,
        )
        .map_err(AuthzRuntimeError::cedar)?;
        if !diagnostic_result.evaluation_errors.is_empty() {
            record_cedar_diagnostics(
                &resource_type,
                &action_name,
                self.runtime.config.version,
                diagnostic_result.determining_policy_ids.len(),
                &diagnostic_result.evaluation_errors,
            );
        }
        let mut response = diagnostic_result.response;

        if response.decision {
            response.context = Some(DecisionContext {
                reason: None,
                effective_permission: best_permission_for_action_with_bits(
                    &self.runtime,
                    &resource_type,
                    &action_name,
                    &effective_permissions,
                ),
                policy_version: None,
                checked_roles: Some(checked_roles),
                acr_values: None,
            });
        } else {
            response = with_checked_roles(response, &checked_roles);
        }

        Ok(response)
    }
}

pub(crate) fn record_cedar_diagnostics(
    resource_type: &str,
    action: &str,
    policy_version: u32,
    determining_policy_count: usize,
    errors: &[CedarEvaluationErrorCategory],
) {
    tracing::warn!(
        resource_type,
        action,
        policy_version,
        determining_policy_count,
        evaluation_error_count = errors.len(),
        evaluation_error_categories = ?errors,
        "Cedar policy evaluation completed with skipped policy errors"
    );
    for category in errors {
        metrics_facade::counter!(
            metrics_facade::CounterMetric::AuthzCedarEvaluationErrorsTotal,
            "category" => category.as_str(),
        )
        .increment(1);
    }
}

#[derive(Debug, Clone)]
pub struct LocalEvaluationInput {
    pub tenant_id: String,
    pub request: EvaluationRequest,
    pub subject_access: SubjectAccessSnapshot,
    pub resource_access: crate::ResourceAccessSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionPolicyDecision {
    DenyMatched,
    AllowMatched,
    NoPolicyAllow,
}

pub fn permissions_for_request_bits(
    runtime: &EvaluationRuntime,
    assignments: &[EffectiveRoleAssignment],
    request: &EvaluationRequest,
    subject: &authz_types::Subject,
) -> ScopedPermissionBits {
    let resource_org = resource_org(request);
    let mut permissions = PermissionBits::default();
    let mut checked_roles = RoleBits::default();

    for role_assignment in assignments {
        let Some(role_idx) = runtime.role_idx(role_assignment.role_id.as_str()) else {
            continue;
        };
        if !role_assignment_covers_resource(
            role_assignment,
            &request.resource.resource_type,
            &request.resource.id,
            resource_org,
        ) {
            continue;
        }

        checked_roles.set(role_idx);
        if let Some(role_permissions) = runtime.role_permissions(role_idx) {
            permissions.union_with(role_permissions);
        }
    }

    if matches!(subject.subject_type, authz_types::SubjectType::Role)
        && let Some(role_idx) = runtime.role_idx(subject.id.as_str())
    {
        checked_roles.set(role_idx);
        if let Some(role_permissions) = runtime.role_permissions(role_idx) {
            permissions.union_with(role_permissions);
        }
    }

    if let Some(jwt_ctx) = request.jwt_context.as_ref()
        && jwt_ctx.is_complete()
    {
        add_jwt_roles_bits(
            runtime,
            jwt_ctx,
            request,
            resource_org,
            &mut permissions,
            &mut checked_roles,
        );
    }

    ScopedPermissionBits {
        permissions,
        checked_roles,
    }
}

pub fn action_policy_decision_bits(
    runtime: &EvaluationRuntime,
    resource_type: &str,
    action: &str,
    permissions: &PermissionBits,
    checked_roles: &RoleBits,
    include_role_actions: bool,
) -> ActionPolicyDecision {
    let Some(action_masks) = runtime.action_masks(resource_type, action) else {
        return ActionPolicyDecision::NoPolicyAllow;
    };

    if permissions.any_intersection(&action_masks.permission_deny) {
        return ActionPolicyDecision::DenyMatched;
    }

    if include_role_actions && checked_roles.any_intersection(&action_masks.role_deny) {
        return ActionPolicyDecision::DenyMatched;
    }

    if permissions.any_intersection(&action_masks.permission_allow) {
        return ActionPolicyDecision::AllowMatched;
    }

    if include_role_actions && checked_roles.any_intersection(&action_masks.role_allow) {
        return ActionPolicyDecision::AllowMatched;
    }

    ActionPolicyDecision::NoPolicyAllow
}

pub fn best_permission_for_action_with_bits(
    runtime: &EvaluationRuntime,
    resource_type: &str,
    action: &str,
    permissions: &PermissionBits,
) -> Option<String> {
    let action_masks = runtime.action_masks(resource_type, action)?;

    let mut best_idx: Option<usize> = None;
    let mut best_score = 0usize;
    let mut best_id: Option<&str> = None;
    permissions.for_each_set_bit(|idx| {
        if !action_masks.permission_allow.contains(idx)
            || action_masks.permission_deny.contains(idx)
        {
            return;
        }
        let Some(candidate_id) = runtime.permission_id(idx) else {
            return;
        };
        let candidate_score = runtime.permission_action_score(idx).unwrap_or(0);
        let should_replace = match (best_idx, best_id) {
            (None, _) => true,
            (Some(_), Some(current_id)) => {
                candidate_score > best_score
                    || (candidate_score == best_score && candidate_id < current_id)
            }
            (Some(_), None) => true,
        };
        if should_replace {
            best_idx = Some(idx);
            best_score = candidate_score;
            best_id = Some(candidate_id);
        }
    });

    best_idx.and_then(|idx| runtime.permission_id(idx).map(ToString::to_string))
}

pub fn build_internal_context_at(
    runtime: &EvaluationRuntime,
    request: &EvaluationRequest,
    effective_permissions: &PermissionBits,
    token_ctx: Option<&TokenContext>,
    assignments: &[EffectiveRoleAssignment],
    session_ctx: Option<&SessionContext>,
    now: DateTime<Utc>,
) -> Value {
    let token_present = token_ctx.is_some();
    let token_valid = token_ctx
        .map(|token| token_is_valid_at(token, now))
        .unwrap_or(true);
    let token_org_id = token_ctx.and_then(|ctx| ctx.scopes.org_id.clone());
    let token_org_id_present = token_org_id.is_some();
    let token_owner_org_ids = token_ctx
        .map(|ctx| token_owner_org_ids_sorted(assignments, &ctx.owner_id))
        .unwrap_or_default();
    let allowed_actions = if token_present {
        allowed_actions_for_resource_bits(
            runtime,
            &request.resource.resource_type,
            effective_permissions,
        )
    } else {
        Vec::new()
    };

    let (token_resource_filter_enabled, token_resource_filter) =
        token_resource_filter(request, token_ctx);
    let resource_scopes = resource_scopes(assignments, request);
    let session = session_context_values(session_ctx, now);

    let mut authz_map = Map::new();
    authz_map.insert("token_present".into(), Value::Bool(token_present));
    authz_map.insert("token_valid".into(), Value::Bool(token_valid));
    authz_map.insert(
        "token_resource_filter_enabled".into(),
        Value::Bool(token_resource_filter_enabled),
    );
    authz_map.insert(
        "token_resource_filter".into(),
        Value::Array(token_resource_filter),
    );
    authz_map.insert("resource_scopes".into(), Value::Array(resource_scopes));
    authz_map.insert(
        "token_org_id_present".into(),
        Value::Bool(token_org_id_present),
    );
    authz_map.insert(
        "token_org_id".into(),
        Value::String(token_org_id.unwrap_or_default()),
    );
    authz_map.insert(
        "token_owner_org_ids".into(),
        Value::Array(token_owner_org_ids.into_iter().map(Value::String).collect()),
    );
    authz_map.insert(
        "allowed_actions".into(),
        Value::Array(allowed_actions.into_iter().map(Value::String).collect()),
    );
    authz_map.insert("session_present".into(), Value::Bool(session.present));
    authz_map.insert(
        "session_acr".into(),
        Value::Number(serde_json::Number::from(session.acr)),
    );
    authz_map.insert(
        "session_amr".into(),
        Value::Array(session.amr.into_iter().map(Value::String).collect()),
    );
    authz_map.insert(
        "session_auth_age_present".into(),
        Value::Bool(session.auth_age_present),
    );
    authz_map.insert(
        "session_auth_age_seconds".into(),
        Value::Number(serde_json::Number::from(session.auth_age_seconds)),
    );
    authz_map.insert(
        "session_mfa_age_present".into(),
        Value::Bool(session.mfa_age_present),
    );
    authz_map.insert(
        "session_mfa_age_seconds".into(),
        Value::Number(serde_json::Number::from(session.mfa_age_seconds)),
    );

    Value::Object(authz_map)
}

pub fn inject_internal_context(request: &mut EvaluationRequest, internal: Value) {
    let mut attributes = request
        .context
        .take()
        .map(|context| context.attributes)
        .unwrap_or_else(|| Value::Object(Map::new()));
    match attributes {
        Value::Object(ref mut map) => {
            map.insert(CONTEXT_INTERNAL_KEY.to_string(), internal);
        }
        _ => {
            let mut map = Map::new();
            map.insert(CONTEXT_INTERNAL_KEY.to_string(), internal);
            attributes = Value::Object(map);
        }
    }

    request.context = Some(authz_types::Context { attributes });
}

fn add_jwt_roles_bits(
    runtime: &EvaluationRuntime,
    jwt_ctx: &authz_types::JwtContext,
    request: &EvaluationRequest,
    resource_org: Option<&str>,
    permissions: &mut PermissionBits,
    checked_roles: &mut RoleBits,
) {
    for role_assignment in &jwt_ctx.roles {
        let Some(role_idx) = runtime.role_idx(role_assignment.role_id.as_str()) else {
            continue;
        };
        if !platform_role_covers_resource(&role_assignment.scope, request, resource_org) {
            continue;
        }

        checked_roles.set(role_idx);
        if let Some(role_permissions) = runtime.role_permissions(role_idx) {
            permissions.union_with(role_permissions);
        }
    }
}

fn platform_role_covers_resource(
    scope: &RoleScope,
    request: &EvaluationRequest,
    resource_org: Option<&str>,
) -> bool {
    match scope {
        RoleScope::Global => true,
        RoleScope::Org { org_id } => resource_org == Some(org_id.as_str()),
        RoleScope::Resource {
            resource_type,
            resource_id,
        } => {
            resource_type == &request.resource.resource_type && resource_id == &request.resource.id
        }
        RoleScope::Group { .. } => false,
    }
}

fn token_selected_resource_mismatch(token_ctx: &TokenContext, request: &EvaluationRequest) -> bool {
    matches!(token_ctx.scopes.scope_type, TokenScopeType::FineGrained)
        && token_ctx.scopes.fine_grained.as_ref().is_some_and(|fine| {
            matches!(fine.resource_selection, ResourceSelection::Selected)
                && !fine.selected_resources.contains(&request.resource.id)
        })
}

fn resource_org(request: &EvaluationRequest) -> Option<&str> {
    request
        .context
        .as_ref()
        .and_then(|context| context.attributes.get("org_id"))
        .and_then(Value::as_str)
        .or_else(|| {
            request
                .resource
                .properties
                .as_ref()
                .and_then(|properties| properties.get("org_id"))
                .and_then(Value::as_str)
        })
}

fn public_read_is_declared(runtime: &EvaluationRuntime, request: &EvaluationRequest) -> bool {
    if request.action.name != "read" {
        return false;
    }
    let Some(resource_type) = runtime
        .config
        .get_resource_type(&request.resource.resource_type)
    else {
        return false;
    };
    if !resource_type
        .actions
        .iter()
        .any(|action| action.name == request.action.name)
    {
        return false;
    }

    request
        .resource
        .properties
        .as_ref()
        .and_then(|properties| properties.get("is_public"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn step_up_response_for_allowed_request(
    runtime: &EvaluationRuntime,
    resource_type: &str,
    action: &str,
    session_ctx: Option<&SessionContext>,
    is_api_key: bool,
    now: DateTime<Utc>,
) -> Option<EvaluationResponse> {
    let step_up = StepUpEvaluator::new(
        &runtime.config.step_up_rules,
        &runtime.config.step_up_config,
        runtime.config.default_step_up_rule.as_deref(),
    );
    match step_up.evaluate_at(
        resource_type,
        action,
        session_ctx,
        is_api_key,
        now.timestamp(),
    ) {
        StepUpResult::Satisfied => None,
        StepUpResult::ChallengeRequired(challenge) => {
            let reason = format!("step_up:{}", challenge.challenge_type.as_str());
            Some(EvaluationResponse::deny_with_challenge(reason, challenge))
        }
    }
}

fn with_checked_roles(
    mut response: EvaluationResponse,
    checked_roles: &[String],
) -> EvaluationResponse {
    if let Some(context) = response.context.as_mut() {
        context.checked_roles = Some(checked_roles.to_vec());
    }
    response
}

fn to_cedar_parent_refs(parents: &[ParentRef]) -> Vec<CedarEntityParentRef> {
    parents
        .iter()
        .map(|parent| CedarEntityParentRef {
            parent_type: parent.ref_type.clone(),
            parent_id: parent.id.clone(),
        })
        .collect()
}

fn token_is_valid_at(token_ctx: &TokenContext, now: DateTime<Utc>) -> bool {
    if token_ctx
        .expires_at
        .is_some_and(|expires_at| expires_at < now.timestamp())
    {
        return false;
    }

    if matches!(token_ctx.scopes.scope_type, TokenScopeType::FineGrained)
        && token_ctx.scopes.fine_grained.is_none()
    {
        return false;
    }

    true
}

fn token_owner_has_org(
    assignments: &[EffectiveRoleAssignment],
    owner_id: &str,
    org_id: &str,
) -> bool {
    assignments.iter().any(|assignment| {
        assignment.principal_id.as_deref() == Some(owner_id)
            && matches!(
                assignment.scope_type.as_deref().map(crate::classify_scope),
                Some(crate::ScopeKind::Org)
            )
            && assignment.scope_id.as_deref() == Some(org_id)
    })
}

fn token_owner_org_ids_sorted(
    assignments: &[EffectiveRoleAssignment],
    owner_id: &str,
) -> Vec<String> {
    let mut org_ids = assignments
        .iter()
        .filter(|assignment| assignment.principal_id.as_deref() == Some(owner_id))
        .filter_map(|assignment| {
            if matches!(
                assignment.scope_type.as_deref().map(crate::classify_scope),
                Some(crate::ScopeKind::Org)
            ) {
                return assignment.scope_id.clone();
            }
            None
        })
        .collect::<Vec<_>>();
    org_ids.sort();
    org_ids.dedup();
    org_ids
}

fn allowed_actions_for_resource_bits(
    runtime: &EvaluationRuntime,
    resource_type: &str,
    permissions: &PermissionBits,
) -> Vec<String> {
    let Some(action_map) = runtime.actions_for_resource(resource_type) else {
        return Vec::new();
    };

    let mut allowed = Vec::new();
    for (action, masks) in action_map {
        if !permissions.any_intersection(&masks.permission_allow) {
            continue;
        }
        if permissions.any_intersection(&masks.permission_deny) {
            continue;
        }
        allowed.push(format!("{resource_type}:{action}"));
    }
    allowed.sort();
    allowed
}

fn token_resource_filter(
    request: &EvaluationRequest,
    token_ctx: Option<&TokenContext>,
) -> (bool, Vec<Value>) {
    let Some(token_ctx) = token_ctx else {
        return (false, Vec::new());
    };
    let Some(fine_grained) = token_ctx.scopes.fine_grained.as_ref() else {
        return (false, Vec::new());
    };
    if !matches!(fine_grained.resource_selection, ResourceSelection::Selected) {
        return (false, Vec::new());
    }

    let entity_type = format!(
        "Authz::{}",
        cedar_resource_entity_type(&request.resource.resource_type)
    );
    let filter = fine_grained
        .selected_resources
        .iter()
        .map(|id| serde_json::json!({ "__entity": { "type": entity_type, "id": id } }))
        .collect();
    (true, filter)
}

fn resource_scopes(
    assignments: &[EffectiveRoleAssignment],
    request: &EvaluationRequest,
) -> Vec<Value> {
    let mut resource_scopes_set: BTreeSet<(String, String, String)> = BTreeSet::new();
    for assignment in assignments {
        let Some(scope_type) = &assignment.scope_type else {
            continue;
        };
        let crate::ScopeKind::Resource {
            resource_type: Some(scope_resource_type),
        } = crate::classify_scope(scope_type)
        else {
            continue;
        };
        if !scope_resource_type.eq_ignore_ascii_case(request.resource.resource_type.as_str()) {
            continue;
        }
        let Some(scope_id) = &assignment.scope_id else {
            continue;
        };
        resource_scopes_set.insert((
            assignment.role_id.clone(),
            request.resource.resource_type.clone(),
            scope_id.clone(),
        ));
    }

    if let Some(jwt_ctx) = request.jwt_context.as_ref() {
        for role_assignment in &jwt_ctx.roles {
            if let RoleScope::Resource {
                resource_type,
                resource_id,
            } = &role_assignment.scope
                && resource_type == &request.resource.resource_type
            {
                resource_scopes_set.insert((
                    role_assignment.role_id.clone(),
                    resource_type.clone(),
                    resource_id.clone(),
                ));
            }
        }
    }

    resource_scopes_set
        .into_iter()
        .map(|(role_id, resource_type, resource_id)| {
            let entity_type = format!("Authz::{}", cedar_resource_entity_type(&resource_type));
            serde_json::json!({
                "role": { "__entity": { "type": "Authz::Role", "id": role_id } },
                "resource": { "__entity": { "type": entity_type, "id": resource_id } }
            })
        })
        .collect()
}

fn cedar_resource_entity_type(resource_type: &str) -> String {
    resource_type
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    first.to_ascii_uppercase().to_string() + &chars.as_str().to_ascii_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<String>()
}

struct SessionContextValues {
    present: bool,
    acr: i64,
    amr: Vec<String>,
    auth_age_present: bool,
    auth_age_seconds: i64,
    mfa_age_present: bool,
    mfa_age_seconds: i64,
}

fn session_context_values(
    session_ctx: Option<&SessionContext>,
    now: DateTime<Utc>,
) -> SessionContextValues {
    let Some(session) = session_ctx else {
        return SessionContextValues {
            present: false,
            acr: 0,
            amr: Vec::new(),
            auth_age_present: false,
            auth_age_seconds: 0,
            mfa_age_present: false,
            mfa_age_seconds: 0,
        };
    };

    let now_seconds = now.timestamp();
    let (auth_age_present, auth_age_seconds) = session
        .auth_time
        .and_then(|auth_time| now_seconds.checked_sub(auth_time))
        .filter(|age| *age >= 0)
        .map(|age| (true, age))
        .unwrap_or((false, 0));
    let (mfa_age_present, mfa_age_seconds) = session
        .mfa_time
        .and_then(|mfa_time| now_seconds.checked_sub(mfa_time))
        .filter(|age| *age >= 0)
        .map(|age| (true, age))
        .unwrap_or((false, 0));

    SessionContextValues {
        present: true,
        acr: session.acr as i64,
        amr: session.amr.clone(),
        auth_age_present,
        auth_age_seconds,
        mfa_age_present,
        mfa_age_seconds,
    }
}
