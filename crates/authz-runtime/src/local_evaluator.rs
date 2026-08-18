use std::{borrow::Borrow, collections::BTreeSet, sync::Arc};

use authz_cedar::{
    CedarEntityRef, CedarEvaluationErrorCategory, CedarInternalContext, CedarResourceScope,
    EntityParentRef as CedarEntityParentRef,
    evaluate_batch_frame_action_with_policy_sets_error_diagnostics as cedar_evaluate_batch_frame_action_with_policy_sets_error_diagnostics,
    prepare_batch_frame_owned_with_registry_and_trusted_internal_context as cedar_prepare_batch_frame_owned_with_registry_and_trusted_internal_context,
};
#[cfg(test)]
use authz_types::CONTEXT_INTERNAL_KEY;
use authz_types::{
    Action, DecisionContext, EvaluationRequest, EvaluationResponse, JwtContext,
    MAX_BATCH_EVALUATIONS, ResourceSelection, RoleScope, SessionContext, Subject, SubjectType,
    TokenContext, TokenScopeType,
};
use chrono::{DateTime, Utc};
#[cfg(test)]
use serde_json::Map;
use serde_json::Value;

use crate::{
    AuthzRuntimeError, AuthzRuntimeResult, EffectiveRoleAssignment, EvaluationRuntime, ParentRef,
    PermissionBits, RoleBits, ScopedPermissionBits, SnapshotFreshnessPolicy, StepUpEvaluator,
    StepUpResult, SubjectAccessSnapshot, enrich_request_with_snapshots_at,
    evaluation_runtime::CompiledActionDescriptor, role_assignment_covers_resource,
};

#[derive(Debug, Clone)]
pub struct LocalAuthzEvaluator {
    runtime: Arc<EvaluationRuntime>,
    snapshot_freshness: SnapshotFreshnessPolicy,
}

/// Authentication and authorization state that has already been validated by
/// the application boundary.
///
/// `EvaluationRequest` is a wire-shaped value and its JWT, session, and token
/// fields are caller-owned. They must never be used as proof of identity or
/// authentication by this storage-free runtime. The application that verifies
/// those credentials constructs this separate value and passes it alongside
/// the request. Keeping the fields private prevents accidental mutation after
/// the trusted boundary; the constructor name makes the provenance obligation
/// explicit for integrations.
#[derive(Debug, Clone, Default)]
pub struct TrustedAuthorizationContext {
    trusted_subject: Option<TrustedSubject>,
    jwt_context: Option<JwtContext>,
    session_context: Option<SessionContext>,
    token_context: Option<TokenContext>,
}

#[derive(Debug, Clone)]
struct TrustedSubject {
    subject_type: SubjectType,
    id: String,
}

impl TrustedAuthorizationContext {
    /// Construct context for a subject whose credentials the caller has
    /// already authenticated and validated against its issuer/session store.
    /// The subject identity is retained and checked before any trusted
    /// credential is used, preventing a caller from pairing one principal's
    /// validated claims or token with another principal's request.
    ///
    /// This crate intentionally does not know issuer keys, session storage, or
    /// service-token policy, so it cannot perform that validation itself.
    #[must_use]
    pub fn from_validated_parts(
        subject: &Subject,
        jwt_context: Option<JwtContext>,
        session_context: Option<SessionContext>,
        token_context: Option<TokenContext>,
    ) -> Self {
        Self {
            trusted_subject: Some(TrustedSubject {
                subject_type: subject.subject_type.clone(),
                id: subject.id.clone(),
            }),
            jwt_context,
            session_context,
            token_context,
        }
    }

    pub(crate) fn matches_subject(&self, subject: &Subject) -> bool {
        self.trusted_subject.as_ref().is_none_or(|trusted| {
            trusted.subject_type == subject.subject_type && trusted.id == subject.id
        })
    }

    pub(crate) fn jwt_context(&self) -> Option<&JwtContext> {
        self.jwt_context.as_ref()
    }

    pub(crate) fn session_context(&self) -> Option<&SessionContext> {
        self.session_context.as_ref()
    }

    pub(crate) fn token_context(&self) -> Option<&TokenContext> {
        self.token_context.as_ref()
    }
}

impl LocalAuthzEvaluator {
    #[cfg(test)]
    pub(crate) fn new(runtime: EvaluationRuntime) -> Self {
        Self {
            runtime: Arc::new(runtime),
            snapshot_freshness: SnapshotFreshnessPolicy::for_tests(),
        }
    }

    pub fn from_arc(runtime: Arc<EvaluationRuntime>) -> Self {
        Self::from_arc_with_snapshot_freshness(runtime, SnapshotFreshnessPolicy::default())
    }

    pub fn from_arc_with_snapshot_freshness(
        runtime: Arc<EvaluationRuntime>,
        snapshot_freshness: SnapshotFreshnessPolicy,
    ) -> Self {
        Self {
            runtime,
            snapshot_freshness,
        }
    }

    pub fn runtime(&self) -> &EvaluationRuntime {
        &self.runtime
    }

    pub fn evaluate<Tenant, SubjectAccess, ResourceAccess>(
        &self,
        input: LocalEvaluationInput<Tenant, SubjectAccess, ResourceAccess>,
    ) -> AuthzRuntimeResult<EvaluationResponse>
    where
        Tenant: Borrow<str>,
        SubjectAccess: Borrow<SubjectAccessSnapshot>,
        ResourceAccess: Borrow<crate::ResourceAccessSnapshot>,
    {
        self.evaluate_at(input, Utc::now())
    }

    pub fn evaluate_at<Tenant, SubjectAccess, ResourceAccess>(
        &self,
        input: LocalEvaluationInput<Tenant, SubjectAccess, ResourceAccess>,
        now: DateTime<Utc>,
    ) -> AuthzRuntimeResult<EvaluationResponse>
    where
        Tenant: Borrow<str>,
        SubjectAccess: Borrow<SubjectAccessSnapshot>,
        ResourceAccess: Borrow<crate::ResourceAccessSnapshot>,
    {
        let action = input.request.action.clone();
        self.evaluate_batch_at(
            LocalBatchEvaluationInput {
                tenant_id: input.tenant_id,
                request: input.request,
                trusted_context: input.trusted_context,
                actions: std::slice::from_ref(&action),
                subject_access: input.subject_access,
                resource_access: input.resource_access,
            },
            now,
        )?
        .pop()
        .ok_or_else(|| AuthzRuntimeError::cedar("single evaluation returned no response"))
    }

    pub fn evaluate_batch_at<Tenant, SubjectAccess, ResourceAccess>(
        &self,
        input: LocalBatchEvaluationInput<'_, Tenant, SubjectAccess, ResourceAccess>,
        now: DateTime<Utc>,
    ) -> AuthzRuntimeResult<Vec<EvaluationResponse>>
    where
        Tenant: Borrow<str>,
        SubjectAccess: Borrow<SubjectAccessSnapshot>,
        ResourceAccess: Borrow<crate::ResourceAccessSnapshot>,
    {
        if input.actions.is_empty() {
            return Ok(Vec::new());
        }
        if input.actions.len() > MAX_BATCH_EVALUATIONS {
            return Err(AuthzRuntimeError::cedar(format!(
                "batch exceeds maximum of {MAX_BATCH_EVALUATIONS} evaluations"
            )));
        }
        let tenant_id = input.tenant_id.borrow();
        let subject_access = input.subject_access.borrow();
        let resource_access = input.resource_access.borrow();
        let request = input.request;
        let mut enriched = enrich_request_with_snapshots_at(
            tenant_id,
            request,
            &input.trusted_context,
            subject_access,
            resource_access,
            now,
            self.snapshot_freshness,
        )?;
        let request = &enriched.request;
        let token_ctx = request.token_context.as_ref();
        let session_ctx = request.session_context.as_ref();
        let assignments = subject_access.active_assignments_at(now);
        let scoped = permissions_for_request_bits(
            &self.runtime,
            &assignments,
            request,
            &input.trusted_context,
            &request.subject,
            &enriched.subject_parents,
        );
        let checked_roles = self.runtime.role_ids_sorted(&scoped.checked_roles);
        let effective_permissions = if let Some(token_ctx) = token_ctx {
            let resolved = self.runtime.resolve_token_permissions_for_resource_at(
                &scoped.permissions,
                token_ctx,
                token_target_org(request),
                now,
            );
            if !resolved.is_valid {
                let reason = resolved
                    .invalid_reason
                    .as_deref()
                    .unwrap_or("Token invalid");
                return Ok(repeated_denials(
                    input.actions.len(),
                    reason,
                    &checked_roles,
                ));
            }
            if matches!(
                token_ctx.subject_binding,
                authz_types::TokenSubjectBinding::Subject
            ) && (token_ctx.owner_id != request.subject.id
                || !matches!(request.subject.subject_type, authz_types::SubjectType::User))
            {
                return Ok(repeated_denials(
                    input.actions.len(),
                    "token_owner_mismatch",
                    &checked_roles,
                ));
            }
            if token_selected_resource_mismatch(token_ctx, request) {
                return Ok(repeated_denials(
                    input.actions.len(),
                    "token_resource_scope",
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
            let resource_org = token_target_org(request).unwrap_or_default();
            let subject_bound = matches!(
                token_ctx.subject_binding,
                authz_types::TokenSubjectBinding::Subject
            );
            if resource_org != org_id
                || (subject_bound
                    && !token_owner_has_org(&assignments, &token_ctx.owner_id, org_id))
            {
                return Ok(repeated_denials(
                    input.actions.len(),
                    "token_org_mismatch",
                    &checked_roles,
                ));
            }
        }

        let resource_type = request.resource.resource_type.clone();
        let resource_is_public = request
            .resource
            .properties
            .as_ref()
            .and_then(|properties| properties.get("is_public"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let action_preparation = BatchActionPreparation {
            runtime: &self.runtime,
            resource_type: &resource_type,
            effective_permissions: &effective_permissions,
            checked_role_bits: &scoped.checked_roles,
            token_present: token_ctx.is_some(),
            checked_roles: &checked_roles,
            resource_is_public,
            session_ctx,
            now,
        };
        let mut single_action = None;
        let mut multiple_actions = Vec::new();
        let prepared_actions = if input.actions.len() == 1 {
            std::slice::from_mut(
                single_action.insert(action_preparation.prepare(&input.actions[0])),
            )
        } else {
            multiple_actions.extend(
                input
                    .actions
                    .iter()
                    .map(|action| action_preparation.prepare(action)),
            );
            multiple_actions.as_mut_slice()
        };
        if prepared_actions
            .iter()
            .all(|action| action.preliminary_response.is_some())
        {
            return Ok(prepared_actions
                .iter_mut()
                .filter_map(|action| action.preliminary_response.take())
                .collect());
        }
        let prepared_action = prepared_actions
            .iter()
            .find_map(|action| {
                (action.preliminary_response.is_none() && action.descriptor.is_some())
                    .then(|| action.action.clone())
            })
            .ok_or_else(|| AuthzRuntimeError::cedar("batch has no prepared Cedar action"))?;

        let internal_ctx = build_cedar_internal_context_at(
            &self.runtime,
            request,
            &effective_permissions,
            token_ctx,
            &assignments,
            session_ctx,
            now,
        )?;
        enriched.request.action = prepared_action;
        let subject_parents = to_cedar_parent_refs(&enriched.subject_parents);
        let resource_parents = to_cedar_parent_refs(&enriched.resource_parents);
        let prepared = cedar_prepare_batch_frame_owned_with_registry_and_trusted_internal_context(
            self.runtime.cedar_uids(),
            enriched.request,
            &subject_parents,
            &resource_parents,
            internal_ctx,
        )
        .map_err(AuthzRuntimeError::cedar)?;
        let mut responses = Vec::with_capacity(prepared_actions.len());
        for action in prepared_actions {
            if let Some(response) = action.preliminary_response.take() {
                responses.push(response);
                continue;
            }
            let descriptor = action.descriptor.ok_or_else(|| {
                AuthzRuntimeError::cedar("allowed action has no compiled descriptor")
            })?;
            let diagnostic_result =
                cedar_evaluate_batch_frame_action_with_policy_sets_error_diagnostics(
                    &self.runtime.policy_sets,
                    &prepared,
                    &descriptor.cedar_action,
                )
                .map_err(AuthzRuntimeError::cedar)?;
            if !diagnostic_result.evaluation_errors.is_empty() {
                record_cedar_diagnostics(
                    &resource_type,
                    &action.action.name,
                    self.runtime.config.version,
                    diagnostic_result.determining_policy_count,
                    &diagnostic_result.evaluation_errors,
                );
            }
            let mut response = diagnostic_result.response;
            if response.decision {
                response.context = Some(DecisionContext {
                    reason: None,
                    effective_permission: best_permission_for_descriptor(
                        &self.runtime,
                        descriptor,
                        &effective_permissions,
                    ),
                    policy_version: None,
                    checked_roles: Some(checked_roles.clone()),
                    acr_values: None,
                });
            } else {
                response = with_checked_roles(response, &checked_roles);
            }
            responses.push(response);
        }
        Ok(responses)
    }
}

struct BatchActionPreparation<'runtime, 'request> {
    runtime: &'runtime EvaluationRuntime,
    resource_type: &'request str,
    effective_permissions: &'request PermissionBits,
    checked_role_bits: &'request RoleBits,
    token_present: bool,
    checked_roles: &'request [String],
    resource_is_public: bool,
    session_ctx: Option<&'request SessionContext>,
    now: DateTime<Utc>,
}

impl<'runtime, 'request> BatchActionPreparation<'runtime, 'request> {
    fn prepare<'action>(&self, action: &'action Action) -> PreparedBatchAction<'action, 'runtime> {
        let descriptor = self
            .runtime
            .action_descriptor(self.resource_type, &action.name);
        let decision = descriptor.map_or(ActionPolicyDecision::NoPolicyAllow, |descriptor| {
            action_policy_decision_for_descriptor(
                descriptor,
                self.effective_permissions,
                self.checked_role_bits,
                !self.token_present,
            )
        });
        let preliminary_response =
            if self.token_present && !matches!(decision, ActionPolicyDecision::AllowMatched) {
                Some(with_checked_roles(
                    EvaluationResponse::deny_with_reason("token_permission_ceiling"),
                    self.checked_roles,
                ))
            } else if !matches!(decision, ActionPolicyDecision::AllowMatched)
                && !public_read_is_declared_for_action(
                    self.runtime,
                    self.resource_type,
                    &action.name,
                    self.resource_is_public,
                )
            {
                let reason = if matches!(decision, ActionPolicyDecision::DenyMatched) {
                    "deny_matched"
                } else {
                    "no_policy_allow"
                };
                Some(with_checked_roles(
                    EvaluationResponse::deny_with_reason(reason),
                    self.checked_roles,
                ))
            } else {
                step_up_response_for_allowed_request(
                    self.runtime,
                    self.resource_type,
                    &action.name,
                    self.session_ctx,
                    self.token_present,
                    self.now,
                )
            };
        PreparedBatchAction {
            action,
            descriptor,
            preliminary_response,
        }
    }
}

fn repeated_denials(
    count: usize,
    reason: &str,
    checked_roles: &[String],
) -> Vec<EvaluationResponse> {
    (0..count)
        .map(|_| with_checked_roles(EvaluationResponse::deny_with_reason(reason), checked_roles))
        .collect()
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
pub struct LocalEvaluationInput<
    Tenant = String,
    SubjectAccess = SubjectAccessSnapshot,
    ResourceAccess = crate::ResourceAccessSnapshot,
> {
    pub tenant_id: Tenant,
    pub request: EvaluationRequest,
    pub trusted_context: TrustedAuthorizationContext,
    pub subject_access: SubjectAccess,
    pub resource_access: ResourceAccess,
}

pub struct LocalBatchEvaluationInput<
    'a,
    Tenant = String,
    SubjectAccess = SubjectAccessSnapshot,
    ResourceAccess = crate::ResourceAccessSnapshot,
> {
    pub tenant_id: Tenant,
    /// Invariant request fields shared by every action. `request.action` is
    /// ignored; `actions` owns the evaluated action sequence.
    pub request: EvaluationRequest,
    pub trusted_context: TrustedAuthorizationContext,
    pub actions: &'a [Action],
    pub subject_access: SubjectAccess,
    pub resource_access: ResourceAccess,
}

struct PreparedBatchAction<'action, 'runtime> {
    action: &'action Action,
    descriptor: Option<&'runtime CompiledActionDescriptor>,
    preliminary_response: Option<EvaluationResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionPolicyDecision {
    DenyMatched,
    AllowMatched,
    NoPolicyAllow,
}

/// Resolve the permission ceiling for a request using caller-validated context.
///
/// The request remains the source of resource and action identity, but its
/// credential-bearing fields are intentionally ignored. Callers must pass a
/// [`TrustedAuthorizationContext`] built after authenticating the JWT, session,
/// or token against their issuer or session store.
pub fn permissions_for_request_bits(
    runtime: &EvaluationRuntime,
    assignments: &[EffectiveRoleAssignment],
    request: &EvaluationRequest,
    trusted_context: &TrustedAuthorizationContext,
    subject: &authz_types::Subject,
    subject_parents: &[ParentRef],
) -> ScopedPermissionBits {
    if !trusted_context.matches_subject(subject) {
        return ScopedPermissionBits {
            permissions: PermissionBits::default(),
            checked_roles: RoleBits::default(),
        };
    }
    let resource_org = resource_org(request);
    let mut permissions = PermissionBits::default();
    let mut checked_roles = RoleBits::default();

    for role_assignment in assignments {
        if !assignment_belongs_to_subject(role_assignment, subject, subject_parents) {
            continue;
        }
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
        // A role principal is a compatibility path used by callers that
        // evaluate a role's tenant-wide policy directly. If the trusted
        // snapshot contains assignments for that role, those assignments are
        // authoritative and must belong to this role principal and cover the
        // requested resource before the role's permissions are considered.
        // This prevents an out-of-scope role assignment from being bypassed by
        // the role subject identity.
        let role_is_scoped = assignments
            .iter()
            .any(|assignment| assignment.role_id == subject.id);
        let role_covers_resource = assignments
            .iter()
            .filter(|assignment| assignment.role_id == subject.id)
            .filter(|assignment| {
                assignment
                    .principal_id
                    .as_deref()
                    .is_none_or(|principal_id| principal_id == subject.id)
            })
            .any(|assignment| {
                role_assignment_covers_resource(
                    assignment,
                    &request.resource.resource_type,
                    &request.resource.id,
                    resource_org,
                )
            });

        if !role_is_scoped || role_covers_resource {
            checked_roles.set(role_idx);
            if let Some(role_permissions) = runtime.role_permissions(role_idx) {
                permissions.union_with(role_permissions);
            }
        }
    }

    if let Some(jwt_ctx) = trusted_context.jwt_context()
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

fn assignment_belongs_to_subject(
    assignment: &EffectiveRoleAssignment,
    subject: &authz_types::Subject,
    subject_parents: &[ParentRef],
) -> bool {
    let Some(principal_id) = assignment.principal_id.as_deref() else {
        return true;
    };
    if principal_id == subject.id {
        return true;
    }

    // A group assignment is effective for a user only when the trusted
    // subject snapshot proves that the user is a member of that exact group.
    // Other principal types, including role subjects, never inherit through
    // this compatibility path.
    matches!(subject.subject_type, authz_types::SubjectType::User)
        && subject_parents
            .iter()
            .any(|parent| parent.ref_type == "group" && parent.id == principal_id)
}

pub fn action_policy_decision_bits(
    runtime: &EvaluationRuntime,
    resource_type: &str,
    action: &str,
    permissions: &PermissionBits,
    checked_roles: &RoleBits,
    include_role_actions: bool,
) -> ActionPolicyDecision {
    let Some(descriptor) = runtime.action_descriptor(resource_type, action) else {
        return ActionPolicyDecision::NoPolicyAllow;
    };
    action_policy_decision_for_descriptor(
        descriptor,
        permissions,
        checked_roles,
        include_role_actions,
    )
}

fn action_policy_decision_for_descriptor(
    descriptor: &CompiledActionDescriptor,
    permissions: &PermissionBits,
    checked_roles: &RoleBits,
    include_role_actions: bool,
) -> ActionPolicyDecision {
    let action_masks = &descriptor.masks;

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
    let descriptor = runtime.action_descriptor(resource_type, action)?;
    best_permission_for_descriptor(runtime, descriptor, permissions)
}

fn best_permission_for_descriptor(
    runtime: &EvaluationRuntime,
    descriptor: &CompiledActionDescriptor,
    permissions: &PermissionBits,
) -> Option<String> {
    descriptor
        .best_permission_candidates
        .iter()
        .find(|index| permissions.contains(**index))
        .and_then(|index| runtime.permission_id(*index))
        .map(ToString::to_string)
}

#[cfg(test)]
pub(crate) fn legacy_action_resolution_for_profile(
    runtime: &EvaluationRuntime,
    resource_type: &str,
    action: &str,
    permissions: &PermissionBits,
    checked_roles: &RoleBits,
) -> (ActionPolicyDecision, Option<String>) {
    let decision = action_policy_decision_bits(
        runtime,
        resource_type,
        action,
        permissions,
        checked_roles,
        true,
    );
    let Some(descriptor) = runtime.action_descriptor(resource_type, action) else {
        return (decision, None);
    };
    let mut best_idx = None;
    let mut best_score = 0;
    let mut best_id = None;
    permissions.for_each_set_bit(|index| {
        if !descriptor.masks.permission_allow.contains(index)
            || descriptor.masks.permission_deny.contains(index)
        {
            return;
        }
        let Some(candidate_id) = runtime.permission_id(index) else {
            return;
        };
        let candidate_score = runtime.permission_action_score(index).unwrap_or(0);
        if best_idx.is_none()
            || candidate_score > best_score
            || (candidate_score == best_score
                && best_id.is_none_or(|current| candidate_id < current))
        {
            best_idx = Some(index);
            best_score = candidate_score;
            best_id = Some(candidate_id);
        }
    });
    (
        decision,
        best_idx.and_then(|index| runtime.permission_id(index).map(ToString::to_string)),
    )
}

#[cfg(test)]
pub(crate) fn compiled_action_resolution_for_profile(
    runtime: &EvaluationRuntime,
    resource_type: &str,
    action: &str,
    permissions: &PermissionBits,
    checked_roles: &RoleBits,
) -> (ActionPolicyDecision, Option<String>) {
    let Some(descriptor) = runtime.action_descriptor(resource_type, action) else {
        return (ActionPolicyDecision::NoPolicyAllow, None);
    };
    (
        action_policy_decision_for_descriptor(descriptor, permissions, checked_roles, true),
        best_permission_for_descriptor(runtime, descriptor, permissions),
    )
}

#[cfg(test)]
pub(crate) fn build_internal_context_at(
    runtime: &EvaluationRuntime,
    request: &EvaluationRequest,
    effective_permissions: &PermissionBits,
    token_ctx: Option<&TokenContext>,
    assignments: &[EffectiveRoleAssignment],
    session_ctx: Option<&SessionContext>,
    now: DateTime<Utc>,
) -> Value {
    let values = internal_context_values_at(
        runtime,
        request,
        effective_permissions,
        token_ctx,
        assignments,
        session_ctx,
        now,
    );
    let mut authz_map = Map::new();
    authz_map.insert("token_present".into(), Value::Bool(values.token_present));
    authz_map.insert("token_valid".into(), Value::Bool(values.token_valid));
    authz_map.insert(
        "token_resource_filter_enabled".into(),
        Value::Bool(values.token_resource_filter_enabled),
    );
    authz_map.insert(
        "token_resource_filter".into(),
        Value::Array(
            values
                .token_resource_filter
                .into_iter()
                .map(internal_entity_ref_json)
                .collect(),
        ),
    );
    authz_map.insert(
        "resource_scopes".into(),
        Value::Array(
            values
                .resource_scopes
                .into_iter()
                .map(|scope| {
                    serde_json::json!({
                        "role": internal_entity_ref_json(scope.role),
                        "resource": internal_entity_ref_json(scope.resource),
                    })
                })
                .collect(),
        ),
    );
    authz_map.insert(
        "token_org_id_present".into(),
        Value::Bool(values.token_org_id.is_some()),
    );
    authz_map.insert(
        "token_org_id".into(),
        Value::String(values.token_org_id.unwrap_or_default()),
    );
    authz_map.insert(
        "token_owner_org_ids".into(),
        Value::Array(
            values
                .token_owner_org_ids
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    authz_map.insert(
        "allowed_actions".into(),
        Value::Array(
            values
                .allowed_actions
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    authz_map.insert(
        "session_present".into(),
        Value::Bool(values.session.present),
    );
    authz_map.insert(
        "session_acr".into(),
        Value::Number(serde_json::Number::from(values.session.acr)),
    );
    authz_map.insert(
        "session_amr".into(),
        Value::Array(values.session.amr.into_iter().map(Value::String).collect()),
    );
    authz_map.insert(
        "session_auth_age_present".into(),
        Value::Bool(values.session.auth_age_present),
    );
    authz_map.insert(
        "session_auth_age_seconds".into(),
        Value::Number(serde_json::Number::from(values.session.auth_age_seconds)),
    );
    authz_map.insert(
        "session_mfa_age_present".into(),
        Value::Bool(values.session.mfa_age_present),
    );
    authz_map.insert(
        "session_mfa_age_seconds".into(),
        Value::Number(serde_json::Number::from(values.session.mfa_age_seconds)),
    );

    Value::Object(authz_map)
}

pub(crate) fn build_cedar_internal_context_at(
    runtime: &EvaluationRuntime,
    request: &EvaluationRequest,
    effective_permissions: &PermissionBits,
    token_ctx: Option<&TokenContext>,
    assignments: &[EffectiveRoleAssignment],
    session_ctx: Option<&SessionContext>,
    now: DateTime<Utc>,
) -> AuthzRuntimeResult<CedarInternalContext> {
    let values = internal_context_values_at(
        runtime,
        request,
        effective_permissions,
        token_ctx,
        assignments,
        session_ctx,
        now,
    );
    let token_resource_filter = values
        .token_resource_filter
        .into_iter()
        .map(|entity| {
            CedarEntityRef::new(&entity.entity_type, &entity.id).map_err(AuthzRuntimeError::cedar)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let resource_scopes = values
        .resource_scopes
        .into_iter()
        .map(|scope| {
            Ok(CedarResourceScope {
                role: CedarEntityRef::new(&scope.role.entity_type, &scope.role.id)
                    .map_err(AuthzRuntimeError::cedar)?,
                resource: CedarEntityRef::new(&scope.resource.entity_type, &scope.resource.id)
                    .map_err(AuthzRuntimeError::cedar)?,
            })
        })
        .collect::<Result<Vec<_>, AuthzRuntimeError>>()?;

    Ok(CedarInternalContext {
        token_present: values.token_present,
        token_valid: values.token_valid,
        token_resource_filter_enabled: values.token_resource_filter_enabled,
        token_resource_filter,
        resource_scopes,
        token_org_id_present: values.token_org_id.is_some(),
        token_org_id: values.token_org_id.unwrap_or_default(),
        token_owner_org_ids: values.token_owner_org_ids,
        allowed_actions: values.allowed_actions,
        session_present: values.session.present,
        session_acr: values.session.acr,
        session_amr: values.session.amr,
        session_auth_age_present: values.session.auth_age_present,
        session_auth_age_seconds: values.session.auth_age_seconds,
        session_mfa_age_present: values.session.mfa_age_present,
        session_mfa_age_seconds: values.session.mfa_age_seconds,
    })
}

struct InternalContextValues {
    token_present: bool,
    token_valid: bool,
    token_resource_filter_enabled: bool,
    token_resource_filter: Vec<InternalEntityRef>,
    resource_scopes: Vec<InternalResourceScope>,
    token_org_id: Option<String>,
    token_owner_org_ids: Vec<String>,
    allowed_actions: Vec<String>,
    session: SessionContextValues,
}

struct InternalEntityRef {
    entity_type: String,
    id: String,
}

struct InternalResourceScope {
    role: InternalEntityRef,
    resource: InternalEntityRef,
}

fn internal_context_values_at(
    runtime: &EvaluationRuntime,
    request: &EvaluationRequest,
    effective_permissions: &PermissionBits,
    token_ctx: Option<&TokenContext>,
    assignments: &[EffectiveRoleAssignment],
    session_ctx: Option<&SessionContext>,
    now: DateTime<Utc>,
) -> InternalContextValues {
    let token_present = token_ctx.is_some();
    let token_valid = token_ctx
        .map(|token| token_is_valid_at(token, now))
        .unwrap_or(true);
    let token_org_id = token_ctx.and_then(|ctx| ctx.scopes.org_id.clone());
    let token_owner_org_ids = token_ctx.map_or_else(Vec::new, |ctx| {
        if matches!(
            ctx.subject_binding,
            authz_types::TokenSubjectBinding::Delegated
        ) {
            ctx.scopes.org_id.iter().cloned().collect()
        } else {
            token_owner_org_ids_sorted(assignments, &ctx.owner_id)
        }
    });
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
        internal_token_resource_filter(request, token_ctx);

    InternalContextValues {
        token_present,
        token_valid,
        token_resource_filter_enabled,
        token_resource_filter,
        resource_scopes: internal_resource_scopes(assignments, request),
        token_org_id,
        token_owner_org_ids,
        allowed_actions,
        session: session_context_values(session_ctx, now),
    }
}

#[cfg(test)]
fn internal_entity_ref_json(entity: InternalEntityRef) -> Value {
    serde_json::json!({
        "__entity": {
            "type": entity.entity_type,
            "id": entity.id,
        }
    })
}

#[cfg(test)]
pub(crate) fn inject_internal_context(request: &mut EvaluationRequest, internal: Value) {
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
            if !matches!(fine.resource_selection, ResourceSelection::Selected) {
                return false;
            }

            if fine.selected_resources.iter().any(|selected| {
                selected == &format!("{}:{}", request.resource.resource_type, request.resource.id)
            }) {
                return false;
            }

            let has_bare_id = fine.selected_resources.contains(&request.resource.id);
            let has_single_resource_type = fine.resource_permissions.len() == 1
                && fine
                    .resource_permissions
                    .contains_key(request.resource.resource_type.as_str());
            !has_bare_id || !has_single_resource_type
        })
}

fn token_target_org(request: &EvaluationRequest) -> Option<&str> {
    if request.resource.resource_type == "organization" {
        Some(request.resource.id.as_str())
    } else {
        resource_org(request)
    }
}

fn resource_org(request: &EvaluationRequest) -> Option<&str> {
    request
        .resource
        .properties
        .as_ref()
        .and_then(|properties| properties.get("org_id"))
        .and_then(Value::as_str)
}

fn public_read_is_declared_for_action(
    runtime: &EvaluationRuntime,
    resource_type: &str,
    action: &str,
    is_public: bool,
) -> bool {
    if action != "read" {
        return false;
    }
    let Some(resource_type) = runtime.config.get_resource_type(resource_type) else {
        return false;
    };
    if !resource_type
        .actions
        .iter()
        .any(|configured_action| configured_action.name == action)
    {
        return false;
    }
    is_public
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
        .is_some_and(|expires_at| now.timestamp() >= expires_at)
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
    for (action, descriptor) in action_map {
        if !permissions.any_intersection(&descriptor.masks.permission_allow) {
            continue;
        }
        if permissions.any_intersection(&descriptor.masks.permission_deny) {
            continue;
        }
        allowed.push(format!("{resource_type}:{action}"));
    }
    allowed.sort();
    allowed
}

fn internal_token_resource_filter(
    request: &EvaluationRequest,
    token_ctx: Option<&TokenContext>,
) -> (bool, Vec<InternalEntityRef>) {
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
        .filter_map(|selected| {
            let bare_id = (selected == &request.resource.id).then_some(selected.as_str());
            let typed_id = selected
                .strip_prefix(&format!("{}:", request.resource.resource_type))
                .filter(|id| !id.is_empty());
            bare_id.or(typed_id).map(|id| InternalEntityRef {
                entity_type: entity_type.clone(),
                id: id.to_string(),
            })
        })
        .collect();
    (true, filter)
}

fn internal_resource_scopes(
    assignments: &[EffectiveRoleAssignment],
    request: &EvaluationRequest,
) -> Vec<InternalResourceScope> {
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
            let resource_entity_type =
                format!("Authz::{}", cedar_resource_entity_type(&resource_type));
            InternalResourceScope {
                role: InternalEntityRef {
                    entity_type: "Authz::Role".to_string(),
                    id: role_id,
                },
                resource: InternalEntityRef {
                    entity_type: resource_entity_type,
                    id: resource_id,
                },
            }
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
