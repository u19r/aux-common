use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use authz_types::{
    BatchEvaluationRequest, BatchEvaluationResponse, CONTEXT_INTERNAL_KEY, EvaluationRequest,
    EvaluationResponse, ValidatedConfigurationModel,
};
use cedar_policy::{
    AuthorizationError, Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName,
    EntityUid, EvaluationError, PolicySet, Request, RestrictedExpression,
};

use crate::{CedarError, CompiledBundle};

#[derive(Debug, Clone)]
pub struct ParsedPolicySets {
    by_resource_type: HashMap<String, Arc<PolicySet>>,
}

impl ParsedPolicySets {
    fn get(&self, resource_type: &str) -> Option<&PolicySet> {
        self.by_resource_type
            .get(resource_type)
            .map(std::ops::Deref::deref)
    }
}

#[derive(Debug, Clone)]
/// A parent relationship supplied by trusted authorization enrichment.
///
/// Do not construct these values directly from caller-controlled request
/// context. The default evaluation APIs ignore reserved parent context keys.
pub struct EntityParentRef {
    pub parent_type: String,
    pub parent_id: String,
}

pub struct CedarRequestUids {
    resource_type: String,
    principal: EntityUid,
    action: EntityUid,
    resource: EntityUid,
}

#[derive(Debug, Clone)]
pub struct CedarUidRegistry {
    subject_types: HashMap<&'static str, EntityTypeName>,
    resources: HashMap<String, CedarResourceUids>,
}

#[derive(Debug, Clone)]
pub struct PreparedCedarAction(EntityUid);

#[derive(Debug, Clone)]
struct CedarResourceUids {
    entity_type: EntityTypeName,
    actions: HashMap<String, EntityUid>,
}

impl CedarUidRegistry {
    pub fn new(config: &ValidatedConfigurationModel) -> Result<Self, CedarError> {
        let subject_types = ["user", "group", "role", "api_key", "machine", "protocol"]
            .into_iter()
            .map(|subject_type| {
                let cedar_type = format!("Authz::{}", subject_entity_type(subject_type));
                let entity_type = EntityTypeName::from_str(&cedar_type)
                    .map_err(|error| CedarError::evaluation(error.to_string()))?;
                Ok((subject_type, entity_type))
            })
            .collect::<Result<HashMap<_, _>, CedarError>>()?;
        let action_type = EntityTypeName::from_str("Authz::Action")
            .map_err(|error| CedarError::evaluation(error.to_string()))?;
        let resources = config
            .resource_types
            .iter()
            .map(|resource| {
                let cedar_type = format!(
                    "Authz::{}",
                    super::schema_generator::to_pascal_case(&resource.id)
                );
                let entity_type = EntityTypeName::from_str(&cedar_type)
                    .map_err(|error| CedarError::evaluation(error.to_string()))?;
                let actions = resource
                    .actions
                    .iter()
                    .map(|action| {
                        let action_id = format!("{}:{}", resource.id, action.name);
                        let uid = EntityUid::from_type_name_and_id(
                            action_type.clone(),
                            EntityId::new(action_id),
                        );
                        (action.name.clone(), uid)
                    })
                    .collect();
                Ok((
                    resource.id.clone(),
                    CedarResourceUids {
                        entity_type,
                        actions,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>, CedarError>>()?;
        Ok(Self {
            subject_types,
            resources,
        })
    }

    pub(crate) fn request_uids(
        &self,
        request: &EvaluationRequest,
    ) -> Result<CedarRequestUids, CedarError> {
        let subject_type = self
            .subject_types
            .get(request.subject.subject_type.as_str())
            .ok_or_else(|| CedarError::evaluation("subject type is not prepared"))?;
        let resource = self
            .resources
            .get(&request.resource.resource_type)
            .ok_or_else(|| CedarError::evaluation("resource type is not prepared"))?;
        let action = resource
            .actions
            .get(&request.action.name)
            .ok_or_else(|| CedarError::evaluation("resource action is not prepared"))?;

        Ok(CedarRequestUids {
            resource_type: request.resource.resource_type.clone(),
            principal: EntityUid::from_type_name_and_id(
                subject_type.clone(),
                EntityId::new(request.subject.id.clone()),
            ),
            action: action.clone(),
            resource: EntityUid::from_type_name_and_id(
                resource.entity_type.clone(),
                EntityId::new(request.resource.id.clone()),
            ),
        })
    }

    pub fn prepare_action(
        &self,
        resource_type: &str,
        action: &str,
    ) -> Result<PreparedCedarAction, CedarError> {
        self.resources
            .get(resource_type)
            .and_then(|resource| resource.actions.get(action))
            .cloned()
            .map(PreparedCedarAction)
            .ok_or_else(|| CedarError::evaluation("resource action is not prepared"))
    }
}

impl CedarRequestUids {
    pub fn resource_type(&self) -> &str {
        self.resource_type.as_str()
    }

    #[cfg(test)]
    pub(crate) fn principal(&self) -> &EntityUid {
        &self.principal
    }

    #[cfg(test)]
    pub(crate) fn action(&self) -> &EntityUid {
        &self.action
    }

    #[cfg(test)]
    pub(crate) fn resource(&self) -> &EntityUid {
        &self.resource
    }
}

pub struct CedarEntitiesContext {
    entities: Entities,
    context: Context,
}

#[derive(Debug, Clone)]
pub struct CedarEntityRef {
    uid: EntityUid,
}

impl CedarEntityRef {
    pub fn new(entity_type: &str, entity_id: &str) -> Result<Self, CedarError> {
        Ok(Self {
            uid: entity_uid(entity_type, entity_id).map_err(CedarError::evaluation)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CedarResourceScope {
    pub role: CedarEntityRef,
    pub resource: CedarEntityRef,
}

#[derive(Debug, Clone)]
pub struct CedarInternalContext {
    pub token_present: bool,
    pub token_valid: bool,
    pub token_resource_filter_enabled: bool,
    pub token_resource_filter: Vec<CedarEntityRef>,
    pub resource_scopes: Vec<CedarResourceScope>,
    pub token_org_id_present: bool,
    pub token_org_id: String,
    pub token_owner_org_ids: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub session_present: bool,
    pub session_acr: i64,
    pub session_amr: Vec<String>,
    pub session_auth_age_present: bool,
    pub session_auth_age_seconds: i64,
    pub session_mfa_age_present: bool,
    pub session_mfa_age_seconds: i64,
}

pub struct PreparedCedarEvaluation {
    resource_type: String,
    request: Request,
    entities: Entities,
}

pub struct PreparedCedarBatchFrame {
    resource_type: String,
    principal: EntityUid,
    resource: EntityUid,
    context: Context,
    entities: Entities,
}

#[derive(Debug, Clone)]
pub struct InternalEvaluationResult {
    pub response: EvaluationResponse,
    pub determining_policy_ids: Vec<String>,
    pub evaluation_errors: Vec<CedarEvaluationErrorCategory>,
}

#[derive(Debug, Clone)]
pub struct CedarErrorDiagnostics {
    pub response: EvaluationResponse,
    pub determining_policy_count: usize,
    pub evaluation_errors: Vec<CedarEvaluationErrorCategory>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CedarEvaluationErrorCategory {
    EntityMissing,
    AttributeMissing,
    ExtensionLookup,
    Type,
    ExtensionArgumentCount,
    IntegerOverflow,
    UnlinkedSlot,
    ExtensionExecution,
    NonValue,
    RecursionLimit,
}

impl CedarEvaluationErrorCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntityMissing => "entity_missing",
            Self::AttributeMissing => "attribute_missing",
            Self::ExtensionLookup => "extension_lookup",
            Self::Type => "type",
            Self::ExtensionArgumentCount => "extension_argument_count",
            Self::IntegerOverflow => "integer_overflow",
            Self::UnlinkedSlot => "unlinked_slot",
            Self::ExtensionExecution => "extension_execution",
            Self::NonValue => "non_value",
            Self::RecursionLimit => "recursion_limit",
        }
    }
}

impl PreparedCedarEvaluation {
    pub fn resource_type(&self) -> &str {
        self.resource_type.as_str()
    }
}

/// Evaluate a single request against the compiled bundle.
pub fn evaluate(
    bundle: &CompiledBundle,
    request: &EvaluationRequest,
) -> Result<EvaluationResponse, CedarError> {
    let parsed = parse_policy_sets(bundle)?;
    evaluate_with_policy_sets(&parsed, request)
}

pub fn evaluate_with_policy_sets(
    policy_sets: &ParsedPolicySets,
    request: &EvaluationRequest,
) -> Result<EvaluationResponse, CedarError> {
    let uids = prepare_request_uids(request)?;
    let (entities, context) = build_entities_and_context_ref_with_parents(request, &[], &[])
        .map_err(CedarError::evaluation)?;
    let prepared = prepare_request_from_parts(uids, CedarEntitiesContext { entities, context })?;
    evaluate_prepared_with_policy_sets(policy_sets, prepared)
}

pub fn evaluate_owned_with_policy_sets(
    policy_sets: &ParsedPolicySets,
    request: EvaluationRequest,
) -> Result<EvaluationResponse, CedarError> {
    let prepared = prepare_evaluation_owned(request)?;
    evaluate_prepared_with_policy_sets(policy_sets, prepared)
}

/// Evaluate with parent relationships supplied through the trusted boundary.
pub fn evaluate_owned_with_policy_sets_with_parents(
    policy_sets: &ParsedPolicySets,
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
) -> Result<EvaluationResponse, CedarError> {
    let prepared =
        prepare_evaluation_owned_with_parents(request, subject_parents, resource_parents)?;
    evaluate_prepared_with_policy_sets(policy_sets, prepared)
}

/// Evaluate multiple requests against the compiled bundle.
pub fn evaluate_batch(
    bundle: &CompiledBundle,
    request: &BatchEvaluationRequest,
) -> Result<BatchEvaluationResponse, CedarError> {
    let parsed = parse_policy_sets(bundle)?;
    evaluate_batch_with_policy_sets(&parsed, request)
}

pub fn evaluate_batch_with_policy_sets(
    policy_sets: &ParsedPolicySets,
    request: &BatchEvaluationRequest,
) -> Result<BatchEvaluationResponse, CedarError> {
    let evaluations = request
        .evaluations
        .iter()
        .map(|req| evaluate_with_policy_sets(policy_sets, req))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BatchEvaluationResponse { evaluations })
}

pub fn evaluate_batch_owned_with_policy_sets(
    policy_sets: &ParsedPolicySets,
    request: BatchEvaluationRequest,
) -> Result<BatchEvaluationResponse, CedarError> {
    let evaluations = request
        .evaluations
        .into_iter()
        .map(|req| evaluate_owned_with_policy_sets(policy_sets, req))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BatchEvaluationResponse { evaluations })
}

pub fn parse_policy_sets(bundle: &CompiledBundle) -> Result<ParsedPolicySets, CedarError> {
    let mut policy_sets_by_resource: HashMap<&str, PolicySet> = HashMap::new();
    for policy_slice in &bundle.policy_slices {
        let slice_policy_set = PolicySet::from_json_str(&policy_slice.policies_json)
            .map_err(|e| CedarError::evaluation(format!("invalid policies json: {e}")))?;
        let entry = policy_sets_by_resource
            .entry(policy_slice.resource_type.as_str())
            .or_default();
        entry
            .merge(&slice_policy_set, false)
            .map_err(|e| CedarError::evaluation(format!("invalid policies json: {e}")))?;
    }

    let mut by_resource_type = HashMap::with_capacity(policy_sets_by_resource.len());
    for (resource_type, policy_set) in policy_sets_by_resource {
        by_resource_type.insert(resource_type.to_string(), Arc::new(policy_set));
    }

    Ok(ParsedPolicySets { by_resource_type })
}

pub fn prepare_request_uids(request: &EvaluationRequest) -> Result<CedarRequestUids, CedarError> {
    let resource_type = request.resource.resource_type.clone();
    let subject_id = request.subject.id.clone();
    let resource_id = request.resource.id.clone();

    let action = entity_uid_owned(
        "Authz::Action",
        format!("{}:{}", resource_type, request.action.name),
    )
    .map_err(CedarError::evaluation)?;
    let principal = principal_uid_owned(request.subject.subject_type.as_str(), subject_id)
        .map_err(CedarError::evaluation)?;
    let resource =
        resource_uid_owned(&resource_type, resource_id).map_err(CedarError::evaluation)?;

    Ok(CedarRequestUids {
        resource_type,
        principal,
        action,
        resource,
    })
}

pub fn prepare_entities_and_context_owned(
    request: EvaluationRequest,
) -> Result<CedarEntitiesContext, CedarError> {
    prepare_entities_and_context_owned_with_parents(request, &[], &[])
}

pub fn prepare_entities_and_context_owned_with_parents(
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
) -> Result<CedarEntitiesContext, CedarError> {
    let (entities, context) = build_entities_and_context_owned_with_parents(
        request,
        subject_parents,
        resource_parents,
        None,
        None,
    )
    .map_err(CedarError::evaluation)?;
    Ok(CedarEntitiesContext { entities, context })
}

pub fn prepare_request_from_parts(
    uids: CedarRequestUids,
    entities_context: CedarEntitiesContext,
) -> Result<PreparedCedarEvaluation, CedarError> {
    let CedarRequestUids {
        resource_type,
        principal,
        action,
        resource,
    } = uids;
    let CedarEntitiesContext { entities, context } = entities_context;

    let request = Request::new(principal, action, resource, context, None)
        .map_err(|e| CedarError::evaluation(e.to_string()))?;

    Ok(PreparedCedarEvaluation {
        resource_type,
        request,
        entities,
    })
}

pub fn prepare_evaluation_owned(
    request: EvaluationRequest,
) -> Result<PreparedCedarEvaluation, CedarError> {
    let uids = prepare_request_uids(&request)?;
    let (entities, context) =
        build_entities_and_context_owned_with_parents(request, &[], &[], None, Some(&uids))
            .map_err(CedarError::evaluation)?;
    prepare_request_from_parts(uids, CedarEntitiesContext { entities, context })
}

/// Prepare an evaluation with parent relationships supplied by trusted
/// authorization enrichment.
pub fn prepare_evaluation_owned_with_parents(
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
) -> Result<PreparedCedarEvaluation, CedarError> {
    let uids = prepare_request_uids(&request)?;
    let (entities, context) = build_entities_and_context_owned_with_parents(
        request,
        subject_parents,
        resource_parents,
        None,
        Some(&uids),
    )
    .map_err(CedarError::evaluation)?;
    prepare_request_from_parts(uids, CedarEntitiesContext { entities, context })
}

pub fn prepare_evaluation_owned_with_parents_and_internal_context(
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
    internal_context: CedarInternalContext,
) -> Result<PreparedCedarEvaluation, CedarError> {
    let uids = prepare_request_uids(&request)?;
    let (entities, context) = build_entities_and_context_owned_with_parents(
        request,
        subject_parents,
        resource_parents,
        Some(internal_context),
        Some(&uids),
    )
    .map_err(CedarError::evaluation)?;
    prepare_request_from_parts(uids, CedarEntitiesContext { entities, context })
}

pub fn prepare_evaluation_owned_with_registry_and_internal_context(
    uid_registry: &CedarUidRegistry,
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
    internal_context: CedarInternalContext,
) -> Result<PreparedCedarEvaluation, CedarError> {
    let uids = uid_registry.request_uids(&request)?;
    let (entities, context) = build_entities_and_context_owned_with_parents(
        request,
        subject_parents,
        resource_parents,
        Some(internal_context),
        Some(&uids),
    )
    .map_err(CedarError::evaluation)?;
    prepare_request_from_parts(uids, CedarEntitiesContext { entities, context })
}

pub fn prepare_batch_frame_owned_with_registry_and_internal_context(
    uid_registry: &CedarUidRegistry,
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
    internal_context: CedarInternalContext,
) -> Result<PreparedCedarBatchFrame, CedarError> {
    let uids = uid_registry.request_uids(&request)?;
    let (entities, context) = build_entities_and_context_owned_with_parents(
        request,
        subject_parents,
        resource_parents,
        Some(internal_context),
        Some(&uids),
    )
    .map_err(CedarError::evaluation)?;
    Ok(PreparedCedarBatchFrame {
        resource_type: uids.resource_type,
        principal: uids.principal,
        resource: uids.resource,
        context,
        entities,
    })
}

pub fn evaluate_batch_frame_action_with_policy_sets_error_diagnostics(
    policy_sets: &ParsedPolicySets,
    prepared: &PreparedCedarBatchFrame,
    action: &PreparedCedarAction,
) -> Result<CedarErrorDiagnostics, CedarError> {
    let Some(policy_set) = policy_sets.get(prepared.resource_type.as_str()) else {
        return Ok(CedarErrorDiagnostics {
            response: EvaluationResponse::deny_with_reason(format!(
                "policy slice not found for {}",
                prepared.resource_type
            )),
            determining_policy_count: 0,
            evaluation_errors: Vec::new(),
        });
    };
    let request = Request::new(
        prepared.principal.clone(),
        action.0.clone(),
        prepared.resource.clone(),
        prepared.context.clone(),
        None,
    )
    .map_err(|error| CedarError::evaluation(error.to_string()))?;
    Ok(evaluate_authorizer_with_error_diagnostics(
        &request,
        policy_set,
        &prepared.entities,
    ))
}

pub fn evaluate_prepared_with_policy_sets(
    policy_sets: &ParsedPolicySets,
    prepared: PreparedCedarEvaluation,
) -> Result<EvaluationResponse, CedarError> {
    let PreparedCedarEvaluation {
        resource_type,
        request,
        entities,
    } = prepared;
    let Some(policy_set) = policy_sets.get(resource_type.as_str()) else {
        return Ok(EvaluationResponse::deny_with_reason(format!(
            "policy slice not found for {}",
            resource_type
        )));
    };
    Ok(evaluate_authorizer(&request, policy_set, &entities))
}

pub fn evaluate_prepared_with_policy_sets_error_diagnostics(
    policy_sets: &ParsedPolicySets,
    prepared: PreparedCedarEvaluation,
) -> Result<CedarErrorDiagnostics, CedarError> {
    let PreparedCedarEvaluation {
        resource_type,
        request,
        entities,
    } = prepared;
    let Some(policy_set) = policy_sets.get(resource_type.as_str()) else {
        return Ok(CedarErrorDiagnostics {
            response: EvaluationResponse::deny_with_reason(format!(
                "policy slice not found for {}",
                resource_type
            )),
            determining_policy_count: 0,
            evaluation_errors: Vec::new(),
        });
    };
    Ok(evaluate_authorizer_with_error_diagnostics(
        &request, policy_set, &entities,
    ))
}

pub fn evaluate_prepared_with_policy_sets_diagnostics(
    policy_sets: &ParsedPolicySets,
    prepared: PreparedCedarEvaluation,
) -> Result<InternalEvaluationResult, CedarError> {
    let PreparedCedarEvaluation {
        resource_type,
        request,
        entities,
    } = prepared;
    let Some(policy_set) = policy_sets.get(resource_type.as_str()) else {
        return Ok(InternalEvaluationResult {
            response: EvaluationResponse::deny_with_reason(format!(
                "policy slice not found for {}",
                resource_type
            )),
            determining_policy_ids: Vec::new(),
            evaluation_errors: Vec::new(),
        });
    };

    Ok(evaluate_authorizer_with_diagnostics(
        &request, policy_set, &entities,
    ))
}

#[cfg(test)]
pub(crate) fn evaluate_prepared_with_policy_set_diagnostics(
    policy_set: &PolicySet,
    prepared: &PreparedCedarEvaluation,
) -> InternalEvaluationResult {
    evaluate_authorizer_with_diagnostics(&prepared.request, policy_set, &prepared.entities)
}

#[cfg(test)]
pub(crate) fn evaluate_prepared_with_policy_set_error_diagnostics(
    policy_set: &PolicySet,
    prepared: &PreparedCedarEvaluation,
) -> CedarErrorDiagnostics {
    evaluate_authorizer_with_error_diagnostics(&prepared.request, policy_set, &prepared.entities)
}

fn evaluate_authorizer(
    request: &Request,
    policy_set: &PolicySet,
    entities: &Entities,
) -> EvaluationResponse {
    let response = Authorizer::new().is_authorized(request, policy_set, entities);
    response_from_decision(response.decision())
}

fn evaluate_authorizer_with_error_diagnostics(
    request: &Request,
    policy_set: &PolicySet,
    entities: &Entities,
) -> CedarErrorDiagnostics {
    let response = Authorizer::new().is_authorized(request, policy_set, entities);
    let evaluation_errors = response
        .diagnostics()
        .errors()
        .map(error_category)
        .collect::<Vec<_>>();
    let determining_policy_count = if evaluation_errors.is_empty() {
        0
    } else {
        response.diagnostics().reason().count()
    };
    CedarErrorDiagnostics {
        response: response_from_decision(response.decision()),
        determining_policy_count,
        evaluation_errors,
    }
}

pub(crate) fn evaluate_authorizer_with_diagnostics(
    request: &Request,
    policy_set: &PolicySet,
    entities: &Entities,
) -> InternalEvaluationResult {
    let response = Authorizer::new().is_authorized(request, policy_set, entities);
    let mut determining_policy_ids = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    determining_policy_ids.sort();
    let evaluation_errors = response
        .diagnostics()
        .errors()
        .map(error_category)
        .collect();
    InternalEvaluationResult {
        response: response_from_decision(response.decision()),
        determining_policy_ids,
        evaluation_errors,
    }
}

fn error_category(error: &AuthorizationError) -> CedarEvaluationErrorCategory {
    let AuthorizationError::PolicyEvaluationError(error) = error;
    match error.inner() {
        EvaluationError::EntityDoesNotExist(_) => CedarEvaluationErrorCategory::EntityMissing,
        EvaluationError::EntityAttrDoesNotExist(_) | EvaluationError::RecordAttrDoesNotExist(_) => {
            CedarEvaluationErrorCategory::AttributeMissing
        }
        EvaluationError::FailedExtensionFunctionLookup(_) => {
            CedarEvaluationErrorCategory::ExtensionLookup
        }
        EvaluationError::TypeError(_) => CedarEvaluationErrorCategory::Type,
        EvaluationError::WrongNumArguments(_) => {
            CedarEvaluationErrorCategory::ExtensionArgumentCount
        }
        EvaluationError::IntegerOverflow(_) => CedarEvaluationErrorCategory::IntegerOverflow,
        EvaluationError::UnlinkedSlot(_) => CedarEvaluationErrorCategory::UnlinkedSlot,
        EvaluationError::FailedExtensionFunctionExecution(_) => {
            CedarEvaluationErrorCategory::ExtensionExecution
        }
        EvaluationError::NonValue(_) => CedarEvaluationErrorCategory::NonValue,
        EvaluationError::RecursionLimit(_) => CedarEvaluationErrorCategory::RecursionLimit,
    }
}

fn response_from_decision(decision: Decision) -> EvaluationResponse {
    match decision {
        Decision::Allow => EvaluationResponse::allow(),
        Decision::Deny => EvaluationResponse::deny_with_reason("denied"),
    }
}

fn build_entities_and_context_ref_with_parents(
    request: &EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
) -> Result<(Entities, Context), String> {
    let principal_type = subject_entity_type(request.subject.subject_type.as_str());
    let resource_type = super::schema_generator::to_pascal_case(&request.resource.resource_type);

    let mut principal_attrs = match request.subject.properties.as_ref() {
        Some(serde_json::Value::Object(map)) => restricted_attrs_from_map_ref(map)?,
        _ => Vec::new(),
    };
    principal_attrs.push((
        "id".to_string(),
        RestrictedExpression::new_string(request.subject.id.clone()),
    ));
    let resource_attrs = match request.resource.properties.as_ref() {
        Some(serde_json::Value::Object(map)) => restricted_attrs_from_map_ref(map)?,
        _ => Vec::new(),
    };
    let context = context_from_attrs_ref(request.context.as_ref().map(|ctx| &ctx.attributes))?;

    let entities = build_entities_from_converted_inputs(EntityConvertedBuildInputs {
        principal_uid: principal_uid(&principal_type, &request.subject.id)?,
        principal_attrs,
        resource_uid: resource_uid(&resource_type, &request.resource.id)?,
        resource_attrs,
        subject_parents: subject_parents.to_vec(),
        resource_parents: resource_parents.to_vec(),
    })?;

    Ok((entities, context))
}

fn build_entities_and_context_owned_with_parents(
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
    internal_context: Option<CedarInternalContext>,
    request_uids: Option<&CedarRequestUids>,
) -> Result<(Entities, Context), String> {
    let principal_type = subject_entity_type(request.subject.subject_type.as_str());
    let resource_type = super::schema_generator::to_pascal_case(&request.resource.resource_type);

    let mut principal_props = match request.subject.properties {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    principal_props.insert(
        "id".to_string(),
        serde_json::Value::String(request.subject.id.clone()),
    );
    let resource_props = match request.resource.properties {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };

    let mut context_attrs = request
        .context
        .map(|ctx| ctx.attributes)
        .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
    remove_parent_keys_from_context(&mut context_attrs);
    let context = context_from_value(context_attrs, internal_context)?;

    let principal_uid = match request_uids {
        Some(uids) => uids.principal.clone(),
        None => principal_uid(&principal_type, &request.subject.id)?,
    };
    let resource_uid = match request_uids {
        Some(uids) => uids.resource.clone(),
        None => resource_uid(&resource_type, &request.resource.id)?,
    };

    let entities = build_entities_from_converted_inputs(EntityConvertedBuildInputs {
        principal_uid,
        principal_attrs: restricted_attrs_from_map(principal_props)?,
        resource_uid,
        resource_attrs: restricted_attrs_from_map(resource_props)?,
        subject_parents: subject_parents.to_vec(),
        resource_parents: resource_parents.to_vec(),
    })?;

    Ok((entities, context))
}

struct EntityConvertedBuildInputs {
    principal_uid: EntityUid,
    principal_attrs: Vec<(String, RestrictedExpression)>,
    resource_uid: EntityUid,
    resource_attrs: Vec<(String, RestrictedExpression)>,
    subject_parents: Vec<EntityParentRef>,
    resource_parents: Vec<EntityParentRef>,
}

fn build_entities_from_converted_inputs(
    inputs: EntityConvertedBuildInputs,
) -> Result<Entities, String> {
    let EntityConvertedBuildInputs {
        principal_uid,
        principal_attrs,
        resource_uid,
        resource_attrs,
        subject_parents,
        resource_parents,
    } = inputs;

    let principal_parent_uids = parent_uids(&subject_parents)?;
    let resource_parent_uids = parent_uids(&resource_parents)?;

    let principal_entity = Entity::new_with_tags(
        principal_uid,
        principal_attrs,
        principal_parent_uids.clone(),
        [],
    )
    .map_err(|e| e.to_string())?;
    let resource_entity = Entity::new_with_tags(
        resource_uid,
        resource_attrs,
        resource_parent_uids.clone(),
        [],
    )
    .map_err(|e| e.to_string())?;

    let mut entities = Vec::with_capacity(2 + subject_parents.len() + resource_parents.len());
    entities.push(principal_entity);
    entities.push(resource_entity);

    let mut seen_parent_uids =
        HashSet::with_capacity(principal_parent_uids.len() + resource_parent_uids.len());
    for parent_uid in principal_parent_uids
        .into_iter()
        .chain(resource_parent_uids)
    {
        if !seen_parent_uids.insert(parent_uid.clone()) {
            continue;
        }
        entities.push(Entity::new_no_attrs(parent_uid, HashSet::new()));
    }

    Entities::from_entities(entities, None).map_err(|e| e.to_string())
}

fn context_from_value(
    context: serde_json::Value,
    internal_context: Option<CedarInternalContext>,
) -> Result<Context, String> {
    let mut map = match context {
        serde_json::Value::Object(map) => map,
        _ if internal_context.is_some() => serde_json::Map::new(),
        _ => return Err("context must be an object".to_string()),
    };
    if internal_context.is_some() {
        map.remove(CONTEXT_INTERNAL_KEY);
    }
    if map.is_empty() && internal_context.is_none() {
        return Ok(Context::empty());
    }
    let mut pairs = Vec::with_capacity(map.len() + usize::from(internal_context.is_some()));
    for (key, value) in map {
        pairs.push((key, restricted_expr_from_value(value)?));
    }
    if let Some(internal_context) = internal_context {
        pairs.push((
            CONTEXT_INTERNAL_KEY.to_string(),
            restricted_expr_from_internal_context(internal_context)?,
        ));
    }
    Context::from_pairs(pairs).map_err(|e| e.to_string())
}

fn restricted_expr_from_internal_context(
    context: CedarInternalContext,
) -> Result<RestrictedExpression, String> {
    let entity_set = |entities: Vec<CedarEntityRef>| {
        RestrictedExpression::new_set(
            entities
                .into_iter()
                .map(|entity| RestrictedExpression::new_entity_uid(entity.uid)),
        )
    };
    let string_set = |values: Vec<String>| {
        RestrictedExpression::new_set(values.into_iter().map(RestrictedExpression::new_string))
    };
    let resource_scopes = context
        .resource_scopes
        .into_iter()
        .map(|scope| {
            RestrictedExpression::new_record([
                (
                    "role".to_string(),
                    RestrictedExpression::new_entity_uid(scope.role.uid),
                ),
                (
                    "resource".to_string(),
                    RestrictedExpression::new_entity_uid(scope.resource.uid),
                ),
            ])
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    RestrictedExpression::new_record([
        (
            "token_present".to_string(),
            RestrictedExpression::new_bool(context.token_present),
        ),
        (
            "token_valid".to_string(),
            RestrictedExpression::new_bool(context.token_valid),
        ),
        (
            "token_resource_filter_enabled".to_string(),
            RestrictedExpression::new_bool(context.token_resource_filter_enabled),
        ),
        (
            "token_resource_filter".to_string(),
            entity_set(context.token_resource_filter),
        ),
        (
            "resource_scopes".to_string(),
            RestrictedExpression::new_set(resource_scopes),
        ),
        (
            "token_org_id_present".to_string(),
            RestrictedExpression::new_bool(context.token_org_id_present),
        ),
        (
            "token_org_id".to_string(),
            RestrictedExpression::new_string(context.token_org_id),
        ),
        (
            "token_owner_org_ids".to_string(),
            string_set(context.token_owner_org_ids),
        ),
        (
            "allowed_actions".to_string(),
            string_set(context.allowed_actions),
        ),
        (
            "session_present".to_string(),
            RestrictedExpression::new_bool(context.session_present),
        ),
        (
            "session_acr".to_string(),
            RestrictedExpression::new_long(context.session_acr),
        ),
        ("session_amr".to_string(), string_set(context.session_amr)),
        (
            "session_auth_age_present".to_string(),
            RestrictedExpression::new_bool(context.session_auth_age_present),
        ),
        (
            "session_auth_age_seconds".to_string(),
            RestrictedExpression::new_long(context.session_auth_age_seconds),
        ),
        (
            "session_mfa_age_present".to_string(),
            RestrictedExpression::new_bool(context.session_mfa_age_present),
        ),
        (
            "session_mfa_age_seconds".to_string(),
            RestrictedExpression::new_long(context.session_mfa_age_seconds),
        ),
    ])
    .map_err(|error| error.to_string())
}

fn context_from_attrs_ref(context_attrs: Option<&serde_json::Value>) -> Result<Context, String> {
    let Some(context_attrs) = context_attrs else {
        return Ok(Context::empty());
    };
    let Some(map) = context_attrs.as_object() else {
        return Err("context must be an object".to_string());
    };
    if map.is_empty() {
        return Ok(Context::empty());
    }

    let mut pairs = Vec::with_capacity(map.len());
    for (key, value) in map {
        if key == "subject_parents" || key == "resource_parents" {
            continue;
        }
        pairs.push((key.clone(), restricted_expr_from_value_ref(value)?));
    }
    if pairs.is_empty() {
        return Ok(Context::empty());
    }

    Context::from_pairs(pairs).map_err(|e| e.to_string())
}

fn restricted_attrs_from_map(
    map: serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<(String, RestrictedExpression)>, String> {
    let mut attrs = Vec::with_capacity(map.len());
    for (key, value) in map {
        attrs.push((key, restricted_expr_from_value(value)?));
    }
    Ok(attrs)
}

fn restricted_attrs_from_map_ref(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<(String, RestrictedExpression)>, String> {
    let mut attrs = Vec::with_capacity(map.len());
    for (key, value) in map {
        attrs.push((key.clone(), restricted_expr_from_value_ref(value)?));
    }
    Ok(attrs)
}

fn restricted_expr_from_value(value: serde_json::Value) -> Result<RestrictedExpression, String> {
    match value {
        serde_json::Value::Null => Err("null values are not supported in Cedar values".to_string()),
        serde_json::Value::Bool(value) => Ok(RestrictedExpression::new_bool(value)),
        serde_json::Value::Number(value) => {
            if let Some(i64_value) = value.as_i64() {
                return Ok(RestrictedExpression::new_long(i64_value));
            }
            if let Some(u64_value) = value.as_u64()
                && let Ok(i64_value) = i64::try_from(u64_value)
            {
                return Ok(RestrictedExpression::new_long(i64_value));
            }
            Err(format!("unsupported numeric value: {value}"))
        }
        serde_json::Value::String(value) => Ok(RestrictedExpression::new_string(value)),
        serde_json::Value::Array(values) => {
            let mut exprs = Vec::with_capacity(values.len());
            for value in values {
                exprs.push(restricted_expr_from_value(value)?);
            }
            Ok(RestrictedExpression::new_set(exprs))
        }
        serde_json::Value::Object(mut map) => {
            if let Some(entity_value) = map.remove("__entity") {
                if !map.is_empty() {
                    return Err("entity escape object must only contain __entity".to_string());
                }
                let entity_uid = entity_uid_from_escape_ref(&entity_value)?;
                return Ok(RestrictedExpression::new_entity_uid(entity_uid));
            }

            let mut fields = Vec::with_capacity(map.len());
            for (key, value) in map {
                fields.push((key, restricted_expr_from_value(value)?));
            }
            RestrictedExpression::new_record(fields).map_err(|e| e.to_string())
        }
    }
}

fn restricted_expr_from_value_ref(
    value: &serde_json::Value,
) -> Result<RestrictedExpression, String> {
    match value {
        serde_json::Value::Null => Err("null values are not supported in Cedar values".to_string()),
        serde_json::Value::Bool(value) => Ok(RestrictedExpression::new_bool(*value)),
        serde_json::Value::Number(value) => {
            if let Some(i64_value) = value.as_i64() {
                return Ok(RestrictedExpression::new_long(i64_value));
            }
            if let Some(u64_value) = value.as_u64()
                && let Ok(i64_value) = i64::try_from(u64_value)
            {
                return Ok(RestrictedExpression::new_long(i64_value));
            }
            Err(format!("unsupported numeric value: {value}"))
        }
        serde_json::Value::String(value) => Ok(RestrictedExpression::new_string(value.clone())),
        serde_json::Value::Array(values) => {
            let mut exprs = Vec::with_capacity(values.len());
            for value in values {
                exprs.push(restricted_expr_from_value_ref(value)?);
            }
            Ok(RestrictedExpression::new_set(exprs))
        }
        serde_json::Value::Object(map) => {
            if let Some(entity_value) = map.get("__entity") {
                if map.len() != 1 {
                    return Err("entity escape object must only contain __entity".to_string());
                }
                let entity_uid = entity_uid_from_escape_ref(entity_value)?;
                return Ok(RestrictedExpression::new_entity_uid(entity_uid));
            }

            let mut fields = Vec::with_capacity(map.len());
            for (key, value) in map {
                fields.push((key.clone(), restricted_expr_from_value_ref(value)?));
            }
            RestrictedExpression::new_record(fields).map_err(|e| e.to_string())
        }
    }
}

fn entity_uid_from_escape_ref(value: &serde_json::Value) -> Result<EntityUid, String> {
    let serde_json::Value::Object(map) = value else {
        return Err("__entity must be an object".to_string());
    };
    let Some(entity_type) = map.get("type").and_then(serde_json::Value::as_str) else {
        return Err("__entity.type must be a string".to_string());
    };
    let Some(entity_id) = map.get("id").and_then(serde_json::Value::as_str) else {
        return Err("__entity.id must be a string".to_string());
    };
    entity_uid(entity_type, entity_id)
}

fn entity_uid(entity_type: &str, entity_id: &str) -> Result<EntityUid, String> {
    let type_name = EntityTypeName::from_str(entity_type).map_err(|e| e.to_string())?;
    let entity_id = EntityId::new(entity_id);
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
}

fn entity_uid_owned(entity_type: &str, entity_id: String) -> Result<EntityUid, String> {
    let type_name = EntityTypeName::from_str(entity_type).map_err(|e| e.to_string())?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(entity_id),
    ))
}

fn parent_uids(parents: &[EntityParentRef]) -> Result<HashSet<EntityUid>, String> {
    let mut parent_uids = HashSet::with_capacity(parents.len());
    for parent in parents {
        parent_uids.insert(parent_uid(parent)?);
    }
    Ok(parent_uids)
}

fn parent_uid(parent: &EntityParentRef) -> Result<EntityUid, String> {
    let parent_type = format!(
        "Authz::{}",
        super::schema_generator::to_pascal_case(&parent.parent_type)
    );
    entity_uid(parent_type.as_str(), parent.parent_id.as_str())
}

fn remove_parent_keys_from_context(context: &mut serde_json::Value) {
    if let Some(context_map) = context.as_object_mut() {
        context_map.remove("subject_parents");
        context_map.remove("resource_parents");
    }
}

fn principal_uid(subject_type: &str, id: &str) -> Result<EntityUid, String> {
    let entity_type = subject_entity_type(subject_type);
    entity_uid(&format!("Authz::{entity_type}"), id)
}

fn principal_uid_owned(subject_type: &str, id: String) -> Result<EntityUid, String> {
    let entity_type = subject_entity_type(subject_type);
    entity_uid_owned(&format!("Authz::{entity_type}"), id)
}

fn resource_uid(resource_type: &str, id: &str) -> Result<EntityUid, String> {
    let entity_type = super::schema_generator::to_pascal_case(resource_type);
    entity_uid(&format!("Authz::{entity_type}"), id)
}

fn resource_uid_owned(resource_type: &str, id: String) -> Result<EntityUid, String> {
    let entity_type = super::schema_generator::to_pascal_case(resource_type);
    entity_uid_owned(&format!("Authz::{entity_type}"), id)
}

fn subject_entity_type(subject_type: &str) -> String {
    match subject_type {
        "user" | "User" => "User".to_string(),
        "group" | "Group" => "Group".to_string(),
        "role" | "Role" => "Role".to_string(),
        "api_key" | "ApiKey" => "ApiKey".to_string(),
        "service_account" | "ServiceAccount" => "ServiceAccount".to_string(),
        other => super::schema_generator::to_pascal_case(other),
    }
}
