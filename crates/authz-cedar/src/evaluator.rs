use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use authz_types::{
    BatchEvaluationRequest, BatchEvaluationResponse, EvaluationRequest, EvaluationResponse,
};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl CedarRequestUids {
    pub fn resource_type(&self) -> &str {
        self.resource_type.as_str()
    }
}

pub struct CedarEntitiesContext {
    entities: Entities,
    context: Context,
}

pub struct PreparedCedarEvaluation {
    resource_type: String,
    request: Request,
    entities: Entities,
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
    let (subject_parents, resource_parents) = parent_refs_from_request_context(request);
    let (entities, context) =
        build_entities_and_context_ref_with_parents(request, &subject_parents, &resource_parents)
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
    let action_name = request.action.name.clone();
    let subject_type = request.subject.subject_type.as_str().to_string();
    let subject_id = request.subject.id.clone();
    let resource_id = request.resource.id.clone();

    let action = EntityUid::from_str(&format!(
        "Authz::Action::\"{}:{}\"",
        resource_type, action_name
    ))
    .map_err(|e| CedarError::evaluation(e.to_string()))?;
    let principal = principal_uid(&subject_type, &subject_id).map_err(CedarError::evaluation)?;
    let resource = resource_uid(&resource_type, &resource_id).map_err(CedarError::evaluation)?;

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
    let mut request = request;
    let (subject_parents, resource_parents) = take_parent_refs_from_request_context(&mut request);
    prepare_entities_and_context_owned_with_parents(request, &subject_parents, &resource_parents)
}

pub fn prepare_entities_and_context_owned_with_parents(
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
) -> Result<CedarEntitiesContext, CedarError> {
    let (entities, context) =
        build_entities_and_context_owned_with_parents(request, subject_parents, resource_parents)
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
    let mut request = request;
    let (subject_parents, resource_parents) = take_parent_refs_from_request_context(&mut request);
    let uids = prepare_request_uids(&request)?;
    let entities_context = prepare_entities_and_context_owned_with_parents(
        request,
        &subject_parents,
        &resource_parents,
    )?;
    prepare_request_from_parts(uids, entities_context)
}

pub fn prepare_evaluation_owned_with_parents(
    request: EvaluationRequest,
    subject_parents: &[EntityParentRef],
    resource_parents: &[EntityParentRef],
) -> Result<PreparedCedarEvaluation, CedarError> {
    let uids = prepare_request_uids(&request)?;
    let entities_context = prepare_entities_and_context_owned_with_parents(
        request,
        subject_parents,
        resource_parents,
    )?;
    prepare_request_from_parts(uids, entities_context)
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

    let response = Authorizer::new().is_authorized(&request, policy_set, &entities);
    Ok(response_from_decision(response.decision()))
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
        principal_type,
        principal_id: request.subject.id.clone(),
        principal_attrs,
        resource_type,
        resource_id: request.resource.id.clone(),
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
    let resource_props = request
        .resource
        .properties
        .unwrap_or_else(|| serde_json::Value::Object(Default::default()))
        .as_object()
        .cloned()
        .unwrap_or_default();

    let mut context_attrs = request
        .context
        .map(|ctx| ctx.attributes)
        .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
    remove_parent_keys_from_context(&mut context_attrs);
    let context = context_from_value(context_attrs)?;

    let entities = build_entities_from_converted_inputs(EntityConvertedBuildInputs {
        principal_type,
        principal_id: request.subject.id,
        principal_attrs: restricted_attrs_from_map(principal_props)?,
        resource_type,
        resource_id: request.resource.id,
        resource_attrs: restricted_attrs_from_map(resource_props)?,
        subject_parents: subject_parents.to_vec(),
        resource_parents: resource_parents.to_vec(),
    })?;

    Ok((entities, context))
}

struct EntityConvertedBuildInputs {
    principal_type: String,
    principal_id: String,
    principal_attrs: Vec<(String, RestrictedExpression)>,
    resource_type: String,
    resource_id: String,
    resource_attrs: Vec<(String, RestrictedExpression)>,
    subject_parents: Vec<EntityParentRef>,
    resource_parents: Vec<EntityParentRef>,
}

fn build_entities_from_converted_inputs(
    inputs: EntityConvertedBuildInputs,
) -> Result<Entities, String> {
    let EntityConvertedBuildInputs {
        principal_type,
        principal_id,
        principal_attrs,
        resource_type,
        resource_id,
        resource_attrs,
        subject_parents,
        resource_parents,
    } = inputs;

    let principal_uid = principal_uid(principal_type.as_str(), principal_id.as_str())?;
    let resource_uid = resource_uid(resource_type.as_str(), resource_id.as_str())?;
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

fn context_from_value(context: serde_json::Value) -> Result<Context, String> {
    let serde_json::Value::Object(map) = context else {
        return Err("context must be an object".to_string());
    };
    if map.is_empty() {
        return Ok(Context::empty());
    }
    let mut pairs = Vec::with_capacity(map.len());
    for (key, value) in map {
        pairs.push((key, restricted_expr_from_value(value)?));
    }
    Context::from_pairs(pairs).map_err(|e| e.to_string())
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
    let entity_id = EntityId::from_str(entity_id).map_err(|e| e.to_string())?;
    Ok(EntityUid::from_type_name_and_id(type_name, entity_id))
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

fn take_parent_refs_from_request_context(
    request: &mut EvaluationRequest,
) -> (Vec<EntityParentRef>, Vec<EntityParentRef>) {
    let Some(context) = request.context.as_mut() else {
        return (Vec::new(), Vec::new());
    };
    let Some(map) = context.attributes.as_object_mut() else {
        return (Vec::new(), Vec::new());
    };

    let subject_parents = map
        .remove("subject_parents")
        .map(|value| parent_refs_from_value_ref(&value))
        .unwrap_or_default();
    let resource_parents = map
        .remove("resource_parents")
        .map(|value| parent_refs_from_value_ref(&value))
        .unwrap_or_default();
    (subject_parents, resource_parents)
}

fn parent_refs_from_request_context(
    request: &EvaluationRequest,
) -> (Vec<EntityParentRef>, Vec<EntityParentRef>) {
    let Some(context) = request.context.as_ref() else {
        return (Vec::new(), Vec::new());
    };
    let Some(map) = context.attributes.as_object() else {
        return (Vec::new(), Vec::new());
    };

    let subject_parents = map
        .get("subject_parents")
        .map(parent_refs_from_value_ref)
        .unwrap_or_default();
    let resource_parents = map
        .get("resource_parents")
        .map(parent_refs_from_value_ref)
        .unwrap_or_default();
    (subject_parents, resource_parents)
}

fn parent_refs_from_value_ref(value: &serde_json::Value) -> Vec<EntityParentRef> {
    let serde_json::Value::Array(parents) = value else {
        return Vec::new();
    };

    let mut parsed = Vec::with_capacity(parents.len());
    for parent in parents {
        let Some(parent_obj) = parent.as_object() else {
            continue;
        };
        let Some(parent_type) = parent_obj.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(parent_id) = parent_obj.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        parsed.push(EntityParentRef {
            parent_type: parent_type.to_string(),
            parent_id: parent_id.to_string(),
        });
    }
    parsed
}

fn principal_uid(subject_type: &str, id: &str) -> Result<EntityUid, String> {
    let entity_type = subject_entity_type(subject_type);
    EntityUid::from_str(&format!("Authz::{entity_type}::\"{id}\"")).map_err(|e| e.to_string())
}

fn resource_uid(resource_type: &str, id: &str) -> Result<EntityUid, String> {
    let entity_type = super::schema_generator::to_pascal_case(resource_type);
    EntityUid::from_str(&format!("Authz::{entity_type}::\"{id}\"")).map_err(|e| e.to_string())
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
