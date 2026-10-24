use std::collections::HashMap;

use authz_cedar::{
    BUNDLE_MANIFEST_MAX_BYTES, BUNDLE_POLICY_MAX_BYTES, CedarInternalContext, CedarResourceScope,
    CedarUidRegistry, CompiledBundle, EntityParentRef, MAX_POLICY_SLICES, MAX_SCHEMA_SLICES,
    PolicySlice, SLICE_SOFT_MAX_BYTES, SliceMeta, compile_policy_bundle,
    evaluate_batch_frame_action_with_policy_sets_error_diagnostics,
    evaluate_prepared_with_policy_sets, evaluate_prepared_with_policy_sets_diagnostics,
    evaluate_prepared_with_policy_sets_error_diagnostics, parse_policy_sets,
    prepare_batch_frame_owned_with_registry_and_trusted_internal_context,
    prepare_entities_and_context_owned_with_trusted_parents, prepare_evaluation_owned,
    prepare_evaluation_owned_with_registry_and_trusted_internal_context,
    prepare_evaluation_owned_with_trusted_parents_and_internal_context, prepare_request_from_parts,
    prepare_request_uids, validate_bundle_for_config, validate_bundle_integrity,
};
use authz_types::{
    Action, ActionDefinition, ConfigurationModel, Context, EvaluationRequest, Permission,
    PermissionActionRef, PermissionId, Resource, ResourceType, Role, RolePermission, Scope,
    Subject,
};
use sha2::{Digest, Sha256};

fn minimal_config() -> authz_types::ValidatedConfigurationModel {
    ConfigurationModel {
        version: 1,
        resource_types: vec![ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: Vec::new(),
        roles: Vec::new(),
        scope_mappings: Vec::new(),
        authn_providers: Vec::new(),
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
    .into_validated()
    .expect("minimal configuration should validate")
}

fn role_config(scope: Scope) -> authz_types::ValidatedConfigurationModel {
    ConfigurationModel {
        version: 1,
        resource_types: vec![ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![
                ActionDefinition {
                    name: "read".into(),
                    description: None,
                },
                ActionDefinition {
                    name: "write".into(),
                    description: None,
                },
            ],
            context_schema: None,
        }],
        permissions: vec![Permission {
            id: "document:reader".into(),
            actions: vec![PermissionActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
            }],
            not_actions: Vec::new(),
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![scope],
            }],
            actions: Vec::new(),
            not_actions: Vec::new(),
            assignment_policy: authz_types::AccessAssignmentPolicySpec {
                assignment_mode: authz_types::AccessAssignmentMode::PermanentOrTemporary,
                maximum_duration_seconds: None,
            },
        }],
        scope_mappings: Vec::new(),
        authn_providers: Vec::new(),
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
        description: None,
    }
    .into_validated()
    .expect("role configuration should validate")
}

fn request(resource_type: &str) -> EvaluationRequest {
    EvaluationRequest {
        subject: Subject::user("user-1"),
        resource: Resource::new(resource_type, "resource-1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    }
}

fn internal_context() -> CedarInternalContext {
    CedarInternalContext {
        token_present: false,
        token_valid: true,
        token_resource_filter_enabled: false,
        token_resource_filter: Vec::new(),
        resource_scopes: Vec::<CedarResourceScope>::new(),
        token_org_id_present: false,
        token_org_id: String::new(),
        token_owner_org_ids: Vec::new(),
        allowed_actions: Vec::new(),
        session_present: false,
        session_acr: 0,
        session_amr: Vec::new(),
        session_auth_age_present: false,
        session_auth_age_seconds: 0,
        session_mfa_age_present: false,
        session_mfa_age_seconds: 0,
    }
}

fn digest(payload: &str) -> String {
    Sha256::digest(payload.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn assert_integrity_error(bundle: CompiledBundle, expected: &str) {
    let error = validate_bundle_integrity(&bundle).expect_err("tampered bundle must be rejected");
    assert!(
        error.to_string().contains(expected),
        "expected {expected:?}, got {error}"
    );
}

#[test]
fn given_bundle_when_structural_limits_are_exceeded_then_integrity_rejects() {
    let config = minimal_config();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");

    let mut schema_count = bundle.clone();
    schema_count.schema_slices = vec![bundle.schema_slices[0].clone(); MAX_SCHEMA_SLICES + 1];
    assert_integrity_error(schema_count, "schema slice count exceeds maximum");

    let mut policy_count = bundle.clone();
    policy_count.policy_slices = vec![bundle.policy_slices[0].clone(); MAX_POLICY_SLICES + 1];
    let parse_error = parse_policy_sets(&policy_count)
        .expect_err("policy count must be rejected before policy parsing");
    assert!(
        parse_error
            .to_string()
            .contains("policy slice count exceeds maximum")
    );
    assert_integrity_error(policy_count, "policy slice count exceeds maximum");

    let mut schema_manifest_count = bundle.clone();
    schema_manifest_count.manifest.schema_slices =
        vec![bundle.manifest.schema_slices[0].clone(); MAX_SCHEMA_SLICES + 1];
    assert_integrity_error(
        schema_manifest_count,
        "schema manifest count exceeds maximum",
    );

    let mut policy_manifest_count = bundle.clone();
    policy_manifest_count.manifest.policy_slices =
        vec![bundle.manifest.policy_slices[0].clone(); MAX_POLICY_SLICES + 1];
    assert_integrity_error(
        policy_manifest_count,
        "policy manifest count exceeds maximum",
    );

    let mut oversized_schema = bundle.clone();
    oversized_schema.schema_slices[0].schema_json = "x".repeat(SLICE_SOFT_MAX_BYTES + 1);
    assert_integrity_error(oversized_schema, "schema slice exceeds size limit");

    let mut oversized_base_schema = bundle.clone();
    oversized_base_schema.base_schema_json = "x".repeat(SLICE_SOFT_MAX_BYTES + 1);
    assert_integrity_error(oversized_base_schema, "base schema exceeds size limit");

    let mut oversized_manifest = bundle.clone();
    oversized_manifest.manifest.schema_slices[0].key = "x".repeat(BUNDLE_MANIFEST_MAX_BYTES + 1);
    assert_integrity_error(oversized_manifest, "bundle manifest exceeds size limit");

    let mut version_mismatch = bundle.clone();
    version_mismatch.manifest.version += 1;
    assert_integrity_error(
        version_mismatch,
        "manifest version does not match bundle version",
    );

    let mut oversized_policy = bundle.clone();
    oversized_policy.policy_slices[0].policies_json = "x".repeat(SLICE_SOFT_MAX_BYTES + 1);
    let error = parse_policy_sets(&oversized_policy)
        .expect_err("oversized policy payload must be rejected before hashing");
    assert!(error.to_string().contains("policy slice exceeds maximum"));
    assert_integrity_error(oversized_policy, "policy slice exceeds size limit");
}

#[test]
fn given_policy_payloads_when_aggregate_is_exact_then_integrity_accepts_and_plus_one_rejects() {
    let config = minimal_config();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let payload_size = 64 * 1024;
    let exact_count = BUNDLE_POLICY_MAX_BYTES / payload_size;
    let payload = "x".repeat(payload_size);
    let payload_digest = digest(&payload);

    let mut exact = bundle.clone();
    exact.policy_slices = (0..exact_count)
        .map(|_| PolicySlice {
            resource_type: "document".into(),
            policies_json: payload.clone(),
            size_bytes: payload_size,
        })
        .collect();
    exact.manifest.policy_slices = (0..exact_count)
        .map(|index| SliceMeta {
            key: if index == 0 {
                "document".into()
            } else {
                format!("document#{index}")
            },
            size_bytes: payload_size,
            sha256: Some(payload_digest.clone()),
        })
        .collect();
    validate_bundle_integrity(&exact).expect("the exact aggregate limit is valid");

    let mut plus_one = exact;
    plus_one.policy_slices.push(PolicySlice {
        resource_type: "document".into(),
        policies_json: payload,
        size_bytes: payload_size,
    });
    plus_one.manifest.policy_slices.push(SliceMeta {
        key: format!("document#{exact_count}"),
        size_bytes: payload_size,
        sha256: Some(payload_digest),
    });
    assert_integrity_error(plus_one, "policy bundle exceeds maximum");
}

#[test]
fn given_bundle_when_integrity_metadata_is_tampered_then_rejects() {
    let config = minimal_config();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");

    let mut empty_fingerprint = bundle.clone();
    empty_fingerprint.manifest.config_fingerprint = Some(String::new());
    assert_integrity_error(empty_fingerprint, "configuration fingerprint is empty");

    let mut invalid_fingerprint = bundle.clone();
    invalid_fingerprint.manifest.config_fingerprint = Some("G".repeat(64));
    assert_integrity_error(
        invalid_fingerprint,
        "configuration fingerprint is not a SHA-256 hex digest",
    );

    let mut empty_schema_resource = bundle.clone();
    empty_schema_resource.schema_slices[0].resource_type.clear();
    assert_integrity_error(
        empty_schema_resource,
        "schema slice has empty resource type",
    );

    let mut schema_size = bundle.clone();
    schema_size.schema_slices[0].size_bytes += 1;
    assert_integrity_error(schema_size, "schema slice size metadata mismatch");

    let mut empty_manifest_key = bundle.clone();
    empty_manifest_key.manifest.schema_slices[0].key.clear();
    assert_integrity_error(empty_manifest_key, "slice manifest key is empty");

    let mut invalid_digest = bundle.clone();
    invalid_digest.manifest.schema_slices[0].sha256 = Some("not-a-digest".into());
    assert_integrity_error(invalid_digest, "slice digest is not a SHA-256 hex digest");

    let mut schema_manifest_mismatch = bundle.clone();
    schema_manifest_mismatch.manifest.schema_slices[0].key = "other".into();
    assert_integrity_error(schema_manifest_mismatch, "schema slice manifest mismatch");

    let mut empty_policy_resource = bundle.clone();
    empty_policy_resource.policy_slices[0].resource_type.clear();
    assert_integrity_error(
        empty_policy_resource,
        "policy slice has empty resource type",
    );

    let mut policy_size = bundle.clone();
    policy_size.policy_slices[0].size_bytes += 1;
    assert_integrity_error(policy_size, "policy slice size metadata mismatch");

    let mut invalid_policy_key = bundle.clone();
    invalid_policy_key.manifest.policy_slices[0].key = "document#invalid".into();
    assert_integrity_error(invalid_policy_key, "invalid policy slice manifest key");

    let mut noncontiguous_keys = bundle.clone();
    noncontiguous_keys
        .policy_slices
        .push(bundle.policy_slices[0].clone());
    let second_key = SliceMeta {
        key: "document#2".into(),
        ..bundle.manifest.policy_slices[0].clone()
    };
    noncontiguous_keys.manifest.policy_slices.push(second_key);
    assert_integrity_error(
        noncontiguous_keys,
        "policy slice manifest keys are not contiguous",
    );

    let mut empty_digest = bundle.clone();
    empty_digest.manifest.base_schema_sha256 = Some(String::new());
    assert_integrity_error(empty_digest, "base schema digest is empty");

    let mut payload_mismatch = bundle.clone();
    payload_mismatch.base_schema_json.push('x');
    payload_mismatch.manifest.base_schema_sha256 = Some(digest(&payload_mismatch.base_schema_json));
    validate_bundle_integrity(&payload_mismatch).expect("updated digest should pass integrity");
    let error = validate_bundle_for_config(&config, &payload_mismatch)
        .expect_err("payload from another bundle must be rejected");
    assert!(error.to_string().contains("bundle payload does not match"));
}

#[test]
fn given_typed_context_and_trusted_parents_when_evaluating_then_parent_controls_allow() {
    let config = role_config(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");
    let parent = [EntityParentRef {
        parent_type: "role".into(),
        parent_id: "reader".into(),
    }];

    let prepared = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request("document"),
        &parent,
        &[],
        internal_context(),
    )
    .expect("typed trusted-parent preparation");
    let response = evaluate_prepared_with_policy_sets(&policy_sets, prepared)
        .expect("trusted-parent evaluation should return a decision");
    assert!(response.decision);

    let prepared = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request("document"),
        &[],
        &[],
        internal_context(),
    )
    .expect("typed preparation without parent");
    let response = evaluate_prepared_with_policy_sets(&policy_sets, prepared)
        .expect("missing trusted parent should return a decision");
    assert!(!response.decision);
}

#[test]
fn given_prepared_request_for_unknown_resource_when_evaluating_diagnostics_then_denies() {
    let config = minimal_config();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");

    let prepared = prepare_evaluation_owned(request("missing")).expect("prepared request");
    let response = evaluate_prepared_with_policy_sets(&policy_sets, prepared)
        .expect("missing policy slice should be a decision");
    assert!(!response.decision);
    assert_eq!(
        response.context.and_then(|context| context.reason),
        Some("policy slice not found for missing".into())
    );

    let prepared = prepare_evaluation_owned(request("missing")).expect("prepared request");
    let diagnostics = evaluate_prepared_with_policy_sets_error_diagnostics(&policy_sets, prepared)
        .expect("missing policy diagnostics should be returned");
    assert!(!diagnostics.response.decision);
    assert_eq!(diagnostics.determining_policy_count, 0);
    assert!(diagnostics.evaluation_errors.is_empty());

    let prepared = prepare_evaluation_owned(request("missing")).expect("prepared request");
    let internal = evaluate_prepared_with_policy_sets_diagnostics(&policy_sets, prepared)
        .expect("missing policy internal diagnostics should be returned");
    assert!(!internal.response.decision);
    assert!(internal.determining_policy_ids.is_empty());
    assert!(internal.evaluation_errors.is_empty());
}

#[test]
fn given_real_policy_when_evaluating_diagnostics_then_decision_and_determining_metadata_match() {
    let config = role_config(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");
    let parent = [EntityParentRef {
        parent_type: "role".into(),
        parent_id: "reader".into(),
    }];

    let prepared = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request("document"),
        &parent,
        &[],
        internal_context(),
    )
    .expect("allow preparation");
    let allow = evaluate_prepared_with_policy_sets_diagnostics(&policy_sets, prepared)
        .expect("allow diagnostics");
    assert!(allow.response.decision);
    assert!(!allow.determining_policy_ids.is_empty());
    assert!(allow.evaluation_errors.is_empty());

    let prepared = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request("document"),
        &[],
        &[],
        internal_context(),
    )
    .expect("deny preparation");
    let deny = evaluate_prepared_with_policy_sets_error_diagnostics(&policy_sets, prepared)
        .expect("deny diagnostics");
    assert!(!deny.response.decision);
    assert_eq!(deny.determining_policy_count, 0);
    assert!(deny.evaluation_errors.is_empty());
}

#[test]
fn given_non_object_context_when_preparing_owned_entities_then_rejects() {
    let mut request = request("document");
    request.context = Some(Context::new(serde_json::Value::String("invalid".into())));

    let error = match prepare_entities_and_context_owned_with_trusted_parents(request, &[], &[]) {
        Ok(_) => panic!("owned preparation must reject non-object context"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("context must be an object"));
}

#[test]
fn given_registry_and_internal_context_when_preparing_single_and_batch_frames_then_ids_are_bound() {
    let config = role_config(Scope::Own);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");
    let registry = CedarUidRegistry::new(&config).expect("uid registry");
    let parent = [EntityParentRef {
        parent_type: "role".into(),
        parent_id: "reader".into(),
    }];
    let mut request = request("document");
    request.resource.properties = Some(serde_json::json!({"owner_id": "user-1"}));

    let prepared = prepare_evaluation_owned_with_registry_and_trusted_internal_context(
        &registry,
        request.clone(),
        &parent,
        &[],
        internal_context(),
    )
    .expect("registry-backed preparation");
    let response =
        evaluate_prepared_with_policy_sets(&policy_sets, prepared).expect("prepared evaluation");
    assert!(response.decision);

    let frame = prepare_batch_frame_owned_with_registry_and_trusted_internal_context(
        &registry,
        request.clone(),
        &parent,
        &[],
        internal_context(),
    )
    .expect("registry-backed batch frame");
    let action = registry
        .prepare_action("document", "read")
        .expect("configured action");
    let diagnostics = evaluate_batch_frame_action_with_policy_sets_error_diagnostics(
        &policy_sets,
        &frame,
        &action,
    )
    .expect("batch frame evaluation");
    assert!(diagnostics.response.decision);

    let write_action = registry
        .prepare_action("document", "write")
        .expect("configured write action");
    let write_frame = prepare_batch_frame_owned_with_registry_and_trusted_internal_context(
        &registry,
        request.clone(),
        &parent,
        &[],
        internal_context(),
    )
    .expect("write frame");
    let write = evaluate_batch_frame_action_with_policy_sets_error_diagnostics(
        &policy_sets,
        &write_frame,
        &write_action,
    )
    .expect("write evaluation");
    assert!(!write.response.decision);

    let mut other_owner = request.clone();
    other_owner.resource.properties = Some(serde_json::json!({"owner_id": "other-user"}));
    let other_frame = prepare_batch_frame_owned_with_registry_and_trusted_internal_context(
        &registry,
        other_owner,
        &parent,
        &[],
        internal_context(),
    )
    .expect("other-owner frame");
    let other_owner_result = evaluate_batch_frame_action_with_policy_sets_error_diagnostics(
        &policy_sets,
        &other_frame,
        &action,
    )
    .expect("other-owner evaluation");
    assert!(!other_owner_result.response.decision);

    let uids = prepare_request_uids(&request).expect("request UIDs");
    let entities_context =
        prepare_entities_and_context_owned_with_trusted_parents(request.clone(), &parent, &[])
            .expect("standalone entities and context");
    let prepared = prepare_request_from_parts(uids, entities_context).expect("prepared request");
    assert_eq!(prepared.resource_type(), "document");
}
