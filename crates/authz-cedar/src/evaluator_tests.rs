use std::{collections::HashMap, str::FromStr};

use authz_types::{
    AcrLevel, Action, BatchEvaluationRequest, ConfigurationModel, PermissionActionRef,
    PermissionId, Resource, Scope, StepUpRule, Subject,
};
use serde_json::{Map, Value};

use crate::{
    EntityParentRef, compile_policy_bundle, evaluate as evaluate_untrusted, evaluate_batch,
    evaluate_batch_with_policy_sets, evaluate_owned_with_policy_sets,
    evaluate_owned_with_policy_sets_with_parents, evaluate_with_policy_sets, parse_policy_sets,
    prepare_request_uids,
};

#[test]
fn typed_uid_construction_round_trips_all_validated_identifier_shapes() {
    let identifiers = [
        "quote\"id".to_string(),
        "slash/id".to_string(),
        "colon:id".to_string(),
        "unicode-用户-🚀".to_string(),
        "x".repeat(authz_types::MAX_IDENTIFIER_LEN),
    ];

    for identifier in identifiers {
        let request = authz_types::EvaluationRequest {
            subject: Subject::user(identifier.clone()),
            resource: Resource::new("document", identifier.clone()),
            action: Action::new("read"),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        };
        let uids = prepare_request_uids(&request).expect("typed UIDs");
        for uid in [uids.principal(), uids.action(), uids.resource()] {
            let reparsed = cedar_policy::EntityUid::from_str(&uid.to_string())
                .expect("rendered UID remains valid Cedar syntax");
            assert_eq!(&reparsed, uid);
        }
    }
}

fn evaluate(
    bundle: &crate::CompiledBundle,
    request: &authz_types::EvaluationRequest,
) -> Result<authz_types::EvaluationResponse, crate::CedarError> {
    let policy_sets = parse_policy_sets(bundle)?;
    let subject_parents = parent_refs_from_test_context(request, "subject_parents");
    let resource_parents = parent_refs_from_test_context(request, "resource_parents");
    evaluate_owned_with_policy_sets_with_parents(
        &policy_sets,
        request.clone(),
        &subject_parents,
        &resource_parents,
    )
}

fn parent_refs_from_test_context(
    request: &authz_types::EvaluationRequest,
    key: &str,
) -> Vec<EntityParentRef> {
    request
        .context
        .as_ref()
        .and_then(|context| context.attributes.get(key))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|parent| {
            Some(EntityParentRef {
                parent_type: parent.get("type")?.as_str()?.to_string(),
                parent_id: parent.get("id")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn default_internal_context() -> Value {
    serde_json::json!({
        "token_present": false,
        "token_valid": true,
        "token_resource_filter_enabled": false,
        "token_resource_filter": [],
        "token_org_id_present": false,
        "token_org_id": "",
        "token_owner_org_ids": [],
        "allowed_actions": [],
        "resource_scopes": [],
        "session_present": false,
        "session_acr": 0,
        "session_amr": [],
        "session_auth_age_present": false,
        "session_auth_age_seconds": 0,
        "session_mfa_age_present": false,
        "session_mfa_age_seconds": 0
    })
}

fn internal_context_with(overrides: Value) -> Value {
    let mut base = match default_internal_context() {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    if let Value::Object(map) = overrides {
        for (key, value) in map {
            base.insert(key, value);
        }
    }
    Value::Object(base)
}

fn context_with_internal(attrs: Value, internal: Value) -> authz_types::Context {
    let mut map = match attrs {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    map.insert("_authz".to_string(), internal);
    authz_types::Context::new(Value::Object(map))
}

fn resource_scope_record(role_id: &str, resource_type: &str, resource_id: &str) -> Value {
    let entity_type = format!(
        "Authz::{}",
        crate::schema_generator::to_pascal_case(resource_type)
    );
    serde_json::json!({
        "role": { "__entity": { "type": "Authz::Role", "id": role_id } },
        "resource": { "__entity": { "type": entity_type, "id": resource_id } }
    })
}

fn permission_actions(resource_type: &str, action_names: &[String]) -> Vec<PermissionActionRef> {
    action_names
        .iter()
        .map(|action_name| PermissionActionRef {
            resource_type: resource_type.into(),
            action_name: action_name.clone(),
        })
        .collect()
}

fn config_with_scope(scope: Scope) -> authz_types::ValidatedConfigurationModel {
    ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![scope],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config")
}

fn config_with_reader_writer_roles() -> authz_types::ValidatedConfigurationModel {
    ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![
                authz_types::ActionDefinition {
                    name: "read".into(),
                    description: None,
                },
                authz_types::ActionDefinition {
                    name: "write".into(),
                    description: None,
                },
            ],
            context_schema: None,
        }],
        permissions: vec![
            authz_types::Permission {
                id: "document:reader".into(),
                actions: permission_actions("document", &["read".into()]),
                not_actions: vec![],
                name: "Reader".into(),
                description: None,
            },
            authz_types::Permission {
                id: "document:writer".into(),
                actions: permission_actions("document", &["write".into()]),
                not_actions: vec![],
                name: "Writer".into(),
                description: None,
            },
        ],
        roles: vec![
            authz_types::Role {
                id: "reader".into(),
                name: "Reader".into(),
                description: None,
                permissions: vec![authz_types::RolePermission {
                    permission_id: PermissionId::new("document:reader").expect("permission id"),
                    scopes: vec![Scope::Tenant],
                }],
                actions: vec![],
                not_actions: vec![],
            },
            authz_types::Role {
                id: "writer".into(),
                name: "Writer".into(),
                description: None,
                permissions: vec![authz_types::RolePermission {
                    permission_id: PermissionId::new("document:writer").expect("permission id"),
                    scopes: vec![Scope::Tenant],
                }],
                actions: vec![],
                not_actions: vec![],
            },
        ],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config")
}

#[test]
fn evaluator_denies_until_implemented() {
    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };
    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation result");
    assert!(res.decision, "public read should be allowed");
}

#[test]
fn evaluate_with_policy_sets_rejects_null_context_values() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![],
        scope_mappings: vec![],
        description: None,
        authn_providers: vec![],
        step_up_rules: vec![],
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("parse policy sets");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(authz_types::Context::new(serde_json::json!({
            "_authz": default_internal_context(),
            "invalid_null": null
        }))),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let borrowed_error =
        evaluate_with_policy_sets(&policy_sets, &request).expect_err("null context should fail");
    let owned_error = evaluate_owned_with_policy_sets(&policy_sets, request)
        .expect_err("null context should fail");
    assert!(
        borrowed_error
            .to_string()
            .contains("null values are not supported"),
        "unexpected borrowed error: {borrowed_error}",
    );
    assert!(
        owned_error
            .to_string()
            .contains("null values are not supported"),
        "unexpected owned error: {owned_error}",
    );
}

#[test]
fn batch_evaluator_denies_all() {
    let batch = BatchEvaluationRequest {
        evaluations: vec![
            authz_types::EvaluationRequest {
                subject: Subject::user("u1"),
                resource: Resource::new("document", "doc1")
                    .with_properties(serde_json::json!({"is_public": true})),
                action: Action::new("read"),
                context: Some(context_with_internal(
                    Value::Object(Map::new()),
                    default_internal_context(),
                )),
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
            authz_types::EvaluationRequest {
                subject: Subject::user("u2"),
                resource: Resource::new("document", "doc2"),
                action: Action::new("write"),
                context: Some(context_with_internal(
                    Value::Object(Map::new()),
                    default_internal_context(),
                )),
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
        ],
        subject_override: None,
        token_context_override: None,
    };

    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");

    let res = evaluate_batch(&bundle, &batch).expect("batch");
    assert_eq!(2, res.evaluations.len());
    assert!(res.evaluations[0].decision, "public read should allow");
    assert!(
        !res.evaluations[1].decision,
        "write should deny without role"
    );
}

#[test]
fn evaluate_with_policy_sets_denies_when_policy_slice_is_missing() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![],
        scope_mappings: vec![],
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let mut bundle = compile_policy_bundle(&config, 1).expect("bundle");
    bundle
        .policy_slices
        .retain(|slice| slice.resource_type != "document");
    let policy_sets = parse_policy_sets(&bundle).expect("parse policy sets");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let response =
        evaluate_with_policy_sets(&policy_sets, &request).expect("evaluation should not error");

    assert!(!response.decision, "missing policy slice should deny");
}

#[test]
fn evaluate_with_preparsed_policy_sets_matches_standard_evaluate() {
    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");

    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let standard = evaluate(&bundle, &request).expect("standard");
    let parsed = evaluate_with_policy_sets(&policy_sets, &request).expect("parsed");
    assert_eq!(standard.decision, parsed.decision);
    assert_eq!(standard.challenge.is_some(), parsed.challenge.is_some());
}

#[test]
fn evaluate_batch_with_preparsed_policy_sets_matches_standard_batch() {
    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let policy_sets = parse_policy_sets(&bundle).expect("policy sets");

    let batch = BatchEvaluationRequest {
        evaluations: vec![
            authz_types::EvaluationRequest {
                subject: Subject::user("u1"),
                resource: Resource::new("document", "doc1")
                    .with_properties(serde_json::json!({"is_public": true})),
                action: Action::new("read"),
                context: Some(context_with_internal(
                    Value::Object(Map::new()),
                    default_internal_context(),
                )),
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
            authz_types::EvaluationRequest {
                subject: Subject::user("u2"),
                resource: Resource::new("document", "doc2"),
                action: Action::new("write"),
                context: Some(context_with_internal(
                    Value::Object(Map::new()),
                    default_internal_context(),
                )),
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
        ],
        subject_override: None,
        token_context_override: None,
    };

    let standard = evaluate_batch(&bundle, &batch).expect("standard");
    let parsed = evaluate_batch_with_policy_sets(&policy_sets, &batch).expect("parsed");
    assert_eq!(standard.evaluations.len(), parsed.evaluations.len());
    for (left, right) in standard.evaluations.iter().zip(parsed.evaluations.iter()) {
        assert_eq!(left.decision, right.decision);
        assert_eq!(left.challenge.is_some(), right.challenge.is_some());
    }
}

#[test]
fn evaluator_allows_role_membership_parent() {
    // Config: editor role permissions read+write on document (tenant scope)
    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![
                authz_types::ActionDefinition {
                    name: "read".into(),
                    description: None,
                },
                authz_types::ActionDefinition {
                    name: "write".into(),
                    description: None,
                },
            ],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:editor".into(),
            actions: permission_actions("document", &["read".into(), "write".into()]),
            not_actions: vec![],
            name: "Editor".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "editor".into(),
            name: "Editor".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![authz_types::Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("write"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "editor" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(res.decision, "role parent should allow write");
}

#[test]
fn untrusted_context_cannot_inject_role_membership_parent() {
    let config = config_with_reader_writer_roles();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("write"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "editor" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let response = evaluate_untrusted(&bundle, &request).expect("evaluation");

    assert!(
        !response.decision,
        "reserved context keys must not grant role ancestry"
    );
}

#[test]
fn evaluator_denies_when_token_filter_excludes_resource() {
    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![authz_types::Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "token_resource_filter_enabled": true,
        "token_resource_filter": [
            { "__entity": { "type": "Authz::Document", "id": "doc-allowed" } }
        ],
        "allowed_actions": ["document:read"]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc-blocked"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "token filter should deny");
}

#[test]
fn evaluator_denies_when_step_up_missing_session() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("read".to_string(), "mfa".to_string())]
                .into_iter()
                .collect(),
        },
    );
    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![authz_types::Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![authz_types::StepUpRule::require_acr(
            "mfa",
            "Require MFA",
            authz_types::AcrLevel::MultiFactor,
        )],
        step_up_config,
        default_step_up_rule: None,
    };

    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": false
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "step-up guard should deny without session");
}

#[test]
fn evaluator_denies_public_read_without_token_permission() {
    let config = authz_types::ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![],
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    };
    let config = config.into_validated().expect("valid config");
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "allowed_actions": []
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(Value::Object(Map::new()), internal)),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "token ceiling should deny public read");
}

#[test]
fn evaluator_allows_org_scope_when_org_matches() {
    let config = config_with_scope(Scope::Org);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"org_id": "org1"})),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"org_id": "org1"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(res.decision, "org scope should allow when org matches");
}

#[test]
fn evaluator_denies_org_scope_when_org_mismatched() {
    let config = config_with_scope(Scope::Org);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"org_id": "org1"})),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"org_id": "org2"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "org scope should deny when org mismatched");
}

#[test]
fn evaluator_allows_group_scope_when_group_matches() {
    let config = config_with_scope(Scope::Group);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"group_id": "g1"})),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"group_id": "g1"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(res.decision, "group scope should allow when group matches");
}

#[test]
fn evaluator_allows_own_scope_when_owner_matches() {
    let config = config_with_scope(Scope::Own);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"id": "u1"})),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"owner_id": "u1"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(res.decision, "own scope should allow when owner matches");
}

#[test]
fn evaluator_allows_shared_scope_when_user_is_shared() {
    let config = config_with_scope(Scope::Shared);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1").with_properties(serde_json::json!({"id": "u1"})),
        resource: Resource::new("document", "doc1").with_properties(serde_json::json!({
            "shared_with": ["u1"]
        })),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "shared scope should allow when user is in shared_with"
    );
}

#[test]
fn evaluator_allows_resource_scope_when_resource_matches() {
    let config = config_with_scope(Scope::resource("document"));
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "resource_scopes": [resource_scope_record("reader", "document", "doc1")]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "resource scope should allow when resource matches"
    );
}

#[test]
fn evaluator_denies_resource_scope_when_resource_not_scoped() {
    let config = config_with_scope(Scope::resource("document"));
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "resource_scopes": [resource_scope_record("reader", "document", "doc1")]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc2"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "resource scope should deny when resource is not scoped"
    );
}

#[test]
fn evaluator_allows_org_relationship_scope() {
    let config = config_with_scope(Scope::OrgRelationship);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1").with_properties(serde_json::json!({
            "org_parents": ["u1"]
        })),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "org relationship scope should allow when principal is in org_parents"
    );
}

#[test]
fn evaluator_allows_group_relationship_scope() {
    let config = config_with_scope(Scope::GroupRelationship);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1").with_properties(serde_json::json!({
            "group_parents": ["u1"]
        })),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "group relationship scope should allow when principal is in group_parents"
    );
}

#[test]
fn evaluator_denies_when_token_org_guard_missing_resource_org_id() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "token_org_id_present": true,
        "token_org_id": "org1",
        "token_owner_org_ids": ["org1"],
        "allowed_actions": ["document:read"]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "token org guard should deny without resource org_id"
    );
}

#[test]
fn evaluator_allows_when_token_org_guard_matches() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "token_org_id_present": true,
        "token_org_id": "org1",
        "token_owner_org_ids": ["org1"],
        "allowed_actions": ["document:read"]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"org_id": "org1"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "token org guard should allow when org matches"
    );
}

#[test]
fn evaluator_denies_when_token_action_not_allowed_even_with_role() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "allowed_actions": []
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "token action list should deny when action is not permitted"
    );
}

#[test]
fn evaluator_denies_recent_auth_when_auth_age_too_old() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("read".to_string(), "recent".to_string())]
                .into_iter()
                .collect(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_recent_auth("recent", "Recent", 300)],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 1,
        "session_auth_age_present": true,
        "session_auth_age_seconds": 900
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "recent auth rule should deny when auth age exceeds max"
    );
}

#[test]
fn evaluator_allows_recent_auth_when_auth_age_within_limit() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: None,
            action_rules: [("read".to_string(), "recent".to_string())]
                .into_iter()
                .collect(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_recent_auth("recent", "Recent", 300)],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 1,
        "session_auth_age_present": true,
        "session_auth_age_seconds": 120
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "recent auth rule should allow when auth age within max"
    );
}

#[test]
fn evaluator_denies_when_mfa_age_missing() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("mfa_age".to_string()),
            action_rules: HashMap::new(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule {
            rule_id: "mfa_age".into(),
            name: "MFA Age".into(),
            description: None,
            required_acr: AcrLevel::MultiFactor,
            max_auth_age_seconds: None,
            max_mfa_age_seconds: Some(120),
            required_amr: Vec::new(),
            applies_to_api_keys: true,
        }],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 2,
        "session_mfa_age_present": false
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "MFA age rule should deny when mfa age missing"
    );
}

#[test]
fn evaluator_allows_when_mfa_age_within_limit() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("mfa_age".to_string()),
            action_rules: HashMap::new(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule {
            rule_id: "mfa_age".into(),
            name: "MFA Age".into(),
            description: None,
            required_acr: AcrLevel::MultiFactor,
            max_auth_age_seconds: None,
            max_mfa_age_seconds: Some(120),
            required_amr: Vec::new(),
            applies_to_api_keys: true,
        }],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 2,
        "session_mfa_age_present": true,
        "session_mfa_age_seconds": 30
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(res.decision, "MFA age rule should allow when within limit");
}

#[test]
fn evaluator_denies_when_required_amr_missing() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("amr".to_string()),
            action_rules: HashMap::new(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_amr(
            "amr",
            "Require AMR",
            vec!["webauthn".into(), "otp".into()],
        )],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 2,
        "session_amr": []
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        !res.decision,
        "AMR rule should deny when no required amr present"
    );
}

#[test]
fn evaluator_allows_when_required_amr_present() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("amr".to_string()),
            action_rules: HashMap::new(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_amr(
            "amr",
            "Require AMR",
            vec!["webauthn".into(), "otp".into()],
        )],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "session_present": true,
        "session_acr": 2,
        "session_amr": ["otp"]
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "AMR rule should allow when required amr present"
    );
}

#[test]
fn evaluator_allows_step_up_with_token_when_api_keys_exempt() {
    let mut step_up_config = HashMap::new();
    step_up_config.insert(
        "document".to_string(),
        authz_types::StepUpConfig {
            default_rule: Some("recent".to_string()),
            action_rules: HashMap::new(),
        },
    );
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: vec![StepUpRule::require_recent_auth("recent", "Recent", 300)],
        step_up_config,
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let internal = internal_context_with(serde_json::json!({
        "token_present": true,
        "token_valid": true,
        "allowed_actions": ["document:read"],
        "session_present": false
    }));
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal,
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(
        res.decision,
        "step-up should allow token when api keys are exempt"
    );
}

#[test]
fn evaluator_denies_when_subject_has_wrong_linked_role() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![authz_types::Permission {
            id: "document:reader".into(),
            actions: permission_actions("document", &["read".into()]),
            not_actions: vec![],
            name: "Reader".into(),
            description: None,
        }],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![authz_types::RolePermission {
                permission_id: PermissionId::new("document:reader").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "writer" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "wrong linked role must not authorize");
}

#[test]
fn evaluator_keeps_allowed_actions_action_specific() {
    let config = config_with_reader_writer_roles();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("write"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "writer" } ]
            }),
            internal_context_with(serde_json::json!({
                "token_present": true,
                "token_valid": true,
                "allowed_actions": ["document:read"]
            })),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "read allowance must not leak into write");
}

#[test]
fn evaluator_denies_when_token_invalid_even_if_link_matches() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal_context_with(serde_json::json!({
                "token_present": true,
                "token_valid": false,
                "allowed_actions": ["document:read"]
            })),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "invalid token must fail closed");
}

#[test]
fn evaluator_denies_when_token_org_mismatches_resource_org() {
    let config = config_with_scope(Scope::Tenant);
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"org_id": "org-b"})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            internal_context_with(serde_json::json!({
                "token_present": true,
                "token_valid": true,
                "token_org_id_present": true,
                "token_org_id": "org-a",
                "token_owner_org_ids": ["org-a"],
                "allowed_actions": ["document:read"]
            })),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "foreign org resource must be denied");
}

#[test]
fn evaluator_forbid_link_overrides_matching_permit_link() {
    let config = ConfigurationModel {
        version: 1,
        resource_types: vec![authz_types::ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: vec![authz_types::ActionDefinition {
                name: "read".into(),
                description: None,
            }],
            context_schema: None,
        }],
        permissions: vec![],
        roles: vec![authz_types::Role {
            id: "reader".into(),
            name: "Reader".into(),
            description: None,
            permissions: vec![],
            actions: vec![authz_types::RoleActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
                scopes: vec![Scope::Tenant],
            }],
            not_actions: vec![authz_types::RoleActionRef {
                resource_type: "document".into(),
                action_name: "read".into(),
                scopes: vec![Scope::Tenant],
            }],
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("valid config");

    let bundle = compile_policy_bundle(&config, 1).expect("bundle");
    let req = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: Some(context_with_internal(
            serde_json::json!({
                "subject_parents": [ { "type": "role", "id": "reader" } ]
            }),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let res = evaluate(&bundle, &req).expect("evaluation");
    assert!(!res.decision, "forbid should override matching permit");
}

#[test]
fn evaluator_keeps_public_read_separate_from_role_policies() {
    let config = config_with_reader_writer_roles();
    let bundle = compile_policy_bundle(&config, 1).expect("bundle");

    let public_read = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let protected_write = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("write"),
        context: Some(context_with_internal(
            Value::Object(Map::new()),
            default_internal_context(),
        )),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };

    let public_read_res = evaluate(&bundle, &public_read).expect("public read");
    let protected_write_res = evaluate(&bundle, &protected_write).expect("protected write");
    assert!(public_read_res.decision, "public read should stay static");
    assert!(
        !protected_write_res.decision,
        "write should still require a matching role link"
    );
}

#[test]
fn diagnostics_retain_determining_policy_and_evaluation_error_categories() {
    use std::str::FromStr;

    use cedar_policy::PolicySet;

    let policies = PolicySet::from_str(
        r#"
        @id("allow_read") permit(principal, action, resource);
        @id("error_read") permit(principal, action, resource)
            when { resource.missing_attribute == "value" };
        "#,
    )
    .expect("policies");
    let request = authz_types::EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1"),
        action: Action::new("read"),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let prepared = crate::prepare_evaluation_owned(request).expect("prepared request");
    let result =
        crate::evaluator::evaluate_prepared_with_policy_set_diagnostics(&policies, prepared);

    assert!(result.response.decision);
    assert_eq!(result.determining_policy_ids.len(), 1);
    assert!(!result.determining_policy_ids[0].is_empty());
    assert_eq!(
        result.evaluation_errors,
        [crate::CedarEvaluationErrorCategory::AttributeMissing]
    );
}
