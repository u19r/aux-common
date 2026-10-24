#![no_main]

use std::sync::OnceLock;

use authz_cedar::{
    CedarInternalContext, EntityParentRef, evaluate_prepared_with_policy_sets, parse_policy_sets,
    prepare_evaluation_owned_with_trusted_parents_and_internal_context,
};
use authz_types::{
    AccessAssignmentMode, AccessAssignmentPolicySpec, Action, ActionDefinition, ConfigurationModel,
    Permission, PermissionActionRef, PermissionId, Resource, ResourceType, Role, RolePermission,
    Scope, Subject,
};
use libfuzzer_sys::fuzz_target;

// Structured decision oracle for role-gated Cedar authorization on the
// trusted-parents path (the path production enrichment feeds, where parent
// relationships arrive as explicit arguments rather than request bytes).
//
// The bundle grants `read` and `write` on `document` to the `editor` role
// with tenant scope and nothing else. The oracle: evaluation may only
// report allow when the action is `read` or `write` on a `document` and
// the subject parents include the `editor` role. Every byte-driven edit
// models an authorization bypass shape: membership in a wrong or unknown
// role, membership confusion across subject types, action confusion and
// case games, unknown resource types, duplicate or malformed parent
// references, and resource substitution. Any allow outside the shape
// confuses one role, action, or resource for another.
fn seed_bundle() -> authz_cedar::CompiledBundle {
    let config = ConfigurationModel {
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
            id: "document:editor".into(),
            actions: vec![
                PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: "read".into(),
                },
                PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: "write".into(),
                },
            ],
            not_actions: vec![],
            name: "Editor".into(),
            description: None,
        }],
        roles: vec![Role {
            id: "editor".into(),
            name: "Editor".into(),
            description: None,
            permissions: vec![RolePermission {
                permission_id: PermissionId::new("document:editor").expect("permission id"),
                scopes: vec![Scope::Tenant],
            }],
            actions: vec![],
            not_actions: vec![],
            assignment_policy: AccessAssignmentPolicySpec {
                assignment_mode: AccessAssignmentMode::PermanentOrTemporary,
                maximum_duration_seconds: None,
            },
        }],
        description: None,
        scope_mappings: Vec::new(),
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: std::collections::HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("seed config validates");
    authz_cedar::compile_policy_bundle(&config, 1).expect("seed bundle compiles")
}

fn subject_pool(variant: u8) -> Subject {
    match variant % 4 {
        0 => Subject::user("u1"),
        1 => Subject::user("u2"),
        2 => Subject::group("u1"),
        _ => Subject::user(""),
    }
}

fn resource_pool(variant: u8) -> Resource {
    match variant % 4 {
        0 => Resource::new("document", "doc1"),
        1 => Resource::new("document", "doc2"),
        2 => Resource::new("document", ""),
        _ => Resource::new("other", "doc1"),
    }
}

fn action_pool(variant: u8) -> Action {
    match variant % 6 {
        0 => Action::new("read"),
        1 => Action::new("write"),
        2 => Action::new("READ"),
        3 => Action::new(""),
        4 => Action::new("delete"),
        _ => Action::new("read "),
    }
}

fn parents_pool(variant: u8) -> Vec<EntityParentRef> {
    let parent = |parent_type: &str, parent_id: &str| EntityParentRef {
        parent_type: parent_type.to_string(),
        parent_id: parent_id.to_string(),
    };
    match variant % 8 {
        0 => vec![parent("role", "editor")],
        1 => vec![parent("role", "viewer")],
        2 => vec![parent("group", "editor")],
        3 => vec![parent("role", "")],
        4 => vec![parent("", "editor")],
        5 => vec![parent("role", "editor"), parent("role", "editor")],
        6 => vec![parent("role", "editor"), parent("group", "g1")],
        _ => Vec::new(),
    }
}

fn default_internal_context(token_present: bool) -> CedarInternalContext {
    CedarInternalContext {
        token_present,
        token_valid: true,
        token_resource_filter_enabled: false,
        token_resource_filter: Vec::new(),
        resource_scopes: Vec::new(),
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

fn allows_shape(
    action: &str,
    resource_type: &str,
    parents: &[EntityParentRef],
    token_present: bool,
) -> bool {
    (action == "read" || action == "write")
        && resource_type == "document"
        && parents
            .iter()
            .any(|parent| parent.parent_type == "role" && parent.parent_id == "editor")
        && !token_present
}

struct Fixture {
    bundle: authz_cedar::CompiledBundle,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let bundle = seed_bundle();
        let policy_sets = parse_policy_sets(&bundle).expect("seed parses");
        let prepared = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
            authz_types::EvaluationRequest {
                subject: Subject::user("u1"),
                resource: Resource::new("document", "doc1"),
                action: Action::new("write"),
                context: None,
                jwt_context: None,
                session_context: None,
                token_context: None,
            },
            &[EntityParentRef {
                parent_type: "role".to_string(),
                parent_id: "editor".to_string(),
            }],
            &[],
            default_internal_context(false),
        )
        .expect("seed prepares");
        let decision = evaluate_prepared_with_policy_sets(&policy_sets, prepared)
            .expect("seed evaluates")
            .decision;
        assert!(decision, "seed must allow");
        Fixture { bundle }
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let fixture = fixture();
    let policy_sets = parse_policy_sets(&fixture.bundle).expect("bundle parses");
    let select = |byte: u8, extra: u8| byte.wrapping_add(extra);
    let (subject_byte, resource_byte, action_byte, parents_byte, token_byte) = if data.len() > 10 {
        (
            select(data[0], data[5]),
            select(data[1], data[6]),
            select(data[2], data[7]),
            select(data[3], data[8]),
            select(data[4], data[9]),
        )
    } else {
        (data[0], data[1], data[2], data[3], data[4])
    };
    let request = authz_types::EvaluationRequest {
        subject: subject_pool(subject_byte),
        resource: resource_pool(resource_byte),
        action: action_pool(action_byte),
        context: None,
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    let parents = parents_pool(parents_byte);
    let token_present = token_byte % 2 == 0;
    let action = request.action.name.clone();
    let resource_type = request.resource.resource_type.clone();
    let allowed = prepare_evaluation_owned_with_trusted_parents_and_internal_context(
        request,
        &parents,
        &[],
        default_internal_context(token_present),
    )
    .ok()
    .and_then(|prepared| {
        evaluate_prepared_with_policy_sets(&policy_sets, prepared)
            .ok()
            .map(|response| response.decision)
    })
    .unwrap_or(false);
    if !allowed {
        return;
    }
    assert!(
        allows_shape(&action, &resource_type, &parents, token_present),
        "authorization bypass: role-gated allow outside the editor shape"
    );
});
