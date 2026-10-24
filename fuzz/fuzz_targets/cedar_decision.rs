#![no_main]

use std::sync::OnceLock;

use authz_cedar::{compile_policy_bundle, evaluate};
use authz_types::{Action, ConfigurationModel, Context, EvaluationRequest, Resource, Subject};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

// Structured decision oracle for Cedar authorization evaluation.
//
// The bundle carries only a static public-read policy over one resource
// type and action, with no roles, while the production path rejects every
// request carrying properties or context before evaluation. Bare requests
// deny by default for lack of readable properties. Together that yields
// the strongest possible oracle for this configuration: evaluation must
// never report allow, for any request. Every byte-driven edit models an
// authorization bypass shape: principal substitution and type confusion,
// resource substitution and flag tampering, action confusion and case
// games, unknown resource types, token-context smuggling, parent-injection
// through reserved context keys, and stripped-down bare requests. Any
// allow is an authorization bypass.
fn internal_context() -> Value {
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

fn context_with_internal(internal: Value) -> Context {
    let mut map = Map::new();
    map.insert("_authz".to_string(), internal);
    Context::new(Value::Object(map))
}

fn seed_bundle() -> authz_cedar::CompiledBundle {
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
        scope_mappings: Vec::new(),
        description: None,
        authn_providers: vec![],
        step_up_rules: Vec::new(),
        step_up_config: std::collections::HashMap::new(),
        default_step_up_rule: None,
    }
    .into_validated()
    .expect("seed config validates");
    compile_policy_bundle(&config, 1).expect("seed bundle compiles")
}

fn seed_request() -> EvaluationRequest {
    EvaluationRequest {
        subject: Subject::user("u1"),
        resource: Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        action: Action::new("read"),
        context: Some(context_with_internal(internal_context())),
        jwt_context: None,
        session_context: None,
        token_context: None,
    }
}

fn subject_pool(variant: u8) -> Subject {
    match variant % 9 {
        0 => Subject::user("u1"),
        1 => Subject::user("u2"),
        2 => Subject::user(""),
        3 => Subject::group("u1"),
        4 => Subject::role("u1"),
        5 => Subject::service_account("u1"),
        6 => Subject::machine("u1"),
        7 => Subject::protocol("u1"),
        _ => Subject::api_key("u1"),
    }
}

fn resource_pool(variant: u8) -> Resource {
    match variant % 8 {
        0 => Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": true})),
        1 => Resource::new("document", "doc2")
            .with_properties(serde_json::json!({"is_public": true})),
        2 => Resource::new("document", "").with_properties(serde_json::json!({"is_public": true})),
        3 => Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": false})),
        4 => Resource::new("document", "doc1").with_properties(serde_json::json!({"other": 1})),
        5 => Resource::new("document", "doc1")
            .with_properties(serde_json::json!({"is_public": "yes"})),
        6 => Resource::new("document", "doc1"),
        _ => Resource::new("other", "doc1").with_properties(serde_json::json!({"is_public": true})),
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

fn context_pool(variant: u8) -> Option<Context> {
    match variant % 6 {
        0 => Some(context_with_internal(internal_context())),
        1 => {
            let mut internal = match internal_context() {
                Value::Object(map) => map,
                _ => Map::new(),
            };
            internal.insert("token_present".to_string(), Value::Bool(true));
            Some(context_with_internal(Value::Object(internal)))
        }
        2 => {
            let mut outer = Map::new();
            outer.insert("_authz".to_string(), internal_context());
            outer.insert(
                "subject_parents".to_string(),
                Value::Array(vec![Value::String("Group::\"admin\"".to_string())]),
            );
            Some(Context::new(Value::Object(outer)))
        }
        3 => {
            let mut outer = Map::new();
            outer.insert("_authz".to_string(), internal_context());
            outer.insert(
                "resource_parents".to_string(),
                Value::Array(vec![Value::String("Tenant::\"other\"".to_string())]),
            );
            Some(Context::new(Value::Object(outer)))
        }
        4 => {
            let mut outer = Map::new();
            outer.insert("note".to_string(), Value::String("extra".to_string()));
            Some(Context::new(Value::Object(outer)))
        }
        _ => None,
    }
}

struct Fixture {
    bundle: authz_cedar::CompiledBundle,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let bundle = seed_bundle();
        // The enriched seed must fail before evaluation on the production
        // path; a bare request must deny by default.
        assert!(evaluate(&bundle, &seed_request()).is_err());
        Fixture { bundle }
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let fixture = fixture();
    let (subject_byte, resource_byte, action_byte, context_byte) =
        (data[0], data[1], data[2], data[3]);
    let (subject_byte, resource_byte, action_byte, context_byte) = if data.len() > 8 {
        (
            data[4].wrapping_add(subject_byte),
            data[5].wrapping_add(resource_byte),
            data[6].wrapping_add(action_byte),
            data[7].wrapping_add(context_byte),
        )
    } else {
        (subject_byte, resource_byte, action_byte, context_byte)
    };
    let request = EvaluationRequest {
        subject: subject_pool(subject_byte),
        resource: resource_pool(resource_byte),
        action: action_pool(action_byte),
        context: context_pool(context_byte),
        jwt_context: None,
        session_context: None,
        token_context: None,
    };
    assert!(
        !evaluate(&fixture.bundle, &request).is_ok_and(|response| response.decision),
        "authorization bypass: production evaluation allowed"
    );
});
