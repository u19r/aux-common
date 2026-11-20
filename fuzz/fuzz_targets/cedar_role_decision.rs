#![no_main]

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, OnceLock},
};

use authz_runtime::{
    EffectiveRoleAssignment, EvaluationRuntime, LocalAuthzEvaluator, LocalEvaluationInput,
    ParentRef, ResourceAccessSnapshot, SubjectAccessSnapshot, TrustedAuthorizationContext,
    build_subject_parent_template,
};
use authz_types::{
    AccessAssignmentMode, AccessAssignmentPolicySpec, AcrLevel, Action, ActionDefinition,
    ConfigurationModel, EvaluationRequest, JwtContext, Permission, PermissionActionRef,
    PermissionId, Resource, ResourceType, Role, RoleAssignment, RolePermission, RoleScope, Scope,
    SessionContext, StepUpConfig, StepUpRule, Subject, TokenContext, TokenScopeConfig,
};
use jiff::Timestamp;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};

// Structured differential oracle for the local authorization runtime: the
// permission-bit gate, assignment coverage, Cedar role membership, entry
// scopes, resource grants, JWT completeness, delegated and subject-bound
// tokens, and step-up all run through `LocalAuthzEvaluator`. Bytes choose
// assignments (role, scope, principal, expiry), snapshot parents (including
// forged role parents), resource attributes, action, token, session, and
// JWT. A small reference model states the contract: allow only when one role
// both covers the resource through the subject's own active grant and
// permits the action under its entry scope, the token is acceptable, and
// step-up is satisfied by the subject's session unless the token is the
// subject's own API key. Any disagreement in either direction fails.

const SUBJECT_ID: &str = "u1";
const NOW_SECONDS: i64 = 1_000_000;

/// (role, action, entry scope) for every configured role.
fn role_grants() -> Vec<(&'static str, &'static str, Scope)> {
    vec![
        ("tenant_reader", "read", Scope::Tenant),
        ("owner_reader", "read", Scope::Own),
        ("org_reader", "read", Scope::Org),
        ("doc_reader", "read", Scope::resource("document")),
        ("org_deleter", "delete", Scope::Org),
        ("tenant_deleter", "delete", Scope::Tenant),
    ]
}

const ROLE_POOL: [&str; 7] = [
    "tenant_reader",
    "owner_reader",
    "org_reader",
    "doc_reader",
    "org_deleter",
    "tenant_deleter",
    "ghost",
];

fn runtime() -> Arc<EvaluationRuntime> {
    static RUNTIME: OnceLock<Arc<EvaluationRuntime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            let permission = |action: &str| Permission {
                id: format!("document:{action}"),
                name: format!("Document {action}"),
                description: None,
                actions: vec![PermissionActionRef {
                    resource_type: "document".into(),
                    action_name: action.into(),
                }],
                not_actions: Vec::new(),
            };
            let config = ConfigurationModel {
                version: 1,
                resource_types: vec![ResourceType {
                    id: "document".into(),
                    name: "Document".into(),
                    description: None,
                    actions: ["read", "delete"]
                        .into_iter()
                        .map(|name| ActionDefinition {
                            name: name.into(),
                            description: None,
                        })
                        .collect(),
                    context_schema: None,
                }],
                permissions: vec![permission("read"), permission("delete")],
                roles: role_grants()
                    .into_iter()
                    .map(|(role_id, action, scope)| Role {
                        id: role_id.into(),
                        name: role_id.into(),
                        description: None,
                        permissions: vec![RolePermission {
                            permission_id: PermissionId::new(format!("document:{action}"))
                                .expect("permission id"),
                            scopes: vec![scope],
                        }],
                        actions: Vec::new(),
                        not_actions: Vec::new(),
                        assignment_policy: AccessAssignmentPolicySpec {
                            assignment_mode: AccessAssignmentMode::PermanentOrTemporary,
                            maximum_duration_seconds: None,
                        },
                    })
                    .collect(),
                description: None,
                scope_mappings: Vec::new(),
                authn_providers: Vec::new(),
                step_up_rules: vec![StepUpRule {
                    applies_to_api_keys: false,
                    ..StepUpRule::require_acr("mfa", "Require MFA", AcrLevel::MultiFactor)
                }],
                step_up_config: HashMap::from([(
                    "document".to_string(),
                    StepUpConfig {
                        default_rule: None,
                        action_rules: HashMap::from([("delete".to_string(), "mfa".to_string())]),
                    },
                )]),
                default_step_up_rule: None,
            }
            .into_validated()
            .expect("fuzz config validates");
            let bundle = authz_cedar::compile_policy_bundle(&config, 1).expect("bundle compiles");
            Arc::new(EvaluationRuntime::build(config, &bundle).expect("runtime builds"))
        })
        .clone()
}

#[derive(Debug, Clone)]
struct GeneratedAssignment {
    role: &'static str,
    scope: Option<(&'static str, Option<&'static str>)>,
    principal: Option<&'static str>,
    expired: bool,
}

impl GeneratedAssignment {
    fn decode(bytes: [u8; 3]) -> Self {
        let scope = match bytes[1] % 7 {
            0 => None,
            1 => Some(("tenant", None)),
            2 => Some(("org", Some("o1"))),
            3 => Some(("org", Some("o2"))),
            4 => Some(("resource:document", Some("doc1"))),
            5 => Some(("resource:document", Some("doc2"))),
            _ => Some(("group", Some("g1"))),
        };
        let principal = match bytes[2] % 4 {
            0 => None,
            1 => Some(SUBJECT_ID),
            2 => Some("u2"),
            _ => Some("g1"),
        };
        Self {
            role: ROLE_POOL[usize::from(bytes[0]) % ROLE_POOL.len()],
            scope,
            principal,
            expired: bytes[2] & 0x10 != 0,
        }
    }

    fn to_runtime(&self) -> EffectiveRoleAssignment {
        EffectiveRoleAssignment {
            principal_id: self.principal.map(str::to_string),
            role_id: self.role.to_string(),
            scope_type: self.scope.map(|(scope_type, _)| scope_type.to_string()),
            scope_id: self
                .scope
                .and_then(|(_, scope_id)| scope_id.map(str::to_string)),
            expires_at: self
                .expired
                .then(|| now() - jiff::SignedDuration::from_secs(1)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum GeneratedToken {
    None,
    SubjectKey,
    Delegated,
    ForeignSubjectKey,
}

#[derive(Debug, Clone, Copy)]
enum GeneratedSession {
    None,
    Password,
    Mfa,
}

#[derive(Debug, Clone)]
struct GeneratedJwt {
    role: RoleAssignment,
    complete: bool,
}

#[derive(Debug)]
struct Case {
    assignments: Vec<GeneratedAssignment>,
    group_parent: bool,
    org_parents: Vec<&'static str>,
    forged_role_parents: Vec<&'static str>,
    resource_id: &'static str,
    owner: Option<&'static str>,
    resource_org: Option<&'static str>,
    action: &'static str,
    token: GeneratedToken,
    session: GeneratedSession,
    jwt: Option<GeneratedJwt>,
}

impl Case {
    fn decode(data: &[u8]) -> Option<Self> {
        let (header, rest) = data.split_first_chunk::<6>()?;
        let assignment_count = usize::from(header[0] % 4);
        let assignments = rest
            .chunks_exact(3)
            .take(assignment_count)
            .map(|chunk| GeneratedAssignment::decode([chunk[0], chunk[1], chunk[2]]))
            .collect();
        let parents = header[1];
        let mut org_parents = Vec::new();
        if parents & 0x02 != 0 {
            org_parents.push("o1");
        }
        if parents & 0x04 != 0 {
            org_parents.push("o2");
        }
        let mut forged_role_parents = Vec::new();
        if parents & 0x08 != 0 {
            forged_role_parents.push("tenant_reader");
        }
        if parents & 0x10 != 0 {
            forged_role_parents.push("tenant_deleter");
        }
        let resource = header[2];
        let jwt_byte = header[5];
        let jwt_role = match jwt_byte % 4 {
            0 => None,
            1 => Some(RoleAssignment {
                role_id: "tenant_reader".into(),
                scope: RoleScope::Global,
            }),
            2 => Some(RoleAssignment {
                role_id: "org_reader".into(),
                scope: RoleScope::Org {
                    org_id: "o1".into(),
                },
            }),
            _ => Some(RoleAssignment {
                role_id: "doc_reader".into(),
                scope: RoleScope::Resource {
                    resource_type: "document".into(),
                    resource_id: "doc1".into(),
                },
            }),
        };
        Some(Self {
            assignments,
            group_parent: parents & 0x01 != 0,
            org_parents,
            forged_role_parents,
            resource_id: if resource & 0x01 == 0 { "doc1" } else { "doc2" },
            owner: match (resource >> 1) % 3 {
                0 => Some(SUBJECT_ID),
                1 => Some("u2"),
                _ => None,
            },
            resource_org: match (resource >> 3) % 3 {
                0 => Some("o1"),
                1 => Some("o2"),
                _ => None,
            },
            action: if header[3] & 0x01 == 0 {
                "read"
            } else {
                "delete"
            },
            token: match (header[3] >> 1) % 4 {
                0 => GeneratedToken::None,
                1 => GeneratedToken::SubjectKey,
                2 => GeneratedToken::Delegated,
                _ => GeneratedToken::ForeignSubjectKey,
            },
            session: match header[4] % 3 {
                0 => GeneratedSession::None,
                1 => GeneratedSession::Password,
                _ => GeneratedSession::Mfa,
            },
            jwt: jwt_role.map(|role| GeneratedJwt {
                role,
                complete: jwt_byte & 0x10 != 0,
            }),
        })
    }

    fn evaluate(&self) -> bool {
        let subject = Subject::user(SUBJECT_ID);
        let assignments = self
            .assignments
            .iter()
            .map(GeneratedAssignment::to_runtime)
            .collect::<Vec<_>>();
        // Mirror an AuxFn snapshot: template parents, a role parent for every
        // assignment wherever it applies, and the generated relationships.
        let template = build_subject_parent_template(&assignments, &[], "tenant_1");
        let mut subject_parents = template.parents;
        subject_parents.extend(assignments.iter().map(|assignment| ParentRef {
            ref_type: "role".into(),
            id: assignment.role_id.clone(),
        }));
        subject_parents.extend(self.forged_role_parents.iter().map(|role| ParentRef {
            ref_type: "role".into(),
            id: (*role).into(),
        }));
        subject_parents.extend(self.org_parents.iter().map(|org| ParentRef {
            ref_type: "org".into(),
            id: (*org).into(),
        }));
        if self.group_parent {
            subject_parents.push(ParentRef {
                ref_type: "group".into(),
                id: "g1".into(),
            });
        }
        let mut properties = Map::new();
        if let Some(owner) = self.owner {
            properties.insert("owner_id".into(), Value::String(owner.into()));
        }
        if let Some(org) = self.resource_org {
            properties.insert("org_id".into(), Value::String(org.into()));
        }
        let token = match self.token {
            GeneratedToken::None => None,
            GeneratedToken::SubjectKey => Some(TokenContext::new(
                "key".into(),
                SUBJECT_ID.into(),
                TokenScopeConfig::full_access(),
            )),
            GeneratedToken::Delegated => Some(TokenContext::delegated(
                "svc".into(),
                "creator".into(),
                TokenScopeConfig::full_access(),
            )),
            GeneratedToken::ForeignSubjectKey => Some(TokenContext::new(
                "key".into(),
                "u2".into(),
                TokenScopeConfig::full_access(),
            )),
        };
        let session = match self.session {
            GeneratedSession::None => None,
            GeneratedSession::Password => Some(SessionContext::password_only(NOW_SECONDS - 10)),
            GeneratedSession::Mfa => Some(SessionContext::with_mfa(
                NOW_SECONDS - 10,
                NOW_SECONDS - 5,
                "otp",
            )),
        };
        let jwt = self.jwt.as_ref().map(|jwt| {
            if jwt.complete {
                JwtContext::complete(Vec::new(), Vec::new(), vec![jwt.role.clone()])
            } else {
                JwtContext {
                    roles: vec![jwt.role.clone()],
                    ..JwtContext::default()
                }
            }
        });
        let request = EvaluationRequest {
            subject: subject.clone(),
            resource: Resource::new("document", self.resource_id),
            action: Action::new(self.action),
            context: None,
            jwt_context: None,
            session_context: None,
            token_context: None,
        };
        let fetched_at_ms = now().as_millisecond();
        LocalAuthzEvaluator::from_arc(runtime())
            .evaluate_at(
                LocalEvaluationInput {
                    tenant_id: "tenant_1".to_string(),
                    trusted_context: TrustedAuthorizationContext::from_validated_parts(
                        &subject, jwt, session, token,
                    ),
                    subject_access: SubjectAccessSnapshot {
                        tenant_id: "tenant_1".into(),
                        subject: subject.clone(),
                        assignments,
                        subject_parents,
                        resource_scopes: HashMap::new(),
                        fetched_at_ms,
                    },
                    resource_access: ResourceAccessSnapshot {
                        tenant_id: "tenant_1".into(),
                        resource_type: "document".into(),
                        resource_id: self.resource_id.into(),
                        properties: Value::Object(properties),
                        resource_parents: Vec::new(),
                        fetched_at_ms,
                    },
                    request,
                },
                now(),
            )
            .expect("valid snapshots evaluate")
            .decision
    }

    /// The reference contract, written independently of the runtime.
    fn expected(&self) -> bool {
        if matches!(self.token, GeneratedToken::ForeignSubjectKey) {
            return false;
        }
        // Group membership and org membership are trusted parent facts.
        let groups_g1 = self.group_parent
            || self
                .assignments
                .iter()
                .any(|assignment| assignment.scope == Some(("group", Some("g1"))));
        let complete_jwt = self.jwt.as_ref().filter(|jwt| jwt.complete);
        let mut orgs = self.org_parents.clone();
        orgs.extend(self.assignments.iter().filter_map(|assignment| {
            match assignment.scope {
                Some(("org", org)) => org,
                _ => None,
            }
        }));
        if let Some(GeneratedJwt {
            role:
                RoleAssignment {
                    scope: RoleScope::Org { org_id },
                    ..
                },
            ..
        }) = complete_jwt
            && self.resource_org == Some(org_id.as_str())
        {
            // The generated JWT org pool is `o1` only.
            orgs.push("o1");
        }
        orgs.sort_unstable();
        orgs.dedup();
        let principal_org = (orgs.len() == 1).then(|| orgs[0]);

        // Covering roles: role -> covered through a grant naming this resource.
        let mut covering: BTreeMap<&str, bool> = BTreeMap::new();
        for assignment in &self.assignments {
            let belongs = match assignment.principal {
                None | Some(SUBJECT_ID) => true,
                Some("g1") => groups_g1,
                Some(_) => false,
            };
            let (covers, names_resource) = match assignment.scope {
                None | Some(("tenant", _)) => (true, false),
                Some(("org", org)) => (self.resource_org.is_some() && org == self.resource_org, false),
                Some(("resource:document", id)) => (id == Some(self.resource_id), true),
                Some(_) => (false, false),
            };
            if !assignment.expired && belongs && covers && assignment.role != "ghost" {
                *covering.entry(assignment.role).or_default() |= names_resource;
            }
        }
        if let Some(jwt) = complete_jwt {
            let (covers, names_resource) = match &jwt.role.scope {
                RoleScope::Global => (true, false),
                RoleScope::Org { org_id } => (self.resource_org == Some(org_id.as_str()), false),
                RoleScope::Resource { resource_id, .. } => (resource_id == self.resource_id, true),
                RoleScope::Group { .. } => (false, false),
            };
            if covers {
                let role_id = ROLE_POOL
                    .iter()
                    .copied()
                    .find(|role| *role == jwt.role.role_id)
                    .expect("pool role");
                *covering.entry(role_id).or_default() |= names_resource;
            }
        }

        let permitted = role_grants().into_iter().any(|(role, action, scope)| {
            let Some(names_resource) = covering.get(role).copied() else {
                return false;
            };
            action == self.action
                && match scope {
                    Scope::Tenant => true,
                    Scope::Own => self.owner == Some(SUBJECT_ID),
                    Scope::Org => {
                        (self.resource_org.is_some() && principal_org == self.resource_org)
                            || names_resource
                    }
                    Scope::Resource { .. } => names_resource,
                    _ => false,
                }
        });
        let step_up_ok = self.action != "delete"
            || matches!(self.token, GeneratedToken::SubjectKey)
            || matches!(self.session, GeneratedSession::Mfa);
        permitted && step_up_ok
    }
}

fn now() -> Timestamp {
    Timestamp::from_second(NOW_SECONDS).expect("fixed timestamp")
}

fn assert_seed_reaches_allow() {
    static SEEDED: OnceLock<()> = OnceLock::new();
    SEEDED.get_or_init(|| {
        // One tenant_reader assignment for the subject, reading doc1.
        let seed = Case::decode(&[1, 0, 0, 0, 0, 0, 0, 1, 1]).expect("seed decodes");
        assert!(seed.expected() && seed.evaluate(), "seed must allow: {seed:?}");
    });
}

fuzz_target!(|data: &[u8]| {
    assert_seed_reaches_allow();
    let Some(case) = Case::decode(data) else {
        return;
    };
    let expected = case.expected();
    let actual = case.evaluate();
    assert_eq!(
        actual, expected,
        "runtime decision diverged from the reference contract: {case:#?}"
    );
});
