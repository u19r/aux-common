use std::{collections::HashMap, str::FromStr};

use authz_types::{
    AcrLevel, CONTEXT_INTERNAL_KEY, Scope, StepUpConfig, StepUpRule, ValidatedConfigurationModel,
};
use cedar_policy::{
    EntityId, EntityTypeName, EntityUid, Policy, PolicyId, PolicySet, SlotId, Template,
};

use crate::CedarError;

const ORG_SCOPE_GUARD: &str =
    "resource has org_id && principal has org_id && resource.org_id == principal.org_id";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PolicyShapeKey {
    effect: String,
    action_operator: String,
    action_ident: String,
    resource_entity: String,
    condition_clause: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticPolicyEntry {
    pub(crate) policy_id: String,
    pub(crate) policy_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TemplateLinkEntry {
    pub(crate) policy_id: String,
    pub(crate) role_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TemplateGroup {
    pub(crate) template_id: String,
    pub(crate) template_text: String,
    pub(crate) links: Vec<TemplateLinkEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyDocument {
    pub(crate) static_policies: Vec<StaticPolicyEntry>,
    pub(crate) template_groups: Vec<TemplateGroup>,
}

impl PolicyDocument {
    fn empty() -> Self {
        Self {
            static_policies: Vec::new(),
            template_groups: Vec::new(),
        }
    }

    pub(crate) fn as_json_string(&self) -> Result<String, CedarError> {
        let mut policy_set = PolicySet::new();

        for policy in &self.static_policies {
            let policy_id = PolicyId::new(policy.policy_id.clone());
            let parsed = Policy::parse(Some(policy_id), &policy.policy_text)
                .map_err(|error| CedarError::policy_generation(error.to_string()))?;
            policy_set
                .add(parsed)
                .map_err(|error| CedarError::policy_generation(error.to_string()))?;
        }

        let role_type = EntityTypeName::from_str("Authz::Role")
            .map_err(|error| CedarError::policy_generation(error.to_string()))?;
        for group in &self.template_groups {
            let template_id = PolicyId::new(group.template_id.clone());
            let template = Template::parse(Some(template_id.clone()), &group.template_text)
                .map_err(|error| CedarError::policy_generation(error.to_string()))?;
            policy_set
                .add_template(template)
                .map_err(|error| CedarError::policy_generation(error.to_string()))?;

            for link in &group.links {
                let vals = HashMap::from([(
                    SlotId::principal(),
                    EntityUid::from_type_name_and_id(
                        role_type.clone(),
                        EntityId::new(link.role_id.clone()),
                    ),
                )]);
                policy_set
                    .link(
                        template_id.clone(),
                        PolicyId::new(link.policy_id.clone()),
                        vals,
                    )
                    .map_err(|error| CedarError::policy_generation(error.to_string()))?;
            }
        }

        let json = policy_set
            .to_json()
            .map_err(|error| CedarError::policy_generation(error.to_string()))?;
        serde_json::to_string(&json)
            .map_err(|error| CedarError::policy_generation(error.to_string()))
    }
}

struct PolicyDocumentBuilder {
    document: PolicyDocument,
    group_index: HashMap<PolicyShapeKey, usize>,
    next_policy_idx: usize,
    next_template_idx: usize,
}

impl PolicyDocumentBuilder {
    fn new() -> Self {
        Self {
            document: PolicyDocument::empty(),
            group_index: HashMap::new(),
            next_policy_idx: 0,
            next_template_idx: 0,
        }
    }

    fn build(self) -> PolicyDocument {
        self.document
    }

    fn add_role_policy(
        &mut self,
        role_id: &str,
        effect: &str,
        action_ident: &str,
        resource_entity: &str,
        condition_clause: &str,
    ) {
        self.add_role_policy_with_operator(
            role_id,
            effect,
            "==",
            action_ident,
            resource_entity,
            condition_clause,
        );
    }

    fn add_role_policy_with_operator(
        &mut self,
        role_id: &str,
        effect: &str,
        action_operator: &str,
        action_ident: &str,
        resource_entity: &str,
        condition_clause: &str,
    ) {
        let key = PolicyShapeKey {
            effect: effect.to_string(),
            action_operator: action_operator.to_string(),
            action_ident: action_ident.to_string(),
            resource_entity: resource_entity.to_string(),
            condition_clause: condition_clause.to_string(),
        };
        let group_idx = if let Some(group_idx) = self.group_index.get(&key).copied() {
            group_idx
        } else {
            let template_id = format!("tpl_{}", self.next_template_idx);
            self.next_template_idx += 1;
            let template_text = build_template_text(
                effect,
                action_operator,
                action_ident,
                resource_entity,
                condition_clause,
            );
            self.document.template_groups.push(TemplateGroup {
                template_id,
                template_text,
                links: Vec::new(),
            });
            let group_idx = self.document.template_groups.len() - 1;
            self.group_index.insert(key, group_idx);
            group_idx
        };

        self.document.template_groups[group_idx]
            .links
            .push(TemplateLinkEntry {
                policy_id: format!("pol_{}", self.next_policy_idx),
                role_id: role_id.to_string(),
            });
        self.next_policy_idx += 1;
    }

    fn add_static_policy(
        &mut self,
        effect: &str,
        action_ident: &str,
        resource_entity: &str,
        condition_clause: &str,
    ) {
        self.document.static_policies.push(StaticPolicyEntry {
            policy_id: format!("pol_{}", self.next_policy_idx),
            policy_text: build_static_policy_text(
                effect,
                action_ident,
                resource_entity,
                condition_clause,
            ),
        });
        self.next_policy_idx += 1;
    }
}

/// Generate static Cedar policies from the configuration model.
///
/// Emits RBAC policies for roles/permissions/scopes.
pub fn generate_static_policies(
    config: &ValidatedConfigurationModel,
) -> Result<String, CedarError> {
    build_policy_document(config, None)?.as_json_string()
}

/// Generate static policies for a single resource type only.
pub fn generate_static_policies_for_resource(
    config: &ValidatedConfigurationModel,
    resource_type: &str,
) -> Result<String, CedarError> {
    build_policy_document(config, Some(resource_type))?.as_json_string()
}

pub(crate) fn generate_policy_document_for_resource(
    config: &ValidatedConfigurationModel,
    resource_type: &str,
) -> Result<PolicyDocument, CedarError> {
    build_policy_document(config, Some(resource_type))
}

fn build_policy_document(
    config: &ValidatedConfigurationModel,
    resource_filter: Option<&str>,
) -> Result<PolicyDocument, CedarError> {
    let step_up = StepUpPolicyLookup::new(config);
    let mut builder = PolicyDocumentBuilder::new();

    for role in &config.roles {
        for permission_entry in &role.permissions {
            let permission = config
                .get_permission(permission_entry.permission_id.as_str())
                .ok_or_else(|| {
                    CedarError::policy_generation(format!(
                        "permission not found: {}",
                        permission_entry.permission_id.as_str()
                    ))
                })?;
            append_scoped_action_policies(
                &mut builder,
                role,
                permission_entry.scopes.as_slice(),
                permission.actions.as_slice(),
                "permit",
                &step_up,
                resource_filter,
            );

            append_scoped_action_policies(
                &mut builder,
                role,
                permission_entry.scopes.as_slice(),
                permission.not_actions.as_slice(),
                "forbid",
                &step_up,
                resource_filter,
            );
        }

        append_scoped_role_action_policies(
            &mut builder,
            role,
            role.actions.as_slice(),
            "permit",
            &step_up,
            resource_filter,
        );

        append_scoped_role_action_policies(
            &mut builder,
            role,
            role.not_actions.as_slice(),
            "forbid",
            &step_up,
            resource_filter,
        );
    }

    for rt in &config.resource_types {
        if resource_filter.is_some_and(|resource_type| resource_type != rt.id) {
            continue;
        }
        if !rt.actions.iter().any(|action| action.name == "read") {
            continue;
        }
        let resource_entity = super::schema_generator::to_pascal_case(&rt.id);
        let action_id = format!("{}:read", rt.id);
        let mut conditions = vec![
            "resource has is_public && resource.is_public == true".to_string(),
            token_guard_expr(&action_id),
        ];
        if let Some(step_up_guard) = step_up.guard_expr(&rt.id, "read") {
            conditions.push(step_up_guard);
        }
        let condition_clause = build_condition_clause(&conditions);
        builder.add_static_policy(
            "permit",
            &format!("Authz::Action::\"{}:read\"", rt.id),
            resource_entity.as_str(),
            condition_clause.as_str(),
        );
    }

    Ok(builder.build())
}

fn append_scoped_action_policies(
    builder: &mut PolicyDocumentBuilder,
    role: &authz_types::Role,
    scopes: &[Scope],
    action_refs: &[authz_types::PermissionActionRef],
    effect: &str,
    step_up: &StepUpPolicyLookup<'_>,
    resource_filter: Option<&str>,
) {
    for action_ref in action_refs {
        if resource_filter.is_some_and(|resource_type| resource_type != action_ref.resource_type) {
            continue;
        }
        let action_ident = format!(
            "Authz::Action::\"{}:{}\"",
            action_ref.resource_type, action_ref.action_name
        );
        let action_id = format!("{}:{}", action_ref.resource_type, action_ref.action_name);

        for scope in scopes {
            let mut conditions = Vec::new();
            if let Some(scope_guard) = scope_guard_expr(scope, &role.id, &role.name) {
                conditions.push(scope_guard);
            }
            conditions.push(token_guard_expr(&action_id));
            if effect == "permit"
                && let Some(step_up_guard) =
                    step_up.guard_expr(&action_ref.resource_type, &action_ref.action_name)
            {
                conditions.push(step_up_guard);
            }

            let resource_entity =
                super::schema_generator::to_pascal_case(&action_ref.resource_type);
            let condition_clause = build_condition_clause(&conditions);
            builder.add_role_policy(
                role.id.as_str(),
                effect,
                action_ident.as_str(),
                resource_entity.as_str(),
                condition_clause.as_str(),
            );
        }
    }
}

fn append_scoped_role_action_policies(
    builder: &mut PolicyDocumentBuilder,
    role: &authz_types::Role,
    action_refs: &[authz_types::RoleActionRef],
    effect: &str,
    step_up: &StepUpPolicyLookup<'_>,
    resource_filter: Option<&str>,
) {
    for action_ref in action_refs {
        if resource_filter.is_some_and(|resource_type| resource_type != action_ref.resource_type) {
            continue;
        }
        let action_ident = format!(
            "Authz::Action::\"{}:{}\"",
            action_ref.resource_type, action_ref.action_name
        );
        let action_id = format!("{}:{}", action_ref.resource_type, action_ref.action_name);

        for scope in &action_ref.scopes {
            let mut conditions = Vec::new();
            if let Some(scope_guard) = scope_guard_expr(scope, &role.id, &role.name) {
                conditions.push(scope_guard);
            }
            conditions.push(token_guard_expr(&action_id));
            if effect == "permit"
                && let Some(step_up_guard) =
                    step_up.guard_expr(&action_ref.resource_type, &action_ref.action_name)
            {
                conditions.push(step_up_guard);
            }

            let resource_entity =
                super::schema_generator::to_pascal_case(&action_ref.resource_type);
            let condition_clause = build_condition_clause(&conditions);
            builder.add_role_policy(
                role.id.as_str(),
                effect,
                action_ident.as_str(),
                resource_entity.as_str(),
                condition_clause.as_str(),
            );
        }
    }
}

fn build_template_text(
    effect: &str,
    action_operator: &str,
    action_ident: &str,
    resource_entity: &str,
    condition_clause: &str,
) -> String {
    format!(
        r#"{effect}(
  principal in ?principal,
  action {action_operator} {action_ident},
  resource is Authz::{resource_entity}
) {condition_clause};"#
    )
}

fn build_static_policy_text(
    effect: &str,
    action_ident: &str,
    resource_entity: &str,
    condition_clause: &str,
) -> String {
    format!(
        r#"{effect}(
  principal,
  action == {action_ident},
  resource is Authz::{resource_entity}
) {condition_clause};"#
    )
}

fn scope_expr(scope: &Scope) -> &'static str {
    match scope {
        Scope::Tenant => "",
        Scope::Org => ORG_SCOPE_GUARD,
        Scope::Group => {
            "resource has group_id && principal has group_id && resource.group_id == \
             principal.group_id"
        }
        Scope::Own => "resource has owner_id && resource.owner_id == principal.id",
        Scope::Shared => "resource has shared_with && resource.shared_with.contains(principal.id)",
        Scope::Public => "resource has is_public && resource.is_public == true",
        Scope::OrgRelationship => {
            "resource has org_parents && resource.org_parents.contains(principal.id)"
        }
        Scope::GroupRelationship => {
            "resource has group_parents && resource.group_parents.contains(principal.id)"
        }
        Scope::Resource { .. } => "",
    }
}

fn scope_guard_expr(scope: &Scope, role_id: &str, role_display_name: &str) -> Option<String> {
    match scope {
        Scope::Resource { .. } => Some(resource_scope_guard_expr(role_id)),
        Scope::Org if role_display_name.starts_with("org:owner") => {
            Some(ORG_SCOPE_GUARD.to_string())
        }
        _ => {
            let expr = scope_expr(scope);
            if expr.is_empty() {
                None
            } else {
                Some(expr.to_string())
            }
        }
    }
}

fn build_condition_clause(conditions: &[String]) -> String {
    if conditions.is_empty() {
        return String::new();
    }
    format!("when {{ {} }}", conditions.join(" && "))
}

fn authz_ctx_field(field: &str) -> String {
    format!("context.{}.{}", CONTEXT_INTERNAL_KEY, field)
}

fn token_guard_expr(action_id: &str) -> String {
    let token_present = authz_ctx_field("token_present");
    let token_valid = authz_ctx_field("token_valid");
    let token_filter_enabled = authz_ctx_field("token_resource_filter_enabled");
    let token_filter = authz_ctx_field("token_resource_filter");
    let token_org_present = authz_ctx_field("token_org_id_present");
    let token_org_id = authz_ctx_field("token_org_id");
    let token_owner_orgs = authz_ctx_field("token_owner_org_ids");
    let allowed_actions = authz_ctx_field("allowed_actions");
    format!(
        "(!{token_present} || ({token_valid} && (!{token_filter_enabled} || resource in \
         {token_filter}) && (!{token_org_present} || (resource has org_id && resource.org_id == \
         {token_org_id} && {token_owner_orgs}.contains({token_org_id}))) && \
         {allowed_actions}.contains(\"{action_id}\")))"
    )
}

fn resource_scope_guard_expr(role_id: &str) -> String {
    let resource_scopes = authz_ctx_field("resource_scopes");
    format!(
        "{resource_scopes}.contains({{ role: Authz::Role::\"{role_id}\", resource: resource }})"
    )
}

fn step_up_guard_expr(rule: &StepUpRule) -> String {
    let session_present = authz_ctx_field("session_present");
    let session_acr = authz_ctx_field("session_acr");
    let session_amr = authz_ctx_field("session_amr");
    let auth_age_present = authz_ctx_field("session_auth_age_present");
    let auth_age_seconds = authz_ctx_field("session_auth_age_seconds");
    let mfa_age_present = authz_ctx_field("session_mfa_age_present");
    let mfa_age_seconds = authz_ctx_field("session_mfa_age_seconds");

    let mut clauses = vec![session_present];
    let required_acr = rule.required_acr as i64;
    let acr_clause = if matches!(rule.required_acr, AcrLevel::RecentAuth) {
        format!("{session_acr} == {required_acr}")
    } else {
        format!("{session_acr} >= {required_acr}")
    };
    clauses.push(acr_clause);

    if let Some(max_age) = rule.max_auth_age_seconds {
        clauses.push(format!(
            "{auth_age_present} && {auth_age_seconds} <= {max_age}"
        ));
    }

    if let Some(max_age) = rule.max_mfa_age_seconds {
        clauses.push(format!(
            "{mfa_age_present} && {mfa_age_seconds} <= {max_age}"
        ));
    }

    if !rule.required_amr.is_empty() {
        let checks = rule
            .required_amr
            .iter()
            .map(|amr| format!("{session_amr}.contains(\"{amr}\")"))
            .collect::<Vec<_>>();
        clauses.push(format!("({})", checks.join(" || ")));
    }

    let session_ok = clauses.join(" && ");
    if rule.applies_to_api_keys {
        session_ok
    } else {
        let token_present = authz_ctx_field("token_present");
        format!("{token_present} || ({session_ok})")
    }
}

struct StepUpPolicyLookup<'a> {
    rules: HashMap<&'a str, &'a StepUpRule>,
    resource_config: &'a HashMap<String, StepUpConfig>,
    default_rule: Option<&'a str>,
}

impl<'a> StepUpPolicyLookup<'a> {
    fn new(config: &'a ValidatedConfigurationModel) -> Self {
        let rules = config
            .step_up_rules
            .iter()
            .map(|r| (r.rule_id.as_str(), r))
            .collect();
        Self {
            rules,
            resource_config: &config.step_up_config,
            default_rule: config.default_step_up_rule.as_deref(),
        }
    }

    fn guard_expr(&self, resource_type: &str, action: &str) -> Option<String> {
        let rule_id = self.find_rule_id(resource_type, action)?;
        Some(
            self.rules
                .get(rule_id)
                .map(|rule| step_up_guard_expr(rule))
                .unwrap_or_else(|| "false".to_string()),
        )
    }

    fn find_rule_id(&self, resource_type: &str, action: &str) -> Option<&'a str> {
        if let Some(cfg) = self.resource_config.get(resource_type) {
            if let Some(rule_id) = cfg.action_rules.get(action) {
                return Some(rule_id.as_str());
            }
            if let Some(rule_id) = &cfg.default_rule {
                return Some(rule_id.as_str());
            }
        }
        self.default_rule
    }
}
