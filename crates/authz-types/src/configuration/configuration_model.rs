use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    rc::Rc,
};

use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

use super::{
    action_pattern::{ActionPattern, is_action_name_char},
    constants::{
        ACTION_MAX, AUTHN_ALGORITHMS_MAX, AUTHN_AUDIENCES_MAX, AUTHN_URL_MAX, ID_MAX, NAME_MAX,
        RESOURCE_TYPE_MAX,
    },
};
use crate::{
    ActionPatternExpandError, AuthnProviderConfig, ExpandedActionRef,
    MAX_ACTIONS_PER_RESOURCE_TYPE, MAX_AUTHN_PROVIDERS, MAX_EXPANDED_ACTION_REFS,
    MAX_PERMISSION_ACTION_REFS, MAX_PERMISSIONS, MAX_POLICY_LINKS, MAX_RESOURCE_TYPES,
    MAX_ROLE_ACTION_REFS, MAX_ROLE_ENTRY_SCOPES, MAX_ROLE_PERMISSION_REFS, MAX_ROLES,
    MAX_SCOPE_MAPPING_INCLUDES, MAX_SCOPE_MAPPING_PERMISSIONS, MAX_SCOPE_MAPPINGS,
    MAX_STEP_UP_RULES, Permission, PermissionActionRef, ResourceType, ResourceTypeId, Role,
    RoleActionRef, Scope, ScopeMappingEntry, StepUpConfig, StepUpRule, ValidationError,
    expand_action_patterns,
};

/// Match counts per normalized `(resource_type, action)` pattern. Validation
/// counts matches instead of materializing them so wildcard expansion can be
/// bounded before it allocates.
type ActionPatternCountCache = HashMap<(String, String), Result<usize, ActionPatternExpandError>>;

/// Expanded references per normalized pattern, shared across every entry that
/// repeats the pattern. Built only after the expansion bounds pass.
pub(super) type ActionPatternExpansionCache =
    HashMap<(String, String), Result<Rc<[ExpandedActionRef]>, ActionPatternExpandError>>;

/// Complete authorization configuration model.
/// This is what customers send to configure their authorization.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfigurationModel {
    /// Schema version for forward compatibility
    #[serde(default = "default_version")]
    #[schema(default = 1, minimum = 1, example = 1)]
    pub version: u32,

    #[schema(max_items = 100)]
    pub resource_types: Vec<ResourceType>,
    #[schema(max_items = 1024)]
    pub permissions: Vec<Permission>,
    #[schema(max_items = 200)]
    pub roles: Vec<Role>,

    /// Scope string mappings for API token scoping.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 200)]
    pub scope_mappings: Vec<ScopeMappingEntry>,

    /// Optional external authn providers (JWT issuers + JWKS) for token-backed
    /// authz.
    #[serde(default)]
    #[schema(max_items = 5)]
    pub authn_providers: Vec<AuthnProviderConfig>,

    /// Step-up rules for sensitive actions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(example = json!([]))]
    pub step_up_rules: Vec<StepUpRule>,

    /// Per-resource step-up configuration.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[schema(
        value_type = std::collections::HashMap<String, StepUpConfig>,
        example = json!({
            "document": {
                "default_rule": "rule_doc_sensitive",
                "action_rules": { "delete": "rule_doc_delete" }
            }
        })
    )]
    pub step_up_config: HashMap<String, StepUpConfig>,

    /// Global fallback step-up rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 1,
        max_length = 58,
        example = "rule_default"
    )]
    pub default_step_up_rule: Option<String>,

    /// Optional description of this configuration version
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(
        nullable = true,
        min_length = 1,
        max_length = 250,
        example = "Initial policy rollout"
    )]
    pub description: Option<String>,
}

/// Configuration model that has passed validation.
#[derive(Debug, Clone)]
pub struct ValidatedConfigurationModel(ConfigurationModel);

fn default_version() -> u32 {
    1
}

impl ConfigurationModel {
    /// Validate and convert into a typestate-checked configuration model.
    pub fn into_validated(self) -> Result<ValidatedConfigurationModel, Vec<ValidationError>> {
        ValidatedConfigurationModel::try_from(self)
    }

    /// Validate the configuration model for internal consistency.
    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        self.validate_with_options(true)
    }

    fn validate_with_options(&self, allow_wildcards: bool) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();
        let mut references = ActionReferenceValidator {
            resource_types: self.resource_types.as_slice(),
            allow_wildcards,
            match_counts: ActionPatternCountCache::new(),
        };
        let mut expansion = ExpansionBudget::default();
        let mut permission_action_counts = HashMap::with_capacity(self.permissions.len());

        // Check resource type limits
        if self.resource_types.len() > MAX_RESOURCE_TYPES {
            errors.push(ValidationError::LimitExceeded {
                resource: "resource_types",
                limit: MAX_RESOURCE_TYPES,
                actual: self.resource_types.len(),
            });
        }

        // Check permissions reference valid resource types
        let rt_ids: HashSet<_> = self
            .resource_types
            .iter()
            .map(|rt| rt.id.as_str())
            .collect();
        let mut seen_resource_type_ids = HashSet::new();
        let mut seen_resource_type_names = HashSet::new();

        for rt in &self.resource_types {
            if rt.actions.len() > MAX_ACTIONS_PER_RESOURCE_TYPE {
                errors.push(ValidationError::LimitExceeded {
                    resource: "resource_type_actions",
                    limit: MAX_ACTIONS_PER_RESOURCE_TYPE,
                    actual: rt.actions.len(),
                });
            }

            let resource_type_id_key = normalize_name_key(rt.id.as_str());
            if !seen_resource_type_ids.insert(resource_type_id_key.clone()) {
                errors.push(ValidationError::DuplicateId(format!(
                    "resource_type_id:{resource_type_id_key}"
                )));
            }

            let resource_type_name_key = normalize_name_key(rt.name.as_str());
            if !seen_resource_type_names.insert(resource_type_name_key.clone()) {
                errors.push(ValidationError::DuplicateId(format!(
                    "resource_type_name:{resource_type_name_key}"
                )));
            }

            // The resource type ID charset keeps Cedar action IDs
            // (`resource_type:action`), token selections, and bundle
            // manifest keys unambiguous.
            if let Err(mut error) = ResourceTypeId::new(rt.id.as_str()) {
                if let ValidationError::InvalidFormat { field, .. }
                | ValidationError::OutOfRange { field, .. } = &mut error
                {
                    *field = "resource_types[].id";
                }
                errors.push(error);
            }
            if rt.name.is_empty() || rt.name.len() > NAME_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "resource_types[].name",
                    message: format!("must be 1..={NAME_MAX} characters"),
                });
            }
            let mut seen_action_names = HashSet::new();
            for action in &rt.actions {
                let action_name_key = normalize_name_key(action.name.as_str());
                if !seen_action_names.insert(action_name_key.clone()) {
                    errors.push(ValidationError::DuplicateId(format!(
                        "resource_type_action_name:{}:{action_name_key}",
                        rt.id
                    )));
                }
                if action.name.is_empty() || action.name.len() > ACTION_MAX {
                    errors.push(ValidationError::OutOfRange {
                        field: "resource_types[].actions[].name",
                        message: format!("must be 1..={ACTION_MAX} characters"),
                    });
                }
                if !action.name.chars().all(is_action_name_char) {
                    errors.push(ValidationError::InvalidFormat {
                        field: "resource_types[].actions[].name",
                        message: "must use ASCII letters, digits, '_', '-', or '.'".into(),
                    });
                }
            }
        }

        if self.permissions.len() > MAX_PERMISSIONS {
            errors.push(ValidationError::LimitExceeded {
                resource: "permissions",
                limit: MAX_PERMISSIONS,
                actual: self.permissions.len(),
            });
        }

        let mut seen_permission_ids = HashSet::new();
        let mut seen_permission_names = HashSet::new();
        for perm in &self.permissions {
            let permission_id_key = normalize_name_key(perm.id.as_str());
            if !seen_permission_ids.insert(permission_id_key.clone()) {
                errors.push(ValidationError::DuplicateId(format!(
                    "permission_id:{permission_id_key}"
                )));
            }

            let permission_name_key = normalize_name_key(perm.name.as_str());
            if !seen_permission_names.insert(permission_name_key.clone()) {
                errors.push(ValidationError::DuplicateId(format!(
                    "permission_name:{permission_name_key}"
                )));
            }

            if perm.id.is_empty() || perm.id.len() > ID_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "permissions[].id",
                    message: format!("must be 1..={ID_MAX} characters"),
                });
            }
            if perm.name.is_empty() || perm.name.len() > NAME_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "permissions[].name",
                    message: format!("must be 1..={NAME_MAX} characters"),
                });
            }
            if perm.actions.is_empty() {
                errors.push(ValidationError::InvalidFormat {
                    field: "permissions[].actions",
                    message: "must include at least one action reference".into(),
                });
            }
            let action_count = references.validate_all(
                &mut errors,
                "permissions[].actions[]",
                perm.actions
                    .iter()
                    .map(|action| (action.resource_type.as_str(), action.action_name.as_str())),
            );
            expansion.add_entry(
                &mut errors,
                "permission_actions",
                MAX_PERMISSION_ACTION_REFS,
                action_count,
            );
            let not_action_count = references.validate_all(
                &mut errors,
                "permissions[].not_actions[]",
                perm.not_actions
                    .iter()
                    .map(|action| (action.resource_type.as_str(), action.action_name.as_str())),
            );
            expansion.add_entry(
                &mut errors,
                "permission_not_actions",
                MAX_PERMISSION_ACTION_REFS,
                not_action_count,
            );
            permission_action_counts.insert(
                perm.id.as_str(),
                action_count.saturating_add(not_action_count),
            );
        }

        // Check roles reference valid permissions
        let perm_ids: HashSet<_> = self.permissions.iter().map(|p| p.id.as_str()).collect();
        if self.roles.len() > MAX_ROLES {
            errors.push(ValidationError::LimitExceeded {
                resource: "roles",
                limit: MAX_ROLES,
                actual: self.roles.len(),
            });
        }
        let mut seen_role_ids = HashSet::new();
        let mut seen_role_names = HashSet::new();

        if self.step_up_rules.len() > MAX_STEP_UP_RULES {
            errors.push(ValidationError::LimitExceeded {
                resource: "step_up_rules",
                limit: MAX_STEP_UP_RULES,
                actual: self.step_up_rules.len(),
            });
        }

        for role in &self.roles {
            if let Err(error) = role.assignment_policy.validate() {
                errors.push(error);
            }
            let role_id_key = normalize_name_key(role.id.as_str());
            if !seen_role_ids.insert(role_id_key.clone()) {
                errors.push(ValidationError::DuplicateId(format!(
                    "role_id:{role_id_key}"
                )));
            }

            let role_name_key = normalize_name_key(role.name.as_str());
            if !seen_role_names.insert(role_name_key.clone()) {
                errors.push(ValidationError::DuplicateId(format!(
                    "role_name:{role_name_key}"
                )));
            }

            if role.id.is_empty() || role.id.len() > ID_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "roles[].id",
                    message: format!("must be 1..={ID_MAX} characters"),
                });
            }
            if role.name.is_empty() || role.name.len() > NAME_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "roles[].name",
                    message: format!("must be 1..={NAME_MAX} characters"),
                });
            }
            if role.permissions.is_empty() && role.actions.is_empty() {
                errors.push(ValidationError::InvalidFormat {
                    field: "roles[]",
                    message: "must include permissions or actions".into(),
                });
            }
            if role.permissions.len() > MAX_ROLE_PERMISSION_REFS {
                errors.push(ValidationError::LimitExceeded {
                    resource: "role_permissions",
                    limit: MAX_ROLE_PERMISSION_REFS,
                    actual: role.permissions.len(),
                });
            }
            for permission in &role.permissions {
                if !perm_ids.contains(permission.permission_id.as_str()) {
                    errors.push(ValidationError::ReferenceNotFound {
                        entity_type: "permission",
                        id: permission.permission_id.as_str().to_string(),
                    });
                }
                expansion.add_policy_links(
                    permission_action_counts
                        .get(permission.permission_id.as_str())
                        .copied()
                        .unwrap_or_default(),
                    permission.scopes.len(),
                );
                if permission.scopes.len() > MAX_ROLE_ENTRY_SCOPES {
                    errors.push(ValidationError::LimitExceeded {
                        resource: "role_permission_scopes",
                        limit: MAX_ROLE_ENTRY_SCOPES,
                        actual: permission.scopes.len(),
                    });
                }
            }
            let mut role_action_count = 0_usize;
            for action in &role.actions {
                let count = references.validate(
                    &mut errors,
                    "roles[].actions[]",
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                );
                role_action_count = role_action_count.saturating_add(count);
                expansion.add_policy_links(count, action.scopes.len());
                if action.scopes.len() > MAX_ROLE_ENTRY_SCOPES {
                    errors.push(ValidationError::LimitExceeded {
                        resource: "role_action_scopes",
                        limit: MAX_ROLE_ENTRY_SCOPES,
                        actual: action.scopes.len(),
                    });
                }
                if let Some(limit) = &action.limit
                    && let Err(error) = limit.validate()
                {
                    errors.push(error);
                }
            }
            expansion.add_entry(
                &mut errors,
                "role_actions",
                MAX_ROLE_ACTION_REFS,
                role_action_count,
            );
            let mut role_not_action_count = 0_usize;
            for action in &role.not_actions {
                let count = references.validate(
                    &mut errors,
                    "roles[].not_actions[]",
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                );
                role_not_action_count = role_not_action_count.saturating_add(count);
                expansion.add_policy_links(count, action.scopes.len());
                if action.scopes.len() > MAX_ROLE_ENTRY_SCOPES {
                    errors.push(ValidationError::LimitExceeded {
                        resource: "role_not_action_scopes",
                        limit: MAX_ROLE_ENTRY_SCOPES,
                        actual: action.scopes.len(),
                    });
                }
                if action.limit.is_some() {
                    errors.push(ValidationError::InvalidFormat {
                        field: "roles[].not_actions[].limit",
                        message: "limits are only valid on granting actions".to_string(),
                    });
                }
            }
            expansion.add_entry(
                &mut errors,
                "role_not_actions",
                MAX_ROLE_ACTION_REFS,
                role_not_action_count,
            );
        }
        expansion.check_totals(&mut errors);

        validate_resource_scope_configuration(self, &mut errors);

        if self.authn_providers.len() > MAX_AUTHN_PROVIDERS {
            errors.push(ValidationError::LimitExceeded {
                resource: "authn_providers",
                limit: MAX_AUTHN_PROVIDERS,
                actual: self.authn_providers.len(),
            });
        }

        for provider in &self.authn_providers {
            if provider.issuer.trim().is_empty() {
                errors.push(ValidationError::InvalidFormat {
                    field: "authn_providers[].issuer",
                    message: "issuer must be non-empty".into(),
                });
            }
            if !has_nonempty_https_target(&provider.issuer) {
                errors.push(ValidationError::InvalidFormat {
                    field: "authn_providers[].issuer",
                    message: "issuer must be https".into(),
                });
            }
            if provider.issuer.len() > AUTHN_URL_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "authn_providers[].issuer",
                    message: format!("must be at most {AUTHN_URL_MAX} characters"),
                });
            }
            if provider.jwks_uri.trim().is_empty() {
                errors.push(ValidationError::InvalidFormat {
                    field: "authn_providers[].jwks_uri",
                    message: "jwks_uri must be non-empty".into(),
                });
            }
            if !has_nonempty_https_target(&provider.jwks_uri) {
                errors.push(ValidationError::InvalidFormat {
                    field: "authn_providers[].jwks_uri",
                    message: "jwks_uri must be https".into(),
                });
            }
            if provider.jwks_uri.len() > AUTHN_URL_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "authn_providers[].jwks_uri",
                    message: format!("must be at most {AUTHN_URL_MAX} characters"),
                });
            }
            if provider.subject_claim.trim().is_empty() {
                errors.push(ValidationError::InvalidFormat {
                    field: "authn_providers[].subject_claim",
                    message: "subject_claim must be non-empty".into(),
                });
            }
            if provider.subject_claim.len() > NAME_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "authn_providers[].subject_claim",
                    message: format!("must be 1..={NAME_MAX} characters"),
                });
            }
            if let Some(org_claim) = &provider.org_claim {
                if org_claim.trim().is_empty() {
                    errors.push(ValidationError::InvalidFormat {
                        field: "authn_providers[].org_claim",
                        message: "org_claim must be non-empty when provided".into(),
                    });
                }
                if org_claim.len() > NAME_MAX {
                    errors.push(ValidationError::OutOfRange {
                        field: "authn_providers[].org_claim",
                        message: format!("must be 1..={NAME_MAX} characters"),
                    });
                }
            }
            if provider.is_missing_audience_policy() {
                errors.push(ValidationError::InvalidFormat {
                    field: "authn_providers[].audiences",
                    message: "audiences are required unless allow_any_audience is true".into(),
                });
            }
            if let Some(auds) = &provider.audiences
                && auds.is_empty()
            {
                errors.push(ValidationError::InvalidFormat {
                    field: "authn_providers[].audiences",
                    message: "audiences cannot be empty".into(),
                });
            }
            if let Some(auds) = &provider.audiences
                && auds.len() > AUTHN_AUDIENCES_MAX
            {
                errors.push(ValidationError::LimitExceeded {
                    resource: "authn_providers[].audiences",
                    limit: AUTHN_AUDIENCES_MAX,
                    actual: auds.len(),
                });
            }
            if let Some(algs) = &provider.algorithms {
                if algs.len() > AUTHN_ALGORITHMS_MAX {
                    errors.push(ValidationError::LimitExceeded {
                        resource: "authn_providers[].algorithms",
                        limit: AUTHN_ALGORITHMS_MAX,
                        actual: algs.len(),
                    });
                }
                let supported = ["RS256", "RS384", "RS512", "ES256", "ES384", "HS256"];
                for alg in algs {
                    if !supported.contains(&alg.as_str()) {
                        errors.push(ValidationError::InvalidFormat {
                            field: "authn_providers[].algorithms",
                            message: format!("unsupported alg {alg}"),
                        });
                    }
                }
            }
            if provider.cache_ttl_seconds == 0 || provider.cache_ttl_seconds > 86_400 {
                errors.push(ValidationError::OutOfRange {
                    field: "authn_providers[].cache_ttl_seconds",
                    message: "must be 1..=86400".into(),
                });
            }
        }

        if self.scope_mappings.len() > MAX_SCOPE_MAPPINGS {
            errors.push(ValidationError::LimitExceeded {
                resource: "scope_mappings",
                limit: MAX_SCOPE_MAPPINGS,
                actual: self.scope_mappings.len(),
            });
        }

        let mut scope_ids = HashSet::new();
        for entry in &self.scope_mappings {
            if !scope_ids.insert(entry.scope.clone()) {
                errors.push(ValidationError::DuplicateId(entry.scope.clone()));
            }
            if entry.is_empty() {
                errors.push(ValidationError::InvalidFormat {
                    field: "scope_mappings[].permissions",
                    message: "must include permissions or child scopes".into(),
                });
            }
            if entry.permissions.len() > MAX_SCOPE_MAPPING_PERMISSIONS {
                errors.push(ValidationError::LimitExceeded {
                    resource: "scope_mapping_permissions",
                    limit: MAX_SCOPE_MAPPING_PERMISSIONS,
                    actual: entry.permissions.len(),
                });
            }
            if entry.includes.len() > MAX_SCOPE_MAPPING_INCLUDES {
                errors.push(ValidationError::LimitExceeded {
                    resource: "scope_mapping_includes",
                    limit: MAX_SCOPE_MAPPING_INCLUDES,
                    actual: entry.includes.len(),
                });
            }
        }

        for entry in &self.scope_mappings {
            if entry.scope.is_empty() || entry.scope.len() > ID_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "scope_mappings[].scope",
                    message: format!("must be 1..={ID_MAX} characters"),
                });
            }
            if !perm_ids.contains(entry.scope.as_str()) {
                errors.push(ValidationError::ReferenceNotFound {
                    entity_type: "permission",
                    id: entry.scope.clone(),
                });
            }
            for perm in &entry.permissions {
                if !perm_ids.contains(perm.as_str()) {
                    errors.push(ValidationError::ReferenceNotFound {
                        entity_type: "permission",
                        id: perm.clone(),
                    });
                }
            }
            for child in &entry.includes {
                if !scope_ids.contains(child) {
                    errors.push(ValidationError::ReferenceNotFound {
                        entity_type: "scope_mapping",
                        id: child.clone(),
                    });
                }
            }
        }

        // Step-up configuration validation
        let mut step_up_ids = HashSet::new();
        for rule in &self.step_up_rules {
            if !step_up_ids.insert(rule.rule_id.clone()) {
                errors.push(ValidationError::DuplicateId(rule.rule_id.clone()));
            }
            if rule.required_acr == crate::AcrLevel::RecentAuth
                && rule.max_auth_age_seconds.is_none()
            {
                errors.push(ValidationError::InvalidFormat {
                    field: "step_up_rules[].max_auth_age_seconds",
                    message: "is required when required_acr is recent_auth".into(),
                });
            }
            if let Some(age) = rule.max_auth_age_seconds
                && age == 0
            {
                errors.push(ValidationError::InvalidFormat {
                    field: "step_up_rules[].max_auth_age_seconds",
                    message: "must be > 0".into(),
                });
            }
            if let Some(age) = rule.max_mfa_age_seconds
                && age == 0
            {
                errors.push(ValidationError::InvalidFormat {
                    field: "step_up_rules[].max_mfa_age_seconds",
                    message: "must be > 0".into(),
                });
            }
        }

        if let Some(default_rule) = &self.default_step_up_rule
            && !step_up_ids.contains(default_rule.as_str())
        {
            errors.push(ValidationError::ReferenceNotFound {
                entity_type: "step_up_rule",
                id: default_rule.clone(),
            });
        }

        for (rt_id, cfg) in &self.step_up_config {
            if !rt_ids.contains(rt_id.as_str()) {
                errors.push(ValidationError::ReferenceNotFound {
                    entity_type: "resource_type",
                    id: rt_id.clone(),
                });
            }
            let action_names = self
                .resource_types
                .iter()
                .find(|resource_type| resource_type.id == *rt_id)
                .map(|resource_type| {
                    resource_type
                        .actions
                        .iter()
                        .map(|action| action.name.as_str())
                        .collect::<HashSet<_>>()
                })
                .unwrap_or_default();
            if let Some(rule_id) = &cfg.default_rule
                && !step_up_ids.contains(rule_id.as_str())
            {
                errors.push(ValidationError::ReferenceNotFound {
                    entity_type: "step_up_rule",
                    id: rule_id.clone(),
                });
            }
            for (action, rule_id) in &cfg.action_rules {
                if action.trim().is_empty() {
                    errors.push(ValidationError::InvalidFormat {
                        field: "step_up_config[].action_rules",
                        message: "action must be non-empty".into(),
                    });
                }
                if !action_names.contains(action.as_str()) {
                    errors.push(ValidationError::ReferenceNotFound {
                        entity_type: "resource_type_action",
                        id: format!("{rt_id}:{action}"),
                    });
                }
                if !step_up_ids.contains(rule_id.as_str()) {
                    errors.push(ValidationError::ReferenceNotFound {
                        entity_type: "step_up_rule",
                        id: rule_id.clone(),
                    });
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Expand wildcard references. Callers run `validate_with_options(true)`
    /// first, which bounds the expanded size from match counts, so the
    /// allocations here are bounded by `MAX_EXPANDED_ACTION_REFS`.
    fn expand_for_validated(&self) -> Result<Self, Vec<ValidationError>> {
        let mut expanded = self.clone();
        let mut errors = Vec::new();
        let mut expansions = ActionPatternExpansionCache::new();
        let resource_types = self.resource_types.as_slice();

        for permission in &mut expanded.permissions {
            permission.actions = expand_permission_action_refs(
                resource_types,
                permission.actions.as_slice(),
                "permissions[].actions[]",
                &mut errors,
                &mut expansions,
            );
            permission.not_actions = expand_permission_action_refs(
                resource_types,
                permission.not_actions.as_slice(),
                "permissions[].not_actions[]",
                &mut errors,
                &mut expansions,
            );
        }

        for role in &mut expanded.roles {
            role.actions = expand_role_action_refs(
                resource_types,
                role.actions.as_slice(),
                "roles[].actions[]",
                &mut errors,
                &mut expansions,
            );
            role.not_actions = expand_role_action_refs(
                resource_types,
                role.not_actions.as_slice(),
                "roles[].not_actions[]",
                &mut errors,
                &mut expansions,
            );
        }

        if errors.is_empty() {
            Ok(expanded)
        } else {
            Err(errors)
        }
    }
}

/// Validates action references against the catalog and counts what each would
/// expand to, without materializing any expansion.
struct ActionReferenceValidator<'catalog> {
    resource_types: &'catalog [ResourceType],
    allow_wildcards: bool,
    match_counts: ActionPatternCountCache,
}

impl ActionReferenceValidator<'_> {
    /// Validate references and return their total expanded count.
    fn validate_all<'reference>(
        &mut self,
        errors: &mut Vec<ValidationError>,
        field: &'static str,
        references: impl Iterator<Item = (&'reference str, &'reference str)>,
    ) -> usize {
        references.fold(0_usize, |total, (resource_type, action_name)| {
            total.saturating_add(self.validate(errors, field, resource_type, action_name))
        })
    }

    /// Validate one reference and return its expanded count. An invalid
    /// reference counts as one, so a count never undercounts the raw list.
    fn validate(
        &mut self,
        errors: &mut Vec<ValidationError>,
        field: &'static str,
        resource_type: &str,
        action_name: &str,
    ) -> usize {
        let has_wildcard = resource_type.contains('*') || action_name.contains('*');
        if has_wildcard && !self.allow_wildcards {
            errors.push(ValidationError::InvalidFormat {
                field,
                message: "wildcards are not allowed in validated action references".into(),
            });
            return 1;
        }

        match self.count(resource_type, action_name) {
            Ok(count) => count,
            Err(error) => {
                self.append_reference_error(errors, field, error, resource_type, action_name);
                1
            }
        }
    }

    fn append_reference_error(
        &self,
        errors: &mut Vec<ValidationError>,
        field: &'static str,
        error: ActionPatternExpandError,
        resource_type: &str,
        action_name: &str,
    ) {
        match error {
            ActionPatternExpandError::NoMatches {
                resource_type_pattern,
                used_wildcard: false,
                ..
            } => {
                let resource_found = self
                    .resource_types
                    .iter()
                    .any(|entry| normalize_name_key(entry.id.as_str()) == resource_type_pattern);
                errors.push(if resource_found {
                    ValidationError::ReferenceNotFound {
                        entity_type: "resource_type_action",
                        id: format!("{resource_type}:{action_name}"),
                    }
                } else {
                    ValidationError::ReferenceNotFound {
                        entity_type: "resource_type",
                        id: resource_type.to_string(),
                    }
                });
            }
            error => append_expansion_error(errors, field, error),
        }
    }

    fn count(
        &mut self,
        resource_type: &str,
        action_name: &str,
    ) -> Result<usize, ActionPatternExpandError> {
        let key = pattern_key(resource_type, action_name);
        if let Some(result) = self.match_counts.get(&key) {
            return result.clone();
        }
        let result =
            ActionPattern::parse(resource_type, action_name, RESOURCE_TYPE_MAX, ACTION_MAX)
                .and_then(|pattern| {
                    pattern.count_matches(self.resource_types, resource_type, action_name)
                });
        self.match_counts.insert(key, result.clone());
        result
    }
}

/// Expansion size accumulated from match counts. Checked before any
/// expansion is allocated so a small wildcard configuration cannot make
/// validation or policy generation materialize an unbounded model.
#[derive(Default)]
struct ExpansionBudget {
    action_refs: usize,
    policy_links: usize,
}

impl ExpansionBudget {
    fn add_entry(
        &mut self,
        errors: &mut Vec<ValidationError>,
        resource: &'static str,
        limit: usize,
        expanded_count: usize,
    ) {
        if expanded_count > limit {
            errors.push(ValidationError::LimitExceeded {
                resource,
                limit,
                actual: expanded_count,
            });
        }
        self.action_refs = self.action_refs.saturating_add(expanded_count);
    }

    fn add_policy_links(&mut self, expanded_count: usize, scope_count: usize) {
        self.policy_links = self
            .policy_links
            .saturating_add(expanded_count.saturating_mul(scope_count));
    }

    fn check_totals(&self, errors: &mut Vec<ValidationError>) {
        if self.action_refs > MAX_EXPANDED_ACTION_REFS {
            errors.push(ValidationError::LimitExceeded {
                resource: "expanded_action_refs",
                limit: MAX_EXPANDED_ACTION_REFS,
                actual: self.action_refs,
            });
        }
        if self.policy_links > MAX_POLICY_LINKS {
            errors.push(ValidationError::LimitExceeded {
                resource: "policy_links",
                limit: MAX_POLICY_LINKS,
                actual: self.policy_links,
            });
        }
    }
}

fn pattern_key(resource_type: &str, action_name: &str) -> (String, String) {
    (
        resource_type.trim().to_ascii_lowercase(),
        action_name.trim().to_ascii_lowercase(),
    )
}

fn validate_resource_scope_types(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    scopes: &[Scope],
    allowed_resource_types: &HashSet<&str>,
) {
    for scope in scopes {
        let Some(resource_type) = scope.resource_type() else {
            continue;
        };
        let matches_grant = allowed_resource_types.len() == 1
            && allowed_resource_types
                .iter()
                .any(|allowed| normalize_name_key(allowed) == normalize_name_key(resource_type));
        if !matches_grant {
            errors.push(ValidationError::InvalidFormat {
                field,
                message: format!(
                    "resource scope type '{resource_type}' must match the only granted resource \
                     type"
                ),
            });
        }
    }
}

/// Resource scopes must name the only resource type an entry grants. The
/// granted resource types are computed only for entries that carry a
/// resource scope, so ordinary wildcard entries cost nothing here.
fn validate_resource_scope_configuration(
    model: &ConfigurationModel,
    errors: &mut Vec<ValidationError>,
) {
    let catalog = model.resource_types.as_slice();
    let has_resource_scope =
        |scopes: &[Scope]| scopes.iter().any(|scope| scope.resource_type().is_some());
    let mut permission_resource_types: HashMap<&str, HashSet<&str>> = HashMap::new();

    for role in &model.roles {
        for permission in &role.permissions {
            if !has_resource_scope(&permission.scopes) {
                continue;
            }
            let permission_id = permission.permission_id.as_str();
            if !permission_resource_types.contains_key(permission_id) {
                let Some(definition) = model
                    .permissions
                    .iter()
                    .find(|definition| definition.id == permission_id)
                else {
                    continue;
                };
                let resource_types = definition
                    .actions
                    .iter()
                    .chain(definition.not_actions.iter())
                    .flat_map(|action| {
                        granted_resource_types(
                            catalog,
                            action.resource_type.as_str(),
                            action.action_name.as_str(),
                        )
                    })
                    .collect();
                permission_resource_types.insert(permission_id, resource_types);
            }
            if let Some(resource_types) = permission_resource_types.get(permission_id) {
                validate_resource_scope_types(
                    errors,
                    "roles[].permissions[].scopes",
                    &permission.scopes,
                    resource_types,
                );
            }
        }
        for (field, actions) in [
            ("roles[].actions[].scopes", &role.actions),
            ("roles[].not_actions[].scopes", &role.not_actions),
        ] {
            for action in actions
                .iter()
                .filter(|action| has_resource_scope(&action.scopes))
            {
                let resource_types = granted_resource_types(
                    catalog,
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                )
                .collect();
                validate_resource_scope_types(errors, field, &action.scopes, &resource_types);
            }
        }
    }
}

/// Resource types matched by one reference; an invalid reference matches none
/// and is reported by reference validation.
fn granted_resource_types<'catalog>(
    catalog: &'catalog [ResourceType],
    resource_type: &str,
    action_name: &str,
) -> impl Iterator<Item = &'catalog str> {
    ActionPattern::parse(resource_type, action_name, RESOURCE_TYPE_MAX, ACTION_MAX)
        .ok()
        .into_iter()
        .flat_map(move |pattern| {
            pattern
                .matches(catalog)
                .map(|(resource_type, _)| resource_type)
                .collect::<Vec<_>>()
        })
}

fn has_nonempty_https_target(value: &str) -> bool {
    if value.trim() != value {
        return false;
    }

    if value.chars().any(char::is_whitespace) {
        return false;
    }

    let Ok(parsed) = Url::parse(value) else {
        return false;
    };

    parsed.scheme() == "https" && parsed.host_str().is_some_and(|host| !host.is_empty())
}

impl TryFrom<ConfigurationModel> for ValidatedConfigurationModel {
    type Error = Vec<ValidationError>;

    fn try_from(config: ConfigurationModel) -> Result<Self, Self::Error> {
        config.validate_with_options(true)?;
        let expanded = config.expand_for_validated()?;
        expanded.validate_with_options(false)?;
        Ok(Self(expanded))
    }
}

impl Deref for ValidatedConfigurationModel {
    type Target = ConfigurationModel;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ValidatedConfigurationModel {
    pub fn into_inner(self) -> ConfigurationModel {
        self.0
    }
}

fn normalize_name_key(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Expand one pattern once per configuration and share the result across the
/// entries that repeat it.
pub(super) fn expand_action_patterns_shared(
    cache: &mut ActionPatternExpansionCache,
    resource_types: &[ResourceType],
    resource_type_pattern: &str,
    action_name_pattern: &str,
) -> Result<Rc<[ExpandedActionRef]>, ActionPatternExpandError> {
    let key = pattern_key(resource_type_pattern, action_name_pattern);
    if let Some(result) = cache.get(&key) {
        return result.clone();
    }
    let result = expand_action_patterns(
        resource_types,
        resource_type_pattern,
        action_name_pattern,
        RESOURCE_TYPE_MAX,
        ACTION_MAX,
    )
    .map(Rc::from);
    cache.insert(key, result.clone());
    result
}

fn expand_permission_action_refs(
    resource_types: &[ResourceType],
    requested: &[PermissionActionRef],
    field: &'static str,
    errors: &mut Vec<ValidationError>,
    expansions: &mut ActionPatternExpansionCache,
) -> Vec<PermissionActionRef> {
    let mut deduped = HashSet::new();
    let mut expanded = Vec::new();
    for action_ref in requested {
        match expand_action_patterns_shared(
            expansions,
            resource_types,
            action_ref.resource_type.as_str(),
            action_ref.action_name.as_str(),
        ) {
            Ok(matches) => {
                for matched in matches.iter() {
                    if deduped.insert((matched.resource_type.clone(), matched.action_name.clone()))
                    {
                        expanded.push(PermissionActionRef {
                            resource_type: matched.resource_type.clone(),
                            action_name: matched.action_name.clone(),
                        });
                    }
                }
            }
            Err(error) => append_expansion_error(errors, field, error),
        }
    }
    expanded.sort_by_cached_key(|action| {
        (
            normalize_name_key(action.resource_type.as_str()),
            normalize_name_key(action.action_name.as_str()),
        )
    });
    expanded
}

fn expand_role_action_refs(
    resource_types: &[ResourceType],
    requested: &[RoleActionRef],
    field: &'static str,
    errors: &mut Vec<ValidationError>,
    expansions: &mut ActionPatternExpansionCache,
) -> Vec<RoleActionRef> {
    let mut deduped = HashSet::new();
    let mut expanded = Vec::new();
    for action_ref in requested {
        let matches = match expand_action_patterns_shared(
            expansions,
            resource_types,
            action_ref.resource_type.as_str(),
            action_ref.action_name.as_str(),
        ) {
            Ok(matches) => matches,
            Err(error) => {
                append_expansion_error(errors, field, error);
                continue;
            }
        };
        let scope_key = role_scope_key(&action_ref.scopes);
        for matched in matches.iter() {
            let key = (
                matched.resource_type.clone(),
                matched.action_name.clone(),
                scope_key.clone(),
                action_ref.limit.clone(),
            );
            if deduped.insert(key) {
                expanded.push(RoleActionRef {
                    resource_type: matched.resource_type.clone(),
                    action_name: matched.action_name.clone(),
                    scopes: action_ref.scopes.clone(),
                    limit: action_ref.limit.clone(),
                });
            }
        }
    }
    expanded.sort_by_cached_key(|action| {
        (
            normalize_name_key(action.resource_type.as_str()),
            normalize_name_key(action.action_name.as_str()),
            role_scope_key(&action.scopes),
            action.limit.clone(),
        )
    });
    expanded
}

fn role_scope_key(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(Scope::storage_key)
        .collect::<Vec<_>>()
        .join("|")
}

fn append_expansion_error(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    error: ActionPatternExpandError,
) {
    match error {
        ActionPatternExpandError::InvalidPattern(error) => {
            errors.push(ValidationError::InvalidFormat {
                field,
                message: error.to_string(),
            });
        }
        ActionPatternExpandError::NoMatches {
            resource_type_pattern,
            action_name_pattern,
            used_wildcard,
        } => {
            if used_wildcard {
                errors.push(ValidationError::InvalidFormat {
                    field,
                    message: format!(
                        "wildcard pattern matched zero resource_type_action entries: \
                         {resource_type_pattern}:{action_name_pattern}"
                    ),
                });
                return;
            }
            errors.push(ValidationError::ReferenceNotFound {
                entity_type: "resource_type_action",
                id: format!("{resource_type_pattern}:{action_name_pattern}"),
            });
        }
    }
}
