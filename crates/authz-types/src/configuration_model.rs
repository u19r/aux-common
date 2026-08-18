use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;

use crate::{
    ActionPatternExpandError, AuthnProviderConfig, ExpandedActionRef,
    MAX_ACTIONS_PER_RESOURCE_TYPE, MAX_AUTHN_PROVIDERS, MAX_PERMISSION_ACTION_REFS,
    MAX_PERMISSIONS, MAX_RESOURCE_TYPES, MAX_ROLE_ACTION_REFS, MAX_ROLE_ENTRY_SCOPES,
    MAX_ROLE_PERMISSION_REFS, MAX_ROLES, MAX_SCOPE_MAPPING_INCLUDES, MAX_SCOPE_MAPPING_PERMISSIONS,
    MAX_SCOPE_MAPPINGS, MAX_STEP_UP_RULES, Permission, PermissionActionRef, ResourceType, Role,
    RoleActionRef, Scope, ScopeMappingEntry, StepUpConfig, StepUpRule, ValidationError,
    expand_action_patterns,
};

const ID_MAX: usize = 128;
const NAME_MAX: usize = 58;
const RESOURCE_TYPE_MAX: usize = 58;
const ACTION_MAX: usize = 58;
const AUTHN_URL_MAX: usize = 2048;
const AUTHN_ALGORITHMS_MAX: usize = 6;
const AUTHN_AUDIENCES_MAX: usize = 25;

type ActionPatternCache =
    HashMap<(String, String), Result<Vec<ExpandedActionRef>, ActionPatternExpandError>>;

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
        let mut action_pattern_cache = ActionPatternCache::new();

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

            if rt.id.is_empty() || rt.id.len() > RESOURCE_TYPE_MAX {
                errors.push(ValidationError::OutOfRange {
                    field: "resource_types[].id",
                    message: format!("must be 1..={RESOURCE_TYPE_MAX} characters"),
                });
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
            if perm.actions.len() > MAX_PERMISSION_ACTION_REFS {
                errors.push(ValidationError::LimitExceeded {
                    resource: "permission_actions",
                    limit: MAX_PERMISSION_ACTION_REFS,
                    actual: perm.actions.len(),
                });
            }
            if perm.not_actions.len() > MAX_PERMISSION_ACTION_REFS {
                errors.push(ValidationError::LimitExceeded {
                    resource: "permission_not_actions",
                    limit: MAX_PERMISSION_ACTION_REFS,
                    actual: perm.not_actions.len(),
                });
            }
            for action in &perm.actions {
                validate_action_reference(
                    &mut errors,
                    "permissions[].actions[]",
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                    self.resource_types.as_slice(),
                    allow_wildcards,
                    &mut action_pattern_cache,
                );
            }
            for action in &perm.not_actions {
                validate_action_reference(
                    &mut errors,
                    "permissions[].not_actions[]",
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                    self.resource_types.as_slice(),
                    allow_wildcards,
                    &mut action_pattern_cache,
                );
            }
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
            if role.actions.len() > MAX_ROLE_ACTION_REFS {
                errors.push(ValidationError::LimitExceeded {
                    resource: "role_actions",
                    limit: MAX_ROLE_ACTION_REFS,
                    actual: role.actions.len(),
                });
            }
            if role.not_actions.len() > MAX_ROLE_ACTION_REFS {
                errors.push(ValidationError::LimitExceeded {
                    resource: "role_not_actions",
                    limit: MAX_ROLE_ACTION_REFS,
                    actual: role.not_actions.len(),
                });
            }
            for permission in &role.permissions {
                if !perm_ids.contains(permission.permission_id.as_str()) {
                    errors.push(ValidationError::ReferenceNotFound {
                        entity_type: "permission",
                        id: permission.permission_id.as_str().to_string(),
                    });
                }
                if permission.scopes.len() > MAX_ROLE_ENTRY_SCOPES {
                    errors.push(ValidationError::LimitExceeded {
                        resource: "role_permission_scopes",
                        limit: MAX_ROLE_ENTRY_SCOPES,
                        actual: permission.scopes.len(),
                    });
                }
            }
            for action in &role.actions {
                validate_action_reference(
                    &mut errors,
                    "roles[].actions[]",
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                    self.resource_types.as_slice(),
                    allow_wildcards,
                    &mut action_pattern_cache,
                );
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
            for action in &role.not_actions {
                validate_action_reference(
                    &mut errors,
                    "roles[].not_actions[]",
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                    self.resource_types.as_slice(),
                    allow_wildcards,
                    &mut action_pattern_cache,
                );
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
        }

        validate_resource_scope_configuration(self, &mut errors, &mut action_pattern_cache);

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

    fn expand_for_validated(&self) -> Result<Self, Vec<ValidationError>> {
        let mut expanded = self.clone();
        let mut errors = Vec::new();
        let resource_types = expanded.resource_types.clone();
        let mut action_pattern_cache = ActionPatternCache::new();

        for permission in &mut expanded.permissions {
            permission.actions = expand_permission_action_refs(
                resource_types.as_slice(),
                permission.actions.as_slice(),
                "permissions[].actions[]",
                &mut errors,
                &mut action_pattern_cache,
            );
            permission.not_actions = expand_permission_action_refs(
                resource_types.as_slice(),
                permission.not_actions.as_slice(),
                "permissions[].not_actions[]",
                &mut errors,
                &mut action_pattern_cache,
            );
        }

        for role in &mut expanded.roles {
            role.actions = expand_role_action_refs(
                resource_types.as_slice(),
                role.actions.as_slice(),
                "roles[].actions[]",
                &mut errors,
                &mut action_pattern_cache,
            );
            role.not_actions = expand_role_action_refs(
                resource_types.as_slice(),
                role.not_actions.as_slice(),
                "roles[].not_actions[]",
                &mut errors,
                &mut action_pattern_cache,
            );
        }

        if errors.is_empty() {
            Ok(expanded)
        } else {
            Err(errors)
        }
    }

    /// Get a permission by ID.
    pub fn get_permission(&self, id: &str) -> Option<&Permission> {
        self.permissions.iter().find(|p| p.id == id)
    }

    /// Get a resource type by ID.
    pub fn get_resource_type(&self, id: &str) -> Option<&ResourceType> {
        self.resource_types.iter().find(|rt| rt.id == id)
    }

    /// Get a role by ID.
    pub fn get_role(&self, id: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.id == id)
    }
}

fn validate_resource_scope_types(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    scopes: &[Scope],
    allowed_resource_types: &HashSet<String>,
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

fn validate_resource_scope_configuration(
    model: &ConfigurationModel,
    errors: &mut Vec<ValidationError>,
    action_pattern_cache: &mut ActionPatternCache,
) {
    let permission_resource_types: HashMap<_, _> = model
        .permissions
        .iter()
        .map(|permission| {
            let resource_types = permission
                .actions
                .iter()
                .chain(permission.not_actions.iter())
                .flat_map(|action| {
                    expand_action_patterns_cached(
                        action_pattern_cache,
                        model.resource_types.as_slice(),
                        action.resource_type.as_str(),
                        action.action_name.as_str(),
                        RESOURCE_TYPE_MAX,
                        ACTION_MAX,
                    )
                    .unwrap_or_default()
                })
                .map(|action| action.resource_type)
                .collect::<HashSet<_>>();
            (permission.id.as_str(), resource_types)
        })
        .collect::<HashMap<_, _>>();

    for role in &model.roles {
        for permission in &role.permissions {
            if let Some(resource_types) =
                permission_resource_types.get(permission.permission_id.as_str())
            {
                validate_resource_scope_types(
                    errors,
                    "roles[].permissions[].scopes",
                    &permission.scopes,
                    resource_types,
                );
            }
        }
        for action in &role.actions {
            let resource_types = resource_types_for_action(
                action_pattern_cache,
                model.resource_types.as_slice(),
                action.resource_type.as_str(),
                action.action_name.as_str(),
            );
            validate_resource_scope_types(
                errors,
                "roles[].actions[].scopes",
                &action.scopes,
                &resource_types,
            );
        }
        for action in &role.not_actions {
            let resource_types = resource_types_for_action(
                action_pattern_cache,
                model.resource_types.as_slice(),
                action.resource_type.as_str(),
                action.action_name.as_str(),
            );
            validate_resource_scope_types(
                errors,
                "roles[].not_actions[].scopes",
                &action.scopes,
                &resource_types,
            );
        }
    }
}

fn resource_types_for_action(
    action_pattern_cache: &mut ActionPatternCache,
    resource_types: &[ResourceType],
    resource_type: &str,
    action_name: &str,
) -> HashSet<String> {
    expand_action_patterns_cached(
        action_pattern_cache,
        resource_types,
        resource_type,
        action_name,
        RESOURCE_TYPE_MAX,
        ACTION_MAX,
    )
    .unwrap_or_default()
    .into_iter()
    .map(|action| action.resource_type)
    .collect()
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

fn validate_action_reference(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    resource_type: &str,
    action_name: &str,
    resource_types: &[ResourceType],
    allow_wildcards: bool,
    action_pattern_cache: &mut ActionPatternCache,
) {
    let has_wildcard = resource_type.contains('*') || action_name.contains('*');
    if has_wildcard && !allow_wildcards {
        errors.push(ValidationError::InvalidFormat {
            field,
            message: "wildcards are not allowed in validated action references".into(),
        });
        return;
    }

    match expand_action_patterns_cached(
        action_pattern_cache,
        resource_types,
        resource_type,
        action_name,
        RESOURCE_TYPE_MAX,
        ACTION_MAX,
    ) {
        Ok(_) => {}
        Err(ActionPatternExpandError::InvalidPattern(error)) => {
            errors.push(ValidationError::InvalidFormat {
                field,
                message: error.to_string(),
            });
        }
        Err(ActionPatternExpandError::NoMatches {
            resource_type_pattern,
            action_name_pattern,
            used_wildcard,
        }) => {
            if !used_wildcard {
                let resource_found = resource_types
                    .iter()
                    .any(|entry| normalize_name_key(entry.id.as_str()) == resource_type_pattern);
                if !resource_found {
                    errors.push(ValidationError::ReferenceNotFound {
                        entity_type: "resource_type",
                        id: resource_type.to_string(),
                    });
                    return;
                }
                errors.push(ValidationError::ReferenceNotFound {
                    entity_type: "resource_type_action",
                    id: format!("{resource_type}:{action_name}"),
                });
                return;
            }

            errors.push(ValidationError::InvalidFormat {
                field,
                message: format!(
                    "wildcard pattern matched zero resource_type_action entries: \
                     {resource_type_pattern}:{action_name_pattern}"
                ),
            });
        }
    }
}

fn expand_action_patterns_cached(
    cache: &mut ActionPatternCache,
    resource_types: &[ResourceType],
    resource_type_pattern: &str,
    action_name_pattern: &str,
    resource_type_max_len: usize,
    action_name_max_len: usize,
) -> Result<Vec<ExpandedActionRef>, ActionPatternExpandError> {
    let key = (
        resource_type_pattern.trim().to_ascii_lowercase(),
        action_name_pattern.trim().to_ascii_lowercase(),
    );
    if let Some(result) = cache.get(&key) {
        return result.clone();
    }

    let result = expand_action_patterns(
        resource_types,
        resource_type_pattern,
        action_name_pattern,
        resource_type_max_len,
        action_name_max_len,
    );
    cache.insert(key, result.clone());
    result
}

fn expand_permission_action_refs(
    resource_types: &[ResourceType],
    requested: &[PermissionActionRef],
    field: &'static str,
    errors: &mut Vec<ValidationError>,
    action_pattern_cache: &mut ActionPatternCache,
) -> Vec<PermissionActionRef> {
    let mut deduped = HashSet::new();
    let mut expanded = Vec::new();
    for action_ref in requested {
        match expand_action_patterns_cached(
            action_pattern_cache,
            resource_types,
            action_ref.resource_type.as_str(),
            action_ref.action_name.as_str(),
            RESOURCE_TYPE_MAX,
            ACTION_MAX,
        ) {
            Ok(matches) => {
                for matched in matches {
                    let key = (matched.resource_type.clone(), matched.action_name.clone());
                    if deduped.insert(key) {
                        expanded.push(PermissionActionRef {
                            resource_type: matched.resource_type,
                            action_name: matched.action_name,
                        });
                    }
                }
            }
            Err(error) => append_expansion_error(errors, field, error),
        }
    }
    expanded.sort_by(|left, right| {
        (
            normalize_name_key(left.resource_type.as_str()),
            normalize_name_key(left.action_name.as_str()),
        )
            .cmp(&(
                normalize_name_key(right.resource_type.as_str()),
                normalize_name_key(right.action_name.as_str()),
            ))
    });
    expanded
}

fn expand_role_action_refs(
    resource_types: &[ResourceType],
    requested: &[RoleActionRef],
    field: &'static str,
    errors: &mut Vec<ValidationError>,
    action_pattern_cache: &mut ActionPatternCache,
) -> Vec<RoleActionRef> {
    let mut deduped = HashSet::new();
    let mut expanded = Vec::new();
    for action_ref in requested {
        match expand_action_patterns_cached(
            action_pattern_cache,
            resource_types,
            action_ref.resource_type.as_str(),
            action_ref.action_name.as_str(),
            RESOURCE_TYPE_MAX,
            ACTION_MAX,
        ) {
            Ok(matches) => {
                for matched in matches {
                    let scope_key = action_ref
                        .scopes
                        .iter()
                        .map(|scope| scope.storage_key())
                        .collect::<Vec<_>>()
                        .join("|");
                    let key = (
                        matched.resource_type.clone(),
                        matched.action_name.clone(),
                        scope_key,
                        action_ref.limit.clone(),
                    );
                    if deduped.insert(key) {
                        expanded.push(RoleActionRef {
                            resource_type: matched.resource_type,
                            action_name: matched.action_name,
                            scopes: action_ref.scopes.clone(),
                            limit: action_ref.limit.clone(),
                        });
                    }
                }
            }
            Err(error) => append_expansion_error(errors, field, error),
        }
    }
    expanded.sort_by(|left, right| {
        (
            normalize_name_key(left.resource_type.as_str()),
            normalize_name_key(left.action_name.as_str()),
            left.scopes
                .iter()
                .map(|scope| scope.storage_key())
                .collect::<Vec<_>>()
                .join("|"),
        )
            .cmp(&(
                normalize_name_key(right.resource_type.as_str()),
                normalize_name_key(right.action_name.as_str()),
                right
                    .scopes
                    .iter()
                    .map(|scope| scope.storage_key())
                    .collect::<Vec<_>>()
                    .join("|"),
            ))
            .then_with(|| left.limit.cmp(&right.limit))
    });
    expanded
}

fn append_expansion_error(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    error: ActionPatternExpandError,
) {
    match error {
        ActionPatternExpandError::InvalidPattern(parse_error) => {
            errors.push(ValidationError::InvalidFormat {
                field,
                message: parse_error.to_string(),
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

#[cfg(test)]
mod resource_expansion_tests {
    use super::*;

    #[test]
    fn repeated_wildcard_expansion_reuses_the_catalog_match() {
        let resource_types = vec![ResourceType {
            id: "document".into(),
            name: "Document".into(),
            description: None,
            actions: (0..4)
                .map(|index| crate::ActionDefinition {
                    name: format!("read-{index}"),
                    description: None,
                })
                .collect(),
            context_schema: None,
        }];
        let mut cache = ActionPatternCache::new();

        let first = expand_action_patterns_cached(
            &mut cache,
            &resource_types,
            "document",
            "read-*",
            RESOURCE_TYPE_MAX,
            ACTION_MAX,
        )
        .expect("first wildcard expansion");
        let second = expand_action_patterns_cached(
            &mut cache,
            &resource_types,
            "DOCUMENT",
            "READ-*",
            RESOURCE_TYPE_MAX,
            ACTION_MAX,
        )
        .expect("cached wildcard expansion");

        assert_eq!(first, second);
        assert_eq!(
            cache.len(),
            1,
            "duplicate patterns must not rescan the catalog"
        );
    }
}
