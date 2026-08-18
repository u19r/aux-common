use std::collections::{HashMap, HashSet};

use authz_cedar::{
    CedarUidRegistry, CompiledBundle, ParsedPolicySets, PreparedCedarAction, parse_policy_sets,
    validate_bundle_for_config,
};
use authz_types::{
    MAX_PERMISSIONS, MAX_ROLES, TokenContext, TokenScopeType, ValidatedConfigurationModel,
};
use chrono::{DateTime, Utc};

use crate::{AuthzRuntimeError, AuthzRuntimeResult};

const PERMISSION_BITS_WORDS: usize = MAX_PERMISSIONS.div_ceil(64);
const ROLE_BITS_WORDS: usize = MAX_ROLES.div_ceil(64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionBits {
    words: [u64; PERMISSION_BITS_WORDS],
}

impl Default for PermissionBits {
    fn default() -> Self {
        Self {
            words: [0; PERMISSION_BITS_WORDS],
        }
    }
}

impl PermissionBits {
    pub fn set(&mut self, index: usize) {
        if index >= MAX_PERMISSIONS {
            return;
        }
        let word = index / 64;
        let bit = index % 64;
        if let Some(slot) = self.words.get_mut(word) {
            *slot |= 1_u64 << bit;
        }
    }

    pub fn contains(&self, index: usize) -> bool {
        if index >= MAX_PERMISSIONS {
            return false;
        }
        let word = index / 64;
        let bit = index % 64;
        self.words
            .get(word)
            .is_some_and(|slot| (*slot & (1_u64 << bit)) != 0)
    }

    pub fn union_with(&mut self, other: &Self) {
        for (left, right) in self.words.iter_mut().zip(other.words) {
            *left |= right;
        }
    }

    pub fn intersect_with(&mut self, other: &Self) {
        for (left, right) in self.words.iter_mut().zip(other.words) {
            *left &= right;
        }
    }

    pub fn any_intersection(&self, other: &Self) -> bool {
        self.words
            .iter()
            .zip(other.words)
            .any(|(left, right)| (*left & right) != 0)
    }

    pub fn for_each_set_bit(&self, mut visitor: impl FnMut(usize)) {
        for (word_idx, mut bits) in self.words.iter().copied().enumerate() {
            while bits != 0 {
                let trailing_zeros = bits.trailing_zeros() as usize;
                let bit_idx = word_idx * 64 + trailing_zeros;
                if bit_idx < MAX_PERMISSIONS {
                    visitor(bit_idx);
                }
                bits &= bits - 1;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleBits {
    words: [u64; ROLE_BITS_WORDS],
}

impl Default for RoleBits {
    fn default() -> Self {
        Self {
            words: [0; ROLE_BITS_WORDS],
        }
    }
}

impl RoleBits {
    pub fn set(&mut self, index: usize) {
        if index >= MAX_ROLES {
            return;
        }
        let word = index / 64;
        let bit = index % 64;
        if let Some(slot) = self.words.get_mut(word) {
            *slot |= 1_u64 << bit;
        }
    }

    pub fn any_intersection(&self, other: &Self) -> bool {
        self.words
            .iter()
            .zip(other.words)
            .any(|(left, right)| (*left & right) != 0)
    }

    pub fn for_each_set_bit(&self, mut visitor: impl FnMut(usize)) {
        for (word_idx, mut bits) in self.words.iter().copied().enumerate() {
            while bits != 0 {
                let trailing_zeros = bits.trailing_zeros() as usize;
                let bit_idx = word_idx * 64 + trailing_zeros;
                if bit_idx < MAX_ROLES {
                    visitor(bit_idx);
                }
                bits &= bits - 1;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ActionMasks {
    pub(crate) permission_allow: PermissionBits,
    pub(crate) permission_deny: PermissionBits,
    pub(crate) role_allow: RoleBits,
    pub(crate) role_deny: RoleBits,
}

#[derive(Debug, Clone)]
struct PermissionRuntime {
    id: String,
    action_score: usize,
    action_resource_types: Vec<String>,
}

#[derive(Debug, Clone)]
struct RoleRuntime {
    id: String,
    permission_bits: PermissionBits,
}

#[derive(Debug, Clone)]
pub(crate) struct CompiledActionDescriptor {
    pub(crate) masks: ActionMasks,
    pub(crate) best_permission_candidates: Vec<usize>,
    pub(crate) cedar_action: PreparedCedarAction,
}

#[derive(Debug, Clone)]
pub struct EvaluationRuntime {
    pub(crate) config: ValidatedConfigurationModel,
    pub(crate) policy_sets: ParsedPolicySets,
    cedar_uids: CedarUidRegistry,
    roles: Vec<RoleRuntime>,
    permissions: Vec<PermissionRuntime>,
    role_index: HashMap<String, usize>,
    action_descriptors: HashMap<String, HashMap<String, CompiledActionDescriptor>>,
    scope_permission_masks: HashMap<String, PermissionBits>,
}

#[derive(Debug, Clone)]
pub struct ResolvedPermissionBits {
    pub permissions: PermissionBits,
    pub is_valid: bool,
    pub invalid_reason: Option<String>,
}

impl ResolvedPermissionBits {
    pub fn invalid(reason: &str) -> Self {
        Self {
            permissions: PermissionBits::default(),
            is_valid: false,
            invalid_reason: Some(reason.to_string()),
        }
    }

    pub fn valid(permissions: PermissionBits) -> Self {
        Self {
            permissions,
            is_valid: true,
            invalid_reason: None,
        }
    }
}

impl EvaluationRuntime {
    pub fn build(
        config: ValidatedConfigurationModel,
        bundle: &CompiledBundle,
    ) -> AuthzRuntimeResult<Self> {
        if config.permissions.len() > MAX_PERMISSIONS {
            return Err(AuthzRuntimeError::build(format!(
                "permissions exceed bitset capacity: {} > {}",
                config.permissions.len(),
                MAX_PERMISSIONS
            )));
        }
        if config.roles.len() > MAX_ROLES {
            return Err(AuthzRuntimeError::build(format!(
                "roles exceed bitset capacity: {} > {}",
                config.roles.len(),
                MAX_ROLES
            )));
        }

        validate_bundle_for_config(&config, bundle).map_err(AuthzRuntimeError::build)?;
        let policy_sets = parse_policy_sets(bundle).map_err(AuthzRuntimeError::build)?;
        let cedar_uids = CedarUidRegistry::new(&config).map_err(AuthzRuntimeError::build)?;
        let mut permission_index = HashMap::with_capacity(config.permissions.len());
        let mut permissions = Vec::with_capacity(config.permissions.len());
        for (idx, permission) in config.permissions.iter().enumerate() {
            permission_index.insert(permission.id.clone(), idx);
            let mut action_resource_types = permission
                .actions
                .iter()
                .map(|action| action.resource_type.clone())
                .collect::<Vec<_>>();
            action_resource_types.sort();
            action_resource_types.dedup();
            permissions.push(PermissionRuntime {
                id: permission.id.clone(),
                action_score: permission.actions.len() + permission.not_actions.len(),
                action_resource_types,
            });
        }

        let mut role_index = HashMap::with_capacity(config.roles.len());
        let mut roles = Vec::with_capacity(config.roles.len());
        for (idx, role) in config.roles.iter().enumerate() {
            role_index.insert(role.id.clone(), idx);
            let mut role_permissions = PermissionBits::default();
            for permission in &role.permissions {
                if let Some(permission_idx) =
                    permission_index.get(permission.permission_id.as_str())
                {
                    role_permissions.set(*permission_idx);
                }
            }
            roles.push(RoleRuntime {
                id: role.id.clone(),
                permission_bits: role_permissions,
            });
        }

        let mut action_masks: HashMap<String, HashMap<String, ActionMasks>> = HashMap::new();
        for (permission_idx, permission) in config.permissions.iter().enumerate() {
            for action in &permission.actions {
                action_masks_for_mut(
                    &mut action_masks,
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                )
                .permission_allow
                .set(permission_idx);
            }
            for action in &permission.not_actions {
                action_masks_for_mut(
                    &mut action_masks,
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                )
                .permission_deny
                .set(permission_idx);
            }
        }

        for (role_idx, role) in config.roles.iter().enumerate() {
            for action in &role.actions {
                action_masks_for_mut(
                    &mut action_masks,
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                )
                .role_allow
                .set(role_idx);
            }
            for action in &role.not_actions {
                action_masks_for_mut(
                    &mut action_masks,
                    action.resource_type.as_str(),
                    action.action_name.as_str(),
                )
                .role_deny
                .set(role_idx);
            }
        }

        for resource in &config.resource_types {
            for action in &resource.actions {
                action_masks_for_mut(&mut action_masks, &resource.id, &action.name);
            }
        }

        let scope_permission_masks = build_scope_permission_masks(&config, &permission_index);
        let mut action_descriptors = HashMap::with_capacity(action_masks.len());
        for (resource_type, actions) in action_masks {
            let mut descriptors = HashMap::with_capacity(actions.len());
            for (action, masks) in actions {
                let mut best_permission_candidates = (0..permissions.len())
                    .filter(|index| {
                        masks.permission_allow.contains(*index)
                            && !masks.permission_deny.contains(*index)
                    })
                    .collect::<Vec<_>>();
                best_permission_candidates.sort_by(|left, right| {
                    permissions[*right]
                        .action_score
                        .cmp(&permissions[*left].action_score)
                        .then_with(|| permissions[*left].id.cmp(&permissions[*right].id))
                });
                let cedar_action = cedar_uids
                    .prepare_action(&resource_type, &action)
                    .map_err(AuthzRuntimeError::build)?;
                descriptors.insert(
                    action,
                    CompiledActionDescriptor {
                        masks,
                        best_permission_candidates,
                        cedar_action,
                    },
                );
            }
            action_descriptors.insert(resource_type, descriptors);
        }

        Ok(Self {
            config,
            policy_sets,
            cedar_uids,
            roles,
            permissions,
            role_index,
            action_descriptors,
            scope_permission_masks,
        })
    }

    pub fn config(&self) -> &ValidatedConfigurationModel {
        &self.config
    }

    pub(crate) fn role_idx(&self, role_id: &str) -> Option<usize> {
        self.role_index.get(role_id).copied()
    }

    pub(crate) fn role_permissions(&self, role_idx: usize) -> Option<&PermissionBits> {
        self.roles.get(role_idx).map(|role| &role.permission_bits)
    }

    pub(crate) fn action_descriptor(
        &self,
        resource_type: &str,
        action: &str,
    ) -> Option<&CompiledActionDescriptor> {
        self.action_descriptors
            .get(resource_type)
            .and_then(|actions| actions.get(action))
    }

    pub(crate) fn cedar_uids(&self) -> &CedarUidRegistry {
        &self.cedar_uids
    }

    pub(crate) fn actions_for_resource(
        &self,
        resource_type: &str,
    ) -> Option<&HashMap<String, CompiledActionDescriptor>> {
        self.action_descriptors.get(resource_type)
    }

    pub fn role_ids_sorted(&self, bits: &RoleBits) -> Vec<String> {
        let mut out = Vec::new();
        bits.for_each_set_bit(|idx| {
            if let Some(role) = self.roles.get(idx) {
                out.push(role.id.clone());
            }
        });
        out.sort();
        out
    }

    pub(crate) fn permission_id(&self, index: usize) -> Option<&str> {
        self.permissions
            .get(index)
            .map(|permission| permission.id.as_str())
    }

    #[cfg(test)]
    pub(crate) fn permission_action_score(&self, index: usize) -> Option<usize> {
        self.permissions
            .get(index)
            .map(|permission| permission.action_score)
    }

    pub fn resolve_token_permissions(
        &self,
        user_permissions: &PermissionBits,
        token_ctx: &TokenContext,
    ) -> ResolvedPermissionBits {
        self.resolve_token_permissions_at(user_permissions, token_ctx, Utc::now())
    }

    pub fn resolve_token_permissions_at(
        &self,
        user_permissions: &PermissionBits,
        token_ctx: &TokenContext,
        now: DateTime<Utc>,
    ) -> ResolvedPermissionBits {
        self.resolve_token_permissions_for_resource_at(user_permissions, token_ctx, None, now)
    }

    pub(crate) fn resolve_token_permissions_for_resource_at(
        &self,
        user_permissions: &PermissionBits,
        token_ctx: &TokenContext,
        target_org_id: Option<&str>,
        now: DateTime<Utc>,
    ) -> ResolvedPermissionBits {
        if token_is_expired_at(token_ctx, now) {
            return ResolvedPermissionBits::invalid("token_expired");
        }

        match token_ctx.scopes.scope_type {
            TokenScopeType::FullAccess => ResolvedPermissionBits::valid(*user_permissions),
            TokenScopeType::ScopeStrings => {
                let mut token_permissions = PermissionBits::default();
                for scope in &token_ctx.scopes.scope_strings {
                    if let Some(scope_bits) = self.scope_permission_masks.get(scope.as_str()) {
                        token_permissions.union_with(scope_bits);
                    }
                }
                let mut effective = *user_permissions;
                effective.intersect_with(&token_permissions);
                ResolvedPermissionBits::valid(effective)
            }
            TokenScopeType::FineGrained => {
                let Some(fine_grained) = token_ctx.scopes.fine_grained.as_ref() else {
                    return ResolvedPermissionBits::invalid("fine_grained_scope_missing");
                };

                let mut effective = PermissionBits::default();
                user_permissions.for_each_set_bit(|permission_idx| {
                    let Some(permission) = self.permissions.get(permission_idx) else {
                        return;
                    };
                    let allowed_for_every_action_resource = permission
                        .action_resource_types
                        .iter()
                        .all(|resource_type| {
                            fine_grained
                                .resource_permissions
                                .get(resource_type)
                                .is_some_and(|allowed_permissions| {
                                    permission_allowed_for_resource(
                                        allowed_permissions,
                                        permission.id.as_str(),
                                    )
                                })
                        });
                    let allowed_for_target_org = permission
                        .action_resource_types
                        .iter()
                        .filter(|resource_type| resource_type.as_str() == "organization")
                        .all(|_| {
                            target_org_id.is_some_and(|org_id| {
                                fine_grained.org_permissions.get(org_id).is_some_and(
                                    |allowed_permissions| {
                                        permission_allowed_for_resource(
                                            allowed_permissions,
                                            permission.id.as_str(),
                                        )
                                    },
                                )
                            })
                        });
                    if allowed_for_every_action_resource && allowed_for_target_org {
                        effective.set(permission_idx);
                    }
                });

                ResolvedPermissionBits::valid(effective)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ScopedPermissionBits {
    pub permissions: PermissionBits,
    pub checked_roles: RoleBits,
}

fn build_scope_permission_masks(
    config: &ValidatedConfigurationModel,
    permission_index: &HashMap<String, usize>,
) -> HashMap<String, PermissionBits> {
    let mut direct: HashMap<String, PermissionBits> = HashMap::new();
    let mut expansions: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_scopes: HashSet<String> = HashSet::new();

    for mapping in &config.scope_mappings {
        all_scopes.insert(mapping.scope.clone());

        let entry = direct.entry(mapping.scope.clone()).or_default();
        for permission_id in &mapping.permissions {
            if let Some(permission_idx) = permission_index.get(permission_id) {
                entry.set(*permission_idx);
            }
        }

        if !mapping.includes.is_empty() {
            let children = expansions.entry(mapping.scope.clone()).or_default();
            for child in &mapping.includes {
                all_scopes.insert(child.clone());
                children.push(child.clone());
            }
        }
    }

    let mut resolved = HashMap::with_capacity(all_scopes.len());
    for root in all_scopes {
        let mut out = PermissionBits::default();
        let mut visited = HashSet::new();
        let mut stack = vec![root.clone()];
        while let Some(scope) = stack.pop() {
            if !visited.insert(scope.clone()) {
                continue;
            }
            if let Some(mask) = direct.get(scope.as_str()) {
                out.union_with(mask);
            }
            if let Some(children) = expansions.get(scope.as_str()) {
                stack.extend(children.iter().cloned());
            }
        }
        resolved.insert(root, out);
    }

    resolved
}

fn action_masks_for_mut<'a>(
    action_masks: &'a mut HashMap<String, HashMap<String, ActionMasks>>,
    resource_type: &str,
    action_name: &str,
) -> &'a mut ActionMasks {
    action_masks
        .entry(resource_type.to_string())
        .or_default()
        .entry(action_name.to_string())
        .or_default()
}

fn permission_allowed_for_resource(allowed_permissions: &[String], permission_id: &str) -> bool {
    allowed_permissions
        .iter()
        .any(|allowed| allowed == "*" || allowed == permission_id)
}

fn token_is_expired_at(token_ctx: &TokenContext, now: DateTime<Utc>) -> bool {
    token_ctx
        .expires_at
        .is_some_and(|expires_at| now.timestamp() >= expires_at)
}
