mod action;
mod action_pattern;
mod authn_provider;
mod challenge;
mod configuration_model;
mod constants;
mod default_scoping;
mod permission;
mod permission_set;
mod resource_type;
mod role;
mod scope;
mod scope_mapping;
mod step_up;

pub use action::Action;
pub use action_pattern::{
    ActionPatternExpandError, ActionPatternParseError, ExpandedActionRef, expand_action_patterns,
};
pub use authn_provider::AuthnProviderConfig;
pub use challenge::{AuthzChallenge, ChallengeType};
pub use configuration_model::{ConfigurationModel, ValidatedConfigurationModel};
pub use constants::{
    MAX_PERMISSION_SET_CLAIM_BYTES, MAX_PERMISSION_SET_CLAIMS, MAX_PERMISSION_SET_ID_BYTES,
    MAX_PERMISSION_SET_PERMISSIONS,
};
pub use default_scoping::{
    DefaultScopingConfig, ResourceScopingConfig, ScopingPattern, ScopingPatternConfig,
};
pub use permission::{Permission, PermissionActionRef, PermissionId};
pub use permission_set::{
    PermissionSet, PermissionSetAssignment, PermissionSetProtocol, PermissionSetSelectionError,
    eligible_permission_sets, select_interactive_permission_set, select_service_permission_set,
};
pub use resource_type::{ActionDefinition, ResourceType, ResourceTypeId};
pub use role::{
    Role, RoleActionLimit, RoleActionRef, RoleId, RoleLimitAmount, RoleLimitCountScope,
    RoleLimitCountSource, RoleLimitEnforcementMode, RoleLimitKey, RoleLimitReservationTtlSeconds,
    RoleLimitThresholds, RoleLimitUnit, RolePermission,
};
pub use scope::Scope;
pub use scope_mapping::ScopeMappingEntry;
pub use step_up::{AcrLevel, StepUpConfig, StepUpRule};

#[cfg(test)]
mod action_pattern_tests;
#[cfg(test)]
mod configuration_model_tests;
#[cfg(test)]
mod permission_set_tests;
#[cfg(test)]
mod permission_tests;
#[cfg(test)]
mod resource_type_tests;
#[cfg(test)]
mod role_tests;
#[cfg(test)]
mod step_up_tests;
