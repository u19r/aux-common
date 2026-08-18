/// Maximum length for identifier-like customer supplied values.
pub const MAX_IDENTIFIER_LEN: usize = 58;
/// Maximum integer that can safely cross a JavaScript/JSON number boundary.
pub const MAX_PUBLIC_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Default non-renewable reservation lease for a role-action limit.
pub const DEFAULT_RESERVATION_TTL_SECONDS: u32 = 120;
/// Maximum non-renewable reservation lease for a role-action limit.
pub const MAX_RESERVATION_TTL_SECONDS: u32 = 900;
/// Maximum length for human readable description fields.
pub const MAX_DESCRIPTION_LEN: usize = 250;
/// Maximum length for permission identifiers (`resource_type:name`).
pub const MAX_PERMISSION_ID_LEN: usize = 128;
/// Maximum number of evaluations accepted in one batch request.
pub const MAX_BATCH_EVALUATIONS: usize = 100;
/// Maximum number of resource types in one configuration version.
pub const MAX_RESOURCE_TYPES: usize = 100;
/// Maximum number of actions per resource type.
pub const MAX_ACTIONS_PER_RESOURCE_TYPE: usize = 256;
/// Maximum number of permissions in one configuration version.
pub const MAX_PERMISSIONS: usize = 1024;
/// Maximum number of roles in one configuration version.
pub const MAX_ROLES: usize = 200;
/// Maximum number of scope mapping entries in one configuration version.
pub const MAX_SCOPE_MAPPINGS: usize = 200;
/// Maximum number of external authn providers in one configuration version.
pub const MAX_AUTHN_PROVIDERS: usize = 5;
/// Maximum action references on one permission.
pub const MAX_PERMISSION_ACTION_REFS: usize = 500;
/// Maximum permission references on one role.
pub const MAX_ROLE_PERMISSION_REFS: usize = 1_024;
/// Maximum direct action references on one role.
pub const MAX_ROLE_ACTION_REFS: usize = 500;
/// Maximum scope restrictions attached to one role entry.
pub const MAX_ROLE_ENTRY_SCOPES: usize = 100;
/// Maximum permissions listed by one scope mapping.
pub const MAX_SCOPE_MAPPING_PERMISSIONS: usize = 500;
/// Maximum child scopes listed by one scope mapping.
pub const MAX_SCOPE_MAPPING_INCLUDES: usize = 200;
/// Maximum configured step-up rules.
pub const MAX_STEP_UP_RULES: usize = 200;

/// Reserved context keys added by Authz enrichment.
pub const CONTEXT_SUBJECT_PARENTS_KEY: &str = "subject_parents";
pub const CONTEXT_RESOURCE_PARENTS_KEY: &str = "resource_parents";
/// Reserved context key for Authz internal enforcement metadata.
pub const CONTEXT_INTERNAL_KEY: &str = "_authz";
