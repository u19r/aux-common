/// Maximum length for identifier-like customer supplied values.
pub const MAX_IDENTIFIER_LEN: usize = 58;
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

/// Reserved context keys added by Authz enrichment.
pub const CONTEXT_SUBJECT_PARENTS_KEY: &str = "subject_parents";
pub const CONTEXT_RESOURCE_PARENTS_KEY: &str = "resource_parents";
/// Reserved context key for Authz internal enforcement metadata.
pub const CONTEXT_INTERNAL_KEY: &str = "_authz";
