pub(crate) const PERMISSION_BITS_WORDS: usize = authz_types::MAX_PERMISSIONS.div_ceil(64);
pub(crate) const ROLE_BITS_WORDS: usize = authz_types::MAX_ROLES.div_ceil(64);
