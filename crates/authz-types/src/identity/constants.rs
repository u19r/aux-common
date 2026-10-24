pub const MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS: u32 = 900;
pub const MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS: u32 = 2_592_000;
pub const MAX_ACCESS_ASSIGNMENT_EXPLANATION_BYTES: usize = 500;

pub(crate) const MAX_SCOPE_STRINGS: usize = 200;
pub(crate) const MAX_SELECTED_RESOURCES: usize = 1_000;
pub(crate) const MAX_SCOPE_MAP_ENTRIES: usize = 1_000;
pub(crate) const MAX_SCOPE_VALUES: usize = 500;
pub(crate) const MAX_SCOPE_TEXT_BYTES: usize = 128;
pub(crate) const MAX_SCOPE_KEY_BYTES: usize = 58;

pub(crate) const ACCESS_PROFILE_SESSION_ID_PREFIX: &str = "aps_";
pub(crate) const MAX_ACCESS_PROFILE_SESSION_ID_BYTES: usize = 128;
pub(crate) const MAX_ACCESS_PROFILE_KEY_BYTES: usize = 80;
