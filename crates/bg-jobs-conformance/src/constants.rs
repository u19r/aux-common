//! Shared bounds for the conformance runners and Quint store connector.

pub(super) const DEFAULT_KEY_PREFIX: &[u8] = b"bg-jobs-conformance/";

pub(super) const RECOVERY_PAYLOAD: &[u8] = b"accepted-before-producer-death";

// Bound unresolved public scheduler observations without replaying a whole
// workload.
pub(super) const GROWTH_RESOLUTION_ATTEMPTS: usize = 8;
