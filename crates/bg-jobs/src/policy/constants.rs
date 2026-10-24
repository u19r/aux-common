/// Initial payload budget for the small, explicit drive profile.
pub const TINY_MAX_PAYLOAD_BYTES_IN_FLIGHT: usize = 384 * 1024;
/// Initial completion-detail budget for the small, explicit drive profile.
pub const TINY_MAX_COMPLETION_DETAILS: u32 = 8;

/// Default consecutive delivery ceiling; explicit job policies may tighten it.
pub(super) const DEFAULT_MAXIMUM_ATTEMPTS: u16 = 180;
