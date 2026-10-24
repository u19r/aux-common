//! Bounds and defaults shared by the HTTP policy and request boundaries.

use std::time::Duration;

/// Maximum number of request header values accepted at the HTTP job boundary.
/// Repeated values count as separate entries.
pub const MAX_HTTP_HEADER_COUNT: usize = 64;

/// Maximum aggregate bytes of request header names and values.
pub const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

pub(super) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
pub(super) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub(super) const DEFAULT_RETRY_AFTER_MAX: Duration = Duration::from_secs(900);
pub(super) const DEFAULT_RETRY_AFTER_FALLBACK: Duration = Duration::from_secs(1);
pub(super) const MAX_POLICY_ID_BYTES: usize = 128;
