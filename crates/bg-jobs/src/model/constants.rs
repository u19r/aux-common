//! Shared bounds for persisted job model values.

/// Maximum payload size accepted by the v1 job contract.
pub const MAX_INLINE_PAYLOAD_BYTES: usize = 950 * 1_024;
/// Maximum checkpoint size retained with a leased job.
pub const MAX_CHECKPOINT_BYTES: usize = 65_536;
/// SHA-256 digest size used by payload manifests.
pub const PAYLOAD_DIGEST_BYTES: usize = 32;
/// Maximum registered cost units accepted by the scheduler.
pub const MAX_COST_UNITS: u16 = 1_024;
pub(super) const REMOTE_CLAIM_VERSION: u8 = 1;

// Poll checkpoints retain idle history across pages and process restarts.
pub(super) const POLL_CHECKPOINT_HEADER: &[u8; 8] = b"AUXPOLL1";
pub(super) const POLL_CHECKPOINT_PREFIX_BYTES: usize = 13;
pub(super) const MAX_IDLE_POLL_DELAY_MS: u64 = 300_000;
