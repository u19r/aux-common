//! Public authority and reconciliation values.

use std::num::NonZeroU64;

use crate::ids::{LeaseToken, OwnerId};

/// Exact authority tuple required for a lease-gated mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionAuthority {
    pub owner: OwnerId,
    pub token: LeaseToken,
    pub generation: u32,
    pub fence: NonZeroU64,
}

impl TransitionAuthority {
    pub fn matches(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.token == other.token
            && self.generation == other.generation
            && self.fence == other.fence
    }
}

/// Compact outcome used by completion reconciliation; it never invokes a
/// handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReconciliationOutcome {
    Committed,
    AlreadyCommitted,
    LeaseLost,
    RetryCommit,
    Conflict,
}
