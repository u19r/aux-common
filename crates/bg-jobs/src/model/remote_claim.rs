use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use super::{ExecutionContext, constants::REMOTE_CLAIM_VERSION};
use crate::{
    error::StoreDataError,
    ids::{ExecutionId, JobId, LeaseToken, Namespace, OwnerId},
    keys,
    store::StoreKey,
};

/// A versioned claim descriptor for a remote destination registry.
///
/// This is not a credential or the native transactional `JobEffectAuthority`.
/// An authenticated scheduler publishes it before exposing a usable claim.
/// The destination must commit publication durably, then compare the exact
/// registered descriptor atomically with each effect and its replay receipt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RemoteClaimWire", into = "RemoteClaimWire")]
pub struct RemoteJobClaim {
    namespace: Namespace,
    job_id: JobId,
    execution_id: ExecutionId,
    owner: OwnerId,
    token: LeaseToken,
    generation: u32,
    fence: NonZeroU64,
}

impl RemoteJobClaim {
    /// Stable whole-job registry key; never derive authority from a chunk ID.
    pub fn job_key(&self) -> Result<StoreKey, StoreDataError> {
        keys::job_key(&self.namespace, &self.job_id)
    }

    /// A replacement must belong to this same job and advance its durable
    /// fence. Equal fences with different tokens or owners are rejected.
    pub fn is_replacement_of(&self, current: &Self) -> bool {
        self.namespace == current.namespace
            && self.job_id == current.job_id
            && self.fence > current.fence
    }

    /// Binds receipts to the logical execution while allowing a replacement
    /// claim to recover an already committed response.
    pub fn bind_request_identity(&self, identity: &mut Vec<u8>) {
        let namespace = self.namespace.as_bytes();
        identity.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
        identity.extend_from_slice(namespace);
        identity.extend_from_slice(self.job_id.as_bytes());
        identity.extend_from_slice(self.execution_id.as_bytes());
    }
}

impl From<&ExecutionContext<'_>> for RemoteJobClaim {
    fn from(context: &ExecutionContext<'_>) -> Self {
        Self {
            namespace: context.namespace().clone(),
            job_id: context.job_id(),
            execution_id: context.execution_id(),
            owner: context.owner(),
            token: *context.token(),
            generation: context.generation(),
            fence: context.fence(),
        }
    }
}

impl std::fmt::Debug for RemoteJobClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RemoteJobClaim(<redacted>)")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteClaimWire {
    version: u8,
    namespace: Vec<u8>,
    job_id: [u8; 16],
    execution_id: [u8; 16],
    owner: [u8; 16],
    token: [u8; 16],
    generation: u32,
    fence: NonZeroU64,
}

impl TryFrom<RemoteClaimWire> for RemoteJobClaim {
    type Error = StoreDataError;

    fn try_from(wire: RemoteClaimWire) -> Result<Self, Self::Error> {
        if wire.version != REMOTE_CLAIM_VERSION {
            return Err(StoreDataError::UnknownVersion(wire.version));
        }
        if wire.generation == 0 {
            return Err(StoreDataError::Malformed("claim generation"));
        }
        Ok(Self {
            namespace: Namespace::try_new(wire.namespace)?,
            job_id: JobId::from(wire.job_id),
            execution_id: ExecutionId::from(wire.execution_id),
            owner: OwnerId::from(wire.owner),
            token: LeaseToken::from(wire.token),
            generation: wire.generation,
            fence: wire.fence,
        })
    }
}

impl From<RemoteJobClaim> for RemoteClaimWire {
    fn from(claim: RemoteJobClaim) -> Self {
        Self {
            version: REMOTE_CLAIM_VERSION,
            namespace: claim.namespace.as_bytes().to_vec(),
            job_id: claim.job_id.into_bytes(),
            execution_id: claim.execution_id.into_bytes(),
            owner: claim.owner.into_bytes(),
            token: claim.token.into_bytes(),
            generation: claim.generation,
            fence: claim.fence,
        }
    }
}
