use std::num::NonZeroU64;

use crate::{
    codec::decode_job_record,
    ids::{ExecutionId, JobId, LeaseToken, Namespace, OwnerId},
    keys,
    model::{ExecutionContext, JobState},
    store::{StoreDataError, StoreKey},
    time::Timestamp,
};

/// Runtime-issued authority for a destination effect in the same native
/// transaction as a protected read of the authoritative scheduled-job row.
/// This witness cannot be reconstructed from a payload, checkpoint, or fence.
#[derive(Clone)]
pub struct JobEffectAuthority {
    observation_keys: [StoreKey; 2],
    job_id: JobId,
    namespace: Namespace,
    execution_id: ExecutionId,
    owner: OwnerId,
    token: LeaseToken,
    generation: u32,
    fence: NonZeroU64,
}

impl JobEffectAuthority {
    /// Ordered-store keys for the job and cancellation marker. The destination
    /// must read both with native conflict protection in its effect
    /// transaction.
    pub fn observation_keys(&self) -> &[StoreKey; 2] {
        &self.observation_keys
    }

    /// Checks a protected observation using the canonical persisted codec.
    /// Heartbeats may advance the lease deadline without invalidating this
    /// witness. A replacement claim, cancellation, or expiry rejects it.
    pub fn matches_observations(
        &self,
        values: &[Option<bytes::Bytes>],
        now: Timestamp,
    ) -> Result<bool, StoreDataError> {
        let [Some(bytes), cancellation] = values else {
            return match values {
                [None, _] => Ok(false),
                _ => Err(StoreDataError::Malformed("effect observation cardinality")),
            };
        };
        if cancellation.is_some() {
            return Ok(false);
        }
        let record = decode_job_record(bytes)?;
        if record.job_id != self.job_id
            || record.namespace != self.namespace
            || record.execution_id != self.execution_id
            || record.generation != self.generation
        {
            return Ok(false);
        }
        Ok(match record.state {
            JobState::Leased(lease) => {
                lease.owner == self.owner
                    && lease.token == self.token
                    && lease.fence == self.fence
                    && lease.expires_at > now
            }
            JobState::Scheduled
            | JobState::Cancelled
            | JobState::DeadLettered
            | JobState::Suspended => false,
        })
    }

    /// Binds a destination replay identity to this logical execution. The
    /// claim generation is deliberately excluded so recovery can reconcile
    /// an already committed effect after ownership has changed.
    pub fn bind_request_identity(&self, identity: &mut Vec<u8>) {
        identity
            .extend_from_slice(&(self.observation_keys[0].as_bytes().len() as u64).to_be_bytes());
        identity.extend_from_slice(self.observation_keys[0].as_bytes());
        identity.extend_from_slice(self.execution_id.as_bytes());
    }
}

impl TryFrom<&ExecutionContext<'_>> for JobEffectAuthority {
    type Error = StoreDataError;

    fn try_from(context: &ExecutionContext<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            observation_keys: [
                keys::job_key(context.namespace(), &context.job_id())?,
                keys::cancellation_key(context.namespace(), &context.job_id())?,
            ],
            job_id: context.job_id(),
            namespace: context.namespace().clone(),
            execution_id: context.execution_id(),
            owner: context.owner(),
            token: *context.token(),
            generation: context.generation(),
            fence: context.fence(),
        })
    }
}

impl std::fmt::Debug for JobEffectAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JobEffectAuthority(<redacted>)")
    }
}
