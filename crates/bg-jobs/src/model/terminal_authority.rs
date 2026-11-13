use bytes::Bytes;

use crate::{
    error::StoreDataError,
    model::JobState,
    policy::OutcomeCode,
    store::{EffectReceiptGroup, EffectReceiptKind, StoreKey},
};

/// Authority to publish a terminal application projection, never to execute
/// job effects. The destination must protect these reads in its native write.
/// Redrive, deletion, or any lifecycle change invalidates the snapshot.
#[derive(Clone)]
pub struct JobTerminalAuthority {
    observation_keys: [StoreKey; 2],
    encoded_job: Bytes,
    state: JobState,
    outcome: Option<OutcomeCode>,
    group: EffectReceiptGroup,
}

impl JobTerminalAuthority {
    pub(crate) fn from_terminal_record(
        observation_keys: [StoreKey; 2],
        encoded_job: Bytes,
        state: JobState,
        outcome: Option<OutcomeCode>,
        group: EffectReceiptGroup,
    ) -> Self {
        Self {
            observation_keys,
            encoded_job,
            state,
            outcome,
            group,
        }
    }

    pub(crate) fn into_snapshot(self) -> (StoreKey, Bytes) {
        (self.observation_keys[0].clone(), self.encoded_job)
    }

    pub fn observation_keys(&self) -> &[StoreKey; 2] {
        &self.observation_keys
    }

    pub fn state(&self) -> &JobState {
        &self.state
    }

    pub fn outcome(&self) -> Option<&OutcomeCode> {
        self.outcome.as_ref()
    }

    pub fn matches_observations(&self, values: &[Option<Bytes>]) -> Result<bool, StoreDataError> {
        match values {
            [Some(job), _] => Ok(job == &self.encoded_job),
            [None, _] => Ok(false),
            _ => Err(StoreDataError::Malformed(
                "terminal observation cardinality",
            )),
        }
    }

    /// A terminal projection has its own receipt identity. Include the exact
    /// snapshot so a later terminal state cannot replay a previous projection.
    pub fn bind_request_identity(&self, identity: &mut Vec<u8>) {
        identity.extend_from_slice(b"terminal-projection");
        identity.extend_from_slice(self.observation_keys[0].as_bytes());
        identity.extend_from_slice(&self.encoded_job);
    }

    /// The receipt key of this projection. `digest` binds the snapshot and
    /// the caller's token (computed by the destination).
    pub fn receipt_key(&self, digest: &[u8; 32]) -> Result<StoreKey, StoreDataError> {
        self.group
            .member_key(EffectReceiptKind::TerminalProjection, digest)
    }

    pub fn receipt_group(&self) -> &EffectReceiptGroup {
        &self.group
    }
}

impl std::fmt::Debug for JobTerminalAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JobTerminalAuthority(<redacted>)")
    }
}
