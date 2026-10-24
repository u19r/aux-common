use bytes::Bytes;

use crate::{error::StoreDataError, model::JobState, policy::OutcomeCode, store::StoreKey};

/// Authority to publish a terminal application projection, never to execute
/// job effects. The destination must protect these reads in its native write.
/// Redrive, deletion, or any lifecycle change invalidates the snapshot.
#[derive(Clone)]
pub struct JobTerminalAuthority {
    observation_keys: [StoreKey; 2],
    encoded_job: Bytes,
    state: JobState,
    outcome: Option<OutcomeCode>,
}

impl JobTerminalAuthority {
    pub(crate) fn from_terminal_record(
        observation_keys: [StoreKey; 2],
        encoded_job: Bytes,
        state: JobState,
        outcome: Option<OutcomeCode>,
    ) -> Self {
        Self {
            observation_keys,
            encoded_job,
            state,
            outcome,
        }
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
}

impl std::fmt::Debug for JobTerminalAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JobTerminalAuthority(<redacted>)")
    }
}
