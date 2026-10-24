use std::time::Instant;

use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{connection::ValkeyBuffer, metadata::StoredMetadata};
use crate::{
    BufferError, Deadline, Namespace,
    constants::{VALKEY_MAX_VALUE_BYTES, VALKEY_REVISION_PREFIX_BYTES, VALKEY_STATE_VERSION},
    retention::RetentionState,
};

pub(super) enum StateOperation {
    Read,
    Inspect,
    Commit,
}
impl From<StateOperation> for &'static str {
    fn from(operation: StateOperation) -> Self {
        match operation {
            StateOperation::Read => "read",
            StateOperation::Inspect => "inspect",
            StateOperation::Commit => "commit",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct StoredState<T> {
    #[serde(rename = "_revision")]
    revision: Uuid,
    version: u16,
    namespace: Namespace,
    state: T,
}

struct RemoteSnapshot {
    previous: (Option<Vec<u8>>, Option<Vec<u8>>),
    state: RetentionState,
}
struct EncodedMutation {
    state: Vec<u8>,
    metadata: Vec<u8>,
    commit_before: i64,
}

impl RemoteSnapshot {
    fn try_new(
        namespace: &Namespace,
        previous: (Option<Vec<u8>>, Option<Vec<u8>>),
    ) -> Result<Self, BufferError> {
        let state = match (&previous.0, &previous.1) {
            (None, None) => RetentionState::default(),
            (Some(state), Some(metadata)) => {
                let stored: StoredState<RetentionState> =
                    serde_json::from_slice(state).map_err(|_| ValkeyBuffer::corrupt_state())?;
                if stored.version != VALKEY_STATE_VERSION || &stored.namespace != namespace {
                    return Err(ValkeyBuffer::corrupt_state());
                }
                stored.state.validate_recovery(namespace)?;
                StoredMetadata::decode(metadata, namespace)?.validate_revision(stored.revision)?;
                stored.state
            }
            _ => return Err(ValkeyBuffer::corrupt_state()),
        };
        Ok(Self { previous, state })
    }
}

impl EncodedMutation {
    fn try_new(
        state: &mut RetentionState,
        namespace: &Namespace,
        commit_before: Option<i64>,
        now: i64,
    ) -> Result<Self, BufferError> {
        let revision = Uuid::now_v7();
        let metadata = StoredMetadata::capture(state, namespace, now, revision)?;
        let state = serde_json::to_vec(&StoredState {
            revision,
            version: VALKEY_STATE_VERSION,
            namespace: namespace.clone(),
            state,
        })
        .map_err(|_| ValkeyBuffer::corrupt_state())?;
        if state.len() > VALKEY_MAX_VALUE_BYTES || metadata.len() > VALKEY_MAX_VALUE_BYTES {
            return Err(BufferError::Full);
        }
        Ok(Self {
            state,
            metadata,
            commit_before: commit_before.unwrap_or(0),
        })
    }
}

impl ValkeyBuffer {
    pub(super) fn prepare_script(&self, operation: StateOperation) -> redis::ScriptInvocation<'_> {
        let mut invocation = self.protocol.prepare_invoke();
        invocation
            .key(&self.state_key)
            .key(&self.metadata_key)
            .arg(<&str>::from(operation))
            .arg(VALKEY_MAX_VALUE_BYTES)
            .arg(VALKEY_REVISION_PREFIX_BYTES);
        invocation
    }

    pub(super) async fn mutate<R, F>(
        &self,
        deadline: Deadline,
        mutation: F,
    ) -> Result<R, BufferError>
    where
        F: Fn(&mut RetentionState, i64) -> Result<R, BufferError>,
    {
        tokio::time::timeout(
            deadline.remaining_at(Instant::now()),
            self.commit_mutation(mutation),
        )
        .await
        .map_err(|_| BufferError::DeadlineExceeded)?
    }

    async fn commit_mutation<R, F>(&self, mutation: F) -> Result<R, BufferError>
    where F: Fn(&mut RetentionState, i64) -> Result<R, BufferError> {
        let mut connection = self.connect().await?;
        loop {
            let previous = self
                .prepare_script(StateOperation::Read)
                .invoke_async(&mut connection)
                .await
                .map_err(Self::remote_error)?;
            let mut snapshot = RemoteSnapshot::try_new(&self.namespace, previous)?;
            self.record_retention_presence(snapshot.previous.0.is_some())?;
            let now = Self::server_time(&mut connection).await?;
            let old_expiry = snapshot.state.next_active_lease_expiry(now);
            let result = mutation(&mut snapshot.state, now)?;
            let expiry = old_expiry
                .into_iter()
                .chain(snapshot.state.next_active_lease_expiry(now))
                .min();
            let encoded =
                EncodedMutation::try_new(&mut snapshot.state, &self.namespace, expiry, now)?;
            if self
                .commit_snapshot(&mut connection, &snapshot, encoded)
                .await?
            {
                return Ok(result);
            }
            tokio::task::yield_now().await;
        }
    }

    async fn commit_snapshot(
        &self,
        connection: &mut ConnectionManager,
        snapshot: &RemoteSnapshot,
        encoded: EncodedMutation,
    ) -> Result<bool, BufferError> {
        let mut invocation = self.prepare_script(StateOperation::Commit);
        invocation
            .arg(u8::from(snapshot.previous.0.is_some()))
            .arg(u8::from(snapshot.previous.1.is_some()))
            .arg(snapshot.previous.0.as_deref().unwrap_or_default())
            .arg(snapshot.previous.1.as_deref().unwrap_or_default())
            .arg(encoded.state)
            .arg(encoded.metadata)
            .arg(encoded.commit_before);
        let applied: i64 = invocation
            .invoke_async(connection)
            .await
            .map_err(Self::remote_error)?;
        if applied == 1 {
            self.record_retention_presence(true)?;
        }
        Ok(applied == 1)
    }
}
