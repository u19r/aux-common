use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use super::{connection::ValkeyBuffer, transaction::StateOperation};
use crate::{
    BufferError, BufferInspectRequest, BufferSnapshot, BufferStats, Deadline, DurabilityClass,
    TenantScope,
    constants::{VALKEY_MAX_VALUE_BYTES, VALKEY_STATE_VERSION},
    retention::RetentionState,
};

#[derive(Serialize, Deserialize)]
struct SealedLease {
    expires: Option<i64>,
    retry_at: i64,
    retry_scheduled_at: i64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct StoredMetadata {
    #[serde(rename = "_revision")]
    revision: uuid::Uuid,
    version: u16,
    namespace: crate::Namespace,
    admissions: std::collections::BTreeMap<crate::OperationId, crate::buffer::AdmissionReceipt>,
    snapshot: BufferSnapshot,
    oldest_at: Option<i64>,
    open_expiries: Vec<Option<i64>>,
    sealed_leases: Vec<SealedLease>,
    scopes: Vec<TenantScope>,
}

impl StoredMetadata {
    pub(super) fn decode(bytes: &[u8], namespace: &crate::Namespace) -> Result<Self, BufferError> {
        if bytes.len() > VALKEY_MAX_VALUE_BYTES {
            return Err(ValkeyBuffer::corrupt_state());
        }
        let metadata: Self =
            serde_json::from_slice(bytes).map_err(|_| ValkeyBuffer::corrupt_state())?;
        if metadata.version != VALKEY_STATE_VERSION || &metadata.namespace != namespace {
            return Err(ValkeyBuffer::corrupt_state());
        }
        Ok(metadata)
    }

    pub(super) fn validate_revision(&self, revision: uuid::Uuid) -> Result<(), BufferError> {
        if self.revision != revision {
            return Err(ValkeyBuffer::corrupt_state());
        }
        Ok(())
    }

    pub(super) fn capture(
        state: &mut RetentionState,
        namespace: &crate::Namespace,
        now: i64,
        revision: uuid::Uuid,
    ) -> Result<Vec<u8>, BufferError> {
        let oldest_at = Self::oldest_item_time(state);
        let open_expiries = state
            .open_records
            .iter()
            .map(|entry| entry.leased_fence.map(|_| entry.lease_expires_at_ms))
            .collect();
        let sealed_leases = state
            .sealed_batches
            .values()
            .map(|entry| SealedLease {
                expires: entry.lease_expires_at_ms,
                retry_at: entry.next_retry_at_ms,
                retry_scheduled_at: entry.retry_scheduled_at_ms,
            })
            .collect();
        let snapshot = Self::capture_snapshot(state, now);
        serde_json::to_vec(&Self {
            revision,
            version: VALKEY_STATE_VERSION,
            namespace: namespace.clone(),
            admissions: state
                .admission_receipts
                .iter()
                .map(|(id, receipt)| (id.clone(), receipt.observation(id)))
                .collect(),
            snapshot,
            oldest_at,
            open_expiries,
            sealed_leases,
            scopes: Self::collect_scopes(state),
        })
        .map_err(|_| ValkeyBuffer::corrupt_state())
    }

    fn capture_snapshot(state: &mut RetentionState, now: i64) -> BufferSnapshot {
        state.inspect_state(
            BufferInspectRequest {
                operation_id: None,
                now_utc_ms: now,
                now_instant: Instant::now(),
                deadline: Deadline::after(Duration::from_secs(1)),
            },
            DurabilityClass::RemoteValkey,
        )
    }

    fn collect_scopes(state: &RetentionState) -> Vec<TenantScope> {
        let mut scopes: BTreeSet<_> = state
            .open_records
            .iter()
            .map(|r| r.record.scope.clone())
            .chain(
                state
                    .sealed_batches
                    .values()
                    .map(|b| b.batch.scope().clone()),
            )
            .collect();
        scopes.extend(
            state
                .quarantined_items
                .values()
                .map(|record| record.scope.clone()),
        );
        scopes.extend(
            state
                .quarantined_batches
                .values()
                .map(|entry| entry.batch.scope().clone()),
        );
        scopes.into_iter().collect()
    }

    fn oldest_item_time(state: &RetentionState) -> Option<i64> {
        state
            .open_records
            .iter()
            .map(|entry| entry.record.admitted_at_utc_ms)
            .chain(
                state
                    .sealed_batches
                    .values()
                    .map(|entry| entry.batch.first_item_time_ms()),
            )
            .min()
    }

    fn refresh(mut self, now: i64) -> BufferSnapshot {
        let age = self.oldest_at.map_or(Duration::ZERO, |oldest| {
            crate::batch::conservative_age(oldest, now)
        });
        self.snapshot.stats = BufferStats::new(
            self.snapshot.stats.items(),
            self.snapshot.stats.bytes(),
            age,
        );
        self.snapshot.claimable_open_items = self
            .open_expiries
            .iter()
            .filter(|expiry| expiry.is_none_or(|at| at <= now))
            .count();
        self.snapshot.claimable_sealed_batches = self
            .sealed_leases
            .iter()
            .filter(|lease| {
                lease.expires.is_none_or(|at| at <= now)
                    && crate::batch::retry_is_due(lease.retry_scheduled_at, lease.retry_at, now)
            })
            .count();
        self.snapshot.in_flight_batches = self
            .sealed_leases
            .iter()
            .filter(|lease| lease.expires.is_some_and(|at| at > now))
            .count();
        self.snapshot
    }
}

impl ValkeyBuffer {
    pub(super) async fn load_metadata(&self) -> Result<(Option<StoredMetadata>, i64), BufferError> {
        let mut connection = self.connect().await?;
        let (state_exists, bytes): (bool, Option<Vec<u8>>) = self
            .prepare_script(StateOperation::Inspect)
            .invoke_async(&mut connection)
            .await
            .map_err(Self::remote_error)?;
        let now = Self::server_time(&mut connection).await?;
        if state_exists != bytes.is_some() {
            return Err(Self::corrupt_state());
        }
        let metadata = bytes
            .map(|bytes| StoredMetadata::decode(&bytes, &self.namespace))
            .transpose()?;
        self.record_retention_presence(metadata.is_some())?;
        Ok((metadata, now))
    }

    pub(super) async fn fetch_snapshot(
        &self,
        request: BufferInspectRequest,
    ) -> Result<BufferSnapshot, BufferError> {
        let (metadata, now) = self.load_metadata().await?;
        Ok(match metadata {
            Some(metadata) => {
                let admission = request
                    .operation_id
                    .as_ref()
                    .and_then(|id| metadata.admissions.get(id))
                    .copied();
                let mut snapshot = metadata.refresh(now);
                snapshot.admission = admission;
                snapshot
            }
            None => RetentionState::default().inspect_state(request, DurabilityClass::RemoteValkey),
        })
    }

    /// Lists active scopes for recovery without fetching admitted payloads.
    pub async fn list_scopes(
        &self,
        cursor: usize,
        limit: usize,
        deadline: Deadline,
    ) -> Result<(usize, Vec<TenantScope>), BufferError> {
        let (metadata, _) =
            tokio::time::timeout(deadline.remaining_at(Instant::now()), self.load_metadata())
                .await
                .map_err(|_| BufferError::DeadlineExceeded)??;
        let scopes = metadata.map_or_else(Vec::new, |metadata| metadata.scopes);
        let end = cursor
            .saturating_add(limit.clamp(1, crate::constants::VALKEY_SCAN_COUNT))
            .min(scopes.len());
        let page = scopes.get(cursor..end).unwrap_or_default().to_vec();
        Ok((if end == scopes.len() { 0 } else { end }, page))
    }
}
