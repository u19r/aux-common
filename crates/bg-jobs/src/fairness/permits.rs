//! Durable permit-slot discovery for the canonical drive claim.
//!
//! The in-memory fairness ledger chooses *which* candidate should run.  This
//! module only finds a durable slot set for that candidate.  The returned
//! keys must be supplied to the lifecycle claim transaction; its value and
//! absence checks are the authority and make the final acquisition atomic.

use std::{collections::HashSet, num::NonZeroU16};

use bytes::Bytes;

use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    model::JobRecordV1,
    store::{JobStore, StoreCapabilities, StoreKey},
};

/// Finds the first complete slot set whose keys are all absent.  Scope and
/// ordering keys are considered together, so a partially occupied candidate
/// is never returned.  A racing claimant can consume the selected set before
/// the caller commits; the claim's `Absent` checks then fail closed and the
/// caller may retry discovery with the next set.
pub(crate) async fn find_available_permit_keys<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    capacity: NonZeroU16,
) -> JobResult<Option<Vec<StoreKey>>, S::Error> {
    let sets = keys::permit_key_sets(system.namespace(), record, capacity)
        .map_err(JobSystemError::StoreData)?;
    if sets.first().is_some_and(Vec::is_empty) {
        return Ok(Some(Vec::new()));
    }

    let probes = permit_probes(&sets);
    let values = read_permit_values(system, &probes).await?;

    let mut offset = 0usize;
    for set in sets {
        let end = offset.saturating_add(set.len());
        if values[offset..end].iter().all(Option::is_none) {
            return Ok(Some(set));
        }
        offset = end;
    }
    Ok(None)
}

/// Finds the complete durable permit set held by an expired lease.
///
/// Reclaim replaces the existing set in the same checked transaction as the
/// new lease.  Treating those keys as available would permit a second owner
/// to overwrite a live permit, so only a complete set whose values still
/// match this record is eligible.
pub(crate) async fn find_reclaimable_permit_keys<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
) -> JobResult<Option<Vec<StoreKey>>, S::Error> {
    let capacity =
        NonZeroU16::new(keys::MAX_DURABLE_PERMIT_SLOTS).ok_or(JobSystemError::PayloadCorrupt)?;
    let sets = keys::permit_key_sets(system.namespace(), record, capacity)
        .map_err(JobSystemError::StoreData)?;
    if sets.first().is_some_and(Vec::is_empty) {
        return Ok(Some(Vec::new()));
    }
    let expected = keys::permit_value_for_record(record).map_err(JobSystemError::StoreData)?;
    let probes = permit_probes(&sets);
    let values = read_permit_values(system, &probes).await?;

    let mut offset = 0usize;
    for set in sets {
        let end = offset.saturating_add(set.len());
        if values[offset..end]
            .iter()
            .all(|value| value.as_ref().is_some_and(|value| value == &expected))
        {
            return Ok(Some(set));
        }
        offset = end;
    }
    Ok(None)
}

/// Finds every slot currently owned by the exact leased authority.  Recovery
/// APIs do not receive the original drive capacity, so they scan the same
/// bounded key-space and only return values that match the persisted lease.
pub(crate) async fn find_owned_permit_keys<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
) -> JobResult<Vec<StoreKey>, S::Error> {
    let capacity =
        NonZeroU16::new(keys::MAX_DURABLE_PERMIT_SLOTS).ok_or(JobSystemError::PayloadCorrupt)?;
    let sets = keys::permit_key_sets(system.namespace(), record, capacity)
        .map_err(JobSystemError::StoreData)?;
    let probes = permit_probes(&sets);
    if probes.is_empty() {
        return Ok(Vec::new());
    }
    let values = read_permit_values(system, &probes).await?;
    let mut owned = Vec::new();
    let mut seen = HashSet::new();
    for (key, value) in probes.into_iter().zip(values) {
        if let Some(value) = value
            && keys::permit_value_matches_record(&value, record)
                .map_err(JobSystemError::StoreData)?
            && seen.insert(key.clone())
        {
            owned.push(key);
        }
    }
    Ok(owned)
}

/// Returns a conservative physical read bound for one complete permit scan.
/// Permit keys have fixed widths across slots, so the largest key in the
/// first set safely bounds both backend key-count and aggregate-key-byte
/// batching without allocating the complete key-space twice.
pub(crate) fn permit_read_operation_bound<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    capacity: NonZeroU16,
) -> JobResult<u32, S::Error> {
    if capacity.get() > keys::MAX_DURABLE_PERMIT_SLOTS {
        return Err(JobSystemError::StoreData(
            crate::error::StoreDataError::InvalidLength {
                field: "durable permit slots",
                actual: usize::from(capacity.get()),
                maximum: usize::from(keys::MAX_DURABLE_PERMIT_SLOTS),
            },
        ));
    }
    let first_set = keys::permit_key_sets(system.namespace(), record, NonZeroU16::MIN)
        .map_err(JobSystemError::StoreData)?
        .pop()
        .ok_or(JobSystemError::PayloadCorrupt)?;
    let Some(max_key_bytes) = first_set.iter().map(|key| key.as_bytes().len()).max() else {
        return Ok(0);
    };
    let capabilities = system.store().capabilities();
    let keys_per_batch = (capabilities.max_get_many_key_bytes().get() / max_key_bytes)
        .max(1)
        .min(capabilities.max_get_many_keys().get() as usize);
    let total_keys = usize::from(capacity.get())
        .checked_mul(first_set.len())
        .ok_or(JobSystemError::PayloadCorrupt)?;
    u32::try_from(total_keys.div_ceil(keys_per_batch)).map_err(|_| JobSystemError::PayloadCorrupt)
}

async fn read_permit_values<S: JobStore>(
    system: &JobSystem<S>,
    probes: &[StoreKey],
) -> JobResult<Vec<Option<Bytes>>, S::Error> {
    let capabilities = system.store().capabilities();
    let mut values = Vec::with_capacity(probes.len());
    let mut start = 0;
    while start < probes.len() {
        let batch_end = permit_batch_end(probes, start, capabilities);
        let end = batch_end.max(start.saturating_add(1)).min(probes.len());
        let batch = system.read_many(&probes[start..end]).await?;
        if batch.len() != end.saturating_sub(start) {
            return Err(JobSystemError::PayloadCorrupt);
        }
        values.extend(batch);
        start = end;
    }
    Ok(values)
}

fn permit_probes(sets: &[Vec<StoreKey>]) -> Vec<StoreKey> {
    sets.iter().flatten().cloned().collect()
}

fn permit_batch_end(probes: &[StoreKey], start: usize, capabilities: StoreCapabilities) -> usize {
    let max_keys = capabilities.max_get_many_keys().get() as usize;
    let max_key_bytes = capabilities.max_get_many_key_bytes().get();
    let maximum_end = start.saturating_add(max_keys).min(probes.len());
    let mut bytes = 0usize;
    let mut end = start;
    while end < maximum_end {
        let Some(next_bytes) = bytes.checked_add(probes[end].as_bytes().len()) else {
            break;
        };
        if next_bytes > max_key_bytes {
            break;
        }
        bytes = next_bytes;
        end = end.saturating_add(1);
    }
    end
}
