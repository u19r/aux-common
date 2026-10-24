use bytes::Bytes;

use super::{Discovery, budget::DiscoveryBudget, queue_selected};
use crate::{
    budget::{DriveRequest, DriveStopReason},
    codec::{KeyCodec, KeyTag, ValueTag, decode_job_record},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::{JobId, QueueName},
    keys,
    model::{JobRecordV1, JobState},
    store::JobStore,
    time::Timestamp,
};

pub(super) struct LeaseDiscoveryEntry {
    pub(super) entry: crate::store::RangeEntry,
    pub(super) queue: QueueName,
    pub(super) job_id: JobId,
}

pub(super) struct DueDiscoveryEntry {
    pub(super) entry: crate::store::RangeEntry,
    pub(super) queue: QueueName,
    pub(super) job_id: JobId,
    pub(super) when: Timestamp,
}

pub(super) enum DiscoveryRoute {
    Due(DueDiscoveryEntry),
    Lease(LeaseDiscoveryEntry),
}

impl DiscoveryRoute {
    pub(super) fn job_id(&self) -> JobId {
        match self {
            Self::Due(entry) => entry.job_id,
            Self::Lease(entry) => entry.job_id,
        }
    }
}

pub(super) fn collect_due_entries<S: JobStore>(
    system: &JobSystem<S>,
    queue: Option<&crate::ids::QueueName>,
    entries: Vec<crate::store::RangeEntry>,
    due_entries: &mut Vec<DueDiscoveryEntry>,
) -> JobResult<(), S::Error> {
    for entry in entries {
        if let Some(route) = decode_due_entry(system, queue, entry) {
            due_entries.push(route);
        }
    }
    Ok(())
}

fn decode_due_entry<S: JobStore>(
    system: &JobSystem<S>,
    selected_queue: Option<&crate::ids::QueueName>,
    entry: crate::store::RangeEntry,
) -> Option<DueDiscoveryEntry> {
    let decoded = match keys::decode_due_key(system.namespace(), &entry.key) {
        Ok(decoded) => decoded?,
        Err(_) => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    if selected_queue.is_some_and(|queue| queue.as_str() != decoded.queue) {
        return None;
    }
    let job_id = decoded.job_id;
    let when = decoded.when;
    let queue = selected_queue.map_or_else(
        || QueueName::try_new(decoded.queue),
        |queue| Ok(queue.clone()),
    );
    let queue = match queue {
        Ok(queue) => queue,
        Err(_) => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    Some(DueDiscoveryEntry {
        entry,
        queue,
        job_id,
        when,
    })
}

pub(super) fn collect_lease_entries<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    entries: Vec<crate::store::RangeEntry>,
    lease_entries: &mut Vec<LeaseDiscoveryEntry>,
) -> JobResult<(), S::Error> {
    for entry in entries {
        if let Some(route) = decode_lease_entry(system, request, entry) {
            lease_entries.push(route);
        }
    }
    Ok(())
}

fn decode_lease_entry<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    entry: crate::store::RangeEntry,
) -> Option<LeaseDiscoveryEntry> {
    let (queue, job_id) = decode_lease_key(system, &entry.key)?;
    if !queue_selected(request, queue.as_str()) {
        return None;
    }
    let value = match crate::codec::ValueCodec::decode(&entry.value) {
        Ok(value) => value,
        Err(_) => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    if value.tag != ValueTag::Lease || value.body.as_ref() != job_id.as_bytes() {
        return None;
    }
    Some(LeaseDiscoveryEntry {
        entry,
        queue,
        job_id,
    })
}

fn decode_lease_key<S: JobStore>(
    system: &JobSystem<S>,
    key: &crate::store::StoreKey,
) -> Option<(QueueName, JobId)> {
    let decoded = match KeyCodec::decode_borrowed(system.namespace(), key) {
        Ok(decoded) => decoded,
        Err(_) => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    if decoded.tag != KeyTag::Lease {
        return None;
    }
    let [queue_bytes, job_bytes] = decoded.components.as_slice() else {
        observe_discovery_corruption(system);
        return None;
    };
    let queue = std::str::from_utf8(queue_bytes)
        .ok()
        .and_then(|queue| QueueName::try_new(queue).ok());
    let queue = match queue {
        Some(queue) => queue,
        None => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    let job_id = match JobId::try_from_slice(job_bytes) {
        Ok(job_id) => job_id,
        Err(_) => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    Some((queue, job_id))
}

pub(super) struct RecordCandidateContext<'a, S: JobStore> {
    pub(super) system: &'a JobSystem<S>,
    pub(super) request: &'a DriveRequest,
    pub(super) now: Timestamp,
    pub(super) discovery: &'a mut Discovery,
    pub(super) record_entries: &'a [DiscoveryRoute],
    pub(super) record_keys: &'a [crate::store::StoreKey],
    pub(super) discovery_budget: &'a mut DiscoveryBudget,
    pub(super) operation_budget: &'a mut super::super::constants::OperationBudget,
}

impl<S: JobStore> RecordCandidateContext<'_, S> {
    pub(super) async fn load(mut self) -> JobResult<(), S::Error> {
        let capabilities = self.system.store().capabilities();
        let max_value_bytes = capabilities.max_value_bytes().get();
        let mut record_offset = 0;
        while record_offset < self.record_keys.len() {
            let Some(batch_len) = self.batch_len(record_offset, max_value_bytes, capabilities)
            else {
                self.discovery.stop_reason = Some(DriveStopReason::Capacity);
                break;
            };
            if !self.operation_budget.reserve(1) {
                self.discovery.stop_reason = Some(DriveStopReason::Capacity);
                break;
            }
            let batch_end = record_offset.saturating_add(batch_len);
            if !self.load_batch(record_offset, batch_end).await? {
                self.discovery.stop_reason = Some(DriveStopReason::Capacity);
                break;
            }
            record_offset = batch_end;
            if self.discovery_budget.is_exhausted() {
                self.discovery.stop_reason = Some(DriveStopReason::Capacity);
                break;
            }
        }
        Ok(())
    }

    fn batch_len(
        &self,
        offset: usize,
        max_value_bytes: usize,
        capabilities: crate::store::StoreCapabilities,
    ) -> Option<usize> {
        self.discovery_budget.record_batch_len(
            &self.record_keys[offset..],
            max_value_bytes,
            capabilities.max_get_many_keys().get() as usize,
            capabilities.max_get_many_key_bytes().get(),
        )
    }

    async fn load_batch(&mut self, start: usize, end: usize) -> JobResult<bool, S::Error> {
        let batch_keys = &self.record_keys[start..end];
        self.discovery_budget.reserve_record_keys(batch_keys);
        let record_values = self.system.read_many(batch_keys).await?;
        if record_values.len() != end.saturating_sub(start) {
            return Err(JobSystemError::PayloadCorrupt);
        }
        Ok(self.process_batch(start, end, record_values))
    }

    fn process_batch(
        &mut self,
        start: usize,
        end: usize,
        record_values: Vec<Option<Bytes>>,
    ) -> bool {
        let mut within_budget = true;
        for (route, encoded) in self.record_entries[start..end].iter().zip(record_values) {
            let value_bytes = encoded.as_ref().map_or(0, Bytes::len);
            if !self.discovery_budget.reserve_record_value(value_bytes) {
                within_budget = false;
                break;
            }
            match route {
                DiscoveryRoute::Due(route) => {
                    record_due_candidate(self.discovery, route, encoded, self.now, self.system);
                }
                DiscoveryRoute::Lease(route) => {
                    record_lease_candidate(
                        self.discovery,
                        self.request,
                        route,
                        encoded,
                        self.now,
                        self.system,
                    );
                }
            }
        }
        within_budget
    }
}

fn record_due_candidate<S: JobStore>(
    discovery: &mut Discovery,
    route: &DueDiscoveryEntry,
    encoded: Option<Bytes>,
    now: Timestamp,
    system: &JobSystem<S>,
) {
    let Some((record, encoded)) = decode_due_candidate(system, route, encoded) else {
        return;
    };
    discovery.record(
        super::super::candidate::Candidate {
            record,
            encoded,
            key: route.entry.key.clone(),
            value: route.entry.value.clone(),
            when: route.when,
            route_is_due: true,
        },
        now,
    );
}

fn decode_due_candidate<S: JobStore>(
    system: &JobSystem<S>,
    route: &DueDiscoveryEntry,
    encoded: Option<Bytes>,
) -> Option<(JobRecordV1, Bytes)> {
    let encoded = encoded?;
    let record = match decode_job_record(&encoded) {
        Ok(record) => record,
        Err(_) => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    let due_timestamp = match keys::decode_timestamp_value(&route.entry.value, ValueTag::Due) {
        Ok(timestamp) => timestamp,
        Err(_) => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    (record.job_id == route.job_id
        && record.queue == route.queue
        && record.scheduled_at == route.when
        && due_timestamp == route.when)
        .then_some((record, encoded))
}

fn record_lease_candidate<S: JobStore>(
    discovery: &mut Discovery,
    request: &DriveRequest,
    route: &LeaseDiscoveryEntry,
    encoded: Option<Bytes>,
    now: Timestamp,
    system: &JobSystem<S>,
) {
    let Some((record, encoded, lease_expires_at)) =
        decode_lease_candidate(system, request, route, encoded)
    else {
        return;
    };
    discovery.record(
        super::super::candidate::Candidate {
            record,
            encoded,
            key: route.entry.key.clone(),
            value: route.entry.value.clone(),
            when: lease_expires_at,
            route_is_due: false,
        },
        now,
    );
}

fn decode_lease_candidate<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    route: &LeaseDiscoveryEntry,
    encoded: Option<Bytes>,
) -> Option<(JobRecordV1, Bytes, Timestamp)> {
    let encoded = encoded?;
    let record = match decode_job_record(&encoded) {
        Ok(record) => record,
        Err(_) => {
            observe_discovery_corruption(system);
            return None;
        }
    };
    if record.job_id != route.job_id || record.queue.as_str() != route.queue.as_str() {
        observe_discovery_corruption(system);
        return None;
    }
    let JobState::Leased(lease) = &record.state else {
        return None;
    };
    let lease_expires_at = lease.expires_at;
    queue_selected(request, record.queue.as_str()).then_some((record, encoded, lease_expires_at))
}

fn observe_discovery_corruption<S: JobStore>(system: &JobSystem<S>) {
    system.observe_error(crate::observer::SafeJobErrorEvent {
        kind: crate::observer::SafeJobErrorKind::PayloadCorrupt,
        queue: None,
        effect_mode: None,
    });
}
