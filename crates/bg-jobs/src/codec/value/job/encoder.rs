use bytes::Bytes;

use crate::{
    codec::value::{ValueCodec, ValueTag, encode_effect_mode},
    error::StoreDataError,
    ids::{FairnessKey, OrderingKey},
    model::{
        AttemptHistory, JobDefinition, JobPolicySnapshot, JobRecordV1, JobState, PayloadManifest,
    },
    policy::{Deduplication, FairnessClass, OutcomeCode, Priority},
    time::Timestamp,
};

// The v1 field order and wire widths are fixed by the independently maintained
// byte vectors in encoder_tests. Capacity estimates mirror that layout and use
// saturating arithmetic; they do not determine the encoded bytes.

pub fn encode_job_record(record: &JobRecordV1) -> Result<Bytes, StoreDataError> {
    record
        .validate()
        .map_err(|_| StoreDataError::Malformed("invalid job record"))?;
    let mut writer = Writer::with_capacity(record_body_capacity(record));
    write_record(&mut writer, record)?;
    ValueCodec::encode(ValueTag::Job, &writer.bytes)
}

/// Version-one canonical immutable definition. Preserve its encoding when the
/// live job codec changes: terminal receipts retain this digest across
/// upgrades.
pub(crate) fn job_definition_digest(
    definition: &JobDefinition<'_>,
) -> Result<[u8; 32], StoreDataError> {
    use sha2::{Digest, Sha256};

    let mut writer = Writer::with_capacity(crate::codec::value::constants::JOB_DEFINITION_CAPACITY);
    writer.u8(crate::codec::value::constants::JOB_DEFINITION_VERSION);
    writer.fixed(definition.job_id.as_bytes());
    writer.bytes(definition.namespace.as_bytes())?;
    writer.text(definition.queue.as_str())?;
    writer.text(definition.kind.as_str())?;
    writer.u16(definition.schema_version.get());
    writer.u32(definition.payload_length);
    writer.fixed(&definition.payload_digest);
    write_fairness(&mut writer, definition.fairness)?;
    write_optional_bytes(
        &mut writer,
        definition.ordering_key.map(OrderingKey::as_bytes),
    )?;
    writer.u8(priority_byte(definition.priority));
    write_optional_i64(&mut writer, definition.expires_at);
    write_policy(&mut writer, definition.policy)?;
    write_dedupe(&mut writer, definition.deduplication)?;
    Ok(Sha256::digest(&writer.bytes).into())
}

fn write_record(writer: &mut Writer, record: &JobRecordV1) -> Result<(), StoreDataError> {
    writer.fixed(record.job_id.as_bytes());
    writer.bytes(record.namespace.as_bytes())?;
    writer.text(record.queue.as_str())?;
    writer.text(record.kind.as_str())?;
    writer.u16(record.schema_version.get());
    writer.u32(record.generation);
    writer.fixed(record.execution_id.as_bytes());
    write_payload(writer, &record.payload)?;
    write_fairness(writer, &record.fairness)?;
    write_optional_bytes(
        writer,
        record.ordering_key.as_ref().map(OrderingKey::as_bytes),
    )?;
    writer.u8(priority_byte(record.priority));
    writer.i64(record.created_at.as_millis());
    writer.i64(record.scheduled_at.as_millis());
    write_optional_i64(writer, record.expires_at);
    write_policy(writer, record.policy)?;
    write_attempts(writer, record.attempts.as_ref())?;
    write_state(writer, &record.state);
    write_optional_bytes(writer, record.checkpoint.as_deref())?;
    writer.i64(record.retention_deadline.as_millis());
    write_dedupe(writer, record.deduplication.as_ref())?;
    writer.u64(record.revision);
    Ok(())
}

fn write_payload(writer: &mut Writer, payload: &PayloadManifest) -> Result<(), StoreDataError> {
    writer.u32(payload.total_length);
    writer.fixed(&payload.digest);
    let count =
        u16::try_from(payload.chunk_keys.len()).map_err(|_| StoreDataError::LengthOverflow)?;
    writer.u16(count);
    for key in &payload.chunk_keys {
        writer.bytes(key.as_bytes())?;
    }
    Ok(())
}

fn write_fairness(writer: &mut Writer, fairness: &FairnessClass) -> Result<(), StoreDataError> {
    match fairness {
        FairnessClass::LowVolume => writer.u8(0),
        FairnessClass::Scoped(path) => {
            writer.u8(1);
            writer.bytes(path.primary.as_bytes())?;
            write_optional_bytes(writer, path.secondary.as_ref().map(FairnessKey::as_bytes))?;
        }
    }
    Ok(())
}

fn write_retry(writer: &mut Writer, policy: crate::policy::RetryPolicy) {
    writer.u16(policy.maximum_attempts().get());
    writer.u64(policy.maximum_age().as_nanos() as u64);
    writer.u64(policy.minimum_backoff().as_nanos() as u64);
    writer.u64(policy.maximum_backoff().as_nanos() as u64);
    writer.u32(policy.multiplier().get());
    writer.u8(1);
}

fn write_policy(writer: &mut Writer, policy: JobPolicySnapshot) -> Result<(), StoreDataError> {
    writer.u8(encode_effect_mode(policy.effect_mode));
    writer.u16(policy.cost_units.get());
    write_optional_duration(writer, policy.execution_timeout)?;
    write_retry(writer, policy.retry_policy);
    Ok(())
}

fn write_attempts(
    writer: &mut Writer,
    attempts: Option<&AttemptHistory>,
) -> Result<(), StoreDataError> {
    match attempts {
        None => writer.u8(0),
        Some(history) => {
            writer.u8(1);
            writer.u32(history.attempts.get());
            writer.i64(history.first_attempt_at.as_millis());
            writer.i64(history.last_attempt_at.as_millis());
            write_optional_text(
                writer,
                history.last_outcome.as_ref().map(OutcomeCode::as_str),
            )?;
        }
    }
    Ok(())
}

fn write_state(writer: &mut Writer, state: &JobState) {
    match state {
        JobState::Scheduled => writer.u8(0),
        JobState::Leased(lease) => {
            writer.u8(1);
            writer.fixed(lease.owner.as_bytes());
            writer.fixed(lease.token.as_bytes());
            writer.u64(lease.fence.get());
            writer.i64(lease.expires_at.as_millis());
        }
        JobState::DeadLettered => writer.u8(2),
        JobState::Cancelled => writer.u8(3),
        JobState::Suspended => writer.u8(4),
    }
}

fn write_dedupe(writer: &mut Writer, dedupe: Option<&Deduplication>) -> Result<(), StoreDataError> {
    match dedupe {
        None => writer.u8(0),
        Some(value) => {
            writer.u8(1);
            writer.bytes(value.key().as_bytes())?;
            writer.i64(value.retain_until().as_millis());
        }
    }
    Ok(())
}

fn write_optional_bytes(writer: &mut Writer, bytes: Option<&[u8]>) -> Result<(), StoreDataError> {
    match bytes {
        None => writer.u8(0),
        Some(value) => {
            writer.u8(1);
            writer.bytes(value)?;
        }
    }
    Ok(())
}

fn write_optional_text(writer: &mut Writer, value: Option<&str>) -> Result<(), StoreDataError> {
    write_optional_bytes(writer, value.map(str::as_bytes))
}

fn write_optional_i64(writer: &mut Writer, value: Option<Timestamp>) {
    match value {
        None => writer.u8(0),
        Some(timestamp) => {
            writer.u8(1);
            writer.i64(timestamp.as_millis());
        }
    }
}

fn write_optional_duration(
    writer: &mut Writer,
    value: Option<std::time::Duration>,
) -> Result<(), StoreDataError> {
    match value {
        None => writer.u8(0),
        Some(duration) => {
            let nanos =
                u64::try_from(duration.as_nanos()).map_err(|_| StoreDataError::LengthOverflow)?;
            writer.u8(1);
            writer.u64(nanos);
        }
    }
    Ok(())
}

fn priority_byte(priority: Priority) -> u8 {
    match priority {
        Priority::Critical => 0,
        Priority::Default => 1,
        Priority::Bulk => 2,
    }
}

fn record_body_capacity(record: &JobRecordV1) -> usize {
    let mut capacity = record_identity_capacity(record);
    capacity = capacity.saturating_add(payload_capacity(&record.payload));
    capacity = capacity.saturating_add(fairness_capacity(&record.fairness));
    capacity = capacity.saturating_add(ordering_capacity(record));
    capacity = capacity.saturating_add(1 + 8 + 8);
    capacity = capacity.saturating_add(record.expires_at.map_or(1, |_| 9));
    capacity = capacity.saturating_add(policy_capacity(record));
    capacity = capacity.saturating_add(attempts_capacity(record));
    capacity = capacity.saturating_add(state_capacity(record));
    capacity = capacity.saturating_add(checkpoint_capacity(record));
    capacity = capacity.saturating_add(8);
    capacity = capacity.saturating_add(dedupe_capacity(record));
    capacity.saturating_add(8)
}

fn record_identity_capacity(record: &JobRecordV1) -> usize {
    let mut capacity = record.job_id.as_bytes().len();
    capacity = capacity.saturating_add(4 + record.namespace.as_bytes().len());
    capacity = capacity.saturating_add(4 + record.queue.as_str().len());
    capacity = capacity.saturating_add(4 + record.kind.as_str().len());
    capacity.saturating_add(2 + 4 + record.execution_id.as_bytes().len())
}

fn payload_capacity(payload: &PayloadManifest) -> usize {
    let mut capacity = 4usize.saturating_add(32 + 2);
    for key in &payload.chunk_keys {
        capacity = capacity.saturating_add(4 + key.as_bytes().len());
    }
    capacity
}

fn fairness_capacity(fairness: &FairnessClass) -> usize {
    match fairness {
        FairnessClass::LowVolume => 1,
        FairnessClass::Scoped(path) => {
            1 + 4
                + path.primary.as_bytes().len()
                + path
                    .secondary
                    .as_ref()
                    .map_or(1, |secondary| 1 + 4 + secondary.as_bytes().len())
        }
    }
}

fn ordering_capacity(record: &JobRecordV1) -> usize {
    record
        .ordering_key
        .as_ref()
        .map_or(1, |key| 1 + 4 + key.as_bytes().len())
}

fn policy_capacity(record: &JobRecordV1) -> usize {
    1 + 2 + record.policy.execution_timeout.map_or(1, |_| 9) + 31
}

fn attempts_capacity(record: &JobRecordV1) -> usize {
    match record.attempts.as_ref() {
        None => 1,
        Some(history) => {
            1 + 4
                + 8
                + 8
                + history
                    .last_outcome
                    .as_ref()
                    .map_or(1, |outcome| 1 + 4 + outcome.as_str().len())
        }
    }
}

fn state_capacity(record: &JobRecordV1) -> usize {
    match &record.state {
        JobState::Scheduled
        | JobState::DeadLettered
        | JobState::Cancelled
        | JobState::Suspended => 1,
        JobState::Leased(lease) => {
            1 + lease.owner.as_bytes().len() + lease.token.as_bytes().len() + 8 + 8
        }
    }
}

fn checkpoint_capacity(record: &JobRecordV1) -> usize {
    record
        .checkpoint
        .as_ref()
        .map_or(1, |checkpoint| 1 + 4 + checkpoint.len())
}

fn dedupe_capacity(record: &JobRecordV1) -> usize {
    match &record.deduplication {
        None => 1,
        Some(dedupe) => 1 + 4 + dedupe.key().as_bytes().len() + 8,
    }
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), StoreDataError> {
        let length = u32::try_from(value.len()).map_err(|_| StoreDataError::LengthOverflow)?;
        self.u32(length);
        self.fixed(value);
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), StoreDataError> {
        self.bytes(value.as_bytes())
    }
}
