use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
    time::Duration,
};

use bytes::Bytes;

use super::super::decode_effect_mode;
use crate::{
    codec::{ValueCodec, ValueTag},
    error::StoreDataError,
    ids::{
        ExecutionId, FairnessKey, JobId, JobKind, LeaseToken, Namespace, OrderingKey, OwnerId,
        QueueName,
    },
    model::{AttemptHistory, JobPolicySnapshot, JobRecordV1, JobState, Lease, PayloadManifest},
    policy::{
        BackoffMultiplier, Deduplication, FairnessClass, FairnessPath, Priority, RetryPolicyInput,
    },
    store::StoreKey,
    time::Timestamp,
};

pub fn decode_job_record(encoded: &[u8]) -> Result<JobRecordV1, StoreDataError> {
    let (tag, body) = ValueCodec::decode_body(encoded)?;
    if tag != ValueTag::Job {
        return Err(StoreDataError::Malformed("expected job value"));
    }
    let mut reader = Reader::new(body);
    let record = read_record(&mut reader)?;
    reader.finish()?;
    record
        .validate()
        .map_err(|_| StoreDataError::Malformed("invalid job record"))?;
    Ok(record)
}

fn read_record(reader: &mut Reader<'_>) -> Result<JobRecordV1, StoreDataError> {
    let identity = read_record_identity(reader)?;
    let routing = read_record_routing(reader)?;
    let timing = read_record_timing(reader)?;
    let policy = read_policy(reader)?;
    let mutable = read_record_mutable(reader)?;
    Ok(JobRecordV1 {
        job_id: identity.job_id,
        namespace: identity.namespace,
        queue: identity.queue,
        kind: identity.kind,
        schema_version: identity.schema_version,
        generation: identity.generation,
        execution_id: identity.execution_id,
        payload: routing.payload,
        fairness: routing.fairness,
        ordering_key: routing.ordering_key,
        priority: routing.priority,
        created_at: timing.created_at,
        scheduled_at: timing.scheduled_at,
        expires_at: timing.expires_at,
        policy,
        attempts: mutable.attempts,
        state: mutable.state,
        checkpoint: mutable.checkpoint,
        retention_deadline: mutable.retention_deadline,
        deduplication: mutable.deduplication,
        revision: mutable.revision,
    })
}

struct RecordIdentity {
    job_id: JobId,
    namespace: Namespace,
    queue: QueueName,
    kind: JobKind,
    schema_version: NonZeroU16,
    generation: u32,
    execution_id: ExecutionId,
}

fn read_record_identity(reader: &mut Reader<'_>) -> Result<RecordIdentity, StoreDataError> {
    Ok(RecordIdentity {
        job_id: JobId::try_from_slice(reader.fixed_array::<16>()?)?,
        namespace: Namespace::try_new(reader.bytes()?)?,
        queue: QueueName::try_new(reader.text()?)?,
        kind: JobKind::try_new(reader.text()?)?,
        schema_version: nonzero_u16(reader.u16()?, "schema version")?,
        generation: reader.u32()?,
        execution_id: ExecutionId::try_from_slice(reader.fixed_array::<16>()?)?,
    })
}

struct RecordRouting {
    payload: PayloadManifest,
    fairness: FairnessClass,
    ordering_key: Option<OrderingKey>,
    priority: Priority,
}

fn read_record_routing(reader: &mut Reader<'_>) -> Result<RecordRouting, StoreDataError> {
    Ok(RecordRouting {
        payload: read_payload(reader)?,
        fairness: read_fairness(reader)?,
        ordering_key: reader
            .optional_bytes()?
            .map(OrderingKey::try_new)
            .transpose()?,
        priority: priority_from_byte(reader.u8()?)?,
    })
}

struct RecordTiming {
    created_at: Timestamp,
    scheduled_at: Timestamp,
    expires_at: Option<Timestamp>,
}

fn read_record_timing(reader: &mut Reader<'_>) -> Result<RecordTiming, StoreDataError> {
    Ok(RecordTiming {
        created_at: Timestamp::from_millis(reader.i64()?),
        scheduled_at: Timestamp::from_millis(reader.i64()?),
        expires_at: read_optional_i64(reader)?,
    })
}

struct RecordMutable {
    attempts: Option<AttemptHistory>,
    state: JobState,
    checkpoint: Option<Bytes>,
    retention_deadline: Timestamp,
    deduplication: Option<Deduplication>,
    revision: u64,
}

fn read_record_mutable(reader: &mut Reader<'_>) -> Result<RecordMutable, StoreDataError> {
    Ok(RecordMutable {
        attempts: read_attempts(reader)?,
        state: read_state(reader)?,
        checkpoint: reader.optional_bytes()?.map(Bytes::copy_from_slice),
        retention_deadline: Timestamp::from_millis(reader.i64()?),
        deduplication: read_dedupe(reader)?,
        revision: reader.u64()?,
    })
}

fn read_payload(reader: &mut Reader<'_>) -> Result<PayloadManifest, StoreDataError> {
    let total_length = reader.u32()?;
    let digest = reader.fixed_array::<32>()?;
    let count = usize::from(reader.u16()?);
    if count > PayloadManifest::MAX_CHUNKS {
        return Err(StoreDataError::InvalidLength {
            field: "payload chunks",
            actual: count,
            maximum: PayloadManifest::MAX_CHUNKS,
        });
    }
    let mut chunk_keys = Vec::with_capacity(count);
    for _ in 0..count {
        chunk_keys.push(StoreKey::try_from(reader.bytes()?)?);
    }
    PayloadManifest::try_new(total_length, *digest, chunk_keys)
        .map_err(|_| StoreDataError::Malformed("payload manifest"))
}

fn read_fairness(reader: &mut Reader<'_>) -> Result<FairnessClass, StoreDataError> {
    match reader.u8()? {
        0 => Ok(FairnessClass::LowVolume),
        1 => {
            let primary = FairnessKey::try_new(reader.bytes()?)?;
            let secondary = reader
                .optional_bytes()?
                .map(FairnessKey::try_new)
                .transpose()?;
            Ok(FairnessClass::Scoped(FairnessPath::new(primary, secondary)))
        }
        _ => Err(StoreDataError::Malformed("fairness class")),
    }
}

fn read_retry(reader: &mut Reader<'_>) -> Result<crate::policy::RetryPolicy, StoreDataError> {
    let maximum_attempts = nonzero_u16(reader.u16()?, "retry attempts")?;
    let maximum_age = Duration::from_nanos(reader.u64()?);
    let minimum_backoff = Duration::from_nanos(reader.u64()?);
    let maximum_backoff = Duration::from_nanos(reader.u64()?);
    let multiplier = BackoffMultiplier::try_from(reader.u32()?)?;
    if reader.u8()? != 1 {
        return Err(StoreDataError::Malformed("retry jitter"));
    }
    crate::policy::RetryPolicy::try_from(RetryPolicyInput {
        maximum_attempts,
        maximum_age,
        minimum_backoff,
        maximum_backoff,
        multiplier,
    })
    .map_err(|_| StoreDataError::Malformed("retry policy"))
}

fn read_policy(reader: &mut Reader<'_>) -> Result<JobPolicySnapshot, StoreDataError> {
    let policy = JobPolicySnapshot {
        effect_mode: decode_effect_mode(reader.u8()?)?,
        cost_units: nonzero_u16(reader.u16()?, "job cost units")?,
        execution_timeout: read_optional_duration(reader)?,
        retry_policy: read_retry(reader)?,
    };
    policy
        .validate()
        .map_err(|_| StoreDataError::Malformed("job policy"))?;
    Ok(policy)
}

fn read_attempts(reader: &mut Reader<'_>) -> Result<Option<AttemptHistory>, StoreDataError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let attempts = nonzero_u32(reader.u32()?, "attempt count")?;
            let first_attempt_at = Timestamp::from_millis(reader.i64()?);
            let last_attempt_at = Timestamp::from_millis(reader.i64()?);
            let last_outcome = reader
                .optional_text()?
                .map(crate::policy::OutcomeCode::try_new)
                .transpose()?;
            let history = AttemptHistory {
                attempts,
                first_attempt_at,
                last_attempt_at,
                last_outcome,
            };
            history
                .validate()
                .map_err(|_| StoreDataError::Malformed("attempt chronology"))?;
            Ok(Some(history))
        }
        _ => Err(StoreDataError::Malformed("attempt history")),
    }
}

fn read_state(reader: &mut Reader<'_>) -> Result<JobState, StoreDataError> {
    match reader.u8()? {
        0 => Ok(JobState::Scheduled),
        1 => {
            let owner = OwnerId::try_from_slice(reader.fixed_array::<16>()?)?;
            let token = LeaseToken::try_from_slice(reader.fixed_array::<16>()?)?;
            let fence = nonzero_u64(reader.u64()?, "lease fence")?;
            let expires_at = Timestamp::from_millis(reader.i64()?);
            Ok(JobState::Leased(Lease::try_new(
                owner, token, fence, expires_at,
            )?))
        }
        2 => Ok(JobState::DeadLettered),
        3 => Ok(JobState::Cancelled),
        4 => Ok(JobState::Suspended),
        _ => Err(StoreDataError::Malformed("job state")),
    }
}

fn read_dedupe(reader: &mut Reader<'_>) -> Result<Option<Deduplication>, StoreDataError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let key = crate::ids::DeduplicationKey::try_new(reader.bytes()?)?;
            let retain_until = Timestamp::from_millis(reader.i64()?);
            Ok(Some(Deduplication::try_new(key, retain_until)?))
        }
        _ => Err(StoreDataError::Malformed("deduplication")),
    }
}

fn read_optional_duration(reader: &mut Reader<'_>) -> Result<Option<Duration>, StoreDataError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(Duration::from_nanos(reader.u64()?))),
        _ => Err(StoreDataError::Malformed("optional execution timeout")),
    }
}

fn read_optional_i64(reader: &mut Reader<'_>) -> Result<Option<Timestamp>, StoreDataError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(Timestamp::from_millis(reader.i64()?))),
        _ => Err(StoreDataError::Malformed("optional timestamp")),
    }
}

fn priority_from_byte(byte: u8) -> Result<Priority, StoreDataError> {
    match byte {
        0 => Ok(Priority::Critical),
        1 => Ok(Priority::Default),
        2 => Ok(Priority::Bulk),
        _ => Err(StoreDataError::Malformed("priority")),
    }
}

fn nonzero_u16(value: u16, field: &'static str) -> Result<NonZeroU16, StoreDataError> {
    NonZeroU16::new(value).ok_or(StoreDataError::Malformed(field))
}

fn nonzero_u32(value: u32, field: &'static str) -> Result<NonZeroU32, StoreDataError> {
    NonZeroU32::new(value).ok_or(StoreDataError::Malformed(field))
}

fn nonzero_u64(value: u64, field: &'static str) -> Result<NonZeroU64, StoreDataError> {
    NonZeroU64::new(value).ok_or(StoreDataError::Malformed(field))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), StoreDataError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(StoreDataError::TrailingBytes)
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StoreDataError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StoreDataError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(StoreDataError::Truncated);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn fixed_array<const N: usize>(&mut self) -> Result<&'a [u8; N], StoreDataError> {
        self.take(N)?
            .try_into()
            .map_err(|_| StoreDataError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, StoreDataError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StoreDataError> {
        Ok(u16::from_be_bytes(*self.fixed_array()?))
    }

    fn u32(&mut self) -> Result<u32, StoreDataError> {
        Ok(u32::from_be_bytes(*self.fixed_array()?))
    }

    fn u64(&mut self) -> Result<u64, StoreDataError> {
        Ok(u64::from_be_bytes(*self.fixed_array()?))
    }

    fn i64(&mut self) -> Result<i64, StoreDataError> {
        Ok(i64::from_be_bytes(*self.fixed_array()?))
    }

    fn bytes(&mut self) -> Result<&'a [u8], StoreDataError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn text(&mut self) -> Result<&'a str, StoreDataError> {
        core::str::from_utf8(self.bytes()?).map_err(|_| StoreDataError::Malformed("text"))
    }

    fn optional_bytes(&mut self) -> Result<Option<&'a [u8]>, StoreDataError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.bytes()?)),
            _ => Err(StoreDataError::Malformed("optional bytes")),
        }
    }

    fn optional_text(&mut self) -> Result<Option<&'a str>, StoreDataError> {
        self.optional_bytes()?
            .map(|value| core::str::from_utf8(value).map_err(|_| StoreDataError::Malformed("text")))
            .transpose()
    }
}
