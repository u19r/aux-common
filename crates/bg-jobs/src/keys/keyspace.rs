use std::num::NonZeroU16;

use crate::{
    codec::{
        DecodedOperation, KeyCodec, KeyTag, LiveOperationAuthority, ValueCodec, ValueTag,
        decode_operation, encode_operation_marker, encode_operation_receipt,
    },
    error::StoreDataError,
    ids::{DeduplicationKey, JobId, Namespace, OperationId, OrderingKey, QueueName},
    keys::constants::MAX_DURABLE_PERMIT_SLOTS,
    model::{JobRecordV1, JobState, OperationReceipt},
    policy::FairnessClass,
    store::StoreKey,
    time::Timestamp,
};

pub(crate) fn job_key(namespace: &Namespace, job_id: &JobId) -> Result<StoreKey, StoreDataError> {
    KeyCodec::job(namespace, job_id)
}

pub(crate) fn payload_key(
    namespace: &Namespace,
    job_id: &JobId,
    index: u32,
) -> Result<StoreKey, StoreDataError> {
    let index = index.to_be_bytes();
    KeyCodec::encode(
        namespace,
        KeyTag::PayloadChunk,
        &[job_id.as_bytes(), &index],
    )
}

pub(crate) fn due_key(
    namespace: &Namespace,
    queue: &QueueName,
    scheduled_at: Timestamp,
    job_id: &JobId,
) -> Result<StoreKey, StoreDataError> {
    let timestamp = scheduled_at.as_millis().to_be_bytes();
    KeyCodec::encode(
        namespace,
        KeyTag::Due,
        &[queue.as_str().as_bytes(), &timestamp, job_id.as_bytes()],
    )
}

pub(crate) fn fair_key(
    namespace: &Namespace,
    queue: &QueueName,
    job_id: &JobId,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(
        namespace,
        KeyTag::FairReady,
        &[queue.as_str().as_bytes(), job_id.as_bytes()],
    )
}

/// Key for the canonical fair-dispatch owner state.  It lives in the
/// fair-ready namespace but uses a distinct component from per-job ready
/// entries, so existing fair-ready scans cannot mistake owner state for work.
pub(crate) fn fair_state_key(namespace: &Namespace) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::FairReady, &[b"dispatch-state"])
}

pub(crate) fn lease_key(
    namespace: &Namespace,
    queue: &QueueName,
    job_id: &JobId,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(
        namespace,
        KeyTag::Lease,
        &[queue.as_str().as_bytes(), job_id.as_bytes()],
    )
}

pub(crate) fn lease_queue_prefix(
    namespace: &Namespace,
    queue: &QueueName,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Lease, &[queue.as_str().as_bytes()])
}

pub(crate) fn dedupe_key(
    namespace: &Namespace,
    key: &DeduplicationKey,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Dedupe, &[key.as_bytes()])
}

pub(crate) fn wake_key(
    namespace: &Namespace,
    queue: &QueueName,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Wake, &[queue.as_str().as_bytes()])
}

pub(crate) fn operation_key(
    namespace: &Namespace,
    job_id: &JobId,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Operation, &[job_id.as_bytes()])
}

pub(crate) fn cancellation_key(
    namespace: &Namespace,
    job_id: &JobId,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Cancellation, &[job_id.as_bytes()])
}

/// Builds one complete, atomically-acquired permit set for a slot.  Scope
/// dimensions share a slot number so a claim can never reserve a primary and
/// secondary in different capacity windows.  Ordering groups always use slot
/// zero: they are exclusion locks, not a concurrency pool.
fn permit_keys_for_slot(
    namespace: &Namespace,
    record: &JobRecordV1,
    slot: u16,
) -> Result<Vec<StoreKey>, StoreDataError> {
    let slot = u32::from(slot).to_be_bytes();
    let queue = record.queue.as_str().as_bytes();
    let mut keys = Vec::with_capacity(3);
    match &record.fairness {
        // Low-volume work is intentionally outside the distributed scope
        // permit pool.  Its optional ordering key remains authoritative.
        FairnessClass::LowVolume => {}
        FairnessClass::Scoped(path) => {
            keys.push(KeyCodec::encode(
                namespace,
                KeyTag::Permit,
                &[b"scope", b"primary", queue, path.primary.as_bytes(), &slot],
            )?);
            if let Some(secondary) = path.secondary.as_ref() {
                keys.push(KeyCodec::encode(
                    namespace,
                    KeyTag::Permit,
                    &[
                        b"scope",
                        b"secondary",
                        queue,
                        path.primary.as_bytes(),
                        secondary.as_bytes(),
                        &slot,
                    ],
                )?);
            }
        }
    }
    if let Some(ordering) = &record.ordering_key {
        keys.push(ordering_permit_key(namespace, queue, ordering)?);
    }
    Ok(keys)
}

/// Returns the deterministic bounded slot candidates for one record.  The
/// caller reads these candidates and passes one complete set to the claim
/// transaction, whose `Absent` checks make selection and lease creation one
/// atomic store decision.
pub(crate) fn permit_key_sets(
    namespace: &Namespace,
    record: &JobRecordV1,
    capacity: NonZeroU16,
) -> Result<Vec<Vec<StoreKey>>, StoreDataError> {
    if capacity.get() > MAX_DURABLE_PERMIT_SLOTS {
        return Err(StoreDataError::InvalidLength {
            field: "durable permit slots",
            actual: usize::from(capacity.get()),
            maximum: usize::from(MAX_DURABLE_PERMIT_SLOTS),
        });
    }
    (0..capacity.get())
        .map(|slot| permit_keys_for_slot(namespace, record, slot))
        .collect()
}

fn ordering_permit_key(
    namespace: &Namespace,
    queue: &[u8],
    ordering: &OrderingKey,
) -> Result<StoreKey, StoreDataError> {
    // An ordering group has one durable exclusion lock regardless of the
    // configured scope capacity.  Keeping a slot component makes all permit
    // keys versioned and leaves room for future bounded lock variants.
    let slot = 0_u32.to_be_bytes();
    KeyCodec::encode(
        namespace,
        KeyTag::Permit,
        &[b"ordering", queue, ordering.as_bytes(), &slot],
    )
}

pub(crate) fn dead_letter_key(
    namespace: &Namespace,
    queue: &QueueName,
    job_id: &JobId,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(
        namespace,
        KeyTag::DeadLetter,
        &[queue.as_str().as_bytes(), job_id.as_bytes()],
    )
}

pub(crate) fn operation_value(
    job_id: &JobId,
    operation_id: &OperationId,
    fence_high_water: u64,
) -> Result<bytes::Bytes, StoreDataError> {
    encode_operation_marker(job_id, operation_id, fence_high_water)
}

pub(crate) fn decode_operation_authority(
    encoded: &[u8],
    expected_job_id: &JobId,
) -> Result<LiveOperationAuthority, StoreDataError> {
    match decode_operation(encoded)? {
        DecodedOperation::Live(authority) if authority.matches_job(*expected_job_id) => {
            Ok(authority)
        }
        DecodedOperation::Live(_) => Err(StoreDataError::Malformed("operation job identity")),
        DecodedOperation::Receipt(_) => Err(StoreDataError::Malformed("operation marker")),
    }
}

pub(crate) fn decode_active_operation(
    encoded: &[u8],
    expected_job_id: &JobId,
) -> Result<(OperationId, u64), StoreDataError> {
    let authority = decode_operation_authority(encoded, expected_job_id)?;
    let operation = authority
        .operation_id()
        .ok_or(StoreDataError::Malformed("operation marker"))?;
    Ok((operation, authority.fence_high_water()))
}

pub(crate) fn operation_watermark_value(
    job_id: &JobId,
    fence_high_water: u64,
) -> Result<bytes::Bytes, StoreDataError> {
    crate::codec::encode_operation_watermark(job_id, fence_high_water)
}

pub(crate) fn decode_operation_fence_high_water(
    encoded: &[u8],
    expected_job_id: &JobId,
) -> Result<u64, StoreDataError> {
    match decode_operation(encoded)? {
        DecodedOperation::Live(authority) if authority.matches_job(*expected_job_id) => {
            Ok(authority.fence_high_water())
        }
        DecodedOperation::Receipt(receipt) if receipt.job_id == *expected_job_id => {
            Ok(receipt.fence.get())
        }
        DecodedOperation::Live(_) | DecodedOperation::Receipt(_) => {
            Err(StoreDataError::Malformed("operation job identity"))
        }
    }
}

pub(crate) fn operation_receipt_value(
    receipt: &OperationReceipt,
) -> Result<bytes::Bytes, StoreDataError> {
    encode_operation_receipt(receipt)
}

/// Encodes the exact lease authority owning a durable permit.  The value is
/// wrapped in the versioned permit envelope; the slot is part of the key,
/// while the value carries the lease identity needed for stale-owner checks.
pub(crate) fn permit_value_for_record(
    record: &JobRecordV1,
) -> Result<bytes::Bytes, StoreDataError> {
    let JobState::Leased(lease) = &record.state else {
        return Err(StoreDataError::Malformed("permit requires leased record"));
    };
    let mut body = Vec::with_capacity(60);
    body.extend_from_slice(record.job_id.as_bytes());
    body.extend_from_slice(&record.generation.to_be_bytes());
    body.extend_from_slice(lease.owner.as_bytes());
    body.extend_from_slice(lease.token.as_bytes());
    body.extend_from_slice(&lease.fence.get().to_be_bytes());
    ValueCodec::encode(ValueTag::Permit, &body)
}

/// Returns whether an encoded permit belongs to the exact lease authority in
/// `record`, independent of its slot.  Recovery uses this to discover and
/// delete only the owner's slots when the configured capacity is not present
/// in the recovery API.
pub(crate) fn permit_value_matches_record(
    encoded: &[u8],
    record: &JobRecordV1,
) -> Result<bool, StoreDataError> {
    let (tag, body) = ValueCodec::decode_body(encoded)?;
    let JobState::Leased(lease) = &record.state else {
        return Ok(false);
    };
    if tag != ValueTag::Permit || body.len() != 60 {
        return Ok(false);
    }
    Ok(body[..16] == record.job_id.as_bytes()[..]
        && body[16..20] == record.generation.to_be_bytes()
        && body[20..36] == lease.owner.as_bytes()[..]
        && body[36..52] == lease.token.as_bytes()[..]
        && body[52..60] == lease.fence.get().to_be_bytes())
}

pub(crate) fn cancellation_value() -> Result<bytes::Bytes, StoreDataError> {
    ValueCodec::encode(ValueTag::Cancellation, &[])
}

pub(crate) fn dead_letter_value(job_id: &JobId) -> Result<bytes::Bytes, StoreDataError> {
    ValueCodec::encode(ValueTag::DeadLetter, job_id.as_bytes())
}

pub(crate) fn due_prefix(namespace: &Namespace) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Due, &[])
}

/// Prefix for one queue's due index.  Keeping prefix construction beside the
/// canonical key encoding prevents queue-scoped discovery from rebuilding the
/// persisted byte layout in the drive path.
pub(crate) fn due_queue_prefix(
    namespace: &Namespace,
    queue: &QueueName,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Due, &[queue.as_str().as_bytes()])
}

pub(crate) fn due_value(timestamp: Timestamp) -> Result<bytes::Bytes, StoreDataError> {
    ValueCodec::encode(ValueTag::Due, &timestamp.as_millis().to_be_bytes())
}

pub(crate) fn decode_due_key<'a>(
    namespace: &Namespace,
    key: &'a StoreKey,
) -> Result<Option<DecodedDueKey<'a>>, StoreDataError> {
    let decoded = KeyCodec::decode_borrowed(namespace, key)?;
    if decoded.tag != KeyTag::Due {
        return Ok(None);
    }
    let [queue_bytes, timestamp_bytes, job_bytes] = decoded.components.as_slice() else {
        return Err(StoreDataError::Malformed("due key"));
    };
    let queue =
        std::str::from_utf8(queue_bytes).map_err(|_| StoreDataError::Malformed("due queue"))?;
    if queue.is_empty() || queue.len() > QueueName::MAX_BYTES || queue.chars().any(char::is_control)
    {
        return Err(StoreDataError::Malformed("due queue"));
    }
    let timestamp = i64::from_be_bytes(
        (*timestamp_bytes)
            .try_into()
            .map_err(|_| StoreDataError::Malformed("due timestamp"))?,
    );
    let job_id =
        JobId::try_from_slice(job_bytes).map_err(|_| StoreDataError::Malformed("due job ID"))?;
    Ok(Some(DecodedDueKey {
        queue,
        when: Timestamp::from_millis(timestamp),
        job_id,
    }))
}

pub(crate) struct DecodedDueKey<'a> {
    pub(crate) queue: &'a str,
    pub(crate) when: Timestamp,
    pub(crate) job_id: JobId,
}

pub(crate) fn fair_value(job_id: &JobId) -> Result<bytes::Bytes, StoreDataError> {
    ValueCodec::encode(ValueTag::FairReady, job_id.as_bytes())
}

pub(crate) fn lease_value(job_id: &JobId) -> Result<bytes::Bytes, StoreDataError> {
    ValueCodec::encode(ValueTag::Lease, job_id.as_bytes())
}

pub(crate) fn dedupe_value(
    job_id: &JobId,
    retain_until: Timestamp,
) -> Result<bytes::Bytes, StoreDataError> {
    let mut body = Vec::with_capacity(JobId::BYTE_LENGTH + 8);
    body.extend_from_slice(job_id.as_bytes());
    body.extend_from_slice(&retain_until.as_millis().to_be_bytes());
    ValueCodec::encode(ValueTag::Dedupe, &body)
}

pub(crate) fn decode_dedupe_value(encoded: &[u8]) -> Result<(JobId, Timestamp), StoreDataError> {
    let (tag, body) = ValueCodec::decode_body(encoded)?;
    if tag != ValueTag::Dedupe || body.len() != JobId::BYTE_LENGTH + 8 {
        return Err(StoreDataError::Malformed("dedupe marker"));
    }
    let job_id = JobId::try_from_slice(&body[..JobId::BYTE_LENGTH])?;
    let retain_until = Timestamp::from_millis(i64::from_be_bytes(
        body[JobId::BYTE_LENGTH..]
            .try_into()
            .map_err(|_| StoreDataError::Malformed("dedupe retention"))?,
    ));
    Ok((job_id, retain_until))
}

pub(crate) fn validate_job_marker(
    encoded: &[u8],
    expected_tag: ValueTag,
    expected_job_id: &JobId,
) -> Result<(), StoreDataError> {
    let (tag, body) = ValueCodec::decode_body(encoded)?;
    if tag != expected_tag || body != expected_job_id.as_bytes() {
        return Err(StoreDataError::Malformed("job marker"));
    }
    Ok(())
}

pub(crate) fn validate_empty_marker(
    encoded: &[u8],
    expected_tag: ValueTag,
) -> Result<(), StoreDataError> {
    let (tag, body) = ValueCodec::decode_body(encoded)?;
    if tag != expected_tag || !body.is_empty() {
        return Err(StoreDataError::Malformed("empty marker"));
    }
    Ok(())
}

pub(crate) fn wake_value(timestamp: Timestamp) -> Result<bytes::Bytes, StoreDataError> {
    ValueCodec::encode(ValueTag::Wake, &timestamp.as_millis().to_be_bytes())
}

pub(crate) fn decode_timestamp_value(
    encoded: &[u8],
    expected: ValueTag,
) -> Result<Timestamp, StoreDataError> {
    ValueCodec::decode_timestamp(encoded, expected)
}
