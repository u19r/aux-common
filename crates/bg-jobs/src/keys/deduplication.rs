use crate::{
    codec::{KeyCodec, KeyTag, ValueCodec, ValueTag},
    error::StoreDataError,
    ids::{DeduplicationKey, JobId, Namespace},
    store::StoreKey,
    time::Timestamp,
};

pub(crate) fn dedupe_key(
    namespace: &Namespace,
    key: &DeduplicationKey,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(namespace, KeyTag::Dedupe, &[key.as_bytes()])
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

pub(crate) fn dedupe_expiry_key(
    namespace: &Namespace,
    key: &DeduplicationKey,
    retain_until: Timestamp,
) -> Result<StoreKey, StoreDataError> {
    let mut ordered = retain_until.as_millis().to_be_bytes();
    ordered[0] ^= 0x80;
    KeyCodec::encode(namespace, KeyTag::DedupeExpiry, &[&ordered, key.as_bytes()])
}
