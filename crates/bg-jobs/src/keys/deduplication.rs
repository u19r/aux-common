use crate::{
    codec::{KeyCodec, KeyTag, ValueCodec, ValueTag},
    error::StoreDataError,
    ids::{DeduplicationKey, JobId, JobKind, Namespace},
    policy::FairnessClass,
    store::StoreKey,
    time::Timestamp,
};

/// The scope a deduplication key is unique within: job kind, fairness primary
/// (empty for low-volume work), and the caller key. A hit therefore never
/// returns another kind's or another fairness scope's job.
#[derive(Clone, Copy)]
pub(crate) struct DedupeIdentity<'a> {
    kind: &'a [u8],
    scope: &'a [u8],
    key: &'a [u8],
}

impl<'a> DedupeIdentity<'a> {
    pub(crate) fn new(
        kind: &'a JobKind,
        fairness: &'a FairnessClass,
        key: &'a DeduplicationKey,
    ) -> Self {
        let scope: &[u8] = match fairness {
            FairnessClass::Scoped(path) => path.primary.as_bytes(),
            FairnessClass::LowVolume => &[],
        };
        Self {
            kind: kind.as_str().as_bytes(),
            scope,
            key: key.as_bytes(),
        }
    }

    /// Rebuilds an identity from the components of an expiry index key.
    pub(crate) fn from_expiry_components(components: &[&'a [u8]]) -> Result<Self, StoreDataError> {
        let &[_, kind, scope, key] = components else {
            return Err(StoreDataError::Malformed("dedupe expiry key"));
        };
        DeduplicationKey::try_new(key).map_err(|_| StoreDataError::Malformed("dedupe key"))?;
        Ok(Self { kind, scope, key })
    }
}

pub(crate) fn dedupe_key(
    namespace: &Namespace,
    identity: DedupeIdentity<'_>,
) -> Result<StoreKey, StoreDataError> {
    KeyCodec::encode(
        namespace,
        KeyTag::Dedupe,
        &[identity.kind, identity.scope, identity.key],
    )
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
    identity: DedupeIdentity<'_>,
    retain_until: Timestamp,
) -> Result<StoreKey, StoreDataError> {
    let mut ordered = retain_until.as_millis().to_be_bytes();
    ordered[0] ^= 0x80;
    KeyCodec::encode(
        namespace,
        KeyTag::DedupeExpiry,
        &[&ordered, identity.kind, identity.scope, identity.key],
    )
}
