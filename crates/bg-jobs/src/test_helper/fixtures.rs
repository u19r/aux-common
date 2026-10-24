use std::num::{NonZeroU16, NonZeroU32};

use bytes::Bytes;

use crate::{
    Deduplication, DeduplicationKey, FairnessClass, FairnessKey, FairnessPath, JobId, JobKind,
    JobOutcome, NewJob, OutcomeCode, Priority, Timestamp,
};

pub(crate) fn job(
    id: u8,
    payload: Bytes,
    fairness: FairnessClass,
    scheduled_at: Timestamp,
    expires_at: Option<Timestamp>,
    deduplication: Option<Deduplication>,
) -> NewJob {
    NewJob {
        job_id: JobId::from([id; 16]),
        kind: JobKind::try_new("email").expect("test kind is valid"),
        schema_version: NonZeroU16::new(1).expect("schema is non-zero"),
        payload,
        fairness,
        ordering_key: None,
        priority: Priority::Default,
        scheduled_at,
        expires_at,
        retry_override: None,
        deduplication,
    }
}

pub(crate) fn low_volume_job(id: u8, scheduled_at: Timestamp) -> NewJob {
    job(
        id,
        Bytes::from_static(b"payload"),
        FairnessClass::low_volume(),
        scheduled_at,
        None,
        None,
    )
}

pub(crate) fn scoped_fairness() -> FairnessClass {
    FairnessClass::from(FairnessPath::new(
        FairnessKey::try_new(b"tenant-a").expect("fairness key is valid"),
        None,
    ))
}

pub(crate) fn dedupe(key: &[u8], retain_until: Timestamp) -> Deduplication {
    Deduplication::try_new(
        DeduplicationKey::try_new(key).expect("dedupe key is valid"),
        retain_until,
    )
    .expect("dedupe policy is valid")
}

pub(crate) fn completion() -> JobOutcome {
    JobOutcome::Complete(OutcomeCode::try_new("completed").expect("test outcome is valid"))
}

pub(crate) fn one(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("test value is non-zero")
}
