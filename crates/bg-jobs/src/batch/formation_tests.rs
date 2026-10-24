//! Batch admission and formation tests.

use std::{
    num::{NonZeroU16, NonZeroUsize},
    time::Duration,
};

use bytes::Bytes;

use crate::{
    AttemptId, EffectMode, ExecutionId, FairnessClass, JobId, JobKind, OrderingKey, Priority,
    RetryPolicy, Timestamp,
    batch::{
        AuthConfigId, BatchBuilder, BatchCompatibility, BatchItem, BatchKey, BatchLimits,
        BatchLimitsInput, BatchRejection,
    },
    policy::RetryPreset,
};

fn item(job: u8, position: u64) -> BatchItem {
    BatchItem {
        job_id: JobId::from([job; 16]),
        execution_id: ExecutionId::from([job; 16]),
        attempt_id: AttemptId::from([job; 16]),
        payload: Bytes::from_static(b"payload"),
        compatibility: BatchCompatibility {
            handler_kind: JobKind::try_new("handler").expect("valid test handler"),
            schema_version: NonZeroU16::MIN,
            batch_key: BatchKey::new(1),
            auth_config: AuthConfigId::new(1),
            effect_mode: EffectMode::Idempotent,
            retry_policy: RetryPolicy::preset(RetryPreset::Interactive),
            timeout: Duration::from_secs(1),
            priority: Priority::Default,
            fairness: FairnessClass::low_volume(),
        },
        ordering_key: Some(OrderingKey::try_new([1]).expect("valid test ordering key")),
        ordering_position: position,
        enqueued_at: Timestamp::ZERO,
        batch_deadline: Timestamp::from_millis(10),
    }
}

#[test]
fn duplicate_attempt_ids_are_rejected_during_formation() {
    let first = item(1, 1);
    let limits = BatchLimits::try_new(BatchLimitsInput {
        max_items: NonZeroU16::new(2).expect("batch allows two items"),
        max_payload_bytes: NonZeroUsize::new(64).expect("payload bound is non-zero"),
        max_formation_delay: Duration::from_secs(1),
    })
    .expect("limits are valid");
    let mut builder = BatchBuilder::try_new(first.clone(), limits, Timestamp::ZERO)
        .expect("first item forms a batch");
    let mut duplicate = item(2, 2);
    duplicate.attempt_id = first.attempt_id;

    assert_eq!(
        builder.try_add(duplicate, Timestamp::ZERO),
        Err(BatchRejection::DuplicateAttemptId)
    );
    assert_eq!(builder.finish().items.len(), 1);
}
