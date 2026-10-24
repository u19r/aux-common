//! Per-item result application and ordering-barrier tests.

use std::{num::NonZeroU16, time::Duration};

use bytes::Bytes;

use crate::{
    AttemptId, EffectMode, ExecutionId, FairnessClass, JobId, JobKind, JobOutcome, OrderingKey,
    OutcomeCode, Priority, RetryPolicy, Timestamp,
    batch::{
        AuthConfigId, Batch, BatchCompatibility, BatchItem, BatchKey, BatchOutcome, BatchResult,
        BatchResultError,
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
fn unresolved_ordering_head_defers_successor_even_when_result_is_provided() {
    let first = item(1, 1);
    let second = item(2, 2);
    let batch = Batch {
        items: vec![first.clone(), second.clone()],
        formed_at: Timestamp::ZERO,
        deadline: Timestamp::from_millis(10),
        payload_bytes: first.payload.len() + second.payload.len(),
    };
    let application = batch
        .apply_results(&[BatchResult {
            attempt_id: second.attempt_id,
            outcome: JobOutcome::Complete(OutcomeCode::try_new("ok").expect("valid test outcome")),
        }])
        .expect("known attempt result");
    assert!(matches!(
        application.resolutions[0].outcome,
        BatchOutcome::MissingResult
    ));
    assert!(matches!(
        application.resolutions[1].outcome,
        BatchOutcome::DeferredOrdering
    ));
}

#[test]
fn duplicate_attempt_ids_are_rejected_before_result_projection() {
    let first = item(1, 1);
    let mut duplicate = item(2, 2);
    duplicate.attempt_id = first.attempt_id;
    let batch = Batch {
        items: vec![first, duplicate],
        formed_at: Timestamp::ZERO,
        deadline: Timestamp::from_millis(10),
        payload_bytes: 14,
    };

    assert_eq!(
        batch.apply_results(&[]),
        Err(BatchResultError::DuplicateAttemptId)
    );
}
