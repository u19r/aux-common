mod support;

use std::time::{Duration, Instant};

use buffered_writes::{
    AdmittedRecord, BatchId, BufferAppendRequest, BufferCapacity, BufferClaimRequest,
    BufferInspectRequest, BufferSealAction, BufferSealRequest, BufferSettleRequest, ClaimedWork,
    Deadline, OperationId, PersistedRecord, PreparedPayload, SealedBatch, SealedBatchInput,
    SettleDisposition, TenantScope, WriteBuffer,
};

#[tokio::test]
async fn given_memory_claims_when_expired_or_released_then_reject_old_authority_and_preserve_writes()
 {
    support::verify_temporal_leases(
        buffered_writes::MemoryBuffer::new(
            buffered_writes::Namespace::try_from("lease/v1").unwrap(),
        ),
        |_| async {},
    )
    .await;
}

#[cfg(feature = "disk")]
#[tokio::test]
async fn given_disk_claims_when_expired_or_released_then_reject_old_authority_and_preserve_writes()
{
    let directory =
        std::env::temp_dir().join(format!("buffered-writes-lease-{}", uuid::Uuid::now_v7()));
    let buffer = buffered_writes::DiskBuffer::open(
        buffered_writes::Namespace::try_from("lease/v1").unwrap(),
        &directory,
    )
    .unwrap();
    support::verify_temporal_leases(buffer, |_| async {}).await;
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn given_retained_credits_above_new_capacity_when_reused_then_report_configuration_and_preserve_writes()
 {
    use buffered_writes::{BackpressurePolicy, BufferCapacity, MemoryBuffer, Namespace};
    for capacity in [
        BufferCapacity::default().max_bytes(1200),
        BufferCapacity::default()
            .max_items(1)
            .backpressure(BackpressurePolicy::WaitUntilDeadline),
    ] {
        support::verify_lower_capacity(
            MemoryBuffer::new(Namespace::try_from("capacity-recovery/v1").unwrap()),
            |buffer| async move { buffer },
            capacity,
        )
        .await;
    }
}

#[cfg(feature = "disk")]
#[tokio::test]
async fn given_persisted_credits_above_new_capacity_when_disk_reopens_then_preserve_recoverable_writes()
 {
    use buffered_writes::{BufferCapacity, DiskBuffer, Namespace};
    let directory =
        std::env::temp_dir().join(format!("buffered-writes-capacity-{}", uuid::Uuid::now_v7()));
    let namespace = Namespace::try_from("capacity-recovery/v1").unwrap();
    let buffer = DiskBuffer::open(namespace.clone(), &directory).unwrap();
    let reopen_directory = directory.clone();
    support::verify_lower_capacity(
        buffer,
        move |buffer| async move {
            drop(buffer);
            DiskBuffer::open(namespace, &reopen_directory).unwrap()
        },
        BufferCapacity::default().max_bytes(1200),
    )
    .await;
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn given_larger_preparation_than_retained_credits_when_recovered_then_report_configuration_without_quarantine()
 {
    use buffered_writes::{MemoryBuffer, Namespace};
    support::verify_changed_preparation(
        MemoryBuffer::new(Namespace::try_from("preparation-recovery/v1").unwrap()),
        |buffer| async move { buffer },
    )
    .await;
}

#[cfg(feature = "disk")]
#[tokio::test]
async fn given_larger_preparation_than_persisted_credits_when_disk_reopens_then_preserve_recoverable_writes()
 {
    use buffered_writes::{DiskBuffer, Namespace};
    let directory = std::env::temp_dir().join(format!(
        "buffered-writes-preparation-{}",
        uuid::Uuid::now_v7()
    ));
    let namespace = Namespace::try_from("preparation-recovery/v1").unwrap();
    let buffer = DiskBuffer::open(namespace.clone(), &directory).unwrap();
    let reopen_directory = directory.clone();
    support::verify_changed_preparation(buffer, move |buffer| async move {
        drop(buffer);
        DiskBuffer::open(namespace, &reopen_directory).unwrap()
    })
    .await;
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn given_future_retained_timestamp_when_memory_retries_then_inspection_matches_claim_without_bypassing_lease()
 {
    verify_retry_clock(buffered_writes::MemoryBuffer::new(
        buffered_writes::Namespace::try_from("retry-clock/v1").unwrap(),
    ))
    .await;
}

#[cfg(feature = "disk")]
#[tokio::test]
async fn given_future_retained_timestamp_when_disk_retries_then_inspection_matches_claim_without_bypassing_lease()
 {
    let directory =
        std::env::temp_dir().join(format!("buffered-writes-clock-{}", uuid::Uuid::now_v7()));
    let buffer = buffered_writes::DiskBuffer::open(
        buffered_writes::Namespace::try_from("retry-clock/v1").unwrap(),
        &directory,
    )
    .unwrap();
    verify_retry_clock(buffer).await;
    std::fs::remove_dir_all(directory).unwrap();
}

/// A persisted scheduling time detects rollback while the original batch stays
/// old. Retry eligibility must agree between metadata inspection and actual
/// claiming.
pub(crate) async fn verify_retry_clock(buffer: impl WriteBuffer) {
    let regressed = chrono::Utc::now().timestamp_millis();
    let now = regressed + 3_600_000;
    let first_item = now - 7_200_000;
    let deadline = Deadline::after(Duration::from_secs(5));
    let capacity = BufferCapacity::default();
    let id = OperationId::generate_v7();
    let scope = TenantScope::try_from("retry-scope").unwrap();
    buffer
        .append(BufferAppendRequest {
            record: AdmittedRecord {
                operation_id: id.clone(),
                scope: scope.clone(),
                codec_version: "json/v1".to_owned(),
                admitted_at_utc_ms: first_item,
                admitted_at_mono: Instant::now(),
                payload: bytes::Bytes::from_static(b"7"),
            },
            reserved_bytes: 4096,
            capacity,
            deadline,
        })
        .await
        .unwrap();
    let claim = BufferClaimRequest {
        max_watermark: None,
        allow_open_claim: true,
        force_all_ages: false,
        max_items: 25,
        max_bytes: 64 * 1024,
        lease_duration: Duration::from_secs(10),
        now_utc_ms: now,
        now_instant: Instant::now(),
        deadline,
    };
    let ClaimedWork::OpenCandidate(candidate) = buffer.claim(claim).await.unwrap() else {
        panic!("open candidate");
    };
    let batch = SealedBatch::try_new(SealedBatchInput {
        batch_id: BatchId::generate_v7(),
        namespace: buffer.namespace().clone(),
        scope,
        codec_version: "json/v1".to_owned(),
        strategy_version: "records/v1".to_owned(),
        first_item_time_ms: first_item,
        records: vec![PersistedRecord {
            operation_id: id.clone(),
            admitted_at_utc_ms: first_item,
            payload: bytes::Bytes::from_static(b"7"),
        }]
        .into(),
        prepared: PreparedPayload::SharedRecords,
        operation_ids: vec![id].into(),
    })
    .unwrap();
    let leased = buffer
        .seal(BufferSealRequest {
            fencing_token: candidate.fencing_token,
            action: BufferSealAction::InstallBatch(batch.clone()),
            capacity,
            lease_duration: Duration::from_secs(10),
            now_utc_ms: now,
            deadline,
        })
        .await
        .unwrap()
        .unwrap();
    let inspect = BufferInspectRequest {
        operation_id: None,
        now_utc_ms: regressed,
        now_instant: Instant::now(),
        deadline,
    };
    let active = buffer.inspect(inspect.clone()).await.unwrap();
    assert_eq!(
        active.claimable_sealed_batches, 0,
        "rollback cannot bypass active lease"
    );
    assert_eq!(active.in_flight_batches, 1);
    assert!(matches!(
        buffer
            .claim(BufferClaimRequest {
                now_utc_ms: regressed,
                ..claim
            })
            .await
            .unwrap(),
        ClaimedWork::None
    ));
    buffer
        .settle(BufferSettleRequest {
            batch_id: batch.batch_id(),
            fencing_token: leased.fencing_token,
            disposition: SettleDisposition::ReleaseForRetry {
                retry_delay: Duration::from_millis(100),
            },
            now_utc_ms: now,
            deadline,
        })
        .await
        .unwrap();
    let released = buffer.inspect(inspect).await.unwrap();
    assert_eq!(released.claimable_sealed_batches, 1);
    assert_eq!(released.in_flight_batches, 0);
    let ClaimedWork::ExistingSealed(retry) = buffer
        .claim(BufferClaimRequest {
            now_utc_ms: regressed,
            ..claim
        })
        .await
        .unwrap()
    else {
        panic!("rollback stranded sealed writes");
    };
    assert_eq!(retry.batch, batch);
    assert_ne!(retry.fencing_token, leased.fencing_token);
}
