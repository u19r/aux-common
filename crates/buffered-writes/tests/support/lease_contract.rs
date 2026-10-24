use std::{
    future::Future,
    time::{Duration, Instant},
};

use buffered_writes::{
    AdmittedRecord, BatchId, BufferAppendRequest, BufferCapacity, BufferClaimRequest, BufferError,
    BufferRenewRequest, BufferSealAction, BufferSealRequest, BufferSettleRequest, ClaimedWork,
    Deadline, OperationId, PersistedRecord, PreparedPayload, SealedBatch, SealedBatchInput,
    SettleDisposition, TenantScope, WriteBuffer,
};

/// Runs the same ownership contract against caller-clock and server-clock
/// providers. Server-clock callers wait for expiry; local providers advance
/// request timestamps.
pub(crate) async fn verify_temporal_leases<F, Fut>(buffer: impl WriteBuffer, expire: F)
where
    F: Fn(Duration) -> Fut,
    Fut: Future<Output = ()>,
{
    let now = chrono::Utc::now().timestamp_millis();
    let ttl = Duration::from_millis(100);
    let deadline = Deadline::after(Duration::from_secs(5));
    let capacity = BufferCapacity::default();
    let record = AdmittedRecord {
        operation_id: OperationId::generate_v7(),
        scope: TenantScope::try_from("lease-scope").unwrap(),
        codec_version: "json/v1".to_owned(),
        admitted_at_utc_ms: now,
        admitted_at_mono: Instant::now(),
        payload: bytes::Bytes::from_static(b"7"),
    };
    buffer
        .append(BufferAppendRequest {
            record,
            reserved_bytes: 4096,
            capacity,
            deadline,
        })
        .await
        .unwrap();
    let claim_request = BufferClaimRequest {
        max_watermark: None,
        allow_open_claim: true,
        force_all_ages: true,
        max_items: 25,
        max_bytes: 64 * 1024,
        lease_duration: ttl,
        now_utc_ms: now,
        now_instant: Instant::now(),
        deadline,
    };
    let ClaimedWork::OpenCandidate(first) = buffer.claim(claim_request).await.unwrap() else {
        panic!("expected open candidate");
    };
    expire(ttl).await;
    assert!(
        matches!(
            buffer
                .seal(BufferSealRequest {
                    fencing_token: first.fencing_token,
                    action: BufferSealAction::ReleaseCandidate,
                    capacity,
                    lease_duration: ttl,
                    now_utc_ms: now + 100,
                    deadline,
                })
                .await,
            Err(BufferError::StaleFence { .. })
        ),
        "expired open claim retained mutation authority"
    );
    let ClaimedWork::OpenCandidate(second) = buffer
        .claim(BufferClaimRequest {
            now_utc_ms: now + 100,
            ..claim_request
        })
        .await
        .unwrap()
    else {
        panic!("expected expired open candidate takeover");
    };
    assert_ne!(first.fencing_token, second.fencing_token);
    let record = &second.records[0];
    let id = record.operation_id.clone();
    let batch = SealedBatch::try_new(SealedBatchInput {
        batch_id: BatchId::generate_v7(),
        namespace: buffer.namespace().clone(),
        scope: record.scope.clone(),
        codec_version: record.codec_version.clone(),
        strategy_version: "records/v1".to_owned(),
        first_item_time_ms: record.admitted_at_utc_ms,
        records: vec![PersistedRecord {
            operation_id: id.clone(),
            admitted_at_utc_ms: record.admitted_at_utc_ms,
            payload: record.payload.clone(),
        }]
        .into(),
        prepared: PreparedPayload::SharedRecords,
        operation_ids: vec![id.clone()].into(),
    })
    .unwrap();
    let leased = buffer
        .seal(BufferSealRequest {
            fencing_token: second.fencing_token,
            action: BufferSealAction::InstallBatch(batch),
            capacity,
            lease_duration: ttl,
            now_utc_ms: now + 100,
            deadline,
        })
        .await
        .unwrap()
        .unwrap();
    expire(ttl).await;
    let renew = BufferRenewRequest {
        batch_id: leased.batch.batch_id(),
        fencing_token: leased.fencing_token,
        lease_duration: ttl,
        now_utc_ms: now + 200,
        deadline,
    };
    assert!(
        matches!(
            buffer.renew(renew).await,
            Err(BufferError::StaleFence { .. })
        ),
        "expired lease was renewed"
    );
    for disposition in [
        SettleDisposition::Delivered,
        SettleDisposition::HandedOffToQueue,
        SettleDisposition::PartialProgress {
            completed_ids: vec![id],
            retry_delay: Duration::ZERO,
        },
        SettleDisposition::ReleaseForRetry {
            retry_delay: Duration::ZERO,
        },
        SettleDisposition::Quarantine {
            reason: buffered_writes::QuarantineReason::PoisonReplayEnvelope,
            completed_ids: vec![],
        },
    ] {
        assert!(
            matches!(
                buffer
                    .settle(BufferSettleRequest {
                        batch_id: renew.batch_id,
                        fencing_token: renew.fencing_token,
                        disposition,
                        now_utc_ms: now + 200,
                        deadline,
                    })
                    .await,
                Err(BufferError::StaleFence { .. })
            ),
            "expired lease settled retained data"
        );
    }
    let ClaimedWork::ExistingSealed(next) = buffer
        .claim(BufferClaimRequest {
            now_utc_ms: now + 200,
            ..claim_request
        })
        .await
        .unwrap()
    else {
        panic!("expired writes must remain recoverable");
    };
    assert_eq!(leased.batch, next.batch);
    assert_ne!(leased.fencing_token, next.fencing_token);
    buffer
        .renew(BufferRenewRequest {
            fencing_token: next.fencing_token,
            ..renew
        })
        .await
        .unwrap();
    let release = BufferSettleRequest {
        batch_id: renew.batch_id,
        fencing_token: next.fencing_token,
        disposition: SettleDisposition::ReleaseForRetry {
            retry_delay: Duration::ZERO,
        },
        now_utc_ms: now + 200,
        deadline,
    };
    buffer.settle(release.clone()).await.unwrap();
    assert!(
        matches!(
            buffer
                .settle(BufferSettleRequest {
                    disposition: SettleDisposition::Delivered,
                    ..release
                })
                .await,
            Err(BufferError::StaleFence { .. })
        ),
        "released lease retained mutation authority"
    );
    let ClaimedWork::ExistingSealed(final_claim) = buffer
        .claim(BufferClaimRequest {
            now_utc_ms: now + 200,
            ..claim_request
        })
        .await
        .unwrap()
    else {
        panic!("released writes must remain recoverable");
    };
    buffer
        .settle(BufferSettleRequest {
            batch_id: renew.batch_id,
            fencing_token: final_claim.fencing_token,
            disposition: SettleDisposition::Delivered,
            now_utc_ms: now + 200,
            deadline,
        })
        .await
        .unwrap();
}
