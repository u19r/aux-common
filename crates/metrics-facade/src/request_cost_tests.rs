use std::{sync::Arc, time::Duration};

use http::{HeaderMap, HeaderValue, header::CONTENT_LENGTH};
use tokio::sync::{Barrier, Notify};

use crate::{
    CostResponseHeaders, begin_database_call, begin_request_cost_collection,
    constants::{
        MAX_ACTIVE_REQUESTS, MAX_DATABASE_BREAKDOWN_ENTRIES, MAX_METRIC_LABEL_VALUE_BYTES,
        MAX_OPERATION_BYTES, MAX_REQUEST_ID_BYTES, MAX_STORAGE_BREAKDOWN_ENTRIES,
        MAX_STORAGE_BREAKDOWN_HEADER_BYTES,
    },
    finish_request_cost_collection, inherit_request_cost,
    metrics::{CounterMetric, GaugeMetric, HistogramMetric},
    record_analytics_request_cost_by_request_id,
    recorder::MetricLabel,
    request_cost::{
        GaugeUpdate, active_request_has_registration, active_request_registry_len, record_counter,
        record_gauge, record_histogram, set_request_cost_operation,
    },
};

static REQUEST_COST_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A panicking guarded section (or any future one like it) must not disable
/// process-global registration: collection keeps recording once the poisoned
/// registry guard is unwound.
#[tokio::test]
async fn given_poisoned_registry_when_collection_runs_then_registration_and_attribution_recovers() {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;
    crate::request_cost::poison_registry_for_test();

    let snapshot = begin_request_cost_collection(Some("poisoned-registry".to_owned()), || async {
        assert!(
            active_request_has_registration(),
            "registration must survive a poisoned registry"
        );
        drop(begin_database_call("poison.recovery"));
        record_counter(CounterMetric::HttpRequestBytesTotalMetric, &[], 123);
        crate::finish_request_cost_snapshot(1.0, None)
            .await
            .unwrap()
    })
    .await;

    assert_eq!(snapshot.db_calls, 1);
    assert_eq!(snapshot.db_call_breakdown[0].operation, "poison.recovery");
    assert_eq!(snapshot.request_bytes, 123);
}

/// Poisoning the collector itself must not change its outcome bookkeeping:
/// later records and the finish snapshot still agree.
#[tokio::test]
async fn given_poisoned_collector_when_records_follow_then_they_still_accumulate() {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;

    let snapshot = begin_request_cost_collection(Some("poisoned-collector".to_owned()), || async {
        crate::request_cost::poison_current_collector_for_test();
        record_counter(CounterMetric::HttpRequestBytesTotalMetric, &[], 77);
        assert_eq!(
            crate::request_cost::active_request_id(),
            Some("poisoned-collector".to_owned())
        );
        crate::finish_request_cost_snapshot(2.0, None)
            .await
            .unwrap()
    })
    .await;

    assert_eq!(snapshot.request_bytes, 77);
    assert_eq!(snapshot.wall_ms, 2.0);
}

#[tokio::test]
async fn given_registered_costs_when_operational_snapshot_finishes_then_completed_facts_are_captured_and_late_correlation_reports_are_excluded()
 {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;
    begin_request_cost_collection(Some("operational-snapshot".to_owned()), || async {
        assert!(active_request_has_registration());
        drop(begin_database_call("native.completed"));
        let snapshot = crate::finish_request_cost_snapshot(12.0, Some(9))
            .await
            .unwrap();
        assert!(!active_request_has_registration());
        assert_eq!(snapshot.db_calls, 1);
        assert_eq!(snapshot.wall_ms, 12.0);
        assert_eq!(snapshot.response_bytes, Some(9));
        record_analytics_request_cost_by_request_id("operational-snapshot", 2, 50);
        let later = crate::finish_request_cost_snapshot(13.0, Some(10))
            .await
            .unwrap();
        assert_eq!(later.analytics_rows_inserted, 0);
        assert_eq!(snapshot.response_bytes, Some(9));
    })
    .await;
}

#[tokio::test]
async fn given_request_cost_collection_when_native_attempt_is_spawned_then_database_call_is_attributed()
 {
    let snapshot = begin_request_cost_collection(None, || async {
        let attempt = inherit_request_cost(async {
            let _call = begin_database_call("test.native");
        });
        tokio::spawn(attempt).await.unwrap();
        finish_request_cost_collection(None, 1.0, None).await
    })
    .await;

    assert_eq!(snapshot.db_calls, 1);
    assert_eq!(snapshot.db_call_breakdown.len(), 1);
    assert_eq!(snapshot.db_call_breakdown[0].operation, "test.native");
    assert_eq!(snapshot.db_call_breakdown[0].calls, 1);
}

#[tokio::test]
async fn duplicate_request_ids_do_not_overwrite_or_cross_attribute_collectors() {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;
    let registered = Arc::new(Barrier::new(3));
    let finish_first = Arc::new(Notify::new());
    let finish_second = Arc::new(Notify::new());

    let first = tokio::spawn({
        let registered = Arc::clone(&registered);
        let finish_first = Arc::clone(&finish_first);
        async move {
            begin_request_cost_collection(Some("duplicate".to_string()), || async move {
                registered.wait().await;
                finish_first.notified().await;
                finish_request_cost_collection(Some("duplicate"), 1.0, None).await
            })
            .await
        }
    });
    let second = tokio::spawn({
        let registered = Arc::clone(&registered);
        let finish_second = Arc::clone(&finish_second);
        async move {
            begin_request_cost_collection(Some("duplicate".to_string()), || async move {
                registered.wait().await;
                finish_second.notified().await;
                finish_request_cost_collection(Some("duplicate"), 2.0, None).await
            })
            .await
        }
    });

    registered.wait().await;
    record_analytics_request_cost_by_request_id("duplicate", 1, 10);
    finish_first.notify_one();
    let first_snapshot = first.await.unwrap();
    assert_eq!(first_snapshot.analytics_rows_inserted, 0);
    assert_eq!(first_snapshot.analytics_bytes_written, 0);

    record_analytics_request_cost_by_request_id("duplicate", 1, 20);
    finish_second.notify_one();
    let second_snapshot = second.await.unwrap();
    assert_eq!(second_snapshot.analytics_rows_inserted, 1);
    assert_eq!(second_snapshot.analytics_bytes_written, 20);
}

#[tokio::test]
async fn oversized_request_ids_are_not_retained_or_waited_on() {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;
    let oversized_id = "r".repeat(MAX_REQUEST_ID_BYTES + 1);
    let snapshot = begin_request_cost_collection(Some(oversized_id), || async {
        assert_eq!(crate::active_request_id(), None);
        finish_request_cost_collection(Some("oversized"), 1.0, None).await
    })
    .await;

    assert_eq!(snapshot.request_id, None);
    assert_eq!(active_request_registry_len(), 0);
}

#[tokio::test]
async fn storage_breakdown_has_bounded_cardinality() {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;
    let snapshot = begin_request_cost_collection(None, || async {
        for index in 0..=MAX_STORAGE_BREAKDOWN_ENTRIES {
            let labels = [
                MetricLabel::new("ddb_op", format!("op-{index}")),
                MetricLabel::new("item_kind", "item"),
                MetricLabel::new("direction", "read"),
            ];
            record_counter(CounterMetric::StorageBilledItemOpsTotalMetric, &labels, 1);
        }
        finish_request_cost_collection(None, 1.0, None).await
    })
    .await;

    assert_eq!(
        snapshot.storage_breakdown.entries.len(),
        MAX_STORAGE_BREAKDOWN_ENTRIES
    );
    assert_eq!(
        snapshot.db_read_ops,
        (MAX_STORAGE_BREAKDOWN_ENTRIES + 1) as u64
    );
}

#[tokio::test]
async fn given_serial_and_parallel_database_waves_when_collected_then_counts_are_rankable() {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;
    let snapshot = begin_request_cost_collection(None, || async {
        for _ in 0..2 {
            let _call = begin_database_call("get_item");
        }
        let first = async {
            let _call = begin_database_call("query_table");
            tokio::task::yield_now().await;
        };
        let second = async {
            let _call = begin_database_call("query_table");
            tokio::task::yield_now().await;
        };
        tokio::join!(first, second);
        finish_request_cost_collection(None, 1.0, None).await
    })
    .await;

    assert_eq!(snapshot.db_calls, 4);
    assert_eq!(snapshot.db_serial_waves, 3);
    assert_eq!(snapshot.db_max_parallelism, 2);
    assert_eq!(
        snapshot.db_call_breakdown,
        vec![
            crate::RequestCostDatabaseCallEntry {
                operation: "get_item".to_string(),
                calls: 2,
            },
            crate::RequestCostDatabaseCallEntry {
                operation: "query_table".to_string(),
                calls: 2,
            },
        ]
    );
}

#[tokio::test]
async fn given_many_database_operations_when_collected_then_breakdown_stays_bounded() {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;
    let snapshot = begin_request_cost_collection(None, || async {
        for index in 0..=MAX_DATABASE_BREAKDOWN_ENTRIES {
            let _call = begin_database_call(&format!("operation-{index}"));
        }
        finish_request_cost_collection(None, 1.0, None).await
    })
    .await;

    assert_eq!(
        snapshot.db_calls,
        (MAX_DATABASE_BREAKDOWN_ENTRIES + 1) as u64
    );
    assert_eq!(
        snapshot.db_call_breakdown.len(),
        MAX_DATABASE_BREAKDOWN_ENTRIES
    );
}

#[test]
fn given_oversized_storage_breakdown_header_when_reading_response_cost_then_breakdown_is_dropped() {
    let mut headers = HeaderMap::new();
    headers.insert("x-aux-cost-wall-ms", HeaderValue::from_static("1.0"));
    let oversized_breakdown = format!(
        r#"{{"entries":[{{"ddb_op":"{}","item_kind":"item","direction":"read","ops":1,"bytes":1}}]}}"#,
        "x".repeat(MAX_STORAGE_BREAKDOWN_HEADER_BYTES)
    );
    headers.insert(
        "x-aux-cost-storage-breakdown",
        HeaderValue::from_str(&oversized_breakdown).unwrap(),
    );
    let oversized_database_breakdown = format!(
        r#"[{{"operation":"{}","calls":1}}]"#,
        "x".repeat(MAX_STORAGE_BREAKDOWN_HEADER_BYTES)
    );
    headers.insert(
        "x-aux-cost-db-breakdown",
        HeaderValue::from_str(&oversized_database_breakdown).unwrap(),
    );

    let parsed = CostResponseHeaders::read_from_headers(&headers).unwrap();

    assert!(parsed.snapshot().storage_breakdown.entries.is_empty());
    assert!(parsed.snapshot().db_call_breakdown.is_empty());
}

#[test]
fn given_oversized_breakdowns_when_writing_response_cost_then_breakdown_headers_are_omitted() {
    let snapshot = crate::RequestCostSnapshot {
        operation: Some("o".repeat(MAX_OPERATION_BYTES + 1)),
        wall_ms: 1.0,
        db_call_breakdown: vec![crate::RequestCostDatabaseCallEntry {
            operation: "x".repeat(MAX_STORAGE_BREAKDOWN_HEADER_BYTES),
            calls: 1,
        }],
        storage_breakdown: crate::RequestCostStorageBreakdown {
            entries: vec![crate::RequestCostStorageBreakdownEntry {
                ddb_op: "x".repeat(MAX_STORAGE_BREAKDOWN_HEADER_BYTES),
                item_kind: "item".to_owned(),
                direction: crate::RequestCostStorageDirection::Read,
                ops: 1,
                bytes: 1,
            }],
        },
        ..Default::default()
    };
    let mut headers = HeaderMap::new();

    // Given database and storage detail that exceeds the transport budget.
    CostResponseHeaders::from_snapshot(snapshot).write_to_headers(&mut headers);

    // When the response headers are emitted.
    // Then no oversized detail or operation is sent across the boundary.
    assert!(!headers.contains_key("x-aux-cost-db-breakdown"));
    assert!(!headers.contains_key("x-aux-cost-storage-breakdown"));
    assert!(!headers.contains_key("x-aux-cost-operation"));
}

#[tokio::test]
async fn given_full_active_request_registry_when_collecting_cost_then_request_stays_local_only() {
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;
    let registered = Arc::new(Barrier::new(MAX_ACTIVE_REQUESTS + 1));
    let release = Arc::new(Barrier::new(MAX_ACTIVE_REQUESTS + 1));
    let mut held_requests = Vec::with_capacity(MAX_ACTIVE_REQUESTS);

    for index in 0..MAX_ACTIVE_REQUESTS {
        let registered = Arc::clone(&registered);
        let release = Arc::clone(&release);
        held_requests.push(tokio::spawn(async move {
            begin_request_cost_collection(Some(format!("held-{index}")), || async move {
                registered.wait().await;
                release.wait().await;
                finish_request_cost_collection(Some("held"), 1.0, None).await
            })
            .await
        }));
    }

    registered.wait().await;
    assert_eq!(active_request_registry_len(), MAX_ACTIVE_REQUESTS);

    let start = std::time::Instant::now();
    let (active_request_id, has_registration, snapshot) =
        begin_request_cost_collection(Some("overflow".to_string()), || async {
            let active_request_id = crate::active_request_id();
            let has_registration = active_request_has_registration();
            let snapshot = finish_request_cost_collection(Some("overflow"), 1.0, None).await;
            (active_request_id, has_registration, snapshot)
        })
        .await;

    assert_eq!(active_request_id.as_deref(), Some("overflow"));
    assert!(!has_registration);
    assert_eq!(snapshot.request_id.as_deref(), Some("overflow"));
    assert_eq!(active_request_registry_len(), MAX_ACTIVE_REQUESTS);
    assert!(start.elapsed() < Duration::from_millis(200));

    release.wait().await;
    for request in held_requests {
        request.await.unwrap();
    }
    assert_eq!(active_request_registry_len(), 0);
}

#[test]
fn given_no_active_collection_when_cost_apis_are_called_then_they_are_isolated_noops() {
    let _guard = REQUEST_COST_TEST_LOCK.blocking_lock();

    // Given no task-local collector is installed on this test thread.
    assert_eq!(crate::active_request_id(), None);

    // When callers report cost outside a request boundary.
    set_request_cost_operation("GET /outside");
    let guard = begin_database_call("outside");
    record_counter(CounterMetric::HttpRequestBytesTotalMetric, &[], 4);
    record_gauge(
        GaugeMetric::AnalyticsIngestionQueueDepthMetric,
        &[],
        GaugeUpdate::Set,
    );
    record_histogram(HistogramMetric::RequestLatencyMetric, &[], 5.0);
    record_analytics_request_cost_by_request_id("outside", 1, 4);
    drop(guard);

    // Then no ambient state is created or leaked between requests.
    assert_eq!(crate::active_request_id(), None);
    assert_eq!(active_request_registry_len(), 0);
}

#[tokio::test]
async fn given_supported_cost_metrics_when_recorded_then_snapshot_preserves_dimensions_and_bounds()
{
    let _guard = REQUEST_COST_TEST_LOCK.lock().await;

    // Given one registered request with valid and invalid storage labels.
    let snapshot = begin_request_cost_collection(Some("cost-dimensions".to_string()), || async {
        set_request_cost_operation("GET /users/{id}");
        set_request_cost_operation(&"x".repeat(MAX_OPERATION_BYTES + 1));

        let read_labels = [
            MetricLabel::new("ddb_op", "get_item"),
            MetricLabel::new("item_kind", "user"),
            MetricLabel::new("direction", "read"),
        ];
        let write_labels = [
            MetricLabel::new("ddb_op", "put_item"),
            MetricLabel::new("item_kind", "user"),
            MetricLabel::new("direction", "write"),
        ];
        let unknown_direction = [
            MetricLabel::new("ddb_op", "delete_item"),
            MetricLabel::new("item_kind", "user"),
            MetricLabel::new("direction", "unknown"),
        ];
        let missing_label = [MetricLabel::new("ddb_op", "get_item")];
        let invalid_label = [MetricLabel::new(
            "ddb_op",
            "x".repeat(MAX_METRIC_LABEL_VALUE_BYTES + 1),
        )];

        // When each supported metric and every storage direction is recorded.
        record_counter(CounterMetric::HttpRequestBytesTotalMetric, &[], 11);
        record_counter(CounterMetric::RemoteStorageRequestBytesTotalMetric, &[], 12);
        record_counter(
            CounterMetric::RemoteStorageResponseBytesTotalMetric,
            &[],
            13,
        );
        record_counter(
            CounterMetric::AnalyticsIngestionRecordsInsertedTotalMetric,
            &[],
            14,
        );
        record_counter(
            CounterMetric::AnalyticsIngestionRecordsUpdatedTotalMetric,
            &[],
            15,
        );
        record_counter(
            CounterMetric::AnalyticsIngestionRecordsDeletedTotalMetric,
            &[],
            16,
        );
        record_counter(
            CounterMetric::AnalyticsIngestionBytesWrittenTotalMetric,
            &[],
            17,
        );
        record_counter(
            CounterMetric::StorageBilledItemOpsTotalMetric,
            &read_labels,
            2,
        );
        record_counter(
            CounterMetric::StorageBilledItemOpsTotalMetric,
            &write_labels,
            3,
        );
        record_counter(
            CounterMetric::StorageLogicalItemBytesTotalMetric,
            &read_labels,
            20,
        );
        record_counter(
            CounterMetric::StorageLogicalItemBytesTotalMetric,
            &write_labels,
            30,
        );
        record_counter(
            CounterMetric::StorageBilledItemOpsTotalMetric,
            &unknown_direction,
            99,
        );
        record_counter(
            CounterMetric::StorageBilledItemOpsTotalMetric,
            &missing_label,
            99,
        );
        record_counter(
            CounterMetric::StorageBilledItemOpsTotalMetric,
            &invalid_label,
            99,
        );
        record_counter(CounterMetric::AuthzApiDecisionsTotal, &[], 99);
        record_gauge(
            GaugeMetric::AnalyticsIngestionQueueDepthMetric,
            &[],
            GaugeUpdate::Set,
        );
        record_gauge(
            GaugeMetric::StorageDdbCacheHitRatioMetric,
            &[],
            GaugeUpdate::Set,
        );
        record_histogram(HistogramMetric::RequestLatencyMetric, &[], 21.5);
        record_histogram(HistogramMetric::RemoteStorageRequestLatencyMs, &[], 3.25);
        record_histogram(HistogramMetric::StorageOperationLatencyMsMetric, &[], 99.0);
        record_analytics_request_cost_by_request_id("cost-dimensions", 2, 40);
        record_analytics_request_cost_by_request_id("cost-dimensions", -1, 50);
        record_analytics_request_cost_by_request_id("cost-dimensions", 0, 60);
        finish_request_cost_collection(Some("cost-dimensions"), 21.5, Some(22)).await
    })
    .await;

    // Then unrelated metrics remain absent and every owned dimension is
    // isolated.
    assert_eq!(snapshot.operation.as_deref(), Some("GET /users/{id}"));
    assert_eq!(snapshot.wall_ms, 21.5);
    assert_eq!(snapshot.remote_wait_ms, 3.25);
    assert_eq!(snapshot.db_read_ops, 2);
    assert_eq!(snapshot.db_write_ops, 3);
    assert_eq!(snapshot.db_read_bytes, 20);
    assert_eq!(snapshot.db_write_bytes, 30);
    assert_eq!(snapshot.request_bytes, 11);
    assert_eq!(snapshot.remote_request_bytes, 12);
    assert_eq!(snapshot.remote_response_bytes, 13);
    assert_eq!(snapshot.analytics_rows_inserted, 16);
    assert_eq!(snapshot.analytics_rows_updated, 16);
    assert_eq!(snapshot.analytics_rows_deleted, 17);
    assert_eq!(snapshot.analytics_bytes_written, 167);
    assert_eq!(snapshot.response_bytes, Some(22));
}

#[test]
fn given_malformed_cost_headers_when_reading_then_required_wall_value_and_defaults_are_enforced() {
    // Given a malformed required wall-time header.
    let mut headers = HeaderMap::new();
    for value in ["not-a-number", "NaN", "inf", "1e999", "-1.0"] {
        headers.insert("x-aux-cost-wall-ms", HeaderValue::from_static(value));

        // When the response-cost parser reads a non-finite, overflowed, or
        // negative value. Then the required wall-time boundary fails closed.
        assert!(CostResponseHeaders::read_from_headers(&headers).is_none());
    }
    headers.insert(
        "x-aux-cost-wall-ms",
        HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    assert!(CostResponseHeaders::read_from_headers(&headers).is_none());

    // Then a valid wall-time header still fails closed for malformed optional
    // values.
    headers.insert("x-aux-cost-wall-ms", HeaderValue::from_static("2.5"));
    headers.insert(
        "x-aux-cost-db-read-ops",
        HeaderValue::from_static("invalid"),
    );
    headers.insert(
        "x-aux-cost-remote-wait-ms",
        HeaderValue::from_static("-1.0"),
    );
    headers.insert(
        "x-aux-cost-db-write-ops",
        HeaderValue::from_static("18446744073709551616"),
    );
    headers.insert(
        "x-aux-cost-db-read-bytes",
        HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("invalid"));
    headers.insert(
        "x-aux-cost-operation",
        HeaderValue::from_str(&"o".repeat(MAX_OPERATION_BYTES + 1)).unwrap(),
    );
    headers.insert(
        "x-aux-cost-storage-breakdown",
        HeaderValue::from_static("not-json"),
    );
    headers.insert(
        "x-aux-cost-db-breakdown",
        HeaderValue::from_static("not-json"),
    );
    let parsed = CostResponseHeaders::read_from_headers(&headers).unwrap();

    assert_eq!(parsed.snapshot().wall_ms, 2.5);
    assert_eq!(parsed.snapshot().remote_wait_ms, 0.0);
    assert_eq!(parsed.snapshot().db_read_ops, 0);
    assert_eq!(parsed.snapshot().db_write_ops, 0);
    assert_eq!(parsed.snapshot().db_read_bytes, 0);
    assert_eq!(parsed.snapshot().response_bytes, None);
    assert_eq!(parsed.snapshot().operation, None);
    assert!(parsed.snapshot().storage_breakdown.entries.is_empty());
    assert!(parsed.snapshot().db_call_breakdown.is_empty());
}

#[test]
fn given_complete_cost_snapshot_when_written_then_headers_round_trip_all_bounded_fields() {
    let snapshot = crate::RequestCostSnapshot {
        operation: Some("GET /users/{id}".to_string()),
        wall_ms: 1.25,
        remote_wait_ms: 2.5,
        db_calls: 3,
        db_serial_waves: 4,
        db_max_parallelism: 5,
        db_call_breakdown: vec![crate::RequestCostDatabaseCallEntry {
            operation: "get_item".to_string(),
            calls: 6,
        }],
        db_read_ops: 7,
        db_write_ops: 8,
        db_read_bytes: 9,
        db_write_bytes: 10,
        analytics_rows_inserted: 11,
        analytics_rows_updated: 12,
        analytics_rows_deleted: 13,
        analytics_bytes_written: 14,
        request_bytes: 15,
        response_bytes: Some(16),
        remote_request_bytes: 17,
        remote_response_bytes: 18,
        storage_breakdown: crate::RequestCostStorageBreakdown {
            entries: vec![crate::RequestCostStorageBreakdownEntry {
                ddb_op: "put_item".to_string(),
                item_kind: "user".to_string(),
                direction: crate::RequestCostStorageDirection::Write,
                ops: 19,
                bytes: 20,
            }],
        },
        ..Default::default()
    };

    // Given a complete snapshot and a bounded response body.
    let mut headers = HeaderMap::new();
    CostResponseHeaders::from_snapshot(snapshot.clone()).write_to_headers(&mut headers);
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("16"));

    // When another service parses the cost response headers.
    let parsed = CostResponseHeaders::read_from_headers(&headers).unwrap();

    // Then all bounded dimensions survive transport without customer
    // identifiers.
    assert_eq!(parsed.snapshot().operation, snapshot.operation);
    assert_eq!(parsed.snapshot().wall_ms, snapshot.wall_ms);
    assert_eq!(parsed.snapshot().remote_wait_ms, snapshot.remote_wait_ms);
    assert_eq!(parsed.snapshot().db_calls, snapshot.db_calls);
    assert_eq!(parsed.snapshot().db_serial_waves, snapshot.db_serial_waves);
    assert_eq!(
        parsed.snapshot().db_max_parallelism,
        snapshot.db_max_parallelism
    );
    assert_eq!(
        parsed.snapshot().db_call_breakdown,
        snapshot.db_call_breakdown
    );
    assert_eq!(parsed.snapshot().db_read_ops, snapshot.db_read_ops);
    assert_eq!(parsed.snapshot().db_write_ops, snapshot.db_write_ops);
    assert_eq!(parsed.snapshot().db_read_bytes, snapshot.db_read_bytes);
    assert_eq!(parsed.snapshot().db_write_bytes, snapshot.db_write_bytes);
    assert_eq!(
        parsed.snapshot().analytics_rows_inserted,
        snapshot.analytics_rows_inserted
    );
    assert_eq!(
        parsed.snapshot().analytics_rows_updated,
        snapshot.analytics_rows_updated
    );
    assert_eq!(
        parsed.snapshot().analytics_rows_deleted,
        snapshot.analytics_rows_deleted
    );
    assert_eq!(
        parsed.snapshot().analytics_bytes_written,
        snapshot.analytics_bytes_written
    );
    assert_eq!(parsed.snapshot().request_bytes, snapshot.request_bytes);
    assert_eq!(parsed.snapshot().response_bytes, snapshot.response_bytes);
    assert_eq!(
        parsed.snapshot().remote_request_bytes,
        snapshot.remote_request_bytes
    );
    assert_eq!(
        parsed.snapshot().remote_response_bytes,
        snapshot.remote_response_bytes
    );
    assert_eq!(
        parsed.snapshot().storage_breakdown,
        snapshot.storage_breakdown
    );
}

#[test]
fn given_non_finite_or_negative_cost_values_when_writing_then_float_headers_are_omitted() {
    let snapshot = crate::RequestCostSnapshot {
        wall_ms: f64::NAN,
        remote_wait_ms: f64::INFINITY,
        ..Default::default()
    };
    let mut headers = HeaderMap::new();

    // Given a snapshot containing values outside the finite non-negative
    // protocol domain.
    CostResponseHeaders::from_snapshot(snapshot).write_to_headers(&mut headers);

    // When the response-cost writer serializes float dimensions.
    // Then invalid values are omitted instead of being encoded as NaN or
    // infinity.
    assert!(!headers.contains_key("x-aux-cost-wall-ms"));
    assert!(!headers.contains_key("x-aux-cost-remote-wait-ms"));
}
