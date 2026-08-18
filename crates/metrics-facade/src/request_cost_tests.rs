use std::{sync::Arc, time::Duration};

use http::{HeaderMap, HeaderValue};
use tokio::sync::{Barrier, Notify};

use crate::{
    CostResponseHeaders, begin_database_call, begin_request_cost_collection,
    finish_request_cost_collection,
    metrics::CounterMetric,
    record_analytics_request_cost_by_request_id,
    recorder::MetricLabel,
    request_cost::{
        MAX_ACTIVE_REQUESTS, MAX_DATABASE_BREAKDOWN_ENTRIES, MAX_REQUEST_ID_BYTES,
        MAX_STORAGE_BREAKDOWN_ENTRIES, MAX_STORAGE_BREAKDOWN_HEADER_BYTES,
        active_request_has_registration, active_request_registry_len, record_counter,
    },
};

static REQUEST_COST_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    let first_snapshot = first.await.expect("first collector task");
    assert_eq!(first_snapshot.analytics_rows_inserted, 0);
    assert_eq!(first_snapshot.analytics_bytes_written, 0);

    record_analytics_request_cost_by_request_id("duplicate", 1, 20);
    finish_second.notify_one();
    let second_snapshot = second.await.expect("second collector task");
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
        HeaderValue::from_str(&oversized_breakdown).expect("oversized header value"),
    );

    let parsed = CostResponseHeaders::read_from_headers(&headers)
        .expect("wall-ms header should still produce a snapshot");

    assert!(parsed.snapshot().storage_breakdown.entries.is_empty());
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
        request.await.expect("held request task");
    }
    assert_eq!(active_request_registry_len(), 0);
}
