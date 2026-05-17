use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};

use http::{
    HeaderMap, HeaderValue,
    header::{CONTENT_LENGTH, HeaderName},
};
use serde::{Deserialize, Serialize};
use tokio::task_local;

use crate::{
    metrics::{CounterMetric, GaugeMetric, HistogramMetric},
    recorder::MetricLabel,
};

const HEADER_COST_WALL_MS: &str = "x-aux-cost-wall-ms";
const HEADER_COST_REMOTE_WAIT_MS: &str = "x-aux-cost-remote-wait-ms";
const HEADER_COST_DB_READ_OPS: &str = "x-aux-cost-db-read-ops";
const HEADER_COST_DB_WRITE_OPS: &str = "x-aux-cost-db-write-ops";
const HEADER_COST_DB_READ_BYTES: &str = "x-aux-cost-db-read-bytes";
const HEADER_COST_DB_WRITE_BYTES: &str = "x-aux-cost-db-write-bytes";
const HEADER_COST_ANALYTICS_ROWS_INSERTED: &str = "x-aux-cost-analytics-rows-inserted";
const HEADER_COST_ANALYTICS_ROWS_UPDATED: &str = "x-aux-cost-analytics-rows-updated";
const HEADER_COST_ANALYTICS_ROWS_DELETED: &str = "x-aux-cost-analytics-rows-deleted";
const HEADER_COST_ANALYTICS_BYTES_WRITTEN: &str = "x-aux-cost-analytics-bytes-written";
const HEADER_COST_REQUEST_BYTES: &str = "x-aux-cost-request-bytes";
const HEADER_COST_REMOTE_REQUEST_BYTES: &str = "x-aux-cost-remote-request-bytes";
const HEADER_COST_REMOTE_RESPONSE_BYTES: &str = "x-aux-cost-remote-response-bytes";
const HEADER_COST_STORAGE_BREAKDOWN: &str = "x-aux-cost-storage-breakdown";
const COST_STABILIZE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const COST_STABILIZE_IDLE_WINDOW: Duration = Duration::from_millis(250);
const COST_STABILIZE_TIMEOUT: Duration = Duration::from_secs(5);

type RequestCostCollectorHandle = Arc<Mutex<RequestCostCollector>>;

task_local! {
    static REQUEST_COST_COLLECTOR: RequestCostCollectorHandle;
}

#[derive(Clone, Copy)]
pub(crate) enum GaugeUpdate {
    Set,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RequestCostStorageDirection {
    Read,
    Write,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestCostStorageBreakdownEntry {
    pub ddb_op: String,
    pub item_kind: String,
    pub direction: RequestCostStorageDirection,
    pub ops: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RequestCostStorageBreakdown {
    pub entries: Vec<RequestCostStorageBreakdownEntry>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RequestCostSnapshot {
    pub request_id: Option<String>,
    pub wall_ms: f64,
    pub remote_wait_ms: f64,
    pub db_read_ops: u64,
    pub db_write_ops: u64,
    pub db_read_bytes: u64,
    pub db_write_bytes: u64,
    pub analytics_rows_inserted: u64,
    pub analytics_rows_updated: u64,
    pub analytics_rows_deleted: u64,
    pub analytics_bytes_written: u64,
    pub request_bytes: u64,
    pub response_bytes: Option<u64>,
    pub remote_request_bytes: u64,
    pub remote_response_bytes: u64,
    pub storage_breakdown: RequestCostStorageBreakdown,
}

#[derive(Clone, Debug)]
pub struct CostResponseHeaders {
    snapshot: RequestCostSnapshot,
}

impl CostResponseHeaders {
    #[must_use]
    pub fn from_snapshot(snapshot: RequestCostSnapshot) -> Self {
        Self { snapshot }
    }

    #[must_use]
    pub fn snapshot(&self) -> &RequestCostSnapshot {
        &self.snapshot
    }

    pub fn write_to_headers(&self, headers: &mut HeaderMap) {
        insert_header_f64(headers, HEADER_COST_WALL_MS, self.snapshot.wall_ms);
        insert_header_f64(
            headers,
            HEADER_COST_REMOTE_WAIT_MS,
            self.snapshot.remote_wait_ms,
        );
        insert_header_u64(headers, HEADER_COST_DB_READ_OPS, self.snapshot.db_read_ops);
        insert_header_u64(
            headers,
            HEADER_COST_DB_WRITE_OPS,
            self.snapshot.db_write_ops,
        );
        insert_header_u64(
            headers,
            HEADER_COST_DB_READ_BYTES,
            self.snapshot.db_read_bytes,
        );
        insert_header_u64(
            headers,
            HEADER_COST_DB_WRITE_BYTES,
            self.snapshot.db_write_bytes,
        );
        insert_header_u64(
            headers,
            HEADER_COST_ANALYTICS_ROWS_INSERTED,
            self.snapshot.analytics_rows_inserted,
        );
        insert_header_u64(
            headers,
            HEADER_COST_ANALYTICS_ROWS_UPDATED,
            self.snapshot.analytics_rows_updated,
        );
        insert_header_u64(
            headers,
            HEADER_COST_ANALYTICS_ROWS_DELETED,
            self.snapshot.analytics_rows_deleted,
        );
        insert_header_u64(
            headers,
            HEADER_COST_ANALYTICS_BYTES_WRITTEN,
            self.snapshot.analytics_bytes_written,
        );
        insert_header_u64(
            headers,
            HEADER_COST_REQUEST_BYTES,
            self.snapshot.request_bytes,
        );
        insert_header_u64(
            headers,
            HEADER_COST_REMOTE_REQUEST_BYTES,
            self.snapshot.remote_request_bytes,
        );
        insert_header_u64(
            headers,
            HEADER_COST_REMOTE_RESPONSE_BYTES,
            self.snapshot.remote_response_bytes,
        );
        if let Ok(serialized) = serde_json::to_string(&self.snapshot.storage_breakdown) {
            insert_header_string(headers, HEADER_COST_STORAGE_BREAKDOWN, &serialized);
        }
    }

    #[must_use]
    pub fn read_from_headers(headers: &HeaderMap) -> Option<Self> {
        let wall_ms = parse_header_f64(headers, HEADER_COST_WALL_MS)?;
        let response_bytes = headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let storage_breakdown = headers
            .get(HEADER_COST_STORAGE_BREAKDOWN)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| serde_json::from_str::<RequestCostStorageBreakdown>(value).ok())
            .unwrap_or_default();
        Some(Self {
            snapshot: RequestCostSnapshot {
                request_id: None,
                wall_ms,
                remote_wait_ms: parse_header_f64(headers, HEADER_COST_REMOTE_WAIT_MS)
                    .unwrap_or(0.0),
                db_read_ops: parse_header_u64(headers, HEADER_COST_DB_READ_OPS).unwrap_or(0),
                db_write_ops: parse_header_u64(headers, HEADER_COST_DB_WRITE_OPS).unwrap_or(0),
                db_read_bytes: parse_header_u64(headers, HEADER_COST_DB_READ_BYTES).unwrap_or(0),
                db_write_bytes: parse_header_u64(headers, HEADER_COST_DB_WRITE_BYTES).unwrap_or(0),
                analytics_rows_inserted: parse_header_u64(
                    headers,
                    HEADER_COST_ANALYTICS_ROWS_INSERTED,
                )
                .unwrap_or(0),
                analytics_rows_updated: parse_header_u64(
                    headers,
                    HEADER_COST_ANALYTICS_ROWS_UPDATED,
                )
                .unwrap_or(0),
                analytics_rows_deleted: parse_header_u64(
                    headers,
                    HEADER_COST_ANALYTICS_ROWS_DELETED,
                )
                .unwrap_or(0),
                analytics_bytes_written: parse_header_u64(
                    headers,
                    HEADER_COST_ANALYTICS_BYTES_WRITTEN,
                )
                .unwrap_or(0),
                request_bytes: parse_header_u64(headers, HEADER_COST_REQUEST_BYTES).unwrap_or(0),
                response_bytes,
                remote_request_bytes: parse_header_u64(headers, HEADER_COST_REMOTE_REQUEST_BYTES)
                    .unwrap_or(0),
                remote_response_bytes: parse_header_u64(headers, HEADER_COST_REMOTE_RESPONSE_BYTES)
                    .unwrap_or(0),
                storage_breakdown,
            },
        })
    }
}

#[derive(Default)]
struct RequestCostCollector {
    request_id: Option<String>,
    wall_ms: Option<f64>,
    remote_wait_ms: f64,
    db_read_ops: u64,
    db_write_ops: u64,
    db_read_bytes: u64,
    db_write_bytes: u64,
    analytics_rows_inserted: u64,
    analytics_rows_updated: u64,
    analytics_rows_deleted: u64,
    analytics_bytes_written: u64,
    request_bytes: u64,
    response_bytes: Option<u64>,
    remote_request_bytes: u64,
    remote_response_bytes: u64,
    storage_breakdown: BTreeMap<(String, String, RequestCostStorageDirection), (u64, u64)>,
    last_update_at: Option<Instant>,
}

impl RequestCostCollector {
    fn mark_updated(&mut self) {
        self.last_update_at = Some(Instant::now());
    }

    fn snapshot(&self) -> RequestCostSnapshot {
        let entries = self
            .storage_breakdown
            .iter()
            .map(|((ddb_op, item_kind, direction), (ops, bytes))| {
                RequestCostStorageBreakdownEntry {
                    ddb_op: ddb_op.clone(),
                    item_kind: item_kind.clone(),
                    direction: *direction,
                    ops: *ops,
                    bytes: *bytes,
                }
            })
            .collect();
        RequestCostSnapshot {
            request_id: self.request_id.clone(),
            wall_ms: self.wall_ms.unwrap_or_default(),
            remote_wait_ms: self.remote_wait_ms,
            db_read_ops: self.db_read_ops,
            db_write_ops: self.db_write_ops,
            db_read_bytes: self.db_read_bytes,
            db_write_bytes: self.db_write_bytes,
            analytics_rows_inserted: self.analytics_rows_inserted,
            analytics_rows_updated: self.analytics_rows_updated,
            analytics_rows_deleted: self.analytics_rows_deleted,
            analytics_bytes_written: self.analytics_bytes_written,
            request_bytes: self.request_bytes,
            response_bytes: self.response_bytes,
            remote_request_bytes: self.remote_request_bytes,
            remote_response_bytes: self.remote_response_bytes,
            storage_breakdown: RequestCostStorageBreakdown { entries },
        }
    }
}

#[derive(Default)]
struct ActiveRequestRegistry {
    requests: Mutex<BTreeMap<String, Weak<Mutex<RequestCostCollector>>>>,
}

fn registry() -> &'static ActiveRequestRegistry {
    static REGISTRY: OnceLock<ActiveRequestRegistry> = OnceLock::new();
    REGISTRY.get_or_init(ActiveRequestRegistry::default)
}

fn register_request(request_id: &str, collector: &RequestCostCollectorHandle) {
    let mut requests = registry()
        .requests
        .lock()
        .expect("request cost registry poisoned");
    requests.insert(request_id.to_string(), Arc::downgrade(collector));
}

fn unregister_request(request_id: &str) {
    let mut requests = registry()
        .requests
        .lock()
        .expect("request cost registry poisoned");
    requests.remove(request_id);
}

fn with_active_collector<F>(request_id: &str, f: F)
where F: FnOnce(&mut RequestCostCollector) {
    let collector = {
        let requests = registry()
            .requests
            .lock()
            .expect("request cost registry poisoned");
        requests.get(request_id).and_then(Weak::upgrade)
    };
    let Some(collector) = collector else {
        return;
    };
    let mut collector = collector.lock().expect("request cost collector poisoned");
    f(&mut collector);
}

#[must_use]
pub fn active_request_id() -> Option<String> {
    REQUEST_COST_COLLECTOR
        .try_with(|collector| {
            collector
                .lock()
                .ok()
                .and_then(|collector| collector.request_id.clone())
        })
        .ok()
        .flatten()
}

pub async fn begin_request_cost_collection<F, Fut, T>(request_id: Option<String>, future: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let collector = Arc::new(Mutex::new(RequestCostCollector {
        request_id: request_id.clone(),
        ..RequestCostCollector::default()
    }));
    if let Some(request_id) = request_id.as_deref() {
        register_request(request_id, &collector);
    }
    REQUEST_COST_COLLECTOR.scope(collector, future()).await
}

pub async fn finish_request_cost_collection(
    request_id: Option<&str>,
    wall_ms: f64,
    response_bytes: Option<u64>,
) -> RequestCostSnapshot {
    let snapshot = REQUEST_COST_COLLECTOR
        .try_with(|collector| {
            let mut collector = collector.lock().expect("request cost collector poisoned");
            collector.wall_ms = Some(wall_ms);
            collector.response_bytes = response_bytes;
            collector.mark_updated();
            collector.snapshot()
        })
        .unwrap_or_default();
    if let Some(request_id) = request_id {
        wait_for_cost_settle(request_id).await;
        let settled = REQUEST_COST_COLLECTOR
            .try_with(|collector| {
                collector
                    .lock()
                    .expect("request cost collector poisoned")
                    .snapshot()
            })
            .unwrap_or_else(|_| snapshot.clone());
        unregister_request(request_id);
        return settled;
    }
    snapshot
}

async fn wait_for_cost_settle(request_id: &str) {
    let deadline = Instant::now() + COST_STABILIZE_TIMEOUT;
    loop {
        let settled = {
            let collector = {
                let requests = registry()
                    .requests
                    .lock()
                    .expect("request cost registry poisoned");
                requests.get(request_id).and_then(Weak::upgrade)
            };
            let Some(collector) = collector else {
                return;
            };
            let collector = collector.lock().expect("request cost collector poisoned");
            collector
                .last_update_at
                .is_none_or(|ts| ts.elapsed() >= COST_STABILIZE_IDLE_WINDOW)
        };
        if settled || Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(COST_STABILIZE_POLL_INTERVAL).await;
    }
}

pub(crate) fn record_counter(metric: CounterMetric, labels: &[MetricLabel], value: u64) {
    REQUEST_COST_COLLECTOR
        .try_with(|collector| {
            let mut collector = collector.lock().expect("request cost collector poisoned");
            match metric {
                CounterMetric::HttpRequestBytesTotalMetric => {
                    collector.request_bytes = collector.request_bytes.saturating_add(value);
                }
                CounterMetric::StorageBilledItemOpsTotalMetric => {
                    record_storage_ops(&mut collector, labels, value);
                }
                CounterMetric::StorageLogicalItemBytesTotalMetric => {
                    record_storage_bytes(&mut collector, labels, value);
                }
                CounterMetric::RemoteStorageRequestBytesTotalMetric => {
                    collector.remote_request_bytes =
                        collector.remote_request_bytes.saturating_add(value);
                }
                CounterMetric::RemoteStorageResponseBytesTotalMetric => {
                    collector.remote_response_bytes =
                        collector.remote_response_bytes.saturating_add(value);
                }
                CounterMetric::AnalyticsIngestionRecordsInsertedTotalMetric => {
                    collector.analytics_rows_inserted =
                        collector.analytics_rows_inserted.saturating_add(value);
                }
                CounterMetric::AnalyticsIngestionRecordsUpdatedTotalMetric => {
                    collector.analytics_rows_updated =
                        collector.analytics_rows_updated.saturating_add(value);
                }
                CounterMetric::AnalyticsIngestionRecordsDeletedTotalMetric => {
                    collector.analytics_rows_deleted =
                        collector.analytics_rows_deleted.saturating_add(value);
                }
                CounterMetric::AnalyticsIngestionBytesWrittenTotalMetric => {
                    collector.analytics_bytes_written =
                        collector.analytics_bytes_written.saturating_add(value);
                }
                _ => return,
            }
            collector.mark_updated();
        })
        .ok();
}

pub(crate) fn record_gauge(metric: GaugeMetric, _labels: &[MetricLabel], update: GaugeUpdate) {
    REQUEST_COST_COLLECTOR
        .try_with(|collector| {
            let mut collector = collector.lock().expect("request cost collector poisoned");
            if let (GaugeMetric::AnalyticsIngestionQueueDepthMetric, GaugeUpdate::Set) =
                (metric, update)
            {
                collector.mark_updated();
            }
        })
        .ok();
}

pub(crate) fn record_histogram(metric: HistogramMetric, _labels: &[MetricLabel], value: f64) {
    REQUEST_COST_COLLECTOR
        .try_with(|collector| {
            let mut collector = collector.lock().expect("request cost collector poisoned");
            match metric {
                HistogramMetric::RequestLatencyMetric => collector.wall_ms = Some(value),
                HistogramMetric::RemoteStorageRequestLatencyMs => {
                    collector.remote_wait_ms += value;
                }
                _ => return,
            }
            collector.mark_updated();
        })
        .ok();
}

pub fn record_analytics_request_cost_by_request_id(request_id: &str, row_delta: i64, bytes: u64) {
    with_active_collector(request_id, |collector| {
        match row_delta.cmp(&0) {
            std::cmp::Ordering::Greater => {
                collector.analytics_rows_inserted = collector
                    .analytics_rows_inserted
                    .saturating_add(row_delta.cast_unsigned());
            }
            std::cmp::Ordering::Less => {
                collector.analytics_rows_deleted = collector
                    .analytics_rows_deleted
                    .saturating_add(row_delta.unsigned_abs());
            }
            std::cmp::Ordering::Equal => {
                collector.analytics_rows_updated =
                    collector.analytics_rows_updated.saturating_add(1);
            }
        }
        collector.analytics_bytes_written = collector.analytics_bytes_written.saturating_add(bytes);
        collector.mark_updated();
    });
}

fn record_storage_ops(collector: &mut RequestCostCollector, labels: &[MetricLabel], value: u64) {
    let Some((ddb_op, item_kind, direction)) = storage_labels(labels) else {
        return;
    };
    match direction {
        RequestCostStorageDirection::Read => {
            collector.db_read_ops = collector.db_read_ops.saturating_add(value);
        }
        RequestCostStorageDirection::Write => {
            collector.db_write_ops = collector.db_write_ops.saturating_add(value);
        }
    }
    let entry = collector
        .storage_breakdown
        .entry((ddb_op, item_kind, direction))
        .or_insert((0, 0));
    entry.0 = entry.0.saturating_add(value);
}

fn record_storage_bytes(collector: &mut RequestCostCollector, labels: &[MetricLabel], value: u64) {
    let Some((ddb_op, item_kind, direction)) = storage_labels(labels) else {
        return;
    };
    match direction {
        RequestCostStorageDirection::Read => {
            collector.db_read_bytes = collector.db_read_bytes.saturating_add(value);
        }
        RequestCostStorageDirection::Write => {
            collector.db_write_bytes = collector.db_write_bytes.saturating_add(value);
        }
    }
    let entry = collector
        .storage_breakdown
        .entry((ddb_op, item_kind, direction))
        .or_insert((0, 0));
    entry.1 = entry.1.saturating_add(value);
}

fn storage_labels(labels: &[MetricLabel]) -> Option<(String, String, RequestCostStorageDirection)> {
    let mut ddb_op = None;
    let mut item_kind = None;
    let mut direction = None;
    for label in labels {
        match label.key() {
            "ddb_op" => ddb_op = Some(label.value().to_string()),
            "item_kind" => item_kind = Some(label.value().to_string()),
            "direction" => {
                direction = match label.value() {
                    "read" => Some(RequestCostStorageDirection::Read),
                    "write" => Some(RequestCostStorageDirection::Write),
                    _ => None,
                }
            }
            _ => {}
        }
    }
    Some((ddb_op?, item_kind?, direction?))
}

fn insert_header_u64(headers: &mut HeaderMap, name: &str, value: u64) {
    insert_header_string(headers, name, &value.to_string());
}

fn insert_header_f64(headers: &mut HeaderMap, name: &str, value: f64) {
    insert_header_string(headers, name, &format!("{value:.6}"));
}

fn insert_header_string(headers: &mut HeaderMap, name: &str, value: &str) {
    let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    let Ok(value) = HeaderValue::from_str(value) else {
        return;
    };
    headers.insert(name, value);
}

fn parse_header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn parse_header_f64(headers: &HeaderMap, name: &str) -> Option<f64> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<f64>().ok())
}
