use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
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
    recorder::{MetricLabel, labels_are_valid},
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
const HEADER_COST_DATABASE_CALLS: &str = "x-aux-cost-db-calls";
const HEADER_COST_DATABASE_SERIAL_WAVES: &str = "x-aux-cost-db-serial-waves";
const HEADER_COST_DATABASE_MAX_PARALLELISM: &str = "x-aux-cost-db-max-parallelism";
const HEADER_COST_DATABASE_BREAKDOWN: &str = "x-aux-cost-db-breakdown";
const HEADER_COST_OPERATION: &str = "x-aux-cost-operation";
const COST_STABILIZE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const COST_STABILIZE_IDLE_WINDOW: Duration = Duration::from_millis(250);
const COST_STABILIZE_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const MAX_REQUEST_ID_BYTES: usize = 256;
pub(crate) const MAX_ACTIVE_REQUESTS: usize = 1_024;
pub(crate) const MAX_STORAGE_BREAKDOWN_ENTRIES: usize = 256;
pub(crate) const MAX_STORAGE_BREAKDOWN_HEADER_BYTES: usize = 16 * 1024;
pub(crate) const MAX_DATABASE_BREAKDOWN_ENTRIES: usize = 128;
pub(crate) const MAX_OPERATION_BYTES: usize = 512;

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestCostDatabaseCallEntry {
    pub operation: String,
    pub calls: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RequestCostSnapshot {
    pub request_id: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    pub wall_ms: f64,
    pub remote_wait_ms: f64,
    #[serde(default)]
    pub db_calls: u64,
    #[serde(default)]
    pub db_serial_waves: u64,
    #[serde(default)]
    pub db_max_parallelism: u64,
    #[serde(default)]
    pub db_call_breakdown: Vec<RequestCostDatabaseCallEntry>,
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
        insert_header_u64(headers, HEADER_COST_DATABASE_CALLS, self.snapshot.db_calls);
        insert_header_u64(
            headers,
            HEADER_COST_DATABASE_SERIAL_WAVES,
            self.snapshot.db_serial_waves,
        );
        insert_header_u64(
            headers,
            HEADER_COST_DATABASE_MAX_PARALLELISM,
            self.snapshot.db_max_parallelism,
        );
        if let Ok(serialized) = serde_json::to_string(&self.snapshot.db_call_breakdown)
            && serialized.len() <= MAX_STORAGE_BREAKDOWN_HEADER_BYTES
        {
            insert_header_string(headers, HEADER_COST_DATABASE_BREAKDOWN, &serialized);
        }
        if let Some(operation) = self.snapshot.operation.as_deref() {
            insert_header_string(headers, HEADER_COST_OPERATION, operation);
        }
        if let Ok(serialized) = serde_json::to_string(&self.snapshot.storage_breakdown)
            && serialized.len() <= MAX_STORAGE_BREAKDOWN_HEADER_BYTES
        {
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
            .filter(|value| value.as_bytes().len() <= MAX_STORAGE_BREAKDOWN_HEADER_BYTES)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| serde_json::from_str::<RequestCostStorageBreakdown>(value).ok())
            .unwrap_or_default();
        let db_call_breakdown = headers
            .get(HEADER_COST_DATABASE_BREAKDOWN)
            .filter(|value| value.as_bytes().len() <= MAX_STORAGE_BREAKDOWN_HEADER_BYTES)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| serde_json::from_str::<Vec<RequestCostDatabaseCallEntry>>(value).ok())
            .unwrap_or_default();
        let operation = headers
            .get(HEADER_COST_OPERATION)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= MAX_OPERATION_BYTES)
            .map(ToOwned::to_owned);
        Some(Self {
            snapshot: RequestCostSnapshot {
                request_id: None,
                operation,
                wall_ms,
                remote_wait_ms: parse_header_f64(headers, HEADER_COST_REMOTE_WAIT_MS)
                    .unwrap_or(0.0),
                db_calls: parse_header_u64(headers, HEADER_COST_DATABASE_CALLS).unwrap_or(0),
                db_serial_waves: parse_header_u64(headers, HEADER_COST_DATABASE_SERIAL_WAVES)
                    .unwrap_or(0),
                db_max_parallelism: parse_header_u64(headers, HEADER_COST_DATABASE_MAX_PARALLELISM)
                    .unwrap_or(0),
                db_call_breakdown,
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
    registration_id: Option<u64>,
    request_id: Option<String>,
    operation: Option<String>,
    wall_ms: Option<f64>,
    remote_wait_ms: f64,
    db_calls: u64,
    db_serial_waves: u64,
    db_max_parallelism: u64,
    active_db_calls: u64,
    db_call_breakdown: BTreeMap<String, u64>,
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
            operation: self.operation.clone(),
            wall_ms: self.wall_ms.unwrap_or_default(),
            remote_wait_ms: self.remote_wait_ms,
            db_calls: self.db_calls,
            db_serial_waves: self.db_serial_waves,
            db_max_parallelism: self.db_max_parallelism,
            db_call_breakdown: self
                .db_call_breakdown
                .iter()
                .map(|(operation, calls)| RequestCostDatabaseCallEntry {
                    operation: operation.clone(),
                    calls: *calls,
                })
                .collect(),
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
    requests: Mutex<BTreeMap<u64, ActiveRequest>>,
}

struct ActiveRequest {
    request_id: String,
    collector: Weak<Mutex<RequestCostCollector>>,
}

static NEXT_REGISTRATION_ID: AtomicU64 = AtomicU64::new(1);

fn registry() -> &'static ActiveRequestRegistry {
    static REGISTRY: OnceLock<ActiveRequestRegistry> = OnceLock::new();
    REGISTRY.get_or_init(ActiveRequestRegistry::default)
}

fn next_registration_id() -> u64 {
    NEXT_REGISTRATION_ID.fetch_add(1, Ordering::Relaxed)
}

fn register_request(
    registration_id: u64,
    request_id: &str,
    collector: &RequestCostCollectorHandle,
) -> bool {
    let Ok(mut requests) = registry().requests.lock() else {
        return false;
    };
    requests.retain(|_, request| request.collector.strong_count() > 0);
    if requests.len() >= MAX_ACTIVE_REQUESTS {
        return false;
    }
    requests.insert(
        registration_id,
        ActiveRequest {
            request_id: request_id.to_string(),
            collector: Arc::downgrade(collector),
        },
    );
    true
}

fn unregister_request(registration_id: u64) {
    let Ok(mut requests) = registry().requests.lock() else {
        return;
    };
    requests.remove(&registration_id);
}

fn with_active_collector<F>(request_id: &str, f: F)
where F: FnOnce(&mut RequestCostCollector) {
    let collector = {
        let Ok(mut requests) = registry().requests.lock() else {
            return;
        };
        requests.retain(|_, request| request.collector.strong_count() > 0);
        let mut matching = requests
            .values()
            .filter(|request| request.request_id == request_id)
            .filter_map(|request| request.collector.upgrade());
        let collector = matching.next();
        if matching.next().is_some() {
            return;
        }
        collector
    };
    let Some(collector) = collector else {
        return;
    };
    let Ok(mut collector) = collector.lock() else {
        return;
    };
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
    let request_id = request_id.filter(|request_id| request_id.len() <= MAX_REQUEST_ID_BYTES);
    let collector = Arc::new(Mutex::new(RequestCostCollector {
        request_id: request_id.clone(),
        ..RequestCostCollector::default()
    }));
    if let Some(request_id) = request_id.as_deref() {
        let registration_id = next_registration_id();
        if register_request(registration_id, request_id, &collector)
            && let Ok(mut collector) = collector.lock()
        {
            collector.registration_id = Some(registration_id);
        }
    }
    REQUEST_COST_COLLECTOR.scope(collector, future()).await
}

/// Associates the current request-cost collector with a bounded route name.
/// Route templates are preferred over raw request paths so this value remains
/// stable and cannot contain customer identifiers.
pub fn set_request_cost_operation(operation: &str) {
    REQUEST_COST_COLLECTOR
        .try_with(|collector| {
            let Ok(mut collector) = collector.lock() else {
                return;
            };
            if operation.len() <= MAX_OPERATION_BYTES {
                collector.operation = Some(operation.to_string());
                collector.mark_updated();
            }
        })
        .ok();
}

/// Records one provider-backed database future for the current request.
/// Dropping the returned guard closes the call and updates active-wave state.
#[must_use]
pub fn begin_database_call(operation: &str) -> DatabaseCallGuard {
    let Ok(collector) = REQUEST_COST_COLLECTOR.try_with(Arc::clone) else {
        return DatabaseCallGuard { collector: None };
    };
    let Ok(mut collector_guard) = collector.lock() else {
        return DatabaseCallGuard { collector: None };
    };
    collector_guard.db_calls = collector_guard.db_calls.saturating_add(1);
    if collector_guard.active_db_calls == 0 {
        collector_guard.db_serial_waves = collector_guard.db_serial_waves.saturating_add(1);
    }
    collector_guard.active_db_calls = collector_guard.active_db_calls.saturating_add(1);
    collector_guard.db_max_parallelism = collector_guard
        .db_max_parallelism
        .max(collector_guard.active_db_calls);
    if operation.len() <= MAX_OPERATION_BYTES {
        if let Some(calls) = collector_guard.db_call_breakdown.get_mut(operation) {
            *calls = calls.saturating_add(1);
        } else if collector_guard.db_call_breakdown.len() < MAX_DATABASE_BREAKDOWN_ENTRIES {
            collector_guard
                .db_call_breakdown
                .insert(operation.to_owned(), 1);
        }
    }
    collector_guard.mark_updated();
    drop(collector_guard);
    DatabaseCallGuard {
        collector: Some(collector),
    }
}

pub struct DatabaseCallGuard {
    collector: Option<RequestCostCollectorHandle>,
}

impl Drop for DatabaseCallGuard {
    fn drop(&mut self) {
        let Some(collector) = self.collector.take() else {
            return;
        };
        let Ok(mut collector) = collector.lock() else {
            return;
        };
        collector.active_db_calls = collector.active_db_calls.saturating_sub(1);
        collector.mark_updated();
    }
}

pub async fn finish_request_cost_collection(
    request_id: Option<&str>,
    wall_ms: f64,
    response_bytes: Option<u64>,
) -> RequestCostSnapshot {
    let Ok(collector) = REQUEST_COST_COLLECTOR.try_with(Arc::clone) else {
        return RequestCostSnapshot::default();
    };
    let (snapshot, registration_id) = {
        let Ok(mut collector) = collector.lock() else {
            return RequestCostSnapshot::default();
        };
        collector.wall_ms = Some(wall_ms);
        collector.response_bytes = response_bytes;
        collector.mark_updated();
        (collector.snapshot(), collector.registration_id)
    };
    if request_id.is_some() && registration_id.is_some() {
        wait_for_cost_settle(&collector).await;
    }
    let settled = collector
        .lock()
        .map(|collector| collector.snapshot())
        .unwrap_or(snapshot);
    if let Some(registration_id) = registration_id {
        unregister_request(registration_id);
    }
    settled
}

async fn wait_for_cost_settle(collector: &RequestCostCollectorHandle) {
    let deadline = Instant::now() + COST_STABILIZE_TIMEOUT;
    loop {
        let settled = {
            let Ok(collector) = collector.lock() else {
                return;
            };
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
            let Ok(mut collector) = collector.lock() else {
                return;
            };
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
            let Ok(mut collector) = collector.lock() else {
                return;
            };
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
            let Ok(mut collector) = collector.lock() else {
                return;
            };
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
    if !labels_are_valid(labels) {
        return;
    }
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
    let key = (ddb_op, item_kind, direction);
    if !collector.storage_breakdown.contains_key(&key)
        && collector.storage_breakdown.len() >= MAX_STORAGE_BREAKDOWN_ENTRIES
    {
        return;
    }
    let entry = collector.storage_breakdown.entry(key).or_insert((0, 0));
    entry.0 = entry.0.saturating_add(value);
}

fn record_storage_bytes(collector: &mut RequestCostCollector, labels: &[MetricLabel], value: u64) {
    if !labels_are_valid(labels) {
        return;
    }
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
    let key = (ddb_op, item_kind, direction);
    if !collector.storage_breakdown.contains_key(&key)
        && collector.storage_breakdown.len() >= MAX_STORAGE_BREAKDOWN_ENTRIES
    {
        return;
    }
    let entry = collector.storage_breakdown.entry(key).or_insert((0, 0));
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

#[cfg(test)]
pub(crate) fn active_request_registry_len() -> usize {
    registry()
        .requests
        .lock()
        .map(|mut requests| {
            requests.retain(|_, request| request.collector.strong_count() > 0);
            requests.len()
        })
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn active_request_has_registration() -> bool {
    REQUEST_COST_COLLECTOR
        .try_with(|collector| {
            collector
                .lock()
                .map(|collector| collector.registration_id.is_some())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}
