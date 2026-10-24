#[cfg(feature = "request-cost")]
use std::time::Duration;

#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_WALL_MS: &str = "x-aux-cost-wall-ms";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_REMOTE_WAIT_MS: &str = "x-aux-cost-remote-wait-ms";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_DB_READ_OPS: &str = "x-aux-cost-db-read-ops";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_DB_WRITE_OPS: &str = "x-aux-cost-db-write-ops";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_DB_READ_BYTES: &str = "x-aux-cost-db-read-bytes";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_DB_WRITE_BYTES: &str = "x-aux-cost-db-write-bytes";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_ANALYTICS_ROWS_INSERTED: &str = "x-aux-cost-analytics-rows-inserted";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_ANALYTICS_ROWS_UPDATED: &str = "x-aux-cost-analytics-rows-updated";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_ANALYTICS_ROWS_DELETED: &str = "x-aux-cost-analytics-rows-deleted";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_ANALYTICS_BYTES_WRITTEN: &str = "x-aux-cost-analytics-bytes-written";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_REQUEST_BYTES: &str = "x-aux-cost-request-bytes";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_REMOTE_REQUEST_BYTES: &str = "x-aux-cost-remote-request-bytes";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_REMOTE_RESPONSE_BYTES: &str = "x-aux-cost-remote-response-bytes";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_STORAGE_BREAKDOWN: &str = "x-aux-cost-storage-breakdown";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_DATABASE_CALLS: &str = "x-aux-cost-db-calls";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_DATABASE_SERIAL_WAVES: &str = "x-aux-cost-db-serial-waves";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_DATABASE_MAX_PARALLELISM: &str = "x-aux-cost-db-max-parallelism";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_DATABASE_BREAKDOWN: &str = "x-aux-cost-db-breakdown";
#[cfg(feature = "request-cost")]
pub(crate) const HEADER_COST_OPERATION: &str = "x-aux-cost-operation";

#[cfg(feature = "request-cost")]
pub(crate) const COST_STABILIZE_POLL_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(feature = "request-cost")]
pub(crate) const COST_STABILIZE_IDLE_WINDOW: Duration = Duration::from_millis(250);
#[cfg(feature = "request-cost")]
pub(crate) const COST_STABILIZE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(feature = "request-cost")]
pub(crate) const MAX_REQUEST_ID_BYTES: usize = 256;
#[cfg(feature = "request-cost")]
pub(crate) const MAX_ACTIVE_REQUESTS: usize = 1_024;
#[cfg(feature = "request-cost")]
pub(crate) const MAX_STORAGE_BREAKDOWN_ENTRIES: usize = 256;
#[cfg(feature = "request-cost")]
pub(crate) const MAX_STORAGE_BREAKDOWN_HEADER_BYTES: usize = 16 * 1024;
#[cfg(feature = "request-cost")]
pub(crate) const MAX_DATABASE_BREAKDOWN_ENTRIES: usize = 128;
#[cfg(feature = "request-cost")]
pub(crate) const MAX_OPERATION_BYTES: usize = 512;

pub(crate) const MAX_METRIC_LABELS: usize = 16;
pub(crate) const MAX_METRIC_LABEL_VALUE_BYTES: usize = 256;
pub(crate) const MAX_HANDLE_CACHE_ENTRIES: usize = 256;
pub(crate) const MAX_REGISTERED_METRIC_KEYS: usize = 4_096;
pub(crate) const INVALID_METRIC_LABEL_VALUE: &str = "<invalid>";

#[cfg(all(feature = "http-observer", not(target_arch = "wasm32")))]
pub(crate) const LABEL_HTTP_METHOD: &str = "method";
#[cfg(all(feature = "http-observer", not(target_arch = "wasm32")))]
pub(crate) const LABEL_HTTP_OUTCOME: &str = "outcome";
#[cfg(all(feature = "http-observer", not(target_arch = "wasm32")))]
pub(crate) const LABEL_HTTP_STATUS_CLASS: &str = "status_class";

#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
pub(crate) const METERING_MODE_LABELS: [&str; 4] =
    ["buffered", "synchronous", "draining", "stopped"];
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
pub(crate) const METERING_HEALTH_LABELS: [&str; 3] = ["closed", "open", "half_open"];
