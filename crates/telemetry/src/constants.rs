use metrics_facade::{CounterMetric, HistogramMetric};

pub(crate) const DEFAULT_LOG_DESTINATION: &str = "stdout";
pub(crate) const DEFAULT_LOG_FILTER: &str = "warn";
pub(crate) const DEFAULT_SLOW_OPERATION_THRESHOLD_MS: u64 = 500;
pub(crate) const DEFAULT_METRICS_PATH: &str = "/internal/metrics";
pub(crate) const DEFAULT_TOP_LEVEL_FIELD_ALLOWLIST: &[&str] = &[
    FIELD_FEATURE,
    FIELD_OPERATION_NAME,
    FIELD_REQUEST_ID,
    FIELD_TRACE_ID,
    FIELD_SOURCE_IP,
    FIELD_TENANT_ID,
    FIELD_ORG_ID,
    FIELD_USER_ID,
    "method",
    "path",
    "host",
    "status_code",
    "duration_ms",
    "request_bytes",
    "response_bytes",
    FIELD_SPAN_ID,
    FIELD_TRACE_FLAGS,
];
pub(crate) const DEFAULT_SENSITIVE_FIELD_BLOCKLIST: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "set_cookie",
    "x-api-key",
    "api-key",
    "api_key",
    "access_token",
    "accessToken",
    "refresh_token",
    "refreshToken",
    "id_token",
    "idToken",
    "client_secret",
    "clientSecret",
    "apiKey",
    "privateKey",
    "secretKey",
    "signingKey",
    "bearerToken",
    "password",
    "secret",
    "token",
];
pub(crate) const UNMATCHED_OPERATION: &str = "_unmatched";

pub const REQUEST_LATENCY_METRIC: HistogramMetric = HistogramMetric::RequestLatencyMetric;
pub const HTTP_REQUEST_BYTES_TOTAL_METRIC: CounterMetric =
    CounterMetric::HttpRequestBytesTotalMetric;
pub const HTTP_RESPONSE_BYTES_TOTAL_METRIC: CounterMetric =
    CounterMetric::HttpResponseBytesTotalMetric;

pub const LABEL_OPERATION: &str = "operation";
pub const LABEL_STATUS_CODE: &str = "status_code";

pub const HEADER_REQUEST_ID: &str = "x-request-id";
pub const HEADER_TRACE_ID: &str = "x-trace-id";
pub const HEADER_TRACEPARENT: &str = "traceparent";
pub const HEADER_TRACESTATE: &str = "tracestate";

pub const FIELD_FEATURE: &str = "feature";
pub const FIELD_OPERATION_NAME: &str = "operation_name";
pub const FIELD_ORG_ID: &str = "org_id";
pub const FIELD_REQUEST_ID: &str = "request_id";
pub const FIELD_SPAN_ID: &str = "span_id";
pub const FIELD_SOURCE_IP: &str = "source_ip";
pub const FIELD_TENANT_ID: &str = "tenant_id";
pub const FIELD_TRACE_FLAGS: &str = "trace_flags";
pub const FIELD_TRACE_ID: &str = "trace_id";
pub const FIELD_USER_ID: &str = "user_id";
