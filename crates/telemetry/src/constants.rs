use metrics_facade::{CounterMetric, HistogramMetric};

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
