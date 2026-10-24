//! Generic telemetry primitives for aux services.
#![cfg_attr(not(test), deny(clippy::print_stderr, clippy::print_stdout))]

mod config;
mod constants;
mod request_cost_collection;
#[cfg(test)]
mod request_cost_collection_tests;
mod safe_value;
mod telemetry_impl;
mod trace_context;
mod trace_layer;
mod wide_log;

pub use config::{
    FieldEmissionMode, FieldSecurityPolicy, ForwardedHeaderConfig, MetricsConfig, RootSpanPolicy,
    SlowOperationThresholds, TraceRuleConfig, TracingConfig,
};
pub use constants::{
    FIELD_FEATURE, FIELD_OPERATION_NAME, FIELD_ORG_ID, FIELD_REQUEST_ID, FIELD_SOURCE_IP,
    FIELD_SPAN_ID, FIELD_TENANT_ID, FIELD_TRACE_FLAGS, FIELD_TRACE_ID, FIELD_USER_ID,
    HEADER_REQUEST_ID, HEADER_TRACE_ID, HEADER_TRACEPARENT, HEADER_TRACESTATE,
    HTTP_REQUEST_BYTES_TOTAL_METRIC, HTTP_RESPONSE_BYTES_TOTAL_METRIC, LABEL_OPERATION,
    LABEL_STATUS_CODE, REQUEST_LATENCY_METRIC,
};
pub use request_cost_collection::RequestCostCollection;
pub use safe_value::{SafeTelemetryValue, TelemetryDisplay};
pub use telemetry_impl::{
    FilterSource, MetricsComponents, MetricsState, TelemetryError, TelemetryGuards, init_tracing,
    init_tracing_with_sink, metrics_handler, resolve_filter, setup_metrics,
};
pub use trace_context::{SpanId, TraceContext, TraceFlags, TraceId};
pub use trace_layer::{
    RequestTraceLayer, SlowOperationLogState, request_trace_layer, slow_operation_log,
};
pub use wide_log::{WideLogInitError, WideLogLayer, WideLogSink};

#[cfg(test)]
mod safe_value_tests;
#[cfg(test)]
mod telemetry_impl_tests;
#[cfg(test)]
mod trace_context_tests;
#[cfg(test)]
mod trace_layer_tests;
