//! Generic telemetry primitives for aux services.

mod config;
mod constants;
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
pub use safe_value::{SafeTelemetryValue, TelemetryDisplay};
pub use telemetry_impl::{
    FilterSource, MetricsComponents, MetricsState, TelemetryError, TelemetryGuards, init_tracing,
    metrics_handler, resolve_filter, setup_metrics,
};
pub use trace_context::{SpanId, TraceContext, TraceFlags, TraceId};
pub use trace_layer::{
    RequestTraceLayer, SlowOperationLogState, request_trace_layer, slow_operation_log,
};
pub use wide_log::{WideLogInitError, WideLogLayer};

#[cfg(test)]
mod allocation_tests;
#[cfg(test)]
mod performance_tests;
#[cfg(test)]
mod safe_value_tests;
#[cfg(test)]
mod telemetry_impl_tests;
#[cfg(test)]
mod trace_context_tests;
#[cfg(test)]
mod trace_layer_tests;
