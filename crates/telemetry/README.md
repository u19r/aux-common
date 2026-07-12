# telemetry

Generic tracing, request telemetry, wide-log emission, and Prometheus helpers.

Security-sensitive log field handling is explicit. Callers must either opt in to
`TracingConfig::with_default_security()` or construct `TracingConfig::new(...)` with their own
`FieldSecurityPolicy`. The default policy uses a strict allowlist and redacts common credential
fields, so newly named free-text fields are omitted until callers explicitly approve them.

```rust
use telemetry::{
    FieldSecurityPolicy, RootSpanPolicy, TraceRuleConfig, TracingConfig, init_tracing,
    request_trace_layer, resolve_filter,
};

let tracing = TracingConfig::with_default_security()
    .with_service_name(Some("billing-api".to_string()))
    .with_trace_rules(vec![TraceRuleConfig {
        feature: "billing".to_string(),
        log_level: "INFO".to_string(),
    }]);

let (filter, _source) = resolve_filter(&tracing);
let _guards = init_tracing(&tracing, filter)?;
let layer = request_trace_layer();
# Ok::<(), Box<dyn std::error::Error>>(())
```

For new services, prefer `FieldSecurityPolicy::strict_allowlist(...)` so free-form fields are
omitted unless the service explicitly allows them. Use `FieldSecurityPolicy::typed_only(...)` for
high-security surfaces where only structured primitives are emitted from `tracing` fields. Service
newtypes that can prove their log representation is safe should implement `TelemetryDisplay` and
wrap the result in `SafeTelemetryValue` at service boundaries.

```rust
use std::borrow::Cow;
use telemetry::{SafeTelemetryValue, TelemetryDisplay};

struct OperationName(&'static str);

impl TelemetryDisplay for OperationName {
    fn telemetry_display(&self) -> Cow<'_, str> {
        Cow::Borrowed(self.0)
    }
}

let operation = SafeTelemetryValue::from_display(&OperationName("billing.invoice.create"));
let span = tracing::info_span!("http.request", operation_name = tracing::field::Empty);
operation.record_on(&span, "operation_name");
```

Use `TraceContext::from_headers` to read inbound `traceparent`, `x-trace-id`, and `x-request-id`.
Use `TraceContext::write_forward_headers` before sending service-to-service requests. The request
trace layer records trace/request ids and `slow_operation_log` writes trace/request ids back to HTTP
responses.

Prometheus helpers are configured independently:

```rust
use telemetry::{MetricsConfig, setup_metrics};

let metrics = setup_metrics(&MetricsConfig::enabled("scrape-token"))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Keep service-specific field names, root span names, and feature prefixes in their own
crate and pass them through `FieldSecurityPolicy`, `RootSpanPolicy`, and `TraceRuleConfig`.
