use std::{
    collections::BTreeMap,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{Router, body::Body, middleware::from_fn_with_state, routing::get};
use http::{HeaderMap, HeaderValue, Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::{
    FieldSecurityPolicy, HEADER_REQUEST_ID, HEADER_TRACE_ID, HEADER_TRACEPARENT, HEADER_TRACESTATE,
    RootSpanPolicy, SlowOperationLogState, SlowOperationThresholds, TraceContext, TracingConfig,
    WideLogLayer, request_trace_layer, slow_operation_log, wide_log::has_sensitive_suffix,
};

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[test]
fn perf_loop_sensitive_suffix_matching_given_old_algorithm_then_optimized_reduces_allocations() {
    let keys = [
        "headers.authorization",
        "client_secret",
        "tenant.id",
        "request.cookie",
        "safe_field",
    ];
    let suffixes = ["authorization", "secret", "cookie", "token"];

    let baseline = measure_allocations("baseline_sensitive_suffix", || {
        let mut matches = 0;
        for _ in 0..1_000 {
            for key in keys {
                for suffix in suffixes {
                    if baseline_sensitive_suffix_match(key, suffix) {
                        matches += 1;
                    }
                }
            }
        }
        assert_eq!(matches, 3_000);
    });

    let optimized = measure_allocations("optimized_sensitive_suffix", || {
        let mut matches = 0;
        for _ in 0..1_000 {
            for key in keys {
                for suffix in suffixes {
                    if has_sensitive_suffix(key, suffix) {
                        matches += 1;
                    }
                }
            }
        }
        assert_eq!(matches, 3_000);
    });

    alloc_counter::emit_report(&baseline);
    alloc_counter::emit_report(&optimized);

    assert_eq!(optimized.allocation_count, 0);
    assert!(
        optimized.allocated_bytes < baseline.allocated_bytes,
        "optimized bytes={} baseline bytes={}",
        optimized.allocated_bytes,
        baseline.allocated_bytes
    );
}

#[test]
fn perf_loop_field_policy_handles_given_vec_clone_then_arc_clone_reduces_allocations() {
    let allowlist: Vec<String> = [
        "feature",
        "operation_name",
        "request_id",
        "trace_id",
        "source_ip",
        "tenant_id",
        "org_id",
        "user_id",
        "method",
        "path",
        "host",
        "status_code",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let blocklist: Vec<String> = [
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "access_token",
        "refresh_token",
        "client_secret",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    let baseline = measure_allocations("baseline_policy_vec_clone", || {
        let mut total = 0;
        for _ in 0..1_000 {
            let cloned_allowlist = allowlist.clone();
            let cloned_blocklist = blocklist.clone();
            total += cloned_allowlist.len() + cloned_blocklist.len();
        }
        assert_eq!(total, 19_000);
    });

    let optimized = measure_allocations("optimized_policy_arc_clone", || {
        let allowlist: Arc<[String]> = Arc::from(allowlist);
        let blocklist: Arc<[String]> = Arc::from(blocklist);
        let mut total = 0;
        for _ in 0..1_000 {
            let cloned_allowlist = allowlist.clone();
            let cloned_blocklist = blocklist.clone();
            total += cloned_allowlist.len() + cloned_blocklist.len();
        }
        assert_eq!(total, 19_000);
    });

    alloc_counter::emit_report(&baseline);
    alloc_counter::emit_report(&optimized);

    assert!(
        optimized.allocation_count < baseline.allocation_count,
        "optimized allocations={} baseline allocations={}",
        optimized.allocation_count,
        baseline.allocation_count
    );
}

#[test]
fn perf_loop_resource_attributes_given_clone_then_borrow_reduces_allocations() {
    let mut resource = serde_json::Map::new();
    resource.insert("service.name".to_string(), json!("telemetry-test"));
    resource.insert("service.namespace".to_string(), json!("test-namespace"));

    let baseline = measure_allocations("baseline_resource_clone", || {
        let mut total = 0;
        for _ in 0..1_000 {
            let cloned = Some(resource.clone());
            total += cloned.as_ref().map_or(0, serde_json::Map::len);
        }
        assert_eq!(total, 2_000);
    });

    let optimized = measure_allocations("optimized_resource_borrow", || {
        let mut total = 0;
        for _ in 0..1_000 {
            let borrowed: Option<&serde_json::Map<String, Value>> = Some(&resource);
            total += borrowed.map_or(0, serde_json::Map::len);
        }
        assert_eq!(total, 2_000);
    });

    alloc_counter::emit_report(&baseline);
    alloc_counter::emit_report(&optimized);

    assert_eq!(optimized.allocation_count, 0);
    assert!(
        optimized.allocated_bytes < baseline.allocated_bytes,
        "optimized bytes={} baseline bytes={}",
        optimized.allocated_bytes,
        baseline.allocated_bytes
    );
}

#[test]
fn perf_loop_small_field_store_given_btree_then_vec_reduces_allocations() {
    let baseline = measure_allocations("baseline_btree_field_store", || {
        let mut fields = BTreeMap::new();
        for _ in 0..1_000 {
            for index in 0..12 {
                baseline_btree_insert(&mut fields, format!("field_{index}"), json!(index));
            }
            fields.clear();
        }
        assert!(fields.is_empty());
    });

    let optimized = measure_allocations("optimized_vec_field_store", || {
        let mut fields = Vec::with_capacity(12);
        for _ in 0..1_000 {
            for index in 0..12 {
                optimized_vec_insert(&mut fields, format!("field_{index}"), json!(index));
            }
            fields.clear();
        }
        assert!(fields.is_empty());
    });

    alloc_counter::emit_report(&baseline);
    alloc_counter::emit_report(&optimized);

    assert!(
        optimized.allocation_count < baseline.allocation_count,
        "optimized allocations={} baseline allocations={}",
        optimized.allocation_count,
        baseline.allocation_count
    );
}

#[test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_small_field_store_reports_cpu() {
    let baseline = best_of_three(|| {
        let mut fields = BTreeMap::new();
        for _ in 0..10_000 {
            for index in 0..12 {
                baseline_btree_insert(&mut fields, format!("field_{index}"), json!(index));
            }
            fields.clear();
        }
        assert!(fields.is_empty());
    });

    let optimized = best_of_three(|| {
        let mut fields = Vec::with_capacity(12);
        for _ in 0..10_000 {
            for index in 0..12 {
                optimized_vec_insert(&mut fields, format!("field_{index}"), json!(index));
            }
            fields.clear();
        }
        assert!(fields.is_empty());
    });

    println!(
        "small_field_store_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline.as_nanos(),
        optimized.as_nanos(),
        percent_improvement(baseline, optimized)
    );
}

#[tokio::test]
#[ignore = "end-to-end performance report; run with --ignored --nocapture --test-threads=1"]
async fn perf_loop_e2e_request_stack_reports_allocations_and_cpu() {
    let allocation_report = measure_allocations_async("e2e_request_stack", async {
        run_e2e_request_stack(25).await;
    })
    .await;
    alloc_counter::emit_report(&allocation_report);

    let duration = best_of_three_async(|| async {
        run_e2e_request_stack(100).await;
    })
    .await;
    println!("e2e_request_stack_100_requests_ns={}", duration.as_nanos());
}

#[test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_trace_context_reports_baseline_and_optimized_cpu() {
    let headers = forwarded_headers();
    let context = TraceContext::from_headers(&headers);
    let trace_id = context.trace_id.to_hex_string();
    let span_id = context.span_id.to_hex_string();

    let baseline = best_of_three(|| {
        let mut bytes = 0;
        for _ in 0..100_000 {
            bytes +=
                baseline_traceparent_format(&trace_id, &span_id, context.trace_flags.as_u8()).len();
        }
        assert_eq!(bytes, 5_500_000);
    });

    let optimized = best_of_three(|| {
        let mut bytes = 0;
        for _ in 0..100_000 {
            bytes += context.traceparent().len();
        }
        assert_eq!(bytes, 5_500_000);
    });

    println!(
        "traceparent_cpu baseline_ns={} optimized_ns={} improvement={:.2}%",
        baseline.as_nanos(),
        optimized.as_nanos(),
        percent_improvement(baseline, optimized)
    );
}

#[test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_trace_context_parse_reports_cpu() {
    let headers = forwarded_headers();

    let optimized = best_of_three(|| {
        let mut observed = 0_u64;
        for _ in 0..100_000 {
            let context = TraceContext::from_headers(&headers);
            observed += u64::from(context.trace_flags.as_u8());
            observed += u64::from(context.parent_span_id.is_some());
        }
        assert_eq!(observed, 200_000);
    });

    println!("trace_context_parse_optimized_ns={}", optimized.as_nanos());
}

#[test]
fn trace_context_parse_only_records_allocation_baseline() {
    let headers = forwarded_headers();

    let allocation_report = measure_allocations("trace_context_parse_only", || {
        let mut observed = 0_u64;
        for _ in 0..1_000 {
            let context = TraceContext::from_headers(&headers);
            observed += u64::from(context.trace_flags.as_u8());
            observed += u64::from(context.parent_span_id.is_some());
        }
        assert_eq!(observed, 2_000);
    });

    alloc_counter::emit_report(&allocation_report);

    assert!(
        allocation_report.allocation_count <= 2_000,
        "parse-only allocation count regressed: {}",
        allocation_report.allocation_count
    );
}

#[test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_trace_context_parse_only_reports_allocations_and_cpu() {
    let headers = forwarded_headers();

    let allocation_report = measure_allocations("trace_context_parse_only", || {
        let mut observed = 0_u64;
        for _ in 0..1_000 {
            let context = TraceContext::from_headers(&headers);
            observed += u64::from(context.trace_flags.as_u8());
            observed += u64::from(context.parent_span_id.is_some());
        }
        assert_eq!(observed, 2_000);
    });
    alloc_counter::emit_report(&allocation_report);

    let duration = best_of_three(|| {
        let mut observed = 0_u64;
        for _ in 0..100_000 {
            let context = TraceContext::from_headers(&headers);
            observed += u64::from(context.trace_flags.as_u8());
            observed += u64::from(context.parent_span_id.is_some());
        }
        assert_eq!(observed, 200_000);
    });

    println!("trace_context_parse_only_100k_ns={}", duration.as_nanos());
}

#[test]
#[ignore = "performance report; run with --ignored --nocapture --test-threads=1"]
fn perf_loop_trace_context_parse_and_forward_reports_allocations_and_cpu() {
    let headers = forwarded_headers();
    let allocation_report = measure_allocations("trace_context_parse_and_forward", || {
        let mut outgoing = HeaderMap::new();
        for _ in 0..1_000 {
            outgoing.clear();
            TraceContext::from_headers(&headers).write_forward_headers(&mut outgoing);
            assert!(outgoing.get(HEADER_TRACEPARENT).is_some());
        }
    });
    alloc_counter::emit_report(&allocation_report);

    let duration = best_of_three(|| {
        let mut outgoing = HeaderMap::new();
        for _ in 0..100_000 {
            outgoing.clear();
            TraceContext::from_headers(&headers).write_forward_headers(&mut outgoing);
            assert!(outgoing.get(HEADER_TRACEPARENT).is_some());
        }
    });

    println!(
        "trace_context_parse_and_forward_100k_ns={}",
        duration.as_nanos()
    );
}

#[test]
fn trace_context_forward_headers_stack_encoding_reduces_allocations() {
    let headers = forwarded_headers();
    let context = TraceContext::from_headers(&headers);

    let baseline = measure_allocations("baseline_trace_context_string_forward_headers", || {
        let mut outgoing = HeaderMap::new();
        for _ in 0..1_000 {
            outgoing.clear();
            baseline_forward_headers(&context, &mut outgoing);
            assert!(outgoing.get(HEADER_TRACEPARENT).is_some());
        }
    });

    let optimized = measure_allocations("optimized_trace_context_stack_forward_headers", || {
        let mut outgoing = HeaderMap::new();
        for _ in 0..1_000 {
            outgoing.clear();
            context.write_forward_headers(&mut outgoing);
            assert!(outgoing.get(HEADER_TRACEPARENT).is_some());
        }
    });

    alloc_counter::emit_report(&baseline);
    alloc_counter::emit_report(&optimized);

    assert!(
        optimized.allocation_count < baseline.allocation_count,
        "optimized allocations={} baseline allocations={}",
        optimized.allocation_count,
        baseline.allocation_count
    );
    assert!(
        optimized.allocated_bytes < baseline.allocated_bytes,
        "optimized bytes={} baseline bytes={}",
        optimized.allocated_bytes,
        baseline.allocated_bytes
    );
}

fn measure_allocations(
    label: &'static str,
    run: impl FnOnce(),
) -> alloc_counter::AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run();
    guard.finish()
}

fn baseline_forward_headers(context: &TraceContext, headers: &mut HeaderMap) {
    if let Ok(value) = HeaderValue::from_str(&context.traceparent()) {
        headers.insert(HEADER_TRACEPARENT, value);
    }
    if let Some(value) = context.trace_state_str()
        && let Ok(value) = HeaderValue::from_str(value)
    {
        headers.insert(HEADER_TRACESTATE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&context.trace_id.to_hex_string()) {
        headers.insert(HEADER_TRACE_ID, value);
    }
    if let Some(value) = context.request_id_str()
        && let Ok(value) = HeaderValue::from_str(value)
    {
        headers.insert(HEADER_REQUEST_ID, value);
    }
}

async fn measure_allocations_async(
    label: &'static str,
    run: impl Future<Output = ()>,
) -> alloc_counter::AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "performance_tests",
        file!(),
        line!(),
        Some(label),
    );
    run.await;
    guard.finish()
}

fn baseline_sensitive_suffix_match(key: &str, suffix: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let suffix = suffix.to_ascii_lowercase();
    lower == suffix
        || lower.ends_with(&format!(".{suffix}"))
        || lower.ends_with(&format!("_{suffix}"))
        || lower.ends_with(&format!("-{suffix}"))
}

fn baseline_traceparent_format(trace_id: &str, span_id: &str, trace_flags: u8) -> String {
    format!("00-{trace_id}-{span_id}-{trace_flags:02x}")
}

fn baseline_btree_insert(fields: &mut BTreeMap<String, Value>, key: String, value: Value) {
    fields.insert(key, value);
}

fn optimized_vec_insert(fields: &mut Vec<(String, Value)>, key: String, value: Value) {
    if let Some((_, existing)) = fields
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing = value;
        return;
    }
    fields.push((key, value));
}

fn best_of_three(mut run: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        run();
        best = best.min(started.elapsed());
    }
    best
}

async fn best_of_three_async<Fut>(mut run: impl FnMut() -> Fut) -> Duration
where Fut: Future<Output = ()> {
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        run().await;
        best = best.min(started.elapsed());
    }
    best
}

fn percent_improvement(baseline: Duration, optimized: Duration) -> f64 {
    let baseline = baseline.as_nanos() as f64;
    let optimized = optimized.as_nanos() as f64;
    ((baseline - optimized) / baseline) * 100.0
}

fn forwarded_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_TRACEPARENT, HeaderValue::from_static(TRACEPARENT));
    headers.insert(HEADER_TRACESTATE, HeaderValue::from_static("vendor=value"));
    headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static("request-1"));
    headers
}

async fn run_e2e_request_stack(iterations: usize) {
    let sink = Arc::new(|_line: String| {});
    let layer = WideLogLayer::new_with_sink(
        &TracingConfig::new(
            "stdout",
            FieldSecurityPolicy::default_allowlist_and_blocklist(),
            RootSpanPolicy::for_http_services(),
        ),
        sink,
    )
    .expect("wide log layer");
    let subscriber = tracing_subscriber::registry().with(layer);
    let _default = tracing::subscriber::set_default(subscriber);
    let router = e2e_router();

    for _ in 0..iterations {
        let response = router
            .clone()
            .oneshot(e2e_request())
            .await
            .expect("request succeeds");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(HEADER_TRACEPARENT).is_some());
    }
}

fn e2e_router() -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .layer(from_fn_with_state(
            SlowOperationLogState {
                thresholds: SlowOperationThresholds::new(u64::MAX, BTreeMap::new()),
                collect_cost: false,
            },
            slow_operation_log,
        ))
        .layer(request_trace_layer())
}

fn e2e_request() -> Request<Body> {
    Request::builder()
        .uri("/health")
        .header(HEADER_TRACEPARENT, TRACEPARENT)
        .header(HEADER_TRACESTATE, "vendor=value")
        .header(HEADER_REQUEST_ID, "request-1")
        .body(Body::empty())
        .expect("request")
}
