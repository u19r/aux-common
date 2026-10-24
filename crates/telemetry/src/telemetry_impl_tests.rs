use std::{
    collections::BTreeMap,
    future::Future,
    process::Command,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use axum::{
    Extension, Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    middleware::from_fn_with_state,
    routing::get,
};
use tower::ServiceExt as _;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::{
    FieldSecurityPolicy, HEADER_REQUEST_ID, HEADER_TRACEPARENT, HEADER_TRACESTATE, MetricsConfig,
    MetricsState, RootSpanPolicy, SlowOperationLogState, SlowOperationThresholds, TracingConfig,
    WideLogLayer, init_tracing, metrics_handler, request_trace_layer, resolve_filter,
    setup_metrics, slow_operation_log,
};

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[test]
fn given_invalid_filter_when_resolving_tracing_then_returns_safe_error() {
    let config = TracingConfig::with_default_security().with_log_level(Some("[".to_string()));

    let error = resolve_filter(&config).expect_err("invalid filter should fail");

    assert_eq!(error.to_string(), "invalid tracing log filter");
}

#[test]
fn given_default_stdout_when_initialising_tracing_then_startup_succeeds() {
    let child_marker = "AUX_TELEMETRY_STDOUT_INIT_CHILD";
    if std::env::var_os(child_marker).is_some() {
        let config = TracingConfig::with_default_security();
        let (filter, _) = resolve_filter(&config).expect("default filter");
        init_tracing(&config, filter).expect("stdout tracing initialization");
        tracing::warn!(target: "telemetry_startup_test", "stdout probe");
        return;
    }

    // The global tracing dispatcher cannot be reset, so exercise public startup
    // in a child copy of this test binary and leave the parent test process
    // unchanged.
    let output = Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "telemetry_impl_tests::given_default_stdout_when_initialising_tracing_then_startup_succeeds",
            "--nocapture",
        ])
        .env(child_marker, "1")
        .output()
        .expect("run isolated stdout initialization");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("telemetry_startup_test"));
}

#[test]
fn given_bearer_token_when_debugging_metrics_config_then_redacts_secret() {
    let secret = "metrics-token-that-must-not-leak";
    let debug = format!("{:?}", MetricsConfig::enabled(secret));

    assert!(!debug.contains(secret));
    assert!(debug.contains("[REDACTED]"));
}

fn metrics_state() -> Arc<MetricsState> {
    static STATE: OnceLock<Arc<MetricsState>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            setup_metrics(&MetricsConfig::enabled("secret"))
                .expect("metrics setup")
                .expect("metrics enabled")
                .state
        })
        .clone()
}

#[test]
fn setup_metrics_given_disabled_config_then_returns_none() {
    let metrics = setup_metrics(&MetricsConfig::disabled()).expect("metrics setup");

    assert!(metrics.is_none());
}

#[test]
fn setup_metrics_given_enabled_config_without_token_then_rejects_config() {
    let err = match setup_metrics(&MetricsConfig {
        enabled: true,
        bearer_token: None,
        metrics_path: "/internal/metrics".to_string(),
    }) {
        Ok(_) => panic!("missing token should fail"),
        Err(err) => err,
    };

    assert_eq!(
        err.to_string(),
        "Prometheus metrics enabled but bearer token missing"
    );
}

#[tokio::test]
async fn metrics_handler_given_missing_bearer_token_then_rejects_request() {
    let err = metrics_handler(Extension(metrics_state()), HeaderMap::new())
        .await
        .expect_err("missing auth should fail");

    assert_eq!(err, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metrics_handler_given_valid_bearer_token_then_returns_metrics() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer secret"),
    );

    let response = metrics_handler(Extension(metrics_state()), headers)
        .await
        .expect("metrics response");

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn given_buffered_metering_when_drained_then_authenticated_scrape_exposes_bounded_operational_metrics()
 {
    use metrics_facade::{
        AtomicSink, BufferedMetering, Deadline, RequestCostSnapshot, RequestMeasurement,
        RequestMeteringContext, SinkError, SinkLimits,
    };

    let state = metrics_state();
    let sink =
        AtomicSink::try_new(SinkLimits::default(), |_| async { Ok::<(), SinkError>(()) }).unwrap();
    let metering = BufferedMetering::builder("scrape-private-namespace", sink)
        .build()
        .unwrap();
    let context = RequestMeteringContext::try_new(
        "scrape-private-tenant",
        "scrape-private-execution",
        Duration::from_secs(1),
    )
    .unwrap();
    metering
        .record_request(
            RequestMeasurement::try_new(context, RequestCostSnapshot::default()).unwrap(),
        )
        .await
        .unwrap();
    assert!(
        metering
            .shutdown(Deadline::after(Duration::from_secs(2)))
            .await
            .unwrap()
            .is_clean()
    );
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer secret".parse().unwrap());
    let response = metrics_handler(Extension(state), headers).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("buffered_metering_writers{mode=\"stopped\"} 1"));
    assert!(
        text.lines()
            .any(|line| line.starts_with("buffered_metering_events_total{")
                && line.contains("event=\"drain\"")
                && line.contains("detail=\"clean\"")
                && line.ends_with(" 1")),
        "{text}"
    );
    assert!(text.contains("buffered_metering_items_total{event=\"flush_completed\"} 1"));
    assert!(text.contains("# TYPE buffered_metering_duration_seconds summary"));
    assert!(text.contains("buffered_metering_duration_seconds_count{phase=\"drain\"} 1"));
    assert!(!text.contains("scrape-private"));
}

#[tokio::test]
#[ignore = "end-to-end performance report; run with --ignored --nocapture --test-threads=1"]
async fn perf_loop_e2e_request_stack_reports_allocations_and_cpu() {
    let allocation_report = measure_allocations_async("e2e_request_stack", async {
        run_e2e_request_stack(25).await;
    })
    .await;
    alloc_counter::emit_report(&allocation_report).expect("allocation report");

    let duration = best_of_three_async(|| async {
        run_e2e_request_stack(100).await;
    })
    .await;
    println!("e2e_request_stack_100_requests_ns={}", duration.as_nanos());
}

async fn measure_allocations_async(
    label: &'static str,
    run: impl Future<Output = ()>,
) -> alloc_counter::AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "telemetry_impl_tests",
        file!(),
        line!(),
        Some(label),
    );
    run.await;
    guard.finish()
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
                cost_collection: crate::RequestCostCollection::Disabled,
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
