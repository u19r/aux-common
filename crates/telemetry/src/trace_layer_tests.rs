use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    middleware,
    routing::get,
};
use tower::ServiceExt as _;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::{
    FieldEmissionMode, FieldSecurityPolicy, ForwardedHeaderConfig, RootSpanPolicy,
    SlowOperationLogState, SlowOperationThresholds, TracingConfig, WideLogLayer,
    request_trace_layer,
};

#[test]
fn tracing_config_given_default_security_opt_in_then_contains_redaction_blocklist() {
    let config = TracingConfig::with_default_security();

    assert!(
        config
            .field_security
            .sensitive_blocklist()
            .iter()
            .any(|field| field == "authorization")
    );
    assert!(
        config
            .field_security
            .top_level_allowlist()
            .iter()
            .any(|field| field == crate::FIELD_TRACE_ID)
    );
    assert_eq!(
        config.field_security.mode(),
        FieldEmissionMode::StrictAllowlist
    );
}

#[test]
fn tracing_config_given_custom_policy_then_does_not_inject_defaults() {
    let policy =
        FieldSecurityPolicy::new(vec!["safe_field".to_string()], vec!["secret".to_string()]);
    let config = TracingConfig::new("stdout", policy, RootSpanPolicy::for_http_services());

    assert_eq!(
        config.field_security.top_level_allowlist(),
        &["safe_field".to_string()]
    );
    assert_eq!(
        config.field_security.sensitive_blocklist(),
        &["secret".to_string()]
    );
    assert_eq!(
        config.field_security.mode(),
        FieldEmissionMode::RedactSensitive
    );
}

#[test]
fn field_security_policy_when_strict_allowlist_then_records_mode() {
    let policy = FieldSecurityPolicy::strict_allowlist(
        vec!["safe_field".to_string()],
        vec!["secret".to_string()],
    );

    assert_eq!(policy.mode(), FieldEmissionMode::StrictAllowlist);
}

#[test]
fn slow_thresholds_given_operation_override_then_uses_override() {
    let thresholds =
        SlowOperationThresholds::new(500, BTreeMap::from([("GET /health".to_string(), 20)]));

    assert_eq!(thresholds.threshold_ms_for("GET /health"), 20);
    assert_eq!(thresholds.threshold_ms_for("GET /other"), 500);
}

#[test]
fn request_without_matched_path_uses_bounded_operation_name() {
    let request = Request::builder()
        .method("GET")
        .uri("/attacker-controlled/unique/123")
        .body(Body::empty())
        .expect("request");
    let method = request.method();
    let operation_path = crate::trace_layer::bounded_operation_path(&request);

    assert_eq!(format!("{method} {operation_path}"), "GET _unmatched");
    assert_ne!(operation_path, request.uri().path());
}

#[tokio::test]
async fn given_untrusted_forwarded_headers_when_request_traced_then_does_not_emit_them() {
    let entry = capture_request_log(false).await;

    assert!(entry["attributes"].get("forwarded_for").is_none());
    assert!(entry["attributes"].get("forwarded_host").is_none());
    assert!(entry["attributes"].get("forwarded_proto").is_none());
    assert_eq!(entry["attributes"]["source_ip"], "");
}

#[tokio::test]
async fn given_trusted_forwarded_headers_when_request_traced_then_emits_them() {
    let entry = capture_request_log(true).await;

    assert_eq!(entry["attributes"]["forwarded_for"], "203.0.113.7");
    assert_eq!(entry["attributes"]["forwarded_host"], "api.example.test");
    assert_eq!(entry["attributes"]["forwarded_proto"], "https");
    assert_eq!(entry["attributes"]["source_ip"], "203.0.113.7");
}

#[tokio::test]
async fn given_unmatched_path_with_secret_when_request_traced_then_does_not_emit_raw_path() {
    let entry = capture_request_log_for_uri(false, "/reset/session-secret").await;

    assert_eq!(entry["attributes"]["path"], "_unmatched");
    assert!(!entry.to_string().contains("session-secret"));
}

async fn capture_request_log(trust_forwarded_headers: bool) -> serde_json::Value {
    capture_request_log_for_uri(trust_forwarded_headers, "/health").await
}

async fn capture_request_log_for_uri(
    trust_forwarded_headers: bool,
    uri: &str,
) -> serde_json::Value {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let captured = captured.clone();
        Arc::new(move |line: String| {
            captured.lock().expect("capture lock").push(line);
        })
    };
    let layer = WideLogLayer::new_with_sink(
        &TracingConfig::new(
            "stdout",
            FieldSecurityPolicy::new(Vec::new(), Vec::new()),
            RootSpanPolicy::for_http_services(),
        ),
        sink,
    )
    .expect("wide log layer");
    let subscriber = tracing_subscriber::registry().with(layer);
    let _default = tracing::subscriber::set_default(subscriber);
    let router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .layer(request_trace_layer());

    let response = router
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("x-forwarded-for", "203.0.113.7")
                .header("x-forwarded-host", "api.example.test")
                .header("x-forwarded-proto", "https")
                .extension(ForwardedHeaderConfig {
                    trust_forwarded_headers,
                })
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("request succeeds");

    if uri == "/health" {
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
    drop(response);

    let lines = captured.lock().expect("capture lock");
    serde_json::from_str(&lines[0]).expect("log json")
}

#[tokio::test]
async fn given_slow_operation_with_cost_collection_when_request_finishes_then_cost_headers_are_bounded()
 {
    // Given a matched route, an explicit request identifier, and a threshold
    // that forces logging.
    let with_cost = run_slow_operation(true, StatusCode::OK).await;

    // When the slow-operation middleware finalizes response metrics.
    assert_eq!(with_cost.status(), StatusCode::OK);

    // Then operation names use the route template and cost headers contain no
    // raw path.
    assert_eq!(
        with_cost
            .headers()
            .get("x-aux-cost-operation")
            .and_then(|value| value.to_str().ok()),
        Some("GET /users/{id}")
    );
    assert!(with_cost.headers().contains_key("x-aux-cost-wall-ms"));
    assert!(!with_cost.headers().values().any(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.contains("/users/42"))
    }));

    // Given the same route without opt-in cost collection.
    let without_cost = run_slow_operation(false, StatusCode::OK).await;

    // Then telemetry remains available while response-cost headers stay opt-in.
    assert_eq!(without_cost.status(), StatusCode::OK);
    assert!(!without_cost.headers().contains_key("x-aux-cost-wall-ms"));
}

#[tokio::test]
async fn given_server_error_when_request_trace_layer_classifies_response_then_failure_is_recorded()
{
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let captured = captured.clone();
        Arc::new(move |line: String| {
            captured.lock().expect("capture lock").push(line);
        })
    };
    let layer = WideLogLayer::new_with_sink(
        &TracingConfig::new(
            "stdout",
            FieldSecurityPolicy::new(Vec::new(), Vec::new()),
            RootSpanPolicy::for_http_services(),
        ),
        sink,
    )
    .expect("wide log layer");
    let subscriber = tracing_subscriber::registry().with(layer);
    let router = Router::new()
        .route(
            "/failure",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        )
        .layer(request_trace_layer());

    // Given a response classified as a server failure.
    let _default = tracing::subscriber::set_default(subscriber);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/failure")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("request succeeds");

    // When the trace layer's failure callback records the classifier.
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    drop(response);

    // Then the emitted HTTP entry includes a failure attribute.
    let lines = captured.lock().expect("capture lock");
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).expect("log json");
    assert!(entry["attributes"].get("failure").is_some());
}

async fn run_slow_operation(collect_cost: bool, status: StatusCode) -> axum::response::Response {
    let router = Router::new()
        .route(
            "/users/{id}",
            get(move || async move {
                tokio::time::sleep(Duration::from_millis(1)).await;
                (status, "response-body")
            }),
        )
        .layer(request_trace_layer())
        .layer(middleware::from_fn_with_state(
            SlowOperationLogState {
                thresholds: SlowOperationThresholds::new(0, BTreeMap::new()),
                cost_collection: if collect_cost {
                    crate::RequestCostCollection::Headers
                } else {
                    crate::RequestCostCollection::Disabled
                },
            },
            crate::slow_operation_log,
        ));

    router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/users/42")
                .header("x-request-id", "request-42")
                .header("content-length", "not-a-number")
                .body(Body::from("request-body"))
                .expect("request"),
        )
        .await
        .expect("request succeeds")
}

#[tokio::test]
async fn given_unpolled_streaming_body_when_response_is_returned_then_costs_are_already_finalized()
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let app = Router::new()
        .route(
            "/stream",
            get(move || std::future::ready(pending_response_body(observed.clone()))),
        )
        .layer(middleware::from_fn_with_state(
            SlowOperationLogState {
                thresholds: SlowOperationThresholds::new(0, BTreeMap::new()),
                cost_collection: crate::RequestCostCollection::Headers,
            },
            crate::slow_operation_log,
        ));
    let request = Request::builder()
        .uri("/stream")
        .header(
            "x-request-id",
            format!("body-boundary-{}", uuid::Uuid::new_v4()),
        )
        .body(Body::empty())
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(1), app.oneshot(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-aux-cost-wall-ms"));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    drop(response);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

fn pending_response_body(polls: Arc<std::sync::atomic::AtomicUsize>) -> Body {
    Body::from_stream(futures_util::stream::poll_fn(move |_| {
        polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::<Option<Result<axum::body::Bytes, std::convert::Infallible>>>::Pending
    }))
}

#[tokio::test]
async fn given_cost_collection_when_response_returns_then_settled_snapshot_is_available_without_parsing_headers()
 {
    let response = run_slow_operation(true, StatusCode::OK).await;
    let settled = response
        .extensions()
        .get::<metrics_facade::CostResponseHeaders>()
        .unwrap();
    assert_eq!(settled.snapshot().request_id.as_deref(), Some("request-42"));
    assert_eq!(
        settled.snapshot().operation.as_deref(),
        Some("GET /users/{id}")
    );
    let mut expected_headers = axum::http::HeaderMap::new();
    settled.write_to_headers(&mut expected_headers);
    for (name, value) in &expected_headers {
        assert_eq!(response.headers().get(name), Some(value));
    }
    assert!(
        run_slow_operation(false, StatusCode::OK)
            .await
            .extensions()
            .get::<metrics_facade::CostResponseHeaders>()
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn given_snapshot_collection_when_response_is_finalized_then_costs_are_available_without_headers()
 {
    let app = Router::new()
        .route("/measurement", get(|| async { "payload" }))
        .layer(middleware::from_fn_with_state(
            SlowOperationLogState {
                cost_collection: crate::RequestCostCollection::Snapshot,
                ..Default::default()
            },
            crate::slow_operation_log,
        ));
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(2),
        app.oneshot(
            Request::builder()
                .uri("/measurement")
                .header("x-request-id", "snapshot-response-ready")
                .body(Body::empty())
                .unwrap(),
        ),
    )
    .await
    .expect("snapshot collection must not wait for a quiet period")
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !response
            .headers()
            .keys()
            .any(|name| name.as_str().starts_with("x-aux-cost-"))
    );
    let snapshot = response
        .extensions()
        .get::<metrics_facade::CostResponseHeaders>()
        .unwrap()
        .snapshot();
    assert!(snapshot.wall_ms.is_finite());
    assert!(snapshot.wall_ms >= 0.0);
    assert_eq!(snapshot.response_bytes, Some(7));
}
