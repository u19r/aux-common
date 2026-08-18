use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::{Router, body::Body, http::Request, routing::get};
use tower::ServiceExt as _;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::{
    FieldEmissionMode, FieldSecurityPolicy, ForwardedHeaderConfig, RootSpanPolicy,
    SlowOperationThresholds, TracingConfig, WideLogLayer, request_trace_layer,
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
