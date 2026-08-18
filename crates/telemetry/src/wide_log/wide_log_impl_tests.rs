use std::sync::{Arc, Mutex};

use serde_json::json;
use tracing_subscriber::layer::SubscriberExt as _;

use super::SpanFields;
use crate::{FieldEmissionMode, FieldSecurityPolicy, RootSpanPolicy, TracingConfig, WideLogLayer};

#[test]
fn span_fields_given_sensitive_blocklist_then_redacts_matching_suffixes() {
    let mut fields = SpanFields::new(
        FieldEmissionMode::RedactSensitive,
        Vec::new(),
        vec!["authorization".to_string(), "secret".to_string()],
    );

    fields.insert_str("headers.authorization", "Bearer token");
    fields.insert_value("client_secret", json!("value"));

    assert_eq!(
        fields.value_as_string("headers.authorization").as_deref(),
        Some("[REDACTED]")
    );
    assert_eq!(
        fields.value_as_string("client_secret").as_deref(),
        Some("[REDACTED]")
    );
}

#[test]
fn given_camel_case_sensitive_field_names_when_storing_span_fields_then_redacts_credentials() {
    let default_policy = FieldSecurityPolicy::default_allowlist_and_blocklist();
    let mut fields = SpanFields::new(
        FieldEmissionMode::RedactSensitive,
        Vec::new(),
        default_policy.sensitive_blocklist().to_vec(),
    );

    fields.insert_str("accessToken", "access-token-value");
    fields.insert_str("requestAccessToken", "request-access-token-value");
    fields.insert_str("clientSecret", "client-secret-value");
    fields.insert_str("oauthClientSecret", "oauth-client-secret-value");
    fields.insert_str("apiKey", "api-key-value");
    fields.insert_str("oauthApiKey", "oauth-api-key-value");
    fields.insert_str("privateKey", "private-key-value");
    fields.insert_str("bearerToken", "bearer-token-value");

    assert_eq!(
        fields.value_as_string("accessToken").as_deref(),
        Some("[REDACTED]")
    );
    assert_eq!(
        fields.value_as_string("requestAccessToken").as_deref(),
        Some("[REDACTED]")
    );
    assert_eq!(
        fields.value_as_string("clientSecret").as_deref(),
        Some("[REDACTED]")
    );
    assert_eq!(
        fields.value_as_string("oauthClientSecret").as_deref(),
        Some("[REDACTED]")
    );
    assert_eq!(
        fields.value_as_string("apiKey").as_deref(),
        Some("[REDACTED]")
    );
    assert_eq!(
        fields.value_as_string("oauthApiKey").as_deref(),
        Some("[REDACTED]")
    );
    assert_eq!(
        fields.value_as_string("privateKey").as_deref(),
        Some("[REDACTED]")
    );
    assert_eq!(
        fields.value_as_string("bearerToken").as_deref(),
        Some("[REDACTED]")
    );
}

#[test]
fn given_extra_allowlisted_credential_when_storing_span_fields_then_redacts_value() {
    let policy = FieldSecurityPolicy::default_allowlist_and_blocklist()
        .with_extra_top_level_fields(["accessToken".to_string()]);
    let mut fields = SpanFields::new(
        policy.mode(),
        policy.top_level_allowlist().to_vec(),
        policy.sensitive_blocklist().to_vec(),
    );

    fields.insert_str("accessToken", "extra-allowlisted-token");

    assert_eq!(
        fields.value_as_string("accessToken").as_deref(),
        Some("[REDACTED]")
    );
}

#[test]
fn span_fields_given_empty_blocklist_then_keeps_values() {
    let mut fields = SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new());

    fields.insert_str("authorization", "Bearer token");

    assert_eq!(
        fields.value_as_string("authorization").as_deref(),
        Some("Bearer token")
    );
}

#[test]
fn span_fields_given_strict_allowlist_then_omits_unlisted_fields() {
    let mut fields = SpanFields::new(
        FieldEmissionMode::StrictAllowlist,
        vec!["safe".to_string()],
        vec!["secret".to_string()],
    );

    fields.insert_str("safe", "kept");
    fields.insert_str("unsafe", "dropped");

    assert_eq!(fields.value_as_string("safe").as_deref(), Some("kept"));
    assert!(fields.value_as_string("unsafe").is_none());
}

#[test]
fn span_fields_given_typed_only_then_keeps_structured_values_and_omits_free_text() {
    let mut fields = SpanFields::new(
        FieldEmissionMode::TypedOnly,
        vec![
            "operation".to_string(),
            "status_code".to_string(),
            "success".to_string(),
        ],
        Vec::new(),
    );

    fields.insert_str("operation", "free text operation");
    fields.insert_value("status_code", json!(200));
    fields.insert_value("success", json!(true));

    assert!(fields.value_as_string("operation").is_none());
    assert_eq!(
        fields.value_as_string("status_code").as_deref(),
        Some("200")
    );
    assert_eq!(fields.value_as_string("success").as_deref(), Some("true"));
}

#[test]
fn default_security_given_benign_free_text_name_then_omits_secret_value() {
    let policy = FieldSecurityPolicy::default_allowlist_and_blocklist();
    let mut fields = SpanFields::new(
        policy.mode(),
        policy.top_level_allowlist().to_vec(),
        policy.sensitive_blocklist().to_vec(),
    );

    fields.insert_str("message", "sentinel-secret-value");
    fields.insert_str("error_detail", "another-sentinel-secret");

    assert!(fields.value_as_string("message").is_none());
    assert!(fields.value_as_string("error_detail").is_none());
}

#[test]
fn typed_only_given_safe_telemetry_value_then_emits_it_end_to_end() {
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
            FieldSecurityPolicy::typed_only(vec!["operation".to_string()], Vec::new()),
            RootSpanPolicy::for_http_services(),
        ),
        sink,
    )
    .expect("wide log layer");
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("http.request", operation = tracing::field::Empty);
        crate::SafeTelemetryValue::from_static("users.lookup").record_on(&span, "operation");
        let _entered = span.enter();
    });

    let lines = captured.lock().expect("capture lock");
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).expect("log json");
    assert_eq!(entry["attributes"]["operation"], "users.lookup");
}

#[test]
fn wide_log_given_http_root_span_then_emits_otel_shaped_log_entry() {
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
            FieldSecurityPolicy::default_allowlist_and_blocklist(),
            RootSpanPolicy::for_http_services(),
        )
        .with_service_name(Some("telemetry-test".to_string()))
        .with_namespace(Some("test-namespace".to_string())),
        sink,
    )
    .expect("wide log layer");
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!(
            "http.request",
            feature = "http",
            trace_id = "4bf92f3577b34da6a3ce929d0e0e4736",
            span_id = "00f067aa0ba902b7",
            trace_flags = "01",
            request_id = "request-1",
            method = "GET",
            path = "/health",
            status_code = 200_u64
        );
        let _entered = span.enter();
        tracing::info!(target = "test", message = "handled request");
    });

    let lines = captured.lock().expect("capture lock");
    assert_eq!(lines.len(), 1);
    let entry: serde_json::Value = serde_json::from_str(&lines[0]).expect("log json");

    assert!(entry.get("time_unix_nano").is_some());
    assert!(entry.get("observed_time_unix_nano").is_some());
    assert_eq!(entry["severity_text"], "INFO");
    assert_eq!(entry["severity_number"], 9);
    assert_eq!(entry["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(entry["span_id"], "00f067aa0ba902b7");
    assert_eq!(entry["trace_flags"], "01");
    assert_eq!(entry["resource"]["service.name"], "telemetry-test");
    assert_eq!(entry["resource"]["service.namespace"], "test-namespace");
    assert_eq!(entry["attributes"]["request_id"], "request-1");
    assert_eq!(entry["attributes"]["method"], "GET");
    assert_eq!(entry["body"]["message"], "http.request");
    assert!(entry.get("body").is_some());
}
