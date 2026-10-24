use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tracing::{Level, field::Visit};
use tracing_subscriber::layer::SubscriberExt as _;

use crate::{
    FieldEmissionMode, FieldSecurityPolicy, RootSpanPolicy, TraceRuleConfig, TracingConfig,
    WideLogLayer,
    wide_log::{
        SpanFields, has_sensitive_suffix,
        span_state::{SpanSnapshotChild, SpanState},
        trace_rule::TraceRule,
    },
};

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

#[test]
fn given_repeated_and_child_fields_when_merged_then_values_are_unique_and_allowlisted() {
    let mut parent = SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new());
    let mut child = SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new());

    // Given parent and child fields with repeated scalar and array values.
    parent.insert_value("status", json!(200));
    parent.insert_value("status", json!(200));
    parent.insert_value("status", json!(201));
    child.insert_value("status", json!([201, 202]));
    child.insert_value("child_only", json!(true));

    // When the child is merged through the parent's explicit field allowlist.
    parent.extend_allowlist(&child, &["status".to_string(), "child_only".to_string()]);

    // Then duplicate values are suppressed and unlisted values remain isolated.
    assert_eq!(parent.get("status"), Some(&json!([200, 201, 202])));
    assert_eq!(parent.get("child_only"), Some(&json!(true)));
    assert!(!parent.contains_key("missing"));
}

#[test]
fn given_typed_only_field_records_when_visited_then_only_structured_values_emit() {
    let mut fields = SpanFields::new(
        FieldEmissionMode::TypedOnly,
        vec![
            "boolean".to_string(),
            "signed".to_string(),
            "unsigned".to_string(),
            "float".to_string(),
            "nan".to_string(),
            "error".to_string(),
            "debug".to_string(),
        ],
        vec!["token".to_string()],
    );
    let span = tracing::info_span!(
        "field-recordings",
        boolean = tracing::field::Empty,
        signed = tracing::field::Empty,
        unsigned = tracing::field::Empty,
        float = tracing::field::Empty,
        nan = tracing::field::Empty,
        error = tracing::field::Empty,
        debug = tracing::field::Empty,
        token = tracing::field::Empty,
    );
    let field = |name| {
        span.metadata()
            .expect("span metadata")
            .fields()
            .field(name)
            .expect("field metadata")
    };

    // Given typed and free-text values delivered through tracing's visitor
    // interface.
    fields.record_bool(&field("boolean"), true);
    fields.record_i64(&field("signed"), -7);
    fields.record_u64(&field("unsigned"), 8);
    fields.record_f64(&field("float"), 1.25);
    fields.record_f64(&field("nan"), f64::NAN);
    fields.record_error(&field("error"), &std::io::Error::other("secret-error"));
    fields.record_debug(&field("debug"), &"secret-debug");
    fields.insert_value("token", json!(true));

    // When the security mode normalizes each recorded value.
    let values: Vec<(&String, &Value)> = fields.iter().collect();

    // Then structured primitives remain available while free text and errors
    // are dropped.
    assert_eq!(fields.value_as_string("boolean").as_deref(), Some("true"));
    assert_eq!(fields.value_as_string("signed").as_deref(), Some("-7"));
    assert_eq!(fields.value_as_string("unsigned").as_deref(), Some("8"));
    assert_eq!(fields.value_as_string("float").as_deref(), Some("1.25"));
    assert!(fields.value_as_string("nan").is_none());
    assert!(fields.value_as_string("error").is_none());
    assert!(fields.value_as_string("debug").is_none());
    assert!(fields.value_as_string("token").is_none());
    assert_eq!(values.len(), 4);
}

#[test]
fn given_sensitive_suffix_candidates_when_checked_then_only_field_boundaries_match() {
    // Given separator-delimited, camel-case, and near-miss field names.
    // When sensitive suffix matching is evaluated case-insensitively.
    // Then credentials are protected without broad substring redaction.
    assert!(super::has_sensitive_suffix(
        "headers.Authorization",
        "authorization"
    ));
    assert!(super::has_sensitive_suffix("clientSecret", "secret"));
    assert!(super::has_sensitive_suffix("x-api-key", "api-key"));
    assert!(!super::has_sensitive_suffix("secretary", "secret"));
    assert!(!super::has_sensitive_suffix("key", "secret"));
    assert!(!super::has_sensitive_suffix("mysecretvalue", "secret"));
}

#[test]
fn given_parent_and_child_span_states_when_snapshot_is_flattened_then_depth_and_events_are_preserved()
 {
    let mut parent = SpanState::new(
        "service",
        "root",
        Level::INFO,
        SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new()),
    );
    parent.record_event(
        "parent-event",
        "service",
        Level::INFO,
        SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new()),
    );
    let mut child = SpanState::new(
        "database",
        "child",
        Level::WARN,
        SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new()),
    );
    child.fields.insert_value("safe", json!("value"));
    child.fields.insert_value("secret", json!("hidden"));
    child.record_event(
        "child-event",
        "database",
        Level::WARN,
        SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new()),
    );

    // Given a parent with an attached child snapshot and an explicit field
    // allowlist.
    parent.merge_child(
        child.into_snapshot(),
        &["safe".to_string(), "secret".to_string()],
    );

    // When the parent snapshot is flattened into minimal and full
    // representations.
    let mut snapshot = parent.into_snapshot();
    let minimal = snapshot.flatten_minimal();
    let full = snapshot.flatten();

    // Then hierarchy metadata, child fields, and event levels remain
    // deterministic.
    assert_eq!(minimal.len(), 2);
    assert_eq!(full.len(), 2);
    assert_eq!(full[1].parent_target, Some("service"));
    assert_eq!(full[1].depth, 1);
    assert!(snapshot.children.is_empty());
    assert_eq!(full[0].events.len(), 2);
    assert_eq!(full[0].level, Level::WARN);
    assert_eq!(
        full[1].fields.value_as_string("safe").as_deref(),
        Some("value")
    );
}

#[test]
fn given_trace_rule_candidates_when_matching_snapshot_then_name_field_event_and_child_paths_are_supported()
 {
    let rule = TraceRule {
        feature: "orders".to_string(),
        level: Level::INFO,
    };
    let base_fields = SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new());

    // Given a snapshot whose level can pass or fail before matching its feature
    // paths.
    let high_level =
        SpanState::new("target", "orders.query", Level::DEBUG, base_fields.clone()).into_snapshot();
    assert!(!high_level.matches_trace_rule(&rule));

    // When the span name, feature field, event, or child supplies the
    // configured feature.
    let name_match =
        SpanState::new("target", "orders.query", Level::INFO, base_fields.clone()).into_snapshot();
    assert!(name_match.matches_trace_rule(&rule));

    let mut feature_fields = base_fields.clone();
    feature_fields.insert_str("feature", "orders.storage");
    let feature_match =
        SpanState::new("target", "other", Level::INFO, feature_fields).into_snapshot();
    assert!(feature_match.matches_trace_rule(&rule));

    let mut event_parent = SpanState::new("target", "other", Level::INFO, base_fields.clone());
    let mut event_fields =
        SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new());
    event_fields.insert_str("feature", "orders.event");
    event_parent.record_event("event", "target", Level::INFO, event_fields);
    let event_match = event_parent.into_snapshot();
    assert!(event_match.matches_trace_rule(&rule));

    let child = SpanState::new("target", "orders.child", Level::INFO, base_fields).into_snapshot();
    let mut child_parent = SpanState::new(
        "target",
        "other",
        Level::INFO,
        SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new()),
    );
    child_parent.merge_child(child, &[]);
    let child_match = child_parent.into_snapshot();
    assert!(child_match.matches_trace_rule(&rule));

    // Then unrelated names remain excluded.
    let unrelated = SpanState::new(
        "target",
        "users.query",
        Level::INFO,
        SpanFields::new(FieldEmissionMode::RedactSensitive, Vec::new(), Vec::new()),
    )
    .into_snapshot();
    assert!(!unrelated.matches_trace_rule(&rule));
    assert!(SpanSnapshotChild::Full(Vec::new()).is_empty());
    assert!(SpanSnapshotChild::Minimal(Vec::new()).is_empty());
    assert!(!SpanSnapshotChild::Full(vec![name_match]).is_empty());
}

#[test]
fn given_spanless_and_minimal_events_when_layer_emits_then_root_policy_and_trace_rules_bound_details()
 {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let captured = captured.clone();
        Arc::new(move |line: String| {
            captured.lock().expect("capture lock").push(line);
        })
    };
    let config = TracingConfig::new(
        "stdout",
        FieldSecurityPolicy::default_allowlist_and_blocklist(),
        RootSpanPolicy::new(vec!["debug-root".to_string()], Vec::new()),
    )
    .with_trace_rules(vec![TraceRuleConfig {
        feature: "debug-feature".to_string(),
        log_level: "debug".to_string(),
    }]);
    let layer = WideLogLayer::new_with_sink(&config, sink).expect("wide log layer");
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        // Given a warning spanless event, an unrelated debug event, and a
        // rule-matched event.
        tracing::warn!(target = "test", message = "warning-event");
        tracing::debug!(target = "test", message = "dropped-debug-event");
        tracing::debug!(
            target = "test",
            feature = "debug-feature",
            message = "kept-debug-event"
        );

        // When a named debug root closes with a child span.
        let root = tracing::debug_span!("debug-root", feature = "other-feature");
        let _root_guard = root.enter();
        let child = tracing::debug_span!("debug-child", feature = "other-feature");
        let _child_guard = child.enter();
        tracing::debug!(target = "test", message = "nested-debug-event");
    });

    // Then warn/rule events are emitted and minimal root details stay bounded.
    let lines = captured.lock().expect("capture lock");
    assert_eq!(lines.len(), 3);
    let entries = lines
        .iter()
        .map(|line| serde_json::from_str::<Value>(line).expect("log json"))
        .collect::<Vec<_>>();
    assert_eq!(entries[0]["severity_text"], "WARN");
    assert_eq!(entries[1]["severity_text"], "DEBUG");
    assert_eq!(entries[2]["body"]["message"], "debug-root");
    assert!(entries[2]["body"]["spans"].is_array());
}

#[test]
fn given_stdout_destination_when_new_layer_is_constructed_then_sink_initialises() {
    // Given the default secure configuration, which uses the stdout
    // destination.
    let config = TracingConfig::with_default_security();

    // When the public constructor builds its configured sink and layer state.
    let layer = WideLogLayer::new(&config);

    // Then the configured stdout sink is available to normal service startup.
    assert!(layer.is_ok());
}

#[test]
fn given_warn_http_root_with_child_when_root_closes_then_full_child_details_are_emitted() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let captured = captured.clone();
        Arc::new(move |line: String| {
            captured.lock().expect("capture lock").push(line);
        })
    };
    let config = TracingConfig::new(
        "stdout",
        FieldSecurityPolicy::default_allowlist_and_blocklist(),
        RootSpanPolicy::for_http_services(),
    );
    let layer = WideLogLayer::new_with_sink(&config, sink).expect("wide log layer");
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        // Given an allowed warning root and an informational database child.
        let root = tracing::span!(
            target: "http",
            Level::WARN,
            "http.request",
            feature = "http",
            request_id = "request-1"
        );
        let root_guard = root.enter();
        let child = tracing::span!(
            target: "database",
            Level::INFO,
            "database.query",
            operation_name = "orders.load",
            status_code = 200_u64
        );
        let child_guard = child.enter();
        tracing::info!(target: "database", message = "query complete");

        // When child and root guards close in nesting order.
        drop(child_guard);
        drop(root_guard);
        drop(child);
        drop(root);
    });

    // Then the emitted body contains the flattened child with full fields and
    // hierarchy.
    let lines = captured.lock().expect("capture lock");
    assert_eq!(lines.len(), 1);
    let entry: Value = serde_json::from_str(&lines[0]).expect("log json");
    let spans = entry["body"]["spans"].as_array().expect("full spans");
    assert_eq!(spans.len(), 1);
    assert_eq!(spans[0]["name"], "database.query");
    assert_eq!(spans[0]["parent_target"], "http");
    assert_eq!(spans[0]["depth"], 1);
    assert_eq!(spans[0]["operation_name"], "orders.load");
    assert_eq!(spans[0]["status_code"], 200);
    assert_eq!(spans[0]["events"][0]["target"], "database");
}

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

    alloc_counter::emit_report(&baseline).expect("allocation report");
    alloc_counter::emit_report(&optimized).expect("allocation report");

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

    alloc_counter::emit_report(&baseline).expect("allocation report");
    alloc_counter::emit_report(&optimized).expect("allocation report");

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

    alloc_counter::emit_report(&baseline).expect("allocation report");
    alloc_counter::emit_report(&optimized).expect("allocation report");

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

    alloc_counter::emit_report(&baseline).expect("allocation report");
    alloc_counter::emit_report(&optimized).expect("allocation report");

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

fn baseline_sensitive_suffix_match(key: &str, suffix: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let suffix = suffix.to_ascii_lowercase();
    lower == suffix
        || lower.ends_with(&format!(".{suffix}"))
        || lower.ends_with(&format!("_{suffix}"))
        || lower.ends_with(&format!("-{suffix}"))
}

fn measure_allocations(
    label: &'static str,
    run: impl FnOnce(),
) -> alloc_counter::AllocationReport<'static> {
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "wide_log_impl_tests",
        file!(),
        line!(),
        Some(label),
    );
    run();
    guard.finish()
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

fn percent_improvement(baseline: Duration, optimized: Duration) -> f64 {
    let baseline = baseline.as_nanos() as f64;
    let optimized = optimized.as_nanos() as f64;
    ((baseline - optimized) / baseline) * 100.0
}
