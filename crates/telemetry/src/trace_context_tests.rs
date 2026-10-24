use std::time::{Duration, Instant};

use http::{HeaderMap, HeaderValue};

use crate::{
    HEADER_REQUEST_ID, HEADER_TRACE_ID, HEADER_TRACEPARENT, HEADER_TRACESTATE, SpanId,
    TraceContext, TraceFlags, TraceId,
};

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[test]
fn trace_id_given_trimmed_mixed_case_value_when_parsed_then_normalizes_nonzero_id() {
    // Given a protocol value with ASCII padding and uppercase hex digits.
    let value = " \t4BF92F3577B34DA6A3CE929D0E0E4736\n ";

    // When the public trace-id parser consumes it.
    let parsed = TraceId::parse(value);

    // Then it returns the canonical lowercase representation.
    assert_eq!(
        parsed.map(|trace_id| trace_id.to_hex_string()),
        Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
    );
}

#[test]
fn trace_id_given_zero_or_malformed_value_when_parsed_then_rejects_identity() {
    // Given values that are too short, contain non-hex data, or are all zero.
    let values = [
        "",
        "4bf92f3577b34da6a3ce929d0e0e473",
        "4bf92f3577b34da6a3ce929d0e0e473z",
        "00000000000000000000000000000000",
    ];

    // When each value is parsed.
    let parsed = values.map(TraceId::parse);

    // Then no invalid value becomes a trace identity.
    assert!(parsed.iter().all(Option::is_none));
}

#[test]
fn span_id_given_trimmed_mixed_case_value_when_parsed_then_normalizes_nonzero_id() {
    // Given a padded span identifier containing uppercase hex digits.
    let value = " 00F067AA0BA902B7 ";

    // When the public span-id parser consumes it.
    let parsed = SpanId::parse(value);

    // Then it returns the canonical lowercase representation.
    assert_eq!(
        parsed.map(|span_id| span_id.to_hex_string()),
        Some("00f067aa0ba902b7".to_string())
    );
}

#[test]
fn span_id_given_zero_or_malformed_value_when_parsed_then_rejects_identity() {
    // Given values that violate the fixed width, hex, or non-zero requirements.
    let values = [
        "",
        "00f067aa0ba902b",
        "00f067aa0ba902b7z",
        "0000000000000000",
    ];

    // When each value is parsed.
    let parsed = values.map(SpanId::parse);

    // Then no invalid value becomes a span identity.
    assert!(parsed.iter().all(Option::is_none));
}

#[test]
fn trace_flags_given_trimmed_hex_value_when_parsed_then_exposes_numeric_and_lowercase_forms() {
    // Given a valid flags byte with padding, uppercase hex, and reserved bits.
    let parsed = TraceFlags::parse(" aF ");

    // When the parsed flags are rendered and inspected.
    let flags = parsed.expect("valid trace flags");

    // Then the supported sampled bit is retained and reserved bits are masked.
    assert_eq!(flags.as_u8(), 0x01);
    assert_eq!(flags.to_string(), "01");
}

#[test]
fn trace_flags_given_wrong_width_or_non_hex_value_when_parsed_then_rejects_flags() {
    // Given values outside the two-hex-digit trace-flags grammar.
    let values = ["", "a", "abc", "gg"];

    // When each value is parsed.
    let parsed = values.map(TraceFlags::parse);

    // Then no malformed flags value is accepted.
    assert!(parsed.iter().all(Option::is_none));
}

#[test]
fn trace_context_given_traceparent_when_built_then_uses_forwarded_trace_id() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_TRACEPARENT,
        HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static("request-1"));

    let context = TraceContext::from_headers(&headers);

    assert_eq!(
        context.trace_id.to_hex_string(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(context.request_id_str(), Some("request-1"));
    assert_eq!(
        context
            .parent_span_id
            .as_ref()
            .map(|span_id| span_id.to_hex_string()),
        Some("00f067aa0ba902b7".to_string())
    );
    assert_eq!(context.trace_flags.to_string(), "01");
    assert_eq!(
        context.parent_trace_id.as_ref().map(TraceId::to_hex_string),
        Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
    );
}

#[test]
fn trace_context_given_invalid_forwarded_ids_when_built_then_generates_trace_id() {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_TRACE_ID, HeaderValue::from_static("not-valid"));

    let context = TraceContext::from_headers(&headers);

    assert_eq!(context.trace_id.to_hex_string().len(), 32);
    assert!(context.parent_trace_id.is_none());
}

#[test]
fn trace_context_given_valid_legacy_trace_id_when_built_then_uses_fallback_identity() {
    // Given a valid legacy trace ID without a W3C traceparent header.
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_TRACE_ID,
        HeaderValue::from_static("4bf92f3577b34da6a3ce929d0e0e4736"),
    );

    // When the inbound context is built.
    let context = TraceContext::from_headers(&headers);

    // Then the legacy ID is retained without inventing a parent span or flags.
    assert_eq!(
        context.trace_id.to_hex_string(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(
        context.parent_trace_id.as_ref().map(TraceId::to_hex_string),
        Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
    );
    assert!(context.parent_span_id.is_none());
    assert_eq!(context.trace_flags.as_u8(), 0);
    assert_eq!(context.trace_state_str(), None);
}

#[test]
fn trace_context_given_valid_tracestate_then_preserves_it_with_traceparent() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_TRACEPARENT,
        HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    headers.insert(HEADER_TRACESTATE, HeaderValue::from_static("vendor=value"));

    let context = TraceContext::from_headers(&headers);

    assert_eq!(context.trace_state_str(), Some("vendor=value"));
}

#[test]
fn trace_context_given_orphan_tracestate_then_discards_it() {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_TRACESTATE, HeaderValue::from_static("vendor=value"));

    let context = TraceContext::from_headers(&headers);

    assert!(context.trace_state_str().is_none());
}

#[test]
fn trace_context_when_forwarded_then_writes_w3c_and_legacy_headers() {
    let mut incoming = HeaderMap::new();
    incoming.insert(
        HEADER_TRACEPARENT,
        HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    incoming.insert(HEADER_TRACESTATE, HeaderValue::from_static("vendor=value"));
    incoming.insert(HEADER_REQUEST_ID, HeaderValue::from_static("request-1"));
    let context = TraceContext::from_headers(&incoming);

    let mut outgoing = HeaderMap::new();
    context.write_forward_headers(&mut outgoing);

    let traceparent = outgoing
        .get(HEADER_TRACEPARENT)
        .and_then(|value| value.to_str().ok())
        .expect("traceparent");
    assert!(traceparent.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
    assert!(!traceparent.contains("00f067aa0ba902b7"));
    assert_eq!(
        outgoing
            .get(HEADER_TRACESTATE)
            .and_then(|value| value.to_str().ok()),
        Some("vendor=value")
    );
    assert_eq!(
        outgoing
            .get(HEADER_TRACE_ID)
            .and_then(|value| value.to_str().ok()),
        Some("4bf92f3577b34da6a3ce929d0e0e4736")
    );
    assert_eq!(
        outgoing
            .get(HEADER_REQUEST_ID)
            .and_then(|value| value.to_str().ok()),
        Some("request-1")
    );

    let expected_traceparent = format!("00-{}-{}-01", context.trace_id, context.span_id);
    assert_eq!(context.traceparent(), expected_traceparent);
    assert_eq!(
        outgoing
            .get(HEADER_TRACEPARENT)
            .and_then(|value| value.to_str().ok()),
        Some(expected_traceparent.as_str())
    );
}

#[test]
fn trace_context_given_reserved_trace_flags_when_built_then_masks_them_on_forwarding() {
    // Given an inbound traceparent with one supported and one reserved flag
    // bit.
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_TRACEPARENT,
        HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03"),
    );

    // When the context is parsed and forwarded.
    let context = TraceContext::from_headers(&headers);
    let mut outgoing = HeaderMap::new();
    context.write_forward_headers(&mut outgoing);

    // Then reserved bits are removed from the public value and exact outbound
    // header.
    assert_eq!(context.trace_flags.as_u8(), 0x01);
    let expected_traceparent = format!("00-{}-{}-01", context.trace_id, context.span_id);
    assert_eq!(context.traceparent(), expected_traceparent);
    assert_eq!(
        outgoing
            .get(HEADER_TRACEPARENT)
            .and_then(|value| value.to_str().ok()),
        Some(expected_traceparent.as_str())
    );
}

#[test]
fn trace_context_given_zero_trace_or_parent_id_then_rejects_traceparent() {
    for traceparent in [
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_TRACEPARENT,
            HeaderValue::from_str(traceparent).expect("header value"),
        );

        let context = TraceContext::from_headers(&headers);

        assert!(context.parent_trace_id.is_none());
        assert!(context.parent_span_id.is_none());
    }
}

#[test]
fn trace_context_given_future_version_then_accepts_common_fields() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_TRACEPARENT,
        HeaderValue::from_static(
            " \t01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-future \t",
        ),
    );

    let context = TraceContext::from_headers(&headers);

    assert_eq!(
        context.parent_trace_id.as_ref().map(TraceId::to_hex_string),
        Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string())
    );
    assert_eq!(context.trace_flags.to_string(), "01");
}

#[test]
fn trace_context_given_uppercase_traceparent_fields_when_built_then_rejects_parent() {
    // Given traceparents with uppercase hex in each common W3C field.
    let values = [
        "01-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01-future",
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00F067AA0BA902B7-01-future",
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0A-future",
    ];

    // When each traceparent is parsed.
    for value in values {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_TRACEPARENT, HeaderValue::from_static(value));

        // Then uppercase protocol fields are rejected and never become parent
        // context.
        assert!(
            TraceContext::from_headers(&headers)
                .parent_trace_id
                .is_none()
        );
    }
}

#[test]
fn trace_context_given_short_traceparent_when_built_then_generates_new_context() {
    // Given a traceparent header shorter than the minimum fixed grammar.
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_TRACEPARENT, HeaderValue::from_static("00-"));

    // When the inbound context is built.
    let context = TraceContext::from_headers(&headers);

    // Then the unusable parent is ignored and a fresh trace is generated.
    assert!(context.parent_trace_id.is_none());
    assert!(context.parent_span_id.is_none());
    assert_eq!(context.trace_id.to_hex_string().len(), 32);
}

#[test]
fn trace_context_given_blank_optional_headers_when_built_then_does_not_forward_them() {
    // Given a valid parent and optional headers containing only ASCII
    // whitespace.
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_TRACEPARENT,
        HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    headers.insert(HEADER_TRACESTATE, HeaderValue::from_static(" \t"));
    headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static(" \t"));

    // When the context is built and its headers are forwarded.
    let context = TraceContext::from_headers(&headers);
    let mut outgoing = HeaderMap::new();
    context.write_forward_headers(&mut outgoing);

    // Then blank optional values are not retained, while the trace identity is
    // forwarded.
    assert_eq!(context.trace_state_str(), None);
    assert_eq!(context.request_id_str(), None);
    assert!(outgoing.get(HEADER_TRACEPARENT).is_some());
    assert!(outgoing.get(HEADER_TRACE_ID).is_some());
    assert!(outgoing.get(HEADER_TRACESTATE).is_none());
    assert!(outgoing.get(HEADER_REQUEST_ID).is_none());
}

#[test]
fn trace_context_given_forbidden_or_malformed_version_then_rejects_traceparent() {
    for traceparent in [
        "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_TRACEPARENT,
            HeaderValue::from_str(traceparent).expect("header value"),
        );

        assert!(
            TraceContext::from_headers(&headers)
                .parent_trace_id
                .is_none()
        );
    }
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

    alloc_counter::emit_report(&allocation_report).expect("allocation report");

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
    alloc_counter::emit_report(&allocation_report).expect("allocation report");

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
    alloc_counter::emit_report(&allocation_report).expect("allocation report");

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

    alloc_counter::emit_report(&baseline).expect("allocation report");
    alloc_counter::emit_report(&optimized).expect("allocation report");

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
        "trace_context_tests",
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

fn baseline_traceparent_format(trace_id: &str, span_id: &str, trace_flags: u8) -> String {
    format!("00-{trace_id}-{span_id}-{trace_flags:02x}")
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

fn forwarded_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_TRACEPARENT, HeaderValue::from_static(TRACEPARENT));
    headers.insert(HEADER_TRACESTATE, HeaderValue::from_static("vendor=value"));
    headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static("request-1"));
    headers
}
