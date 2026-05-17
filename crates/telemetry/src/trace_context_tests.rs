use http::{HeaderMap, HeaderValue};

use crate::{
    HEADER_REQUEST_ID, HEADER_TRACE_ID, HEADER_TRACEPARENT, HEADER_TRACESTATE, TraceContext,
    TraceId,
};

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
}
