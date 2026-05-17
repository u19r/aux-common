use http::{HeaderMap, HeaderValue};

use crate::{HEADER_REQUEST_ID, HEADER_TRACEPARENT, HEADER_TRACESTATE, TraceContext};

#[test]
#[alloc_counter::count_allocations(label = "trace_context_parse_forward_headers")]
fn trace_context_given_forwarded_headers_when_parsed_then_records_allocation_baseline() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_TRACEPARENT,
        HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    headers.insert(HEADER_TRACESTATE, HeaderValue::from_static("vendor=value"));
    headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static("request-1"));

    let context = TraceContext::from_headers(&headers);

    assert_eq!(
        context.trace_id.to_hex_string(),
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    assert_eq!(context.trace_state_str(), Some("vendor=value"));
    assert_eq!(context.request_id_str(), Some("request-1"));
}
