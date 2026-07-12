use std::{
    convert::TryFrom,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use axum::{
    body::{Body, HttpBody},
    extract::{MatchedPath, State, connect_info::ConnectInfo},
    http::{self, header},
    middleware::Next,
    response::Response,
};
use metrics_facade::{CostResponseHeaders, counter, histogram};
use tower_http::{
    classify::{ServerErrorsAsFailures, ServerErrorsFailureClass, SharedClassifier},
    trace::{DefaultOnBodyChunk, DefaultOnEos, DefaultOnRequest, TraceLayer},
};
use tracing::{Span, field, instrument};

use crate::{
    ForwardedHeaderConfig, SlowOperationThresholds, TraceContext,
    constants::{
        FIELD_FEATURE, FIELD_OPERATION_NAME, FIELD_REQUEST_ID, FIELD_SOURCE_IP, FIELD_TRACE_ID,
        HEADER_REQUEST_ID, HTTP_REQUEST_BYTES_TOTAL_METRIC, HTTP_RESPONSE_BYTES_TOTAL_METRIC,
        LABEL_OPERATION, LABEL_STATUS_CODE, REQUEST_LATENCY_METRIC,
    },
};

const UNMATCHED_OPERATION: &str = "_unmatched";

#[derive(Clone, Debug, Default)]
pub struct SlowOperationLogState {
    pub thresholds: SlowOperationThresholds,
    pub collect_cost: bool,
}

pub type RequestTraceLayer = TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    MakeSpanFn,
    DefaultOnRequest,
    OnResponseFn,
    DefaultOnBodyChunk,
    DefaultOnEos,
    OnFailureFn,
>;

type MakeSpanFn = fn(&http::Request<Body>) -> Span;
type OnResponseFn = fn(&http::Response<Body>, Duration, &Span);
type OnFailureFn = fn(ServerErrorsFailureClass, Duration, &Span);

pub fn request_trace_layer() -> RequestTraceLayer {
    TraceLayer::new_for_http()
        .make_span_with(make_span as MakeSpanFn)
        .on_response(on_response as OnResponseFn)
        .on_failure(on_failure as OnFailureFn)
}

pub async fn slow_operation_log(
    State(state): State<SlowOperationLogState>,
    request: http::Request<Body>,
    next: Next,
) -> Response {
    let request_span = tracing::Span::current();
    let method = request.method().clone();
    let raw_path = request.uri().path().to_string();
    let operation_path = bounded_operation_path(&request).to_string();
    let operation_name = format!("{method} {operation_path}");
    let request_bytes = content_length_or_body_size_hint(request.headers(), request.body());
    let request_id = request
        .headers()
        .get(HEADER_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let trace_context = TraceContext::from_headers(request.headers());
    let started = Instant::now();

    let response = if state.collect_cost {
        let operation_name = operation_name.clone();
        let request_id = request_id.clone();
        metrics_facade::begin_request_cost_collection(request_id.clone(), || async move {
            let mut response = next.run(request).await;
            finalize_response_metrics(
                &mut response,
                &operation_name,
                request_bytes,
                request_id.as_deref(),
                started,
                true,
            )
            .await;
            trace_context.write_forward_headers(response.headers_mut());
            response
        })
        .await
    } else {
        let mut response = next.run(request).await;
        finalize_response_metrics(
            &mut response,
            &operation_name,
            request_bytes,
            request_id.as_deref(),
            started,
            false,
        )
        .await;
        trace_context.write_forward_headers(response.headers_mut());
        response
    };

    let status_code = response.status().as_u16();
    let elapsed = started.elapsed();
    let duration_ms_u64 = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let threshold_ms = state.thresholds.threshold_ms_for(&operation_name);
    if duration_ms_u64 > threshold_ms {
        let _entered = request_span.enter();
        tracing::warn!(
            target = "http.request",
            operation_name = %operation_name,
            method = %method,
            path = %raw_path,
            status_code,
            duration_ms = duration_ms_u64,
            slow_operation_threshold_ms = threshold_ms,
            "slow API operation"
        );
    }

    response
}

pub(crate) fn bounded_operation_path(request: &http::Request<Body>) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or(UNMATCHED_OPERATION)
}

async fn finalize_response_metrics(
    response: &mut Response,
    operation_name: &str,
    request_bytes: u64,
    request_id: Option<&str>,
    started: Instant,
    collect_cost: bool,
) {
    let status_code = response.status().as_u16();
    let status_code_label = status_code.to_string();
    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;

    counter!(
        HTTP_REQUEST_BYTES_TOTAL_METRIC,
        LABEL_OPERATION => operation_name.to_string(),
        LABEL_STATUS_CODE => status_code_label.clone()
    )
    .increment(request_bytes);

    let response_bytes = content_length_or_body_size_hint(response.headers(), response.body());
    counter!(
        HTTP_RESPONSE_BYTES_TOTAL_METRIC,
        LABEL_OPERATION => operation_name.to_string(),
        LABEL_STATUS_CODE => status_code_label.clone()
    )
    .increment(response_bytes);
    histogram!(
        REQUEST_LATENCY_METRIC,
        LABEL_OPERATION => operation_name.to_string(),
        LABEL_STATUS_CODE => status_code_label
    )
    .record(duration_ms);

    if collect_cost {
        let cost_headers = CostResponseHeaders::from_snapshot(
            metrics_facade::finish_request_cost_collection(
                request_id,
                duration_ms,
                Some(response_bytes),
            )
            .await,
        );
        cost_headers.write_to_headers(response.headers_mut());
    }
}

#[instrument(
    target = "http.request",
    name = "http.request",
    skip_all,
    fields(feature = "http",
        trace_id = field::Empty,
        parent_trace_id = field::Empty,
        span_id = field::Empty,
        parent_span_id = field::Empty,
        trace_flags = field::Empty,
        request_id = field::Empty,
        operation_name = field::Empty,
        method = field::Empty,
        path = field::Empty,
        host = field::Empty,
        user_agent = field::Empty,
        source_ip = field::Empty,
        forwarded_for = field::Empty,
        forwarded_host = field::Empty,
        forwarded_proto = field::Empty,
        response_bytes = field::Empty,
        status_code = field::Empty,
        failure = field::Empty,
        request_bytes = field::Empty
    )
)]
fn make_span(request: &http::Request<Body>) -> Span {
    let trace_context = TraceContext::from_headers(request.headers());
    let host = header_value(request.headers(), header::HOST.as_str());
    let user_agent = header_value(request.headers(), header::USER_AGENT.as_str());
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip());
    let forwarded = request
        .extensions()
        .get::<ForwardedHeaderConfig>()
        .and_then(|config| {
            config
                .trust_forwarded_headers
                .then(|| forwarded_client_ip(request.headers()))
                .flatten()
        });
    let source_ip = forwarded.or(peer_ip);
    let request_bytes = i64::try_from(content_length_or_body_size_hint(
        request.headers(),
        request.body(),
    ))
    .ok();

    let span = Span::current();
    span.record(FIELD_TRACE_ID, field::display(&trace_context.trace_id));
    span.record("span_id", field::display(&trace_context.span_id));
    span.record("trace_flags", field::display(trace_context.trace_flags));
    if let Some(parent_trace_id) = trace_context.parent_trace_id.as_ref() {
        span.record("parent_trace_id", field::display(parent_trace_id));
    }
    if let Some(parent_span_id) = trace_context.parent_span_id.as_ref() {
        span.record("parent_span_id", field::display(parent_span_id));
    }
    span.record(
        FIELD_REQUEST_ID,
        field::display(trace_context.request_id_str().unwrap_or_default()),
    );
    if let Some(matched_path) = request.extensions().get::<MatchedPath>() {
        span.record(
            FIELD_OPERATION_NAME,
            field::display(format_args!(
                "{} {}",
                request.method(),
                matched_path.as_str()
            )),
        );
    } else {
        span.record(FIELD_OPERATION_NAME, field::display(""));
    }
    span.record("method", field::display(request.method()));
    span.record("path", field::display(request.uri().path()));
    span.record("host", field::display(host));
    span.record("user_agent", field::display(user_agent));
    if let Some(source_ip) = source_ip {
        span.record(FIELD_SOURCE_IP, field::display(source_ip));
    } else {
        span.record(FIELD_SOURCE_IP, field::display(""));
    }
    record_forwarded_header(request.headers(), &span, "forwarded_for", "x-forwarded-for");
    record_forwarded_header(
        request.headers(),
        &span,
        "forwarded_host",
        "x-forwarded-host",
    );
    record_forwarded_header(
        request.headers(),
        &span,
        "forwarded_proto",
        "x-forwarded-proto",
    );
    if let Some(bytes) = request_bytes {
        span.record("request_bytes", bytes);
    }
    span.record(FIELD_FEATURE, "http");

    span
}

fn on_response(response: &http::Response<Body>, duration: Duration, span: &Span) {
    span.record("status_code", response.status().as_u16());
    span.record("duration_ms", duration.as_millis() as u64);

    if let Ok(bytes) = i64::try_from(content_length_or_body_size_hint(
        response.headers(),
        response.body(),
    )) {
        span.record("response_bytes", bytes);
    }
}

fn on_failure(failure: ServerErrorsFailureClass, duration: Duration, span: &Span) {
    span.record("duration_ms", duration.as_millis() as u64);
    span.record("failure", field::display(failure));
}

fn content_length_or_body_size_hint(headers: &http::HeaderMap, body: &Body) -> u64 {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| body.size_hint().exact())
        .unwrap_or(0)
}

fn header_value<'a>(headers: &'a http::HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

fn record_forwarded_header(headers: &http::HeaderMap, span: &Span, field_name: &str, header: &str) {
    let Some(value) = headers.get(header).and_then(|value| value.to_str().ok()) else {
        return;
    };
    span.record(field_name, field::display(value));
}

fn forwarded_client_ip(headers: &http::HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse().ok())
        })
}
