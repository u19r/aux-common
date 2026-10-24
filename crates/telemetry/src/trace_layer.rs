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
use metrics_facade::{counter, histogram};
use tower_http::{
    classify::{ServerErrorsAsFailures, ServerErrorsFailureClass, SharedClassifier},
    trace::{DefaultOnBodyChunk, DefaultOnEos, DefaultOnRequest, TraceLayer},
};
use tracing::{Span, field, instrument};

use crate::{
    ForwardedHeaderConfig, RequestCostCollection, SlowOperationThresholds, TraceContext,
    constants::{
        FIELD_FEATURE, FIELD_OPERATION_NAME, FIELD_REQUEST_ID, FIELD_SOURCE_IP, FIELD_TRACE_ID,
        HEADER_REQUEST_ID, HTTP_REQUEST_BYTES_TOTAL_METRIC, HTTP_RESPONSE_BYTES_TOTAL_METRIC,
        LABEL_OPERATION, LABEL_STATUS_CODE, REQUEST_LATENCY_METRIC, UNMATCHED_OPERATION,
    },
};

#[derive(Clone, Debug, Default)]
pub struct SlowOperationLogState {
    pub thresholds: SlowOperationThresholds,
    pub cost_collection: RequestCostCollection,
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
    let observation = RequestObservation::new(&request);
    let trace_context = TraceContext::from_headers(request.headers());
    let response = async {
        if state.cost_collection.is_enabled() {
            metrics_facade::set_request_cost_operation(&observation.operation_name);
        }
        let mut response = next.run(request).await;
        observation
            .finalize_response(&mut response, state.cost_collection)
            .await;
        trace_context.write_forward_headers(response.headers_mut());
        response
    };
    let response = if state.cost_collection.is_enabled() {
        metrics_facade::begin_request_cost_collection(observation.request_id.clone(), || response)
            .await
    } else {
        response.await
    };
    observation.record_slow_operation(&response, &state.thresholds, &request_span);
    response
}

struct RequestObservation {
    method: http::Method,
    operation_path: String,
    operation_name: String,
    request_id: Option<String>,
    request_bytes: u64,
    started: Instant,
}

impl RequestObservation {
    fn new(request: &http::Request<Body>) -> Self {
        let method = request.method().clone();
        let operation_path = bounded_operation_path(request).to_owned();
        let operation_name = format!("{method} {operation_path}");
        Self {
            method,
            operation_path,
            operation_name,
            request_id: request
                .headers()
                .get(HEADER_REQUEST_ID)
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned),
            request_bytes: content_length_or_body_size_hint(request.headers(), request.body()),
            started: Instant::now(),
        }
    }

    fn record_slow_operation(
        &self,
        response: &Response,
        thresholds: &SlowOperationThresholds,
        span: &Span,
    ) {
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let threshold_ms = thresholds.threshold_ms_for(&self.operation_name);
        if duration_ms <= threshold_ms {
            return;
        }
        let _entered = span.enter();
        tracing::warn!(target: "http.request", operation_name = %self.operation_name,
            method = %self.method, path = %self.operation_path,
            status_code = response.status().as_u16(), duration_ms,
            slow_operation_threshold_ms = threshold_ms, "slow API operation");
    }
}

pub(crate) fn bounded_operation_path(request: &http::Request<Body>) -> &str {
    request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or(UNMATCHED_OPERATION)
}

impl RequestObservation {
    async fn finalize_response(
        &self,
        response: &mut Response,
        cost_collection: RequestCostCollection,
    ) {
        let status_code = response.status().as_u16();
        let status_code_label = status_code.to_string();
        let duration_ms = self.started.elapsed().as_secs_f64() * 1000.0;

        counter!(
            HTTP_REQUEST_BYTES_TOTAL_METRIC,
            LABEL_OPERATION => self.operation_name.clone(),
            LABEL_STATUS_CODE => status_code_label.clone()
        )
        .increment(self.request_bytes);

        let response_bytes = content_length_or_body_size_hint(response.headers(), response.body());
        counter!(
            HTTP_RESPONSE_BYTES_TOTAL_METRIC,
            LABEL_OPERATION => self.operation_name.clone(),
            LABEL_STATUS_CODE => status_code_label.clone()
        )
        .increment(response_bytes);
        cost_collection
            .finalize_response(
                response,
                self.request_id.as_deref(),
                duration_ms,
                response_bytes,
            )
            .await;
        histogram!(
            REQUEST_LATENCY_METRIC,
            LABEL_OPERATION => self.operation_name.clone(),
            LABEL_STATUS_CODE => status_code_label
        )
        .record(self.started.elapsed().as_secs_f64() * 1000.0);
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
    let trust_forwarded_headers = request
        .extensions()
        .get::<ForwardedHeaderConfig>()
        .is_some_and(|config| config.trust_forwarded_headers);
    let forwarded = trust_forwarded_headers
        .then(|| forwarded_client_ip(request.headers()))
        .flatten();
    let source_ip = forwarded.or(peer_ip);
    let forwarded_for = trusted_forwarded_header_value(
        request.headers(),
        trust_forwarded_headers,
        "x-forwarded-for",
    );
    let forwarded_host = trusted_forwarded_header_value(
        request.headers(),
        trust_forwarded_headers,
        "x-forwarded-host",
    );
    let forwarded_proto = trusted_forwarded_header_value(
        request.headers(),
        trust_forwarded_headers,
        "x-forwarded-proto",
    );
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
    // Never emit the attacker-controlled URI path. A matched route template
    // is bounded and low-cardinality; unmatched requests use `_unmatched`.
    span.record("path", field::display(bounded_operation_path(request)));
    span.record("host", field::display(host));
    span.record("user_agent", field::display(user_agent));
    if let Some(source_ip) = source_ip {
        span.record(FIELD_SOURCE_IP, field::display(source_ip));
    } else {
        span.record(FIELD_SOURCE_IP, field::display(""));
    }
    record_forwarded_header(&span, "forwarded_for", forwarded_for);
    record_forwarded_header(&span, "forwarded_host", forwarded_host);
    record_forwarded_header(&span, "forwarded_proto", forwarded_proto);
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

fn trusted_forwarded_header_value<'a>(
    headers: &'a http::HeaderMap,
    trust_forwarded_headers: bool,
    name: &str,
) -> Option<&'a str> {
    trust_forwarded_headers
        .then(|| header_value(headers, name))
        .filter(|value| !value.is_empty())
}

fn record_forwarded_header(span: &Span, field_name: &str, value: Option<&str>) {
    let Some(value) = value else {
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
