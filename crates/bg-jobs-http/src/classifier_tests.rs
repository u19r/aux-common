use std::time::{Duration, SystemTime};

use http::{HeaderMap, HeaderValue, StatusCode, header::RETRY_AFTER};
use http_request::HttpRequestErrorKind;
use proptest::prelude::*;

use crate::{
    HttpResultClass, RetryAfterSource, classifier::classify_response_body_error, classify_status,
    classify_transport, parse_retry_after,
};

fn headers(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        RETRY_AFTER,
        HeaderValue::from_str(value).expect("test header"),
    );
    headers
}

#[test]
fn given_every_status_family_when_classified_then_outcome_owner_is_stable() {
    let cases = [
        (StatusCode::OK, HttpResultClass::Complete),
        (StatusCode::NO_CONTENT, HttpResultClass::Complete),
        (StatusCode::MOVED_PERMANENTLY, HttpResultClass::DeadLetter),
        (StatusCode::BAD_REQUEST, HttpResultClass::DeadLetter),
        (StatusCode::UNAUTHORIZED, HttpResultClass::DeadLetter),
        (StatusCode::REQUEST_TIMEOUT, HttpResultClass::Retry),
        (StatusCode::TOO_EARLY, HttpResultClass::Retry),
        (StatusCode::TOO_MANY_REQUESTS, HttpResultClass::Retry),
        (StatusCode::INTERNAL_SERVER_ERROR, HttpResultClass::Retry),
        (StatusCode::BAD_GATEWAY, HttpResultClass::Retry),
        (StatusCode::SERVICE_UNAVAILABLE, HttpResultClass::Retry),
        (StatusCode::GATEWAY_TIMEOUT, HttpResultClass::Retry),
    ];
    for (status, expected) in cases {
        let classification = classify_status(
            status,
            &HeaderMap::new(),
            Duration::from_secs(30),
            Duration::from_secs(2),
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(classification.class(), expected, "status {status}");
        assert_eq!(classification.status(), Some(status));
    }
}

#[test]
fn given_every_valid_http_status_code_when_classified_then_no_code_is_uncovered() {
    for raw in 100..=999 {
        let status = StatusCode::from_u16(raw).expect("valid HTTP status");
        let expected = if (200..300).contains(&raw) {
            HttpResultClass::Complete
        } else if raw == 408 || raw == 425 || raw == 429 || (500..600).contains(&raw) {
            HttpResultClass::Retry
        } else {
            HttpResultClass::DeadLetter
        };
        let classification = classify_status(
            status,
            &HeaderMap::new(),
            Duration::from_secs(30),
            Duration::from_secs(2),
            SystemTime::UNIX_EPOCH,
        );
        assert_eq!(classification.class(), expected, "status {status}");
    }
}

#[test]
fn given_retry_after_delta_when_over_bound_then_delay_is_clamped() {
    let decision = parse_retry_after(
        &headers("120"),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(30),
        Duration::from_secs(2),
    );
    assert_eq!(decision.source(), RetryAfterSource::Delta);
    assert_eq!(decision.delay(), Some(Duration::from_secs(30)));
}

#[test]
fn given_retry_after_date_when_in_future_or_past_then_delay_is_bounded() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let future = httpdate::fmt_http_date(now + Duration::from_secs(12));
    let future_decision = parse_retry_after(
        &headers(&future),
        now,
        Duration::from_secs(30),
        Duration::from_secs(2),
    );
    assert_eq!(future_decision.source(), RetryAfterSource::Date);
    assert_eq!(future_decision.delay(), Some(Duration::from_secs(12)));

    let past = httpdate::fmt_http_date(now - Duration::from_secs(1));
    let past_decision = parse_retry_after(
        &headers(&past),
        now,
        Duration::from_secs(30),
        Duration::from_secs(2),
    );
    assert_eq!(past_decision.source(), RetryAfterSource::Date);
    assert_eq!(past_decision.delay(), Some(Duration::ZERO));
}

#[test]
fn given_malformed_or_invalid_retry_after_when_classified_then_fallback_is_bounded() {
    let malformed = parse_retry_after(
        &headers("not-a-date"),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(30),
        Duration::from_secs(7),
    );
    assert_eq!(malformed.source(), RetryAfterSource::Malformed);
    assert_eq!(malformed.delay(), Some(Duration::from_secs(7)));
    assert!(malformed.is_malformed());

    let mut invalid = HeaderMap::new();
    invalid.insert(
        RETRY_AFTER,
        HeaderValue::from_bytes(&[0xff]).expect("test header"),
    );
    let invalid_decision = parse_retry_after(
        &invalid,
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(3),
        Duration::from_secs(7),
    );
    assert_eq!(invalid_decision.source(), RetryAfterSource::Malformed);
    assert_eq!(invalid_decision.delay(), Some(Duration::from_secs(3)));

    let missing = parse_retry_after(
        &HeaderMap::new(),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(3),
        Duration::from_secs(7),
    );
    assert_eq!(missing.source(), RetryAfterSource::Missing);
    assert_eq!(missing.delay(), None);

    let empty = parse_retry_after(
        &headers(""),
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(3),
        Duration::from_secs(7),
    );
    assert_eq!(empty.source(), RetryAfterSource::Malformed);
    assert_eq!(empty.delay(), Some(Duration::from_secs(3)));
}

#[test]
fn given_transport_errors_when_classified_then_only_transient_kinds_retry() {
    for kind in [
        HttpRequestErrorKind::Timeout,
        HttpRequestErrorKind::Connect,
        HttpRequestErrorKind::ResponseBody,
    ] {
        assert_eq!(
            classify_transport(kind, Duration::from_secs(4)).class(),
            HttpResultClass::Retry
        );
    }
    for kind in [
        HttpRequestErrorKind::Request,
        HttpRequestErrorKind::Body,
        HttpRequestErrorKind::ResponseTooLarge,
        HttpRequestErrorKind::Redirect,
        HttpRequestErrorKind::Status,
    ] {
        assert_eq!(
            classify_transport(kind, Duration::from_secs(4)).class(),
            HttpResultClass::DeadLetter
        );
    }
}

#[test]
fn given_transient_transport_errors_when_classified_then_retry_metadata_is_identical() {
    let fallback = Duration::from_secs(4);
    let timeout = classify_transport(HttpRequestErrorKind::Timeout, fallback);

    assert_eq!(
        timeout,
        classify_transport(HttpRequestErrorKind::Connect, fallback)
    );
    assert_eq!(
        timeout,
        classify_transport(HttpRequestErrorKind::ResponseBody, fallback)
    );
    assert_eq!(timeout.class(), HttpResultClass::Retry);
    assert_eq!(timeout.status(), StatusCode::from_u16(599).ok());
    assert_eq!(timeout.retry_class(), Some(bg_jobs::RetryClass::Transient));
    assert_eq!(timeout.retry_after().source(), RetryAfterSource::Missing);
    assert_eq!(timeout.retry_after().delay(), Some(fallback));
}

#[test]
fn given_response_stream_failure_when_classified_then_it_retries_instead_of_dead_lettering() {
    let classification = classify_response_body_error(
        StatusCode::OK,
        HttpRequestErrorKind::ResponseBody,
        Duration::from_secs(4),
    );

    assert_eq!(classification.class(), HttpResultClass::Retry);
}

proptest! {
    #[test]
    fn given_arbitrary_retry_after_when_parsing_then_delay_stays_bounded(
        value in "[\x00-\x7F]{0,24}",
        maximum_secs in 0_u64..3600,
        fallback_secs in 0_u64..3600,
    ) {
        // Given any header value with bounded maximum and fallback budgets.
        // Values rejected by header syntax exercise the missing path.
        let mut headers = HeaderMap::new();
        if let Ok(header) = HeaderValue::from_str(&value) {
            headers.insert(RETRY_AFTER, header);
        }
        let maximum = Duration::from_secs(maximum_secs);
        let fallback = Duration::from_secs(fallback_secs);

        // When the bounded parser evaluates the header.
        let decision = parse_retry_after(&headers, SystemTime::UNIX_EPOCH, maximum, fallback);

        // Then malformed, dated, and delta inputs alike never exceed the
        // larger budget, so a hostile server cannot arm an unbounded sleep.
        let bound = maximum_secs.max(fallback_secs);
        prop_assert!(decision.delay().is_none_or(|delay| delay.as_secs() <= bound));
    }
}
