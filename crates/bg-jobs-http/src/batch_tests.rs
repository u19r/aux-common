use std::time::{Duration, SystemTime};

use bg_jobs::{AttemptId, ExecutionId, JobOutcome, Timestamp};
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use http_request::Url;

use crate::{
    ApprovedEndpoint, BatchClassificationLimits, BatchItemContext, BatchItemResponse,
    BatchResponse, BatchResultSet, HttpPolicy, HttpPolicyId, HttpRequest, HttpRequestInput,
};

fn request() -> HttpRequest {
    HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs").expect("URL"),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"body"),
    })
    .expect("request")
}

fn items<'a>(request: &'a HttpRequest) -> [BatchItemContext<'a>; 2] {
    [
        BatchItemContext {
            execution_id: ExecutionId::from([1; 16]),
            attempt_id: AttemptId::from([2; 16]),
            request,
        },
        BatchItemContext {
            execution_id: ExecutionId::from([3; 16]),
            attempt_id: AttemptId::from([4; 16]),
            request,
        },
    ]
}

fn limits() -> BatchClassificationLimits {
    BatchClassificationLimits {
        retry_after_max: Duration::from_secs(30),
        retry_after_fallback: Duration::from_secs(2),
    }
}

#[test]
fn given_per_item_results_when_built_then_each_item_keeps_its_own_outcome() {
    let request = request();
    let items = items(&request);
    let result = BatchResultSet::from_response(
        &items,
        BatchResponse::PerItem(vec![
            BatchItemResponse {
                attempt_id: items[1].attempt_id,
                status: StatusCode::TOO_MANY_REQUESTS,
                headers: HeaderMap::new(),
            },
            BatchItemResponse {
                attempt_id: items[0].attempt_id,
                status: StatusCode::OK,
                headers: HeaderMap::new(),
            },
        ]),
        limits(),
        SystemTime::UNIX_EPOCH,
        Timestamp::from_millis(100),
    )
    .expect("batch result");
    let outcomes = result.into_outcomes();
    assert!(matches!(outcomes[0].outcome, JobOutcome::Complete(_)));
    assert!(matches!(outcomes[1].outcome, JobOutcome::Retry { .. }));
    assert_eq!(outcomes[0].attempt_id, items[0].attempt_id);
    assert_eq!(outcomes[1].attempt_id, items[1].attempt_id);
}

#[test]
fn given_batch_wide_status_when_built_then_status_applies_to_every_member() {
    let request = request();
    let items = items(&request);
    let result = BatchResultSet::from_response(
        &items,
        BatchResponse::BatchWide {
            status: StatusCode::SERVICE_UNAVAILABLE,
            headers: HeaderMap::new(),
        },
        limits(),
        SystemTime::UNIX_EPOCH,
        Timestamp::ZERO,
    )
    .expect("batch result");
    assert!(
        result
            .outcomes()
            .iter()
            .all(|item| matches!(item.outcome, JobOutcome::Retry { .. }))
    );
}

#[test]
fn given_omitted_item_when_built_then_only_omission_is_retryable() {
    let request = request();
    let items = items(&request);
    let result = BatchResultSet::from_response(
        &items,
        BatchResponse::PerItem(vec![BatchItemResponse {
            attempt_id: items[0].attempt_id,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }]),
        limits(),
        SystemTime::UNIX_EPOCH,
        Timestamp::ZERO,
    )
    .expect("omission is represented as an item retry");
    assert!(matches!(
        result.outcomes()[0].outcome,
        JobOutcome::Complete(_)
    ));
    assert!(matches!(
        result.outcomes()[1].outcome,
        JobOutcome::Retry { .. }
    ));
}

#[test]
fn given_unknown_or_duplicate_item_response_when_built_then_batch_invariant_is_not_silent() {
    let request = request();
    let items = items(&request);
    let unknown = BatchResultSet::from_response(
        &items,
        BatchResponse::PerItem(vec![BatchItemResponse {
            attempt_id: AttemptId::from([9; 16]),
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }]),
        limits(),
        SystemTime::UNIX_EPOCH,
        Timestamp::ZERO,
    );
    assert_eq!(unknown, Err(crate::HttpJobError::BatchInvariant));

    let duplicate = BatchResultSet::from_response(
        &items,
        BatchResponse::PerItem(vec![
            BatchItemResponse {
                attempt_id: items[0].attempt_id,
                status: StatusCode::OK,
                headers: HeaderMap::new(),
            },
            BatchItemResponse {
                attempt_id: items[0].attempt_id,
                status: StatusCode::OK,
                headers: HeaderMap::new(),
            },
        ]),
        limits(),
        SystemTime::UNIX_EPOCH,
        Timestamp::ZERO,
    )
    .expect("duplicate is converted to an item-local invariant retry");
    assert!(matches!(
        duplicate.outcomes()[0].outcome,
        JobOutcome::Retry { .. }
    ));
    assert!(matches!(
        duplicate.outcomes()[1].outcome,
        JobOutcome::Retry { .. }
    ));
}

#[test]
fn given_policy_compatible_batch_inputs_when_registered_then_policy_remains_single_owner() {
    let policy = HttpPolicy::builder(HttpPolicyId::try_new("batch").expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .try_build()
        .expect("policy");
    assert_eq!(policy.id().as_str(), "batch");
}
