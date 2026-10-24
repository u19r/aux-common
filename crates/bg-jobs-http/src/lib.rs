//! Bounded HTTP execution and partial-batch adapters for durable jobs.
//!
//! The crate owns destination approval, request/response bounds, one shared
//! transport, status classification, and stable identity propagation. It does
//! not persist credentials or response bodies and does not own job retries.
#![deny(unsafe_code)]

mod authorizer;
mod batch;
mod classifier;
mod constants;
mod error;
mod handler;
mod policy;
mod request;
mod transport;

#[cfg(test)]
mod batch_tests;
#[cfg(test)]
mod classifier_tests;
#[cfg(test)]
mod handler_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod request_tests;

pub use transport::PolicyBoundTransport;

pub use crate::{
    authorizer::{
        AuthorizationErrorKind, AuthorizationFuture, AuthorizationRequest, AuthorizationResult,
        NoopAuthorizer, RequestAuthorizer,
    },
    batch::{
        BatchClassificationLimits, BatchHandlerError, BatchHandlerFuture, BatchItemContext,
        BatchItemOutcome, BatchItemResponse, BatchJobHandler, BatchResponse, BatchResultSet,
    },
    classifier::{
        HttpClassification, HttpResultClass, RetryAfterDecision, RetryAfterSource,
        classify_response, classify_status, classify_transport, parse_retry_after,
    },
    constants::{MAX_HTTP_HEADER_BYTES, MAX_HTTP_HEADER_COUNT},
    error::HttpJobError,
    handler::{HttpExecutor, HttpExecutorBuilder},
    policy::{ApprovedEndpoint, HttpPolicy, HttpPolicyBuilder, HttpPolicyId},
    request::{HttpAttempt, HttpJob, HttpRequest, HttpRequestDiagnostic, HttpRequestInput},
};
