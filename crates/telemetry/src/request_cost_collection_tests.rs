use std::{sync::Arc, time::Duration};

use axum::{Router, body::Body, http::Request, middleware, response::Response, routing::get};
use tower::ServiceExt;

use crate::{RequestCostCollection, SlowOperationLogState, slow_operation_log};

fn cost_router(work_duration: Duration) -> Router {
    Router::new()
        .route(
            "/measurement",
            get(move || async move {
                let work = tokio::spawn(metrics_facade::inherit_request_cost(async move {
                    tokio::time::sleep(work_duration).await;
                    drop(metrics_facade::begin_database_call("detached.completed"));
                }));
                let mut response = Response::new(Body::from("payload"));
                response.extensions_mut().insert(Arc::new(work));
                response
            }),
        )
        .layer(middleware::from_fn_with_state(
            SlowOperationLogState {
                cost_collection: RequestCostCollection::Snapshot,
                ..Default::default()
            },
            slow_operation_log,
        ))
}

#[tokio::test(start_paused = true)]
async fn given_detached_request_work_when_response_is_finalized_then_the_snapshot_contains_settled_costs()
 {
    let started = tokio::time::Instant::now();
    let response = cost_router(Duration::from_millis(20))
        .oneshot(
            Request::builder()
                .uri("/measurement")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let snapshot = response
        .extensions()
        .get::<metrics_facade::CostResponseHeaders>()
        .unwrap();
    assert_eq!(snapshot.snapshot().db_calls, 1);
    assert_eq!(started.elapsed(), Duration::from_millis(20));
    assert!(
        !response
            .headers()
            .keys()
            .any(|name| name.as_str().starts_with("x-aux-cost-"))
    );
}

#[tokio::test(start_paused = true)]
async fn given_unsettled_request_work_when_the_deadline_expires_then_the_response_cannot_admit_partial_costs()
 {
    let started = tokio::time::Instant::now();
    let response = cost_router(Duration::from_secs(60))
        .oneshot(
            Request::builder()
                .uri("/measurement")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response
            .extensions()
            .get::<metrics_facade::CostResponseHeaders>()
            .is_none()
    );
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    response
        .extensions()
        .get::<Arc<tokio::task::JoinHandle<()>>>()
        .unwrap()
        .abort();
}
