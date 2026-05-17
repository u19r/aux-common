use std::sync::{Arc, OnceLock};

use axum::{Extension, http::HeaderMap};

use crate::{MetricsConfig, MetricsState, metrics_handler, setup_metrics};

fn metrics_state() -> Arc<MetricsState> {
    static STATE: OnceLock<Arc<MetricsState>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            setup_metrics(&MetricsConfig::enabled("secret"))
                .expect("metrics setup")
                .expect("metrics enabled")
                .state
        })
        .clone()
}

#[test]
fn setup_metrics_given_disabled_config_then_returns_none() {
    let metrics = setup_metrics(&MetricsConfig::disabled()).expect("metrics setup");

    assert!(metrics.is_none());
}

#[test]
fn setup_metrics_given_enabled_config_without_token_then_rejects_config() {
    let err = match setup_metrics(&MetricsConfig {
        enabled: true,
        bearer_token: None,
        metrics_path: "/internal/metrics".to_string(),
    }) {
        Ok(_) => panic!("missing token should fail"),
        Err(err) => err,
    };

    assert_eq!(
        err.to_string(),
        "Prometheus metrics enabled but bearer token missing"
    );
}

#[tokio::test]
async fn metrics_handler_given_missing_bearer_token_then_rejects_request() {
    let err = metrics_handler(Extension(metrics_state()), HeaderMap::new())
        .await
        .expect_err("missing auth should fail");

    assert_eq!(err, axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metrics_handler_given_valid_bearer_token_then_returns_metrics() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer secret"),
    );

    let response = metrics_handler(Extension(metrics_state()), headers)
        .await
        .expect("metrics response");

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
