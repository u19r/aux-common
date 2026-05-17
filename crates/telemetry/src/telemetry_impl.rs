use std::sync::Arc;

use axum::{
    Extension,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_prometheus::{
    PrometheusMetricLayer, PrometheusMetricLayerBuilder,
    metrics_exporter_prometheus::PrometheusHandle,
};
use subtle::ConstantTimeEq;
use tracing::warn;
use tracing_subscriber::{
    EnvFilter,
    layer::SubscriberExt as _,
    util::{SubscriberInitExt, TryInitError},
};

use crate::{
    MetricsConfig, TracingConfig,
    wide_log::{WideLogInitError, WideLogLayer},
};

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("failed to initialise tracing subscriber: {0}")]
    SubscriberInit(#[source] TryInitError),
    #[error("failed to configure tracing log destination: {0}")]
    WideLogInit(#[source] WideLogInitError),
    #[error("Prometheus metrics enabled but bearer token missing")]
    MetricsTokenMissing,
}

#[derive(Clone, Copy, Debug)]
pub enum FilterSource {
    Config,
    Default,
}

impl std::fmt::Display for FilterSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterSource::Config => write!(f, "config"),
            FilterSource::Default => write!(f, "default"),
        }
    }
}

pub struct TelemetryGuards;

pub fn resolve_filter(tracing_cfg: &TracingConfig) -> (EnvFilter, FilterSource) {
    if let Some(spec) = tracing_cfg.log_level.as_deref() {
        match EnvFilter::try_new(spec) {
            Ok(filter) => return (filter, FilterSource::Config),
            Err(err) => {
                eprintln!(
                    "Invalid log level '{}' in tracing config ({}), falling back to default filter",
                    spec, err
                );
            }
        }
    }

    (EnvFilter::new("warn"), FilterSource::Default)
}

pub fn init_tracing(
    tracing_cfg: &TracingConfig,
    filter: EnvFilter,
) -> Result<TelemetryGuards, TelemetryError> {
    let wide_log_layer = WideLogLayer::new(tracing_cfg).map_err(TelemetryError::WideLogInit)?;

    tracing_subscriber::registry()
        .with(filter)
        .with(wide_log_layer)
        .try_init()
        .map_err(TelemetryError::SubscriberInit)?;

    Ok(TelemetryGuards)
}

pub struct MetricsComponents {
    pub layer: PrometheusMetricLayer<'static>,
    pub state: Arc<MetricsState>,
}

pub struct MetricsState {
    handle: PrometheusHandle,
    bearer_token: String,
}

impl MetricsState {
    fn new(handle: PrometheusHandle, bearer_token: String) -> Self {
        Self {
            handle,
            bearer_token,
        }
    }

    fn render(&self) -> String {
        self.handle.render()
    }
}

pub fn setup_metrics(cfg: &MetricsConfig) -> Result<Option<MetricsComponents>, TelemetryError> {
    if !cfg.enabled {
        return Ok(None);
    }

    let token = cfg
        .bearer_token
        .as_ref()
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty())
        .ok_or(TelemetryError::MetricsTokenMissing)?;

    let metrics_path: &'static str = Box::leak(cfg.metrics_path.clone().into_boxed_str());
    let ignore_patterns: &'static [&'static str] = Box::leak(Box::new([metrics_path]));
    let builder = PrometheusMetricLayerBuilder::new().with_ignore_patterns(ignore_patterns);

    let (layer, handle) = builder.with_default_metrics().build_pair();

    Ok(Some(MetricsComponents {
        layer,
        state: Arc::new(MetricsState::new(handle, token)),
    }))
}

pub async fn metrics_handler(
    Extension(state): Extension<Arc<MetricsState>>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let auth_value = auth_header
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .trim();

    let Some(provided) = auth_value.strip_prefix("Bearer ") else {
        warn!(
            target = "telemetry",
            "metrics scrape missing bearer token prefix"
        );
        return Err(StatusCode::UNAUTHORIZED);
    };

    if provided
        .trim()
        .as_bytes()
        .ct_eq(state.bearer_token.as_bytes())
        .unwrap_u8()
        == 0
    {
        warn!(
            target = "telemetry",
            "metrics scrape supplied invalid bearer token"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    let body = state.render();
    let response = (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        body,
    )
        .into_response();

    Ok(response)
}
