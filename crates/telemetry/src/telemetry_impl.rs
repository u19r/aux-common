use std::sync::Arc;

use axum::{
    Extension,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_prometheus::{
    PrometheusMetricLayer, PrometheusMetricLayerBuilder,
    metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle},
};
use subtle::ConstantTimeEq;
use tracing::warn;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt};

use crate::{
    MetricsConfig, TracingConfig,
    constants::{METRICS_UPKEEP_INTERVAL, REQUEST_STORAGE_DURATION_BUCKETS_SECONDS},
    wide_log::{WideLogInitError, WideLogLayer},
};

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("failed to initialise tracing subscriber")]
    SubscriberInit,
    #[error("invalid tracing log filter")]
    InvalidFilter,
    #[error("failed to configure tracing log destination: {0}")]
    WideLogInit(WideLogInitError),
    #[error("Prometheus metrics enabled but bearer token missing")]
    MetricsTokenMissing,
    #[error("failed to configure Prometheus recorder")]
    MetricsRecorder,
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

pub fn resolve_filter(
    tracing_cfg: &TracingConfig,
) -> Result<(EnvFilter, FilterSource), TelemetryError> {
    if let Some(spec) = tracing_cfg.log_level.as_deref() {
        let filter = EnvFilter::try_new(spec).map_err(|_| TelemetryError::InvalidFilter)?;
        return Ok((filter, FilterSource::Config));
    }

    Ok((EnvFilter::new("warn"), FilterSource::Default))
}

pub fn init_tracing(
    tracing_cfg: &TracingConfig,
    filter: EnvFilter,
) -> Result<TelemetryGuards, TelemetryError> {
    let wide_log_layer = WideLogLayer::new(tracing_cfg).map_err(TelemetryError::WideLogInit)?;

    init_tracing_with_layer(filter, wide_log_layer)
}

pub fn init_tracing_with_sink(
    filter: EnvFilter,
    tracing_cfg: &TracingConfig,
    sink: crate::wide_log::WideLogSink,
) -> Result<TelemetryGuards, TelemetryError> {
    let wide_log_layer =
        WideLogLayer::new_with_sink(tracing_cfg, sink).map_err(TelemetryError::WideLogInit)?;

    init_tracing_with_layer(filter, wide_log_layer)
}

fn init_tracing_with_layer(
    filter: EnvFilter,
    wide_log_layer: WideLogLayer,
) -> Result<TelemetryGuards, TelemetryError> {
    tracing_subscriber::registry()
        .with(filter)
        .with(wide_log_layer)
        .try_init()
        .map_err(|_| TelemetryError::SubscriberInit)?;

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
    let _ = metrics_facade::install_http_request_observer();
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

    let handle = install_metrics_recorder()?;
    let (layer, handle) = builder.with_metrics_from_fn(|| handle).build_pair();

    Ok(Some(MetricsComponents {
        layer,
        state: Arc::new(MetricsState::new(handle, token)),
    }))
}

fn install_metrics_recorder() -> Result<PrometheusHandle, TelemetryError> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(axum_prometheus::utils::requests_duration_name().to_owned()),
            axum_prometheus::utils::SECONDS_DURATION_BUCKETS,
        )
        .and_then(|builder| {
            builder.set_buckets_for_metric(
                Matcher::Full(
                    metrics_facade::HistogramMetric::HttpStorageOperationDurationSeconds
                        .name()
                        .to_owned(),
                ),
                REQUEST_STORAGE_DURATION_BUCKETS_SECONDS,
            )
        })
        .map_err(|_| TelemetryError::MetricsRecorder)?
        .install_recorder()
        .map_err(|_| TelemetryError::MetricsRecorder)?;
    let upkeep = handle.clone();
    // Preserve the upkeep performed by axum-prometheus's default recorder.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(METRICS_UPKEEP_INTERVAL).await;
            upkeep.run_upkeep();
        }
    });
    Ok(handle)
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
