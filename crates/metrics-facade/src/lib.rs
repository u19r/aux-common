#![doc(hidden)]

mod constants;
mod handles;
#[cfg(all(feature = "http-observer", not(target_arch = "wasm32")))]
mod http_request_observer;
#[cfg(all(test, feature = "http-observer", not(target_arch = "wasm32")))]
mod http_request_observer_tests;
mod macros;
mod metrics;
#[cfg(test)]
mod metrics_tests;
mod recorder;
#[cfg(test)]
mod recorder_tests;
#[cfg(feature = "request-cost")]
mod request_cost;
mod request_cost_context;
#[cfg(all(test, feature = "request-cost"))]
mod request_cost_context_tests;
#[cfg(feature = "request-cost")]
mod request_cost_finalization;
#[cfg(all(test, feature = "request-cost"))]
mod request_cost_tests;

#[cfg(feature = "request-cost")]
pub use crate::request_cost::{
    CostResponseHeaders, DatabaseCallGuard, RequestCostDatabaseCallEntry, RequestCostSnapshot,
    RequestCostStorageBreakdown, RequestCostStorageBreakdownEntry, RequestCostStorageDirection,
    active_request_id, begin_database_call, begin_request_cost_collection,
    record_analytics_request_cost_by_request_id, set_request_cost_operation,
};
#[cfg(not(feature = "request-cost"))]
mod request_cost_disabled;
pub use request_cost_context::{RequestCostContext, inherit_request_cost};

#[cfg(all(feature = "http-observer", not(target_arch = "wasm32")))]
pub use crate::http_request_observer::{
    HttpRequestMetricsObserver, http_request_observer, install_http_request_observer,
};
#[cfg(not(feature = "request-cost"))]
pub use crate::request_cost_disabled::{DatabaseCallGuard, begin_database_call};
pub use crate::{
    handles::{counter, gauge, histogram},
    metrics::{CounterMetric, GaugeMetric, HistogramMetric},
    recorder::{
        CounterHandle, GaugeHandle, HistogramHandle, MetricLabel, MetricsCrateFacade,
        MetricsCrateFacadeCacheSnapshot, MetricsFacade, active_metrics_facade,
        metrics_crate_facade_cache_snapshot, reset_metrics_facade, set_metrics_facade,
    },
};

#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
mod buffered_metering;
#[cfg(all(feature = "buffered-lambda", not(target_arch = "wasm32")))]
mod error;
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
mod metering_builder;
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
mod metering_runtime;
#[cfg(all(test, feature = "buffered-lambda", not(target_arch = "wasm32")))]
mod metering_runtime_tests;
#[cfg(all(feature = "buffered-lambda", not(target_arch = "wasm32")))]
pub use error::MeteringSetupError;
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
mod metering_metrics;
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
pub use metering_metrics::MeteringMetricsObserver;
#[cfg(all(test, feature = "buffered-metering", not(target_arch = "wasm32")))]
mod buffered_metering_tests;
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
mod metering_encoding;
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
pub use buffered_metering::BufferedMetering;
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
pub use buffered_writes::{
    Admission, AdmissionRejectReason, AdmissionStatus, AtomicSink, BatchId, BufferCapacity,
    BufferConfig, BufferError, BufferStats, Clock, ConfigurationError, Deadline, DeliveryMode,
    DeliveryPolicy, DrainReport, DurabilityClass, FlushPolicy, FlushReport, FlushReportSummary,
    FlushThresholds, Lifecycle, LifecycleError, LifecycleEvents, Namespace, OperationId,
    QuarantineReason, QueueConfig, QueueError, QueueFailureKind, ReplayGuarantee,
    ReplayObservation, RuntimeGuard, SinkError, SinkFailureKind, SinkHealth, SinkLimits,
    TenantScope, TokioLifecycle, WriteError as MeteringError, WriteEvent, WriteObserver,
    WriteOutcome, WriteSink,
};
#[cfg(all(feature = "buffered-ec2", not(target_arch = "wasm32")))]
pub use buffered_writes::{ImdsSpotSource, SpotLifecycle};
#[cfg(all(feature = "buffered-lambda", not(target_arch = "wasm32")))]
pub use buffered_writes::{
    LambdaExtensionClient, LambdaExtensionServer, LambdaInvocation, LambdaIpcConfig,
};
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
pub use metering_builder::MeteringBuilder;
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
pub use metering_encoding::{RequestMeasurement, RequestMeteringContext};
#[cfg(all(feature = "buffered-metering", not(target_arch = "wasm32")))]
pub type MeteringAttempt = buffered_writes::WriteAttempt<RequestMeasurement>;

#[cfg(feature = "request-cost")]
pub use request_cost_finalization::{
    RequestCostSettlementError, finish_request_cost_collection, finish_request_cost_snapshot,
};
