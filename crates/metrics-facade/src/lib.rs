#![doc(hidden)]

mod handles;
mod metrics;
#[cfg(test)]
mod metrics_tests;
mod recorder;
#[cfg(feature = "request-cost")]
mod request_cost;
#[cfg(all(test, feature = "request-cost"))]
mod request_cost_tests;

#[cfg(feature = "request-cost")]
pub use crate::request_cost::{
    CostResponseHeaders, DatabaseCallGuard, RequestCostDatabaseCallEntry, RequestCostSnapshot,
    RequestCostStorageBreakdown, RequestCostStorageBreakdownEntry, RequestCostStorageDirection,
    active_request_id, begin_database_call, begin_request_cost_collection,
    finish_request_cost_collection, record_analytics_request_cost_by_request_id,
    set_request_cost_operation,
};
#[cfg(not(feature = "request-cost"))]
#[derive(Debug, Default)]
pub struct DatabaseCallGuard;

#[cfg(not(feature = "request-cost"))]
#[must_use]
pub fn begin_database_call(_operation: &str) -> DatabaseCallGuard {
    DatabaseCallGuard
}
pub use crate::{
    handles::{counter, gauge, histogram},
    metrics::{CounterMetric, GaugeMetric, HistogramMetric},
    recorder::{
        CounterHandle, GaugeHandle, HistogramHandle, MetricLabel, MetricsCrateFacade,
        MetricsCrateFacadeCacheSnapshot, MetricsFacade, active_metrics_facade,
        metrics_crate_facade_cache_snapshot, reset_metrics_facade, set_metrics_facade,
    },
};

#[macro_export]
macro_rules! counter {
    ($metric:expr $(,)?) => {
        $crate::counter($metric, ::std::vec::Vec::new())
    };
    ($metric:expr, $($label_key:expr => $label_value:expr),+ $(,)?) => {
        $crate::counter(
            $metric,
            ::std::vec![
                $(
                    $crate::MetricLabel::new($label_key, $label_value)
                ),+
            ],
        )
    };
}

#[macro_export]
macro_rules! gauge {
    ($metric:expr $(,)?) => {
        $crate::gauge($metric, ::std::vec::Vec::new())
    };
    ($metric:expr, $($label_key:expr => $label_value:expr),+ $(,)?) => {
        $crate::gauge(
            $metric,
            ::std::vec![
                $(
                    $crate::MetricLabel::new($label_key, $label_value)
                ),+
            ],
        )
    };
}

#[macro_export]
macro_rules! histogram {
    ($metric:expr $(,)?) => {
        $crate::histogram($metric, ::std::vec::Vec::new())
    };
    ($metric:expr, $($label_key:expr => $label_value:expr),+ $(,)?) => {
        $crate::histogram(
            $metric,
            ::std::vec![
                $(
                    $crate::MetricLabel::new($label_key, $label_value)
                ),+
            ],
        )
    };
}
