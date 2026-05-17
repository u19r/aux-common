#![doc(hidden)]

mod handles;
mod metrics;
#[cfg(test)]
mod metrics_tests;
mod recorder;
mod request_cost;

pub use crate::{
    handles::{counter, gauge, histogram},
    metrics::{CounterMetric, GaugeMetric, HistogramMetric},
    recorder::{
        CounterHandle, GaugeHandle, HistogramHandle, MetricLabel, MetricsCrateFacade,
        MetricsCrateFacadeCacheSnapshot, MetricsFacade, active_metrics_facade,
        metrics_crate_facade_cache_snapshot, reset_metrics_facade, set_metrics_facade,
    },
    request_cost::{
        CostResponseHeaders, RequestCostSnapshot, RequestCostStorageBreakdown,
        RequestCostStorageBreakdownEntry, RequestCostStorageDirection, active_request_id,
        begin_request_cost_collection, finish_request_cost_collection,
        record_analytics_request_cost_by_request_id,
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
