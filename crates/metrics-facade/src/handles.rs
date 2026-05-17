use crate::{
    CounterHandle, CounterMetric, GaugeHandle, GaugeMetric, HistogramHandle, HistogramMetric,
    MetricLabel,
};

#[must_use]
pub fn counter(metric: CounterMetric, labels: Vec<MetricLabel>) -> CounterHandle {
    CounterHandle::new(metric, labels)
}

#[must_use]
pub fn gauge(metric: GaugeMetric, labels: Vec<MetricLabel>) -> GaugeHandle {
    GaugeHandle::new(metric, labels)
}

#[must_use]
pub fn histogram(metric: HistogramMetric, labels: Vec<MetricLabel>) -> HistogramHandle {
    HistogramHandle::new(metric, labels)
}
