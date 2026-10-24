use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::{
    CounterMetric, GaugeMetric, HistogramMetric, MetricLabel, MetricsFacade, set_metrics_facade,
};

#[derive(Debug, Default)]
pub(crate) struct CapturingMetrics {
    values: Mutex<BTreeMap<String, Vec<f64>>>,
}

fn key(name: &str, labels: &[MetricLabel]) -> String {
    let mut labels: Vec<_> = labels
        .iter()
        .map(|label| format!("{}={}", label.key(), label.value()))
        .collect();
    labels.sort();
    format!("{name}|{}", labels.join("|"))
}

impl CapturingMetrics {
    fn record(&self, name: &str, labels: &[MetricLabel], value: f64) {
        self.values
            .lock()
            .unwrap()
            .entry(key(name, labels))
            .or_default()
            .push(value);
    }

    pub(crate) fn total(&self, name: &str, labels: &[MetricLabel]) -> f64 {
        self.values
            .lock()
            .unwrap()
            .get(&key(name, labels))
            .map_or(0.0, |values| values.iter().sum())
    }

    pub(crate) fn snapshot(&self) -> BTreeMap<String, Vec<f64>> {
        self.values.lock().unwrap().clone()
    }
}

impl MetricsFacade for CapturingMetrics {
    fn increment_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        self.record(metric.name(), labels, value as f64);
    }
    fn absolute_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        self.values
            .lock()
            .unwrap()
            .insert(key(metric.name(), labels), vec![value as f64]);
    }
    fn increment_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.record(metric.name(), labels, value);
    }
    fn decrement_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.record(metric.name(), labels, -value);
    }
    fn set_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.values
            .lock()
            .unwrap()
            .insert(key(metric.name(), labels), vec![value]);
    }
    fn record_histogram(&self, metric: HistogramMetric, labels: &[MetricLabel], value: f64) {
        self.record(metric.name(), labels, value);
    }
}

pub(crate) struct FacadeRestore(Arc<dyn MetricsFacade>);
impl Drop for FacadeRestore {
    fn drop(&mut self) {
        set_metrics_facade(self.0.clone());
    }
}

impl FacadeRestore {
    pub(crate) fn install(metrics: Arc<dyn MetricsFacade>) -> Self {
        Self(set_metrics_facade(metrics))
    }
}
