use std::sync::Arc;

use super::{state_metric::StateMetric, test_support::CapturingMetrics};
use crate::{GaugeMetric, MetricLabel, recorder_tests::METRICS_FACADE_TEST_LOCK};

fn mode_total(metrics: &CapturingMetrics, mode: &'static str) -> f64 {
    metrics.total(
        GaugeMetric::BufferedMeteringWriters.name(),
        &[MetricLabel::new("mode", mode)],
    )
}

/// A panicking guarded section (or any future one like it) must not disable
/// the delivery-mode gauge transitions for the process lifetime. The poison
/// probe temporarily swaps the process-global panic hook, so the two tests
/// that use it serialize behind the facade test lock.
#[test]
fn given_poisoned_state_when_observed_then_mode_gauge_still_transitions() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let metrics = Arc::new(CapturingMetrics::default());
    let mode_metric = StateMetric::new(
        metrics.clone(),
        GaugeMetric::BufferedMeteringWriters,
        "mode",
        &["buffered", "synchronous", "draining", "stopped"],
    );

    mode_metric.poison_state_for_test();

    // Same state no-op, then the actual transition must still happen.
    mode_metric.observe(1, 0);
    assert_eq!(mode_total(&metrics, "buffered"), 1.0);

    mode_metric.observe(2, 1);
    assert_eq!(mode_total(&metrics, "synchronous"), 1.0);
    assert_eq!(mode_total(&metrics, "buffered"), 0.0);

    mode_metric.observe(3, 3);
    assert_eq!(mode_total(&metrics, "stopped"), 1.0);
}

#[test]
fn given_poisoned_state_when_older_revision_arrives_then_revision_order_still_holds() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let metrics = Arc::new(CapturingMetrics::default());
    let mode_metric = StateMetric::new(
        metrics.clone(),
        GaugeMetric::BufferedMeteringWriters,
        "mode",
        &["buffered", "synchronous", "draining", "stopped"],
    );

    mode_metric.poison_state_for_test();
    mode_metric.observe(5, 2);
    assert_eq!(mode_total(&metrics, "draining"), 1.0);

    // A delayed older callback cannot subtract a state this observer never
    // saw and cannot walk the gauge backward.
    mode_metric.observe(4, 1);
    assert_eq!(mode_total(&metrics, "synchronous"), 0.0);
    assert_eq!(mode_total(&metrics, "draining"), 1.0);
    assert_eq!(mode_total(&metrics, "buffered"), 0.0);
}
