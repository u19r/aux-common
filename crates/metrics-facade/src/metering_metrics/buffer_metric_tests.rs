use std::{sync::Arc, time::Duration};

use buffered_writes::BufferStats;

use super::{buffer_metric::BufferMetric, test_support::CapturingMetrics};
use crate::{GaugeMetric, recorder_tests::METRICS_FACADE_TEST_LOCK};

fn observed_items_total(metrics: &CapturingMetrics) -> f64 {
    metrics.total(GaugeMetric::BufferedMeteringObservedItems.name(), &[])
}

fn observed_bytes_total(metrics: &CapturingMetrics) -> f64 {
    metrics.total(GaugeMetric::BufferedMeteringObservedBytes.name(), &[])
}

/// A panicking guarded section (or any future one like it) must not disable
/// the buffer gauges for the process lifetime.
#[test]
fn given_poisoned_state_when_buffer_is_observed_then_gauges_still_transition() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let metrics = Arc::new(CapturingMetrics::default());
    let buffer_metric = BufferMetric::new(metrics.clone());

    buffer_metric.poison_state_for_test();

    buffer_metric.observe(1, Some(BufferStats::new(3, 90, Duration::ZERO)));
    assert_eq!(
        observed_items_total(&metrics),
        3.0,
        "observed items recorded after poisoning"
    );
    assert_eq!(
        observed_bytes_total(&metrics),
        90.0,
        "observed bytes recorded after poisoning"
    );
    assert_eq!(
        metrics.total(GaugeMetric::BufferedMeteringUnknownBuffers.name(), &[]),
        0.0,
        "unknown marker cleared after poisoning"
    );

    buffer_metric.observe(2, Some(BufferStats::new(5, 120, Duration::ZERO)));
    assert_eq!(observed_items_total(&metrics), 5.0);
    assert_eq!(observed_bytes_total(&metrics), 120.0);
}

#[test]
fn given_poisoned_state_when_older_revision_arrives_then_revision_order_still_holds() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let metrics = Arc::new(CapturingMetrics::default());
    let buffer_metric = BufferMetric::new(metrics.clone());

    buffer_metric.poison_state_for_test();
    buffer_metric.observe(5, Some(BufferStats::new(4, 40, Duration::ZERO)));

    // A stale revision cannot walk the state backward.
    buffer_metric.observe(4, Some(BufferStats::new(999, 999, Duration::ZERO)));
    assert_eq!(observed_items_total(&metrics), 4.0);
}
