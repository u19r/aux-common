use std::{
    sync::{Arc, Mutex},
    vec::Vec,
};

use crate::{
    CounterMetric, GaugeMetric, HistogramMetric, MetricLabel, MetricsCrateFacade, MetricsFacade,
    constants::{MAX_METRIC_LABEL_VALUE_BYTES, MAX_METRIC_LABELS, MAX_REGISTERED_METRIC_KEYS},
    counter, gauge, histogram, metrics_crate_facade_cache_snapshot,
    recorder::{allow_test_metric_key, registered_metric_key_count, reset_registered_metric_keys},
    set_metrics_facade,
};

const EXPECTED_CACHE_LIMIT: usize = 256;

pub(crate) static METRICS_FACADE_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Default)]
struct CapturingMetricsFacade {
    calls: Arc<Mutex<Vec<String>>>,
}

impl CapturingMetricsFacade {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn push_call(&self, call: impl Into<String>) {
        self.calls.lock().unwrap().push(call.into());
    }
}

fn format_labels(labels: &[MetricLabel]) -> String {
    labels
        .iter()
        .map(|label| format!("{}={}", label.key(), label.value()))
        .collect::<Vec<_>>()
        .join("|")
}

impl MetricsFacade for CapturingMetricsFacade {
    fn increment_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        self.push_call(format!(
            "counter_increment:{}:{}:{}",
            metric.name(),
            format_labels(labels),
            value
        ));
    }

    fn absolute_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        self.push_call(format!(
            "counter_absolute:{}:{}:{}",
            metric.name(),
            format_labels(labels),
            value
        ));
    }

    fn increment_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.push_call(format!(
            "gauge_increment:{}:{}:{}",
            metric.name(),
            format_labels(labels),
            value
        ));
    }

    fn decrement_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.push_call(format!(
            "gauge_decrement:{}:{}:{}",
            metric.name(),
            format_labels(labels),
            value
        ));
    }

    fn set_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.push_call(format!(
            "gauge_set:{}:{}:{}",
            metric.name(),
            format_labels(labels),
            value
        ));
    }

    fn record_histogram(&self, metric: HistogramMetric, labels: &[MetricLabel], value: f64) {
        self.push_call(format!(
            "histogram_record:{}:{}:{}",
            metric.name(),
            format_labels(labels),
            value
        ));
    }
}
#[test]
fn metrics_handles_delegate_to_installed_facade() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let facade = CapturingMetricsFacade::default();
    let previous = set_metrics_facade(Arc::new(facade.clone()));

    counter!(CounterMetric::StorageOperationTotalMetric, "operation" => "get_item").increment(3);
    gauge!(GaugeMetric::StorageDdbCacheHitRatioMetric, "operation" => "query").set(0.75);
    histogram!(HistogramMetric::StorageOperationLatencyMsMetric, "operation" => "scan")
        .record(12.5);

    assert_eq!(
        facade.calls(),
        vec![
            "counter_increment:storage.operation.total:operation=get_item:3",
            "gauge_set:ddb.cache.hit.ratio:operation=query:0.75",
            "histogram_record:storage.operation.latency.ms:operation=scan:12.5",
        ]
    );

    set_metrics_facade(previous);
}

#[test]
fn metrics_crate_facade_re_registers_against_active_recorder() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let threads = (0..8).map(|_| {
        std::thread::spawn(|| {
            let facade = MetricsCrateFacade;
            for _ in 0..10 {
                facade.record_histogram(
                    HistogramMetric::StorageOperationLatencyMsMetric,
                    &[MetricLabel::new("operation", "cache_snapshot_test")],
                    1.0,
                );
            }
        })
    });

    for thread in threads {
        thread.join().expect("metrics thread should not panic");
    }
}

#[test]
fn metrics_crate_facade_reuses_thread_local_handles() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let before = metrics_crate_facade_cache_snapshot();
    let facade = MetricsCrateFacade;

    for _ in 0..10 {
        facade.record_histogram(
            HistogramMetric::StorageOperationLatencyMsMetric,
            &[MetricLabel::new("operation", "thread_local_cache_test")],
            1.0,
        );
    }

    let after = metrics_crate_facade_cache_snapshot();
    assert_eq!(after.histograms - before.histograms, 1);
}

#[test]
fn dynamic_metric_labels_do_not_grow_the_thread_local_cache_without_bound() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let facade = MetricsCrateFacade;

    for index in 0..=EXPECTED_CACHE_LIMIT {
        facade.record_histogram(
            HistogramMetric::StorageOperationLatencyMsMetric,
            &[MetricLabel::new("operation", format!("untrusted-{index}"))],
            1.0,
        );
    }

    let (_, _, histogram_cache_size) =
        crate::recorder::metrics_crate_facade_thread_local_cache_sizes();
    assert!(
        histogram_cache_size <= EXPECTED_CACHE_LIMIT,
        "dynamic label cache retained {histogram_cache_size} entries"
    );
}

#[test]
fn oversized_metric_labels_are_dropped_before_facade_dispatch() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let facade = CapturingMetricsFacade::default();
    let previous = set_metrics_facade(Arc::new(facade.clone()));

    histogram!(
        HistogramMetric::StorageOperationLatencyMsMetric,
        "operation" => "x".repeat(MAX_METRIC_LABEL_VALUE_BYTES + 1)
    )
    .record(1.0);

    assert!(facade.calls().is_empty());
    set_metrics_facade(previous);
}
#[test]
fn given_valid_labels_when_all_metric_handle_operations_run_then_the_facade_receives_them() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let facade = CapturingMetricsFacade::default();
    let previous = set_metrics_facade(Arc::new(facade.clone()));

    // Given one validated, low-cardinality label shared by each handle kind.
    counter!(CounterMetric::StorageOperationTotalMetric, "operation" => "get").increment(2);
    counter!(CounterMetric::StorageOperationTotalMetric, "operation" => "get").absolute(7);
    gauge!(GaugeMetric::StorageDdbCacheHitRatioMetric, "operation" => "get").increment(0.1);
    gauge!(GaugeMetric::StorageDdbCacheHitRatioMetric, "operation" => "get").decrement(0.2);
    gauge!(GaugeMetric::StorageDdbCacheHitRatioMetric, "operation" => "get").set(0.3);
    histogram!(HistogramMetric::StorageOperationLatencyMsMetric, "operation" => "get").record(4.5);

    // When callers use every supported operation on the installed facade.
    let calls = facade.calls();

    // Then no operation is silently lost at the public handle boundary.
    assert_eq!(
        calls,
        vec![
            "counter_increment:storage.operation.total:operation=get:2",
            "counter_absolute:storage.operation.total:operation=get:7",
            "gauge_increment:ddb.cache.hit.ratio:operation=get:0.1",
            "gauge_decrement:ddb.cache.hit.ratio:operation=get:0.2",
            "gauge_set:ddb.cache.hit.ratio:operation=get:0.3",
            "histogram_record:storage.operation.latency.ms:operation=get:4.5",
        ]
    );

    set_metrics_facade(previous);
}

#[test]
fn given_multiple_labels_when_each_handle_records_then_the_facade_receives_ordered_labels() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let facade = CapturingMetricsFacade::default();
    let previous = set_metrics_facade(Arc::new(facade.clone()));
    let labels = vec![
        MetricLabel::new("tenant", "tenant-a"),
        MetricLabel::new("operation", "query"),
        MetricLabel::new("direction", "read"),
    ];

    // Given a valid multi-label key with a deliberate order.
    crate::counter(CounterMetric::StorageOperationTotalMetric, labels.clone()).increment(1);
    crate::counter(CounterMetric::StorageOperationTotalMetric, labels.clone()).absolute(2);
    crate::gauge(GaugeMetric::StorageDdbCacheHitRatioMetric, labels.clone()).increment(3.0);
    crate::gauge(GaugeMetric::StorageDdbCacheHitRatioMetric, labels.clone()).decrement(4.0);
    crate::gauge(GaugeMetric::StorageDdbCacheHitRatioMetric, labels.clone()).set(5.0);
    crate::histogram(HistogramMetric::StorageOperationLatencyMsMetric, labels).record(6.0);

    // When every handle operation forwards its labels to the active facade.
    // Then all keys and values retain their original order.
    assert_eq!(
        facade.calls(),
        vec![
            "counter_increment:storage.operation.total:\
             tenant=tenant-a|operation=query|direction=read:1",
            "counter_absolute:storage.operation.total:\
             tenant=tenant-a|operation=query|direction=read:2",
            "gauge_increment:ddb.cache.hit.ratio:tenant=tenant-a|operation=query|direction=read:3",
            "gauge_decrement:ddb.cache.hit.ratio:tenant=tenant-a|operation=query|direction=read:4",
            "gauge_set:ddb.cache.hit.ratio:tenant=tenant-a|operation=query|direction=read:5",
            "histogram_record:storage.operation.latency.ms:\
             tenant=tenant-a|operation=query|direction=read:6",
        ]
    );

    set_metrics_facade(previous);
}

#[test]
fn given_invalid_labels_when_recording_each_metric_kind_then_no_dispatch_or_cache_entry_occurs() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let invalid_labels = vec![MetricLabel::new(
        "operation",
        "x".repeat(MAX_METRIC_LABEL_VALUE_BYTES + 1),
    )];
    let facade = CapturingMetricsFacade::default();
    let previous = set_metrics_facade(Arc::new(facade.clone()));

    // Given an invalid label value and an over-cardinality label set.
    let too_many_labels = (0..=MAX_METRIC_LABELS)
        .map(|index| MetricLabel::new("operation", format!("bounded-{index}")))
        .collect::<Vec<_>>();
    let concrete = MetricsCrateFacade;
    let concrete_before = metrics_crate_facade_cache_snapshot();
    concrete.increment_counter(
        CounterMetric::StorageOperationTotalMetric,
        &invalid_labels,
        1,
    );
    concrete.absolute_counter(
        CounterMetric::StorageOperationTotalMetric,
        &too_many_labels,
        1,
    );
    concrete.increment_gauge(
        GaugeMetric::StorageDdbCacheHitRatioMetric,
        &invalid_labels,
        1.0,
    );
    concrete.decrement_gauge(
        GaugeMetric::StorageDdbCacheHitRatioMetric,
        &too_many_labels,
        1.0,
    );
    concrete.set_gauge(
        GaugeMetric::StorageDdbCacheHitRatioMetric,
        &invalid_labels,
        1.0,
    );
    concrete.record_histogram(
        HistogramMetric::StorageOperationLatencyMsMetric,
        &too_many_labels,
        1.0,
    );
    assert_eq!(metrics_crate_facade_cache_snapshot(), concrete_before);

    // When the same rejected inputs reach public handles backed by a capturing
    // facade.
    let before = metrics_crate_facade_cache_snapshot();
    crate::counter(
        CounterMetric::StorageOperationTotalMetric,
        invalid_labels.clone(),
    )
    .increment(1);
    crate::counter(
        CounterMetric::StorageOperationTotalMetric,
        invalid_labels.clone(),
    )
    .absolute(1);
    crate::gauge(
        GaugeMetric::StorageDdbCacheHitRatioMetric,
        invalid_labels.clone(),
    )
    .increment(1.0);
    crate::gauge(
        GaugeMetric::StorageDdbCacheHitRatioMetric,
        invalid_labels.clone(),
    )
    .decrement(1.0);
    crate::gauge(
        GaugeMetric::StorageDdbCacheHitRatioMetric,
        invalid_labels.clone(),
    )
    .set(1.0);
    crate::histogram(
        HistogramMetric::StorageOperationLatencyMsMetric,
        invalid_labels,
    )
    .record(1.0);
    crate::counter(
        CounterMetric::StorageOperationTotalMetric,
        too_many_labels.clone(),
    )
    .increment(1);
    crate::gauge(
        GaugeMetric::StorageDdbCacheHitRatioMetric,
        too_many_labels.clone(),
    )
    .set(1.0);
    crate::histogram(
        HistogramMetric::StorageOperationLatencyMsMetric,
        too_many_labels,
    )
    .record(1.0);
    let after = metrics_crate_facade_cache_snapshot();

    // When rejected inputs reach the public handles and concrete facade.
    // Then no operation is dispatched and no thread-local cache entry is
    // consumed.
    assert!(facade.calls().is_empty());
    assert_eq!(after, before);

    set_metrics_facade(previous);
}

#[test]
fn given_isolated_registered_key_registry_when_capacity_is_reached_then_overflow_is_a_noop() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    reset_registered_metric_keys();

    // Given an empty, isolated registry and unique bounded metric keys.
    for index in 0..MAX_REGISTERED_METRIC_KEYS {
        assert!(allow_test_metric_key(format!("within-{index}")));
    }
    assert_eq!(registered_metric_key_count(), MAX_REGISTERED_METRIC_KEYS);

    // When a new key is presented after the global bound is full.
    assert!(!allow_test_metric_key("overflow".to_owned()));

    // Then overflow remains a deterministic no-op without affecting existing
    // keys.
    assert!(!allow_test_metric_key("overflow".to_owned()));
    assert!(allow_test_metric_key("within-0".to_owned()));
    assert_eq!(registered_metric_key_count(), MAX_REGISTERED_METRIC_KEYS);

    reset_registered_metric_keys();
    assert_eq!(registered_metric_key_count(), 0);
}

#[test]
fn given_valid_labels_when_metrics_crate_facade_records_each_kind_then_handles_are_cached() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    let facade = MetricsCrateFacade;
    let labels = [MetricLabel::new("operation", "cache-boundary")];
    let before = metrics_crate_facade_cache_snapshot();

    // Given the concrete facade owns one cache key per metric kind and label
    // set.
    facade.increment_counter(CounterMetric::StorageOperationTotalMetric, &labels, 1);
    facade.absolute_counter(CounterMetric::StorageOperationTotalMetric, &labels, 2);
    facade.increment_gauge(GaugeMetric::StorageDdbCacheHitRatioMetric, &labels, 1.0);
    facade.decrement_gauge(GaugeMetric::StorageDdbCacheHitRatioMetric, &labels, 1.0);
    facade.set_gauge(GaugeMetric::StorageDdbCacheHitRatioMetric, &labels, 1.0);
    facade.record_histogram(
        HistogramMetric::StorageOperationLatencyMsMetric,
        &labels,
        1.0,
    );
    facade.record_histogram(
        HistogramMetric::StorageOperationLatencyMsMetric,
        &labels,
        2.0,
    );

    // When the same handles are used repeatedly.
    let after = metrics_crate_facade_cache_snapshot();

    // Then each cache grows once, while repeated values reuse its bounded
    // entry.
    assert_eq!(after.counters - before.counters, 1);
    assert_eq!(after.gauges - before.gauges, 1);
    assert_eq!(after.histograms - before.histograms, 1);
}

/// A panicking guarded section (or any future one like it) must not disable
/// metric-key registration for the process lifetime. The probe temporarily
/// swaps the process-global panic hook, so it serializes behind the facade
/// test lock.
#[test]
fn given_poisoned_registered_key_registry_then_new_metric_keys_still_register() {
    let _guard = METRICS_FACADE_TEST_LOCK.lock().unwrap();
    reset_registered_metric_keys();

    crate::recorder::poison_registered_keys_for_test();

    assert!(
        allow_test_metric_key("post-poison".to_owned()),
        "metric key registration must recover from a poisoned guard"
    );
    assert_eq!(registered_metric_key_count(), 1);

    reset_registered_metric_keys();
    assert_eq!(registered_metric_key_count(), 0);
}
