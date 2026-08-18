use std::{
    sync::{Arc, Mutex},
    vec::Vec,
};

use crate::{
    CounterMetric, GaugeMetric, HistogramMetric, MetricLabel, MetricsCrateFacade, MetricsFacade,
    counter, gauge, histogram, metrics_crate_facade_cache_snapshot,
    recorder::MAX_METRIC_LABEL_VALUE_BYTES, set_metrics_facade,
};

const EXPECTED_CACHE_LIMIT: usize = 256;

#[test]
fn authz_projection_operation_metric_has_stable_name() {
    assert_eq!(
        CounterMetric::AuthzProjectionOperationsTotal.name(),
        "authz.projection.operations_total"
    );
}

static METRICS_FACADE_TEST_LOCK: Mutex<()> = Mutex::new(());

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

impl MetricsFacade for CapturingMetricsFacade {
    fn increment_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        self.push_call(format!(
            "counter_increment:{}:{}:{}",
            metric.name(),
            labels[0].value(),
            value
        ));
    }

    fn absolute_counter(&self, metric: CounterMetric, _labels: &[MetricLabel], value: u64) {
        self.push_call(format!("counter_absolute:{}:{}", metric.name(), value));
    }

    fn increment_gauge(&self, metric: GaugeMetric, labels: &[MetricLabel], value: f64) {
        self.push_call(format!(
            "gauge_increment:{}:{}:{}",
            metric.name(),
            labels[0].value(),
            value
        ));
    }

    fn decrement_gauge(&self, metric: GaugeMetric, _labels: &[MetricLabel], value: f64) {
        self.push_call(format!("gauge_decrement:{}:{}", metric.name(), value));
    }

    fn set_gauge(&self, metric: GaugeMetric, _labels: &[MetricLabel], value: f64) {
        self.push_call(format!("gauge_set:{}:{}", metric.name(), value));
    }

    fn record_histogram(&self, metric: HistogramMetric, labels: &[MetricLabel], value: f64) {
        self.push_call(format!(
            "histogram_record:{}:{}:{}",
            metric.name(),
            labels[0].value(),
            value
        ));
    }
}

#[test]
fn storage_cache_metric_names_match_expected_ddb_operation_pattern() {
    assert_eq!(
        CounterMetric::StorageDdbGetItemCacheHitMetric.name(),
        "ddb.get.item.cache.hit"
    );
    assert_eq!(
        CounterMetric::StorageDdbGetItemCacheMissMetric.name(),
        "ddb.get.item.cache.miss"
    );
    assert_eq!(
        CounterMetric::StorageDdbBatchGetItemCacheHitMetric.name(),
        "ddb.batch.get.item.cache.hit"
    );
    assert_eq!(
        CounterMetric::StorageDdbBatchGetItemCacheHitPartialMetric.name(),
        "ddb.batch.get.item.cache.hit.partial"
    );
    assert_eq!(
        CounterMetric::StorageDdbBatchGetItemCacheMissMetric.name(),
        "ddb.batch.get.item.cache.miss"
    );
    assert_eq!(
        CounterMetric::StorageDdbQueryCacheHitMetric.name(),
        "ddb.query.cache.hit"
    );
    assert_eq!(
        CounterMetric::StorageDdbQueryCacheHitPartialMetric.name(),
        "ddb.query.cache.hit.partial"
    );
    assert_eq!(
        CounterMetric::StorageDdbQueryCacheMissMetric.name(),
        "ddb.query.cache.miss"
    );
    assert_eq!(
        CounterMetric::StorageDdbAuthoritativePreimageHitMetric.name(),
        "ddb.authoritative.preimage.hit"
    );
    assert_eq!(
        CounterMetric::StorageDdbAuthoritativePreimageMissMetric.name(),
        "ddb.authoritative.preimage.miss"
    );
    assert_eq!(
        CounterMetric::StorageDdbGuardConflictFallbackMetric.name(),
        "ddb.guard.conflict.fallback"
    );
    assert_eq!(
        CounterMetric::StorageDdbGuardUnsupportedFallbackMetric.name(),
        "ddb.guard.unsupported.fallback"
    );
    assert_eq!(
        GaugeMetric::StorageDdbCacheHitRatioMetric.name(),
        "ddb.cache.hit.ratio"
    );
    assert_eq!(
        GaugeMetric::MetricFederatedProvisionEnabledSources.name(),
        "authn.federated.provision_enabled_sources"
    );
}

#[test]
fn limits_capacity_metric_names_are_stable() {
    assert_eq!(
        CounterMetric::LimitsExpiryReclaimedTotal.name(),
        "limits.expiry.reclaimed.total"
    );
    assert_eq!(
        CounterMetric::LimitsExpiryRowsScannedTotal.name(),
        "limits.expiry.rows.scanned.total"
    );
    assert_eq!(
        CounterMetric::LimitsExpirySweepsTotal.name(),
        "limits.expiry.sweeps.total"
    );
    assert_eq!(
        CounterMetric::LimitsTransitionConflictsTotal.name(),
        "limits.transition.conflicts.total"
    );
    assert_eq!(
        CounterMetric::LimitsTransitionTotal.name(),
        "limits.transition.total"
    );
    assert_eq!(
        HistogramMetric::LimitsExpirySweepDurationMs.name(),
        "limits.expiry.sweep.duration.ms"
    );
    assert_eq!(
        HistogramMetric::LimitsTransitionDurationMs.name(),
        "limits.transition.duration.ms"
    );
}

#[test]
fn managed_tenant_metric_names_match_expected_operational_surface() {
    assert_eq!(
        CounterMetric::ManagedTenantDecisionsTotal.name(),
        "managed_tenant_decisions_total"
    );
    assert_eq!(
        CounterMetric::ManagedTenantQuotaDenialsTotal.name(),
        "managed_tenant_quota_denials_total"
    );
    assert_eq!(
        CounterMetric::ManagedTenantTemplateApplyTotal.name(),
        "managed_tenant_template_apply_total"
    );
    assert_eq!(
        CounterMetric::ManagedTenantSupportSessionTransitionsTotal.name(),
        "managed_tenant_support_session_transitions_total"
    );
    assert_eq!(
        CounterMetric::ManagedTenantSuspensionsTotal.name(),
        "managed_tenant_suspensions_total"
    );
}

#[test]
fn authn_identity_security_metric_names_match_expected_nist_surface() {
    assert_eq!(
        CounterMetric::MetricAuthnAuthenticationAttemptTotal.name(),
        "authn.authentication_attempt_total"
    );
    assert_eq!(
        CounterMetric::MetricAuthnAuthenticatorDisabledTotal.name(),
        "authn.authenticator_disabled_total"
    );
    assert_eq!(
        CounterMetric::MetricAuthnRecoveryAttemptTotal.name(),
        "authn.recovery_attempt_total"
    );
    assert_eq!(
        HistogramMetric::MetricAuthnLockoutDurationMs.name(),
        "authn.lockout_duration_ms"
    );
    assert_eq!(
        CounterMetric::MetricAuthnSupportInterventionTotal.name(),
        "authn.support_intervention_total"
    );
    assert_eq!(
        CounterMetric::MetricAuthnAuthenticatorLifecycleTotal.name(),
        "authn.authenticator_lifecycle_total"
    );
    assert_eq!(
        CounterMetric::MetricAuthnSessionAssuranceTotal.name(),
        "authn.session_assurance_total"
    );
    assert_eq!(
        CounterMetric::MetricAuthnFraudReportTotal.name(),
        "authn.fraud_report_total"
    );
    assert_eq!(
        HistogramMetric::MetricAuthnFraudResolutionMs.name(),
        "authn.fraud_resolution_ms"
    );
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
            "counter_increment:storage.operation.total:get_item:3",
            "gauge_set:ddb.cache.hit.ratio:0.75",
            "histogram_record:storage.operation.latency.ms:scan:12.5",
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
