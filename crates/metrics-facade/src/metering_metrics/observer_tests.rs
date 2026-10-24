use std::{sync::Arc, time::Duration};

use buffered_writes::{RecordingWriteObserver, WriteAttempt};

use super::test_support::{CapturingMetrics, FacadeRestore};
use crate::{
    AdmissionRejectReason, AdmissionStatus, AtomicSink, BufferStats, BufferedMetering,
    CounterMetric, Deadline, DeliveryMode, DurabilityClass, GaugeMetric, LifecycleError,
    MeteringMetricsObserver, MetricLabel, QuarantineReason, ReplayObservation, RequestCostSnapshot,
    RequestMeasurement, RequestMeteringContext, SinkError, SinkFailureKind, SinkHealth, SinkLimits,
    WriteEvent, WriteObserver,
};

fn mode(metrics: &CapturingMetrics, mode: &'static str) -> f64 {
    metrics.total(
        GaugeMetric::BufferedMeteringWriters.name(),
        &[MetricLabel::new("mode", mode)],
    )
}

fn health(metrics: &CapturingMetrics, health: &'static str) -> f64 {
    metrics.total(
        GaugeMetric::BufferedMeteringSinkWriters.name(),
        &[MetricLabel::new("health", health)],
    )
}

#[test]
fn given_reordered_inspections_when_drain_finishes_then_terminal_gauges_cannot_be_overwritten() {
    for clean in [true, false] {
        let metrics = Arc::new(CapturingMetrics::default());
        let observer = Arc::new(MeteringMetricsObserver::new(metrics.clone()));
        observer.observe(WriteEvent::BufferObserved {
            stats: BufferStats::new(3, 90, Duration::ZERO),
            revision: 2,
        });
        observer.observe(WriteEvent::BufferInspectionFailed { revision: 1 });
        assert_eq!(
            metrics.total(GaugeMetric::BufferedMeteringUnknownBuffers.name(), &[]),
            0.0
        );
        observer.observe(WriteEvent::DrainCompleted {
            elapsed: Duration::ZERO,
            unresolved_items: if clean { 0 } else { 3 },
            unresolved_batches: 0,
            state_unknown: !clean,
            clean,
        });
        let barrier = Arc::new(std::sync::Barrier::new(9));
        std::thread::scope(|threads| {
            for revision in 3..11 {
                let observer = observer.clone();
                let barrier = barrier.clone();
                threads.spawn(move || {
                    barrier.wait();
                    observer.observe(WriteEvent::BufferObserved {
                        stats: BufferStats::new(12, 100, Duration::ZERO),
                        revision,
                    });
                    observer.observe(WriteEvent::BufferInspectionFailed {
                        revision: revision + 10,
                    });
                });
            }
            barrier.wait();
        });
        assert_eq!(
            metrics.total(GaugeMetric::BufferedMeteringObservedItems.name(), &[]),
            if clean { 0.0 } else { 3.0 }
        );
        assert_eq!(
            metrics.total(GaugeMetric::BufferedMeteringObservedBytes.name(), &[]),
            90.0
        );
        assert_eq!(
            metrics.total(GaugeMetric::BufferedMeteringUnknownBuffers.name(), &[]),
            f64::from(!clean)
        );
        drop(observer);
        for (name, samples) in metrics.snapshot() {
            if name.starts_with("buffered_metering_observed_")
                || name.starts_with("buffered_metering_unknown_buffers|")
            {
                let mut total = 0.0;
                for sample in samples {
                    total += sample;
                    assert!(total >= 0.0, "{name}");
                }
                assert_eq!(total, 0.0, "{name}");
            }
        }
    }
}

#[test]
fn given_two_writers_when_observations_fail_reorder_and_drop_then_aggregate_gauges_preserve_last_known_samples_and_balance_to_zero()
 {
    let metrics = Arc::new(CapturingMetrics::default());
    let first = MeteringMetricsObserver::new(metrics.clone());
    let second = MeteringMetricsObserver::new(metrics.clone());
    assert_eq!(mode(&metrics, "buffered"), 2.0);
    assert_eq!(health(&metrics, "closed"), 2.0);
    assert_eq!(
        metrics.total(GaugeMetric::BufferedMeteringUnknownBuffers.name(), &[]),
        2.0
    );
    first.observe(WriteEvent::BufferObserved {
        stats: BufferStats::new(3, 90, Duration::from_secs(2)),
        revision: 1,
    });
    second.observe(WriteEvent::BufferObserved {
        stats: BufferStats::new(2, 50, Duration::from_secs(1)),
        revision: 1,
    });
    first.observe(WriteEvent::BufferInspectionFailed { revision: 2 });
    assert_eq!(
        metrics.total(GaugeMetric::BufferedMeteringObservedItems.name(), &[]),
        5.0
    );
    assert_eq!(
        metrics.total(GaugeMetric::BufferedMeteringObservedBytes.name(), &[]),
        140.0
    );
    assert_eq!(
        metrics.total(GaugeMetric::BufferedMeteringUnknownBuffers.name(), &[]),
        1.0
    );
    first.observe(WriteEvent::ModeChanged {
        from: DeliveryMode::Synchronous,
        to: DeliveryMode::Draining,
        revision: 2,
    });
    assert!(
        mode(&metrics, "synchronous") >= 0.0,
        "an interleaved scrape must not observe a negative writer count"
    );
    first.observe(WriteEvent::ModeChanged {
        from: DeliveryMode::Buffered,
        to: DeliveryMode::Synchronous,
        revision: 1,
    });
    first.observe(WriteEvent::HealthChanged {
        from: SinkHealth::Open,
        to: SinkHealth::HalfOpen,
        revision: 2,
    });
    assert!(
        health(&metrics, "open") >= 0.0,
        "an interleaved scrape must not observe a negative health count"
    );
    first.observe(WriteEvent::HealthChanged {
        from: SinkHealth::Closed,
        to: SinkHealth::Open,
        revision: 1,
    });
    assert_eq!(mode(&metrics, "buffered"), 1.0);
    assert_eq!(mode(&metrics, "synchronous"), 0.0);
    assert_eq!(mode(&metrics, "draining"), 1.0);
    assert_eq!(health(&metrics, "closed"), 1.0);
    assert_eq!(health(&metrics, "open"), 0.0);
    assert_eq!(health(&metrics, "half_open"), 1.0);
    drop(first);
    assert_eq!(
        metrics.total(GaugeMetric::BufferedMeteringObservedItems.name(), &[]),
        2.0
    );
    assert_eq!(
        metrics.total(GaugeMetric::BufferedMeteringObservedBytes.name(), &[]),
        50.0
    );
    assert_eq!(
        metrics.total(GaugeMetric::BufferedMeteringUnknownBuffers.name(), &[]),
        0.0
    );
    assert_eq!(mode(&metrics, "draining"), 0.0);
    assert_eq!(health(&metrics, "half_open"), 0.0);
    drop(second);
    for (name, samples) in metrics.snapshot() {
        if name.starts_with("buffered_metering_writers|")
            || name.starts_with("buffered_metering_sink_writers|")
            || name.starts_with("buffered_metering_observed_")
            || name.starts_with("buffered_metering_unknown_buffers|")
        {
            assert_eq!(samples.iter().sum::<f64>(), 0.0, "{name}");
        }
    }
}

#[test]
fn given_default_facade_observer_when_real_writes_flush_and_drain_then_metrics_have_terminal_state_and_no_customer_labels()
 {
    let _lock = crate::recorder_tests::METRICS_FACADE_TEST_LOCK
        .lock()
        .unwrap();
    let metrics = Arc::new(CapturingMetrics::default());
    let _restore = FacadeRestore::install(metrics.clone());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let sink = AtomicSink::try_new(
                SinkLimits::default(),
                |_: WriteAttempt<RequestMeasurement>| async { Ok::<(), SinkError>(()) },
            )
            .unwrap();
            let facade = BufferedMetering::builder("private-namespace-secret", sink)
                .flush_policy(|_: &BufferStats| false)
                .build()
                .unwrap();
            let measurement = RequestMeasurement::try_new(
                RequestMeteringContext::try_new(
                    "tenant-secret",
                    "execution-secret",
                    Duration::from_secs(2),
                )
                .unwrap(),
                RequestCostSnapshot {
                    request_id: Some("correlation-secret".to_owned()),
                    ..Default::default()
                },
            )
            .unwrap();
            facade.record_request(measurement).await.unwrap();
            facade.after_response().await.unwrap();
            assert_eq!(
                metrics.total(GaugeMetric::BufferedMeteringObservedItems.name(), &[]),
                1.0
            );
            assert_eq!(
                metrics.total(GaugeMetric::BufferedMeteringUnknownBuffers.name(), &[]),
                0.0
            );
            let report = facade
                .shutdown(Deadline::after(Duration::from_secs(2)))
                .await
                .unwrap();
            assert!(report.is_clean());
            assert_eq!(mode(&metrics, "stopped"), 1.0);
            assert_eq!(mode(&metrics, "draining"), 0.0);
            assert_eq!(
                metrics.total(GaugeMetric::BufferedMeteringObservedItems.name(), &[]),
                0.0
            );
            assert_eq!(
                metrics.total(
                    CounterMetric::BufferedMeteringEventsTotal.name(),
                    &[
                        MetricLabel::new("event", "drain"),
                        MetricLabel::new("detail", "clean")
                    ]
                ),
                1.0
            );
            assert_eq!(
                metrics.total(
                    CounterMetric::BufferedMeteringItemsTotal.name(),
                    &[MetricLabel::new("event", "flush_completed")]
                ),
                1.0
            );
            drop(facade);
            assert_eq!(mode(&metrics, "stopped"), 0.0);
        });
    assert!(!format!("{:?}", metrics.snapshot()).contains("secret"));
}

#[test]
fn given_custom_observer_when_metering_runs_then_default_process_metrics_are_not_installed() {
    let _lock = crate::recorder_tests::METRICS_FACADE_TEST_LOCK
        .lock()
        .unwrap();
    let metrics = Arc::new(CapturingMetrics::default());
    let _restore = FacadeRestore::install(metrics.clone());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let sink = AtomicSink::try_new(
                SinkLimits::default(),
                |_: WriteAttempt<RequestMeasurement>| async { Ok::<(), SinkError>(()) },
            )
            .unwrap();
            let observer = RecordingWriteObserver::default();
            let facade = BufferedMetering::builder("custom-observer", sink)
                .with_observer(observer.clone())
                .build()
                .unwrap();
            let report = facade
                .shutdown(Deadline::after(Duration::from_secs(2)))
                .await
                .unwrap();
            assert!(report.is_clean());
            assert!(!observer.events().is_empty());
        });
    assert!(
        !metrics
            .snapshot()
            .keys()
            .any(|key| key.starts_with("buffered_metering_"))
    );
}

#[test]
fn given_failure_and_replay_observations_when_metrics_are_emitted_then_categories_are_bounded_and_unknown_drain_is_not_clean()
 {
    let metrics = Arc::new(CapturingMetrics::default());
    let observer = MeteringMetricsObserver::new(metrics.clone());
    let observations = [
        WriteEvent::Admitted {
            status: AdmissionStatus::Buffered,
            durability: DurabilityClass::Volatile,
            bytes: 20,
        },
        WriteEvent::AdmissionRejected {
            reason: AdmissionRejectReason::Full,
        },
        WriteEvent::BatchSealed {
            operations: 2,
            bytes: 50,
            oldest_age: Duration::from_secs(3),
        },
        WriteEvent::FlushAttempted {
            operations: 2,
            retry_attempt: 0,
        },
        WriteEvent::FlushAttempted {
            operations: 2,
            retry_attempt: 1,
        },
        WriteEvent::FlushFailed {
            kind: SinkFailureKind::UnknownOutcome,
            retrying: true,
        },
        WriteEvent::PartialProgress {
            completed: 1,
            remaining: 1,
        },
        WriteEvent::QueueFailed {
            kind: crate::QueueFailureKind::Unavailable,
        },
        WriteEvent::QueueHandoff {
            operations: 1,
            bytes: 20,
        },
        WriteEvent::ReplayOutcome {
            outcome: ReplayObservation::RetainedForRetry,
        },
        WriteEvent::Quarantined {
            reason: QuarantineReason::PoisonReplayEnvelope,
        },
        WriteEvent::LifecycleSourceFailed {
            error: LifecycleError::SourceUnavailable {
                reason: "source-secret",
            },
        },
        WriteEvent::GuardDroppedBeforeShutdown,
        WriteEvent::DrainCompleted {
            elapsed: Duration::from_millis(30),
            unresolved_items: 0,
            unresolved_batches: 0,
            state_unknown: true,
            clean: false,
        },
    ];
    for observation in observations {
        observer.observe(observation);
    }
    let event = |event, detail| {
        metrics.total(
            CounterMetric::BufferedMeteringEventsTotal.name(),
            &[
                MetricLabel::new("event", event),
                MetricLabel::new("detail", detail),
            ],
        )
    };
    assert_eq!(event("flush_attempt", "initial"), 1.0);
    assert_eq!(event("flush_attempt", "retry"), 1.0);
    assert_eq!(event("flush_failed", "unknown_outcome"), 1.0);
    assert_eq!(event("retry_scheduled", "none"), 1.0);
    assert_eq!(event("replay", "retained_for_retry"), 1.0);
    assert_eq!(event("quarantined", "poison_replay"), 1.0);
    assert_eq!(event("queue_failed", "unavailable"), 1.0);
    assert_eq!(event("drain", "unclean"), 1.0);
    assert_eq!(event("drain", "clean"), 0.0);
    assert_eq!(
        metrics.total(
            CounterMetric::BufferedMeteringItemsTotal.name(),
            &[MetricLabel::new("event", "partial_completed")]
        ),
        1.0
    );
    assert_eq!(
        metrics.total(
            CounterMetric::BufferedMeteringBytesTotal.name(),
            &[MetricLabel::new("event", "queue_handoff")]
        ),
        20.0
    );
    assert!(!format!("{:?}", metrics.snapshot()).contains("secret"));
}
