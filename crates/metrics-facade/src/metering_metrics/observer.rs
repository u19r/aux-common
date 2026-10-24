use std::{sync::Arc, time::Duration};

use buffered_writes::{WriteEvent, WriteObserver};

use super::{buffer_metric::BufferMetric, labels, state_metric::StateMetric};
use crate::{
    CounterMetric, GaugeMetric, HistogramMetric, MetricLabel, MetricsFacade, active_metrics_facade,
    constants::{METERING_HEALTH_LABELS, METERING_MODE_LABELS},
};

/// Bounded process metrics for buffered metering, without tenant, namespace or
/// operation labels. Gauges sum the last local writer observations; shared
/// remote buffers can be observed by more than one writer. Buffer ages are
/// sampled histograms, not continuously advancing gauges.
pub struct MeteringMetricsObserver {
    facade: Arc<dyn MetricsFacade>,
    mode: StateMetric,
    health: StateMetric,
    buffer: BufferMetric,
}

impl MeteringMetricsObserver {
    #[must_use]
    pub fn new(facade: Arc<dyn MetricsFacade>) -> Self {
        Self {
            mode: StateMetric::new(
                facade.clone(),
                GaugeMetric::BufferedMeteringWriters,
                "mode",
                &METERING_MODE_LABELS,
            ),
            health: StateMetric::new(
                facade.clone(),
                GaugeMetric::BufferedMeteringSinkWriters,
                "health",
                &METERING_HEALTH_LABELS,
            ),
            buffer: BufferMetric::new(facade.clone()),
            facade,
        }
    }

    fn record_event(&self, event: &'static str, detail: &'static str) {
        self.facade.increment_counter(
            CounterMetric::BufferedMeteringEventsTotal,
            &[
                MetricLabel::new("event", event),
                MetricLabel::new("detail", detail),
            ],
            1,
        );
    }

    fn record_volume(&self, event: &'static str, items: usize, bytes: Option<usize>) {
        let labels = [MetricLabel::new("event", event)];
        self.facade.increment_counter(
            CounterMetric::BufferedMeteringItemsTotal,
            &labels,
            u64::try_from(items).unwrap_or(u64::MAX),
        );
        if let Some(bytes) = bytes {
            self.facade.increment_counter(
                CounterMetric::BufferedMeteringBytesTotal,
                &labels,
                u64::try_from(bytes).unwrap_or(u64::MAX),
            );
        }
    }

    fn record_duration(&self, phase: &'static str, duration: Duration) {
        self.facade.record_histogram(
            HistogramMetric::BufferedMeteringDurationSeconds,
            &[MetricLabel::new("phase", phase)],
            duration.as_secs_f64(),
        );
    }

    fn record_age(&self, phase: &'static str, age: Duration) {
        self.facade.record_histogram(
            HistogramMetric::BufferedMeteringBatchAgeSeconds,
            &[MetricLabel::new("phase", phase)],
            age.as_secs_f64(),
        );
    }

    fn observe_writes(&self, event: WriteEvent) {
        match event {
            WriteEvent::Admitted {
                status,
                durability,
                bytes,
            } => {
                self.record_event("admitted", labels::admission(status));
                self.record_event("durability", labels::durability(durability));
                self.record_volume("admitted", 1, Some(bytes));
            }
            WriteEvent::AdmissionRejected { reason } => {
                self.record_event("admission_rejected", labels::rejection(reason))
            }
            WriteEvent::BatchSealed {
                operations,
                bytes,
                oldest_age,
            } => {
                self.record_event("sealed", "none");
                self.record_volume("sealed", operations, Some(bytes));
                self.record_age("sealed", oldest_age);
            }
            remaining => self.observe_delivery(remaining),
        }
    }

    fn observe_delivery(&self, event: WriteEvent) {
        match event {
            WriteEvent::FlushAttempted {
                operations,
                retry_attempt,
            } => {
                self.record_event("flush_attempt", labels::attempt(retry_attempt));
                self.record_volume("flush_attempt", operations, None);
            }
            WriteEvent::FlushCompleted {
                operations,
                elapsed,
            } => {
                self.record_event("flush_completed", "none");
                self.record_volume("flush_completed", operations, None);
                self.record_duration("flush", elapsed);
            }
            WriteEvent::FlushFailed { kind, retrying } => {
                self.record_event("flush_failed", labels::failure(kind));
                if retrying {
                    self.record_event("retry_scheduled", "none");
                }
            }
            remaining => self.observe_recovery(remaining),
        }
    }

    fn observe_recovery(&self, event: WriteEvent) {
        match event {
            WriteEvent::PartialProgress {
                completed,
                remaining,
            } => {
                self.record_event("partial_progress", "none");
                self.record_volume("partial_completed", completed, None);
                self.record_volume("partial_remaining", remaining, None);
            }
            WriteEvent::QueueHandoff { operations, bytes } => {
                self.record_event("queue_handoff", "none");
                self.record_volume("queue_handoff", operations, Some(bytes));
            }
            WriteEvent::QueueFailed { kind } => {
                self.record_event("queue_failed", labels::queue_failure(kind))
            }
            WriteEvent::ReplayOutcome { outcome } => {
                self.record_event("replay", labels::replay(outcome))
            }
            WriteEvent::Quarantined { reason } => {
                self.record_event("quarantined", labels::quarantine(reason))
            }
            // These events have already been emitted by their owning
            // observation stage.
            WriteEvent::Admitted { .. }
            | WriteEvent::AdmissionRejected { .. }
            | WriteEvent::BatchSealed { .. }
            | WriteEvent::FlushAttempted { .. }
            | WriteEvent::FlushCompleted { .. }
            | WriteEvent::FlushFailed { .. }
            | WriteEvent::ModeChanged { .. }
            | WriteEvent::HealthChanged { .. }
            | WriteEvent::DrainCompleted { .. }
            | WriteEvent::GuardDroppedBeforeShutdown
            | WriteEvent::LifecycleSourceFailed { .. }
            | WriteEvent::BufferObserved { .. }
            | WriteEvent::BufferInspectionFailed { .. } => {}
        }
    }
}

impl Default for MeteringMetricsObserver {
    fn default() -> Self {
        Self::new(active_metrics_facade())
    }
}

impl std::fmt::Debug for MeteringMetricsObserver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MeteringMetricsObserver")
    }
}

impl WriteObserver for MeteringMetricsObserver {
    fn observe(&self, event: WriteEvent) {
        match event {
            WriteEvent::ModeChanged { to, revision, .. } => {
                self.mode.observe(revision, labels::mode(to));
                self.record_event(
                    "mode_changed",
                    crate::constants::METERING_MODE_LABELS[labels::mode(to)],
                );
            }
            WriteEvent::HealthChanged { to, revision, .. } => {
                self.health.observe(revision, labels::health(to));
                self.record_event(
                    "health_changed",
                    crate::constants::METERING_HEALTH_LABELS[labels::health(to)],
                );
            }
            remaining => self.observe_lifecycle(remaining),
        }
    }
}

impl MeteringMetricsObserver {
    fn observe_lifecycle(&self, event: WriteEvent) {
        match event {
            WriteEvent::BufferObserved { stats, revision } => {
                self.buffer.observe(revision, Some(stats));
                if stats.items() > 0 {
                    self.record_age("observed", stats.oldest_age());
                }
            }
            WriteEvent::BufferInspectionFailed { revision } => {
                self.buffer.observe(revision, None);
                self.record_event("buffer_inspection_failed", "none");
            }
            WriteEvent::DrainCompleted {
                elapsed,
                unresolved_items,
                unresolved_batches,
                state_unknown,
                clean,
            } => {
                self.record_drain_outcome(elapsed, state_unknown, clean);
                self.record_volume("drain_unresolved_items", unresolved_items, None);
                self.record_volume("drain_unresolved_batches", unresolved_batches, None);
            }
            WriteEvent::GuardDroppedBeforeShutdown => {
                self.record_event("guard_dropped", "shutdown_incomplete")
            }
            WriteEvent::LifecycleSourceFailed { .. } => {
                self.record_event("lifecycle_failed", "none")
            }
            remaining => self.observe_writes(remaining),
        }
    }

    fn record_drain_outcome(&self, elapsed: Duration, state_unknown: bool, clean: bool) {
        self.record_event("drain", if clean { "clean" } else { "unclean" });
        self.buffer.finish(state_unknown, clean);
        self.record_duration("drain", elapsed);
    }
}
