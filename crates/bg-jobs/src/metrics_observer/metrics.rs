use metrics_facade::{CounterMetric, counter};

use crate::{
    JobEvent, JobObserver, SafeJobErrorEvent, SafeJobErrorKind, budget::DriveStopReason,
    model::EnqueueDisposition, policy::RetryClass,
};

/// Closed HTTP classes accepted by the first-party observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMetricOutcome {
    Complete,
    Retry,
    DeadLetter,
}

/// Closed batch item classes accepted by the first-party observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchMetricOutcome {
    Complete,
    Retry,
    DeadLetter,
    Missing,
    Duplicate,
}

/// Metrics observer with only registration-owned or closed labels.
#[derive(Debug, Default)]
pub struct MetricsObserver;

impl MetricsObserver {
    pub const fn new() -> Self {
        Self
    }

    pub fn observe_http(&self, outcome: HttpMetricOutcome) {
        counter!(
            CounterMetric::MetricHttpRequestAttempts,
            "classification" => http_outcome_label(outcome)
        )
        .increment(1);
    }

    pub fn observe_batch(&self, outcome: BatchMetricOutcome) {
        counter!(
            CounterMetric::BgWorkerItemsProcessedTotalMetric,
            "outcome" => batch_outcome_label(outcome)
        )
        .increment(1);
    }
}

impl JobObserver for MetricsObserver {
    fn observe(&self, event: JobEvent) {
        match event {
            JobEvent::AttemptStarted {
                queue,
                kind,
                due_delay,
            } => super::diagnostics::observe_attempt_started(queue, kind, due_delay),
            JobEvent::AttemptFinished {
                queue,
                kind,
                duration,
            } => super::diagnostics::observe_attempt_finished(queue, kind, duration),
            JobEvent::CapacityLimited { resource } => {
                super::diagnostics::observe_capacity(resource)
            }
            JobEvent::StoreOperationsReserved { operations } => {
                super::diagnostics::observe_reserved(operations)
            }
            JobEvent::StoreOperation { operation } => {
                super::diagnostics::observe_store_call(operation)
            }
            JobEvent::Continued { queue, kind } => {
                super::diagnostics::observe_continued(queue, kind)
            }
            JobEvent::Enqueued { queue, disposition } => observe_enqueued(queue, disposition),
            JobEvent::Claimed { queue, .. } => observe_claimed(queue),
            JobEvent::Completed { queue, .. } => observe_completed(queue),
            JobEvent::Retried { queue, class, .. } => observe_retried(queue, class),
            JobEvent::DeadLettered { queue, .. } => observe_dead_letter(queue),
            JobEvent::LeaseConflict { queue } => observe_lease_conflict(queue),
            JobEvent::StoreError { kind } => count_store_error(kind),
            JobEvent::DriveStopped { reason } => count_stop(reason),
            JobEvent::Heartbeat { .. }
            | JobEvent::RenewalLost { .. }
            | JobEvent::Checkpoint { .. }
            | JobEvent::CancellationRequested { .. }
            | JobEvent::Cancelled { .. }
            | JobEvent::Suspended { .. }
            | JobEvent::Resumed { .. }
            | JobEvent::Redriven { .. }
            | JobEvent::Repaired { .. } => {}
        }
    }

    fn observe_error(&self, event: SafeJobErrorEvent) {
        counter!(
            CounterMetric::BgWorkerProcessErrorsTotalMetric,
            "error" => safe_error_label(event.kind)
        )
        .increment(1);
    }
}

fn observe_enqueued(queue: crate::QueueName, disposition: EnqueueDisposition) {
    count_queue(
        CounterMetric::BgJobsRunsTotalMetric,
        &queue,
        disposition_label(disposition),
    );
}

fn observe_claimed(queue: crate::QueueName) {
    count_queue(
        CounterMetric::BgWorkerItemsProcessedTotalMetric,
        &queue,
        "claimed",
    );
}

fn observe_completed(queue: crate::QueueName) {
    count_queue(
        CounterMetric::BgWorkerItemsProcessedTotalMetric,
        &queue,
        "completed",
    );
}

fn observe_retried(queue: crate::QueueName, class: RetryClass) {
    count_queue(
        CounterMetric::BgJobsRunErrorsTotalMetric,
        &queue,
        retry_label(class),
    );
}

fn observe_dead_letter(queue: crate::QueueName) {
    count_queue(
        CounterMetric::BgWorkerProcessErrorsTotalMetric,
        &queue,
        "dead_letter",
    );
}

fn observe_lease_conflict(queue: crate::QueueName) {
    count_queue(
        CounterMetric::BgWorkerLeaseConflictsTotalMetric,
        &queue,
        "conflict",
    );
}

fn count_store_error(kind: SafeJobErrorKind) {
    counter!(
        CounterMetric::BgWorkerProcessErrorsTotalMetric,
        "error" => safe_error_label(kind)
    )
    .increment(1);
}

fn count_stop(reason: DriveStopReason) {
    counter!(
        CounterMetric::BgJobsRunsTotalMetric,
        "stop_reason" => stop_reason_label(reason)
    )
    .increment(1);
}

fn count_queue(metric: CounterMetric, queue: &crate::QueueName, outcome: &'static str) {
    counter!(metric, "queue" => queue.as_str(), "outcome" => outcome).increment(1);
}

fn disposition_label(disposition: EnqueueDisposition) -> &'static str {
    match disposition {
        EnqueueDisposition::Enqueued => "enqueued",
        EnqueueDisposition::AlreadyPresent => "already_present",
        EnqueueDisposition::Deduplicated => "deduplicated",
    }
}

fn retry_label(class: RetryClass) -> &'static str {
    match class {
        RetryClass::Transient => "transient",
        RetryClass::Throttled => "throttled",
        RetryClass::AmbiguousEffect => "ambiguous_effect",
    }
}

fn http_outcome_label(outcome: HttpMetricOutcome) -> &'static str {
    match outcome {
        HttpMetricOutcome::Complete => "complete",
        HttpMetricOutcome::Retry => "retry",
        HttpMetricOutcome::DeadLetter => "dead_letter",
    }
}

fn batch_outcome_label(outcome: BatchMetricOutcome) -> &'static str {
    match outcome {
        BatchMetricOutcome::Complete => "complete",
        BatchMetricOutcome::Retry => "retry",
        BatchMetricOutcome::DeadLetter => "dead_letter",
        BatchMetricOutcome::Missing => "missing",
        BatchMetricOutcome::Duplicate => "duplicate",
    }
}

fn safe_error_label(kind: SafeJobErrorKind) -> &'static str {
    match kind {
        SafeJobErrorKind::StoreUnavailable => "store_unavailable",
        SafeJobErrorKind::StoreTimeout => "store_timeout",
        SafeJobErrorKind::UnknownCommit => "unknown_commit",
        SafeJobErrorKind::LeaseLost => "lease_lost",
        SafeJobErrorKind::PayloadCorrupt => "payload_corrupt",
        SafeJobErrorKind::UnregisteredHandler => "unregistered_handler",
        SafeJobErrorKind::InvariantViolation => "invariant_violation",
        SafeJobErrorKind::RepairConflict => "repair_conflict",
    }
}

fn stop_reason_label(reason: DriveStopReason) -> &'static str {
    match reason {
        DriveStopReason::ClaimsExhausted => "claims_exhausted",
        DriveStopReason::Deadline => "deadline",
        DriveStopReason::NoVisibleWork => "no_visible_work",
        DriveStopReason::Capacity => "capacity",
        DriveStopReason::StoreFailure => "store_failure",
        DriveStopReason::Shutdown => "shutdown",
    }
}
