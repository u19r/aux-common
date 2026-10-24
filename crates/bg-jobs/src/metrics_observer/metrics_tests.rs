use crate::*;

#[test]
fn given_all_closed_http_and_batch_outcomes_when_observed_then_only_bounded_labels_are_used() {
    let observer = MetricsObserver::new();
    for outcome in [
        HttpMetricOutcome::Complete,
        HttpMetricOutcome::Retry,
        HttpMetricOutcome::DeadLetter,
    ] {
        observer.observe_http(outcome);
    }
    for outcome in [
        BatchMetricOutcome::Complete,
        BatchMetricOutcome::Retry,
        BatchMetricOutcome::DeadLetter,
        BatchMetricOutcome::Missing,
        BatchMetricOutcome::Duplicate,
    ] {
        observer.observe_batch(outcome);
    }
}

#[test]
fn given_every_lifecycle_event_when_observed_then_counter_histogram_and_gauge_paths_remain_safe() {
    let observer = MetricsObserver::new();
    let queue = QueueName::try_new("metrics-test").expect("queue");
    let code = OutcomeCode::try_new("ok").expect("outcome code");
    let events = [
        JobEvent::Enqueued {
            queue: queue.clone(),
            disposition: EnqueueDisposition::Enqueued,
        },
        JobEvent::Claimed {
            queue: queue.clone(),
            priority: Priority::Critical,
            attempt: AttemptBucket::First,
        },
        JobEvent::Completed {
            queue: queue.clone(),
            effect_mode: EffectMode::Fenced,
        },
        JobEvent::Retried {
            queue: queue.clone(),
            class: RetryClass::AmbiguousEffect,
            attempt: AttemptBucket::Many,
        },
        JobEvent::DeadLettered {
            queue: queue.clone(),
            outcome: code,
        },
        JobEvent::LeaseConflict { queue },
        JobEvent::StoreError {
            kind: SafeJobErrorKind::UnknownCommit,
        },
        JobEvent::DriveStopped {
            reason: DriveStopReason::Deadline,
        },
    ];
    for event in events {
        observer.observe(event);
    }
    observer.observe_error(SafeJobErrorEvent {
        kind: SafeJobErrorKind::InvariantViolation,
        queue: None,
        effect_mode: None,
    });
}

#[test]
fn given_debug_output_when_metrics_observer_is_rendered_then_it_contains_no_dynamic_state() {
    let rendered = format!("{:?}", MetricsObserver::new());
    assert_eq!(rendered, "MetricsObserver");
}
