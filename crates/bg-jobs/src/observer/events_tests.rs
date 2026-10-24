use std::sync::{Arc, Mutex};

use crate::*;

const SECRET_STORE_DETAILS: &str = "customer-token=store-secret";

#[derive(Debug)]
struct SecretStoreError(&'static str);

impl std::fmt::Display for SecretStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for SecretStoreError {}

#[derive(Clone, Default)]
struct Collector {
    events: Arc<Mutex<Vec<JobEvent>>>,
    errors: Arc<Mutex<Vec<SafeJobErrorEvent>>>,
}

impl JobObserver for Collector {
    fn observe(&self, event: JobEvent) {
        self.events.lock().expect("collector lock").push(event);
    }

    fn observe_error(&self, event: SafeJobErrorEvent) {
        self.errors.lock().expect("collector lock").push(event);
    }
}

#[test]
fn given_attempt_counts_when_sampling_observer_events_then_buckets_are_bounded() {
    assert_eq!(AttemptBucket::from_attempt(0), AttemptBucket::First);
    assert_eq!(AttemptBucket::from_attempt(1), AttemptBucket::First);
    assert_eq!(AttemptBucket::from_attempt(2), AttemptBucket::Few);
    assert_eq!(AttemptBucket::from_attempt(4), AttemptBucket::Few);
    assert_eq!(AttemptBucket::from_attempt(5), AttemptBucket::Many);
    assert_eq!(AttemptBucket::from_attempt(u32::MAX), AttemptBucket::Many);
}

#[test]
fn given_safe_error_fields_when_constructing_an_event_then_sensitive_details_are_unrepresentable() {
    const CUSTOMER_QUEUE: &str = "customer-account=alice@example.com";
    let queue = QueueName::try_new(CUSTOMER_QUEUE).expect("queue is valid");
    let event = SafeJobErrorEvent {
        kind: SafeJobErrorKind::UnknownCommit,
        queue: Some(queue),
        effect_mode: Some(EffectMode::Idempotent),
    };
    let debug = format!("{event:?}");
    assert_eq!(
        debug,
        "SafeJobErrorEvent { kind: UnknownCommit, effect_mode: Some(Idempotent) }"
    );
    assert!(!debug.contains("payload"));
    assert!(!debug.contains("https://"));
    assert!(!debug.contains("token"));
    assert!(!debug.contains(CUSTOMER_QUEUE));
}

#[test]
fn given_a_customer_bearing_store_error_when_displayed_then_only_its_fixed_category_is_rendered() {
    let error = JobSystemError::Store(SecretStoreError(SECRET_STORE_DETAILS));

    assert_eq!(error.to_string(), "job store failure");
    assert!(!error.to_string().contains(SECRET_STORE_DETAILS));
}

#[test]
fn given_a_customer_bearing_store_error_when_debugged_then_its_details_are_redacted() {
    let error = JobSystemError::Store(SecretStoreError(SECRET_STORE_DETAILS));
    let debug = format!("{error:?}");

    assert_eq!(debug, "Store(<redacted>)");
    assert!(!debug.contains(SECRET_STORE_DETAILS));
}

#[test]
fn given_corrupt_store_data_when_displayed_or_debugged_then_only_its_fixed_category_is_rendered() {
    let error = StoreFailure::Corrupt(StoreDataError::Malformed(SECRET_STORE_DETAILS));

    assert_eq!(error.to_string(), "corrupt store data");
    let debug = format!("{error:?}");
    assert_eq!(debug, "Corrupt(<redacted>)");
    assert!(!debug.contains(SECRET_STORE_DETAILS));
}

#[test]
fn given_the_closed_event_set_when_observing_then_every_variant_has_a_bounded_shape() {
    let queue = QueueName::try_new("default").expect("queue is valid");
    let code = OutcomeCode::try_new("ok").expect("code is valid");
    let events = vec![
        JobEvent::Enqueued {
            queue: queue.clone(),
            disposition: EnqueueDisposition::Enqueued,
        },
        JobEvent::Claimed {
            queue: queue.clone(),
            priority: Priority::Default,
            attempt: AttemptBucket::First,
        },
        JobEvent::Heartbeat {
            queue: queue.clone(),
            coalesced: true,
        },
        JobEvent::RenewalLost {
            queue: queue.clone(),
        },
        JobEvent::Checkpoint {
            queue: queue.clone(),
            bytes: 8,
        },
        JobEvent::Completed {
            queue: queue.clone(),
            effect_mode: EffectMode::Idempotent,
        },
        JobEvent::Continued {
            queue: queue.clone(),
            kind: JobKind::try_new("email").expect("kind"),
        },
        JobEvent::Retried {
            queue: queue.clone(),
            class: RetryClass::Transient,
            attempt: AttemptBucket::Few,
        },
        JobEvent::DeadLettered {
            queue: queue.clone(),
            outcome: code,
        },
        JobEvent::CancellationRequested {
            queue: queue.clone(),
        },
        JobEvent::Cancelled {
            queue: queue.clone(),
        },
        JobEvent::Redriven {
            queue: queue.clone(),
            reused_execution: false,
        },
        JobEvent::Repaired {
            queue: queue.clone(),
        },
        JobEvent::StoreError {
            kind: SafeJobErrorKind::StoreTimeout,
        },
        JobEvent::LeaseConflict {
            queue: queue.clone(),
        },
        JobEvent::DriveStopped {
            reason: DriveStopReason::Shutdown,
        },
    ];
    let collector = Collector::default();
    for event in events {
        collector.observe(event);
    }
    assert_eq!(collector.events.lock().expect("collector lock").len(), 16);
    collector.observe_error(SafeJobErrorEvent {
        kind: SafeJobErrorKind::LeaseLost,
        queue: None,
        effect_mode: None,
    });
    assert_eq!(collector.errors.lock().expect("collector lock").len(), 1);
}
