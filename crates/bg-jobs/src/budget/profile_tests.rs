use std::time::Duration;

use crate::{
    DriveBudget, DriveBudgetInput, DriveProfile, DriveProfileInput, MAX_INLINE_PAYLOAD_BYTES,
    MonotonicDeadline, QueueName, QueueSelection, ValidationError,
};

fn profile_input() -> DriveProfileInput {
    DriveProfileInput {
        queues: QueueSelection::only(vec![
            QueueName::try_new("periodic").expect("queue is valid"),
        ])
        .expect("queue selection is valid"),
        max_claims: 4,
        max_concurrency: 2,
        max_payload_bytes_in_flight: 4096,
        max_completion_details: 4,
        max_store_operations: 32,
        stop_claiming_after: Duration::from_secs(4),
        finish_after: Duration::from_secs(5),
    }
}

#[test]
fn given_a_valid_profile_when_requesting_at_a_clock_value_then_deadlines_are_bounded() {
    let profile = DriveProfile::try_from(profile_input()).expect("profile is valid");

    let request = profile
        .request_at(MonotonicDeadline::from_nanos(10))
        .expect("profile produces a request");

    assert_eq!(request.max_claims().get(), 4);
    assert_eq!(request.max_concurrency().get(), 2);
    assert_eq!(request.stop_claiming_at().as_nanos(), 4_000_000_010);
    assert_eq!(request.finish_by().as_nanos(), 5_000_000_010);
}

#[test]
fn given_bounded_budget_when_requesting_then_safe_payload_defaults_are_applied() {
    let budget = DriveBudget::try_from(DriveBudgetInput {
        queues: QueueSelection::all(),
        max_claims: 4,
        max_concurrency: 2,
        max_store_operations: 32,
        stop_claiming_after: Duration::from_secs(4),
        finish_after: Duration::from_secs(5),
    })
    .expect("budget is valid");

    let request = budget
        .request_at(MonotonicDeadline::ZERO)
        .expect("budget produces a request");

    assert_eq!(request.max_completion_details(), 4);
    assert_eq!(
        request.max_payload_bytes_in_flight().get(),
        MAX_INLINE_PAYLOAD_BYTES
    );
}

#[test]
fn given_zero_budget_values_when_constructing_then_validation_rejects_them() {
    for (field, input) in [
        (
            "max claims",
            DriveProfileInput {
                max_claims: 0,
                ..profile_input()
            },
        ),
        (
            "max concurrency",
            DriveProfileInput {
                max_concurrency: 0,
                ..profile_input()
            },
        ),
        (
            "max payload bytes in flight",
            DriveProfileInput {
                max_payload_bytes_in_flight: 0,
                ..profile_input()
            },
        ),
        (
            "max store operations",
            DriveProfileInput {
                max_store_operations: 0,
                ..profile_input()
            },
        ),
    ] {
        assert!(matches!(
            DriveProfile::try_from(input),
            Err(ValidationError::InvalidValue { field: actual }) if actual == field
        ));
    }
}

#[test]
fn given_completion_details_above_claims_when_constructing_then_validation_rejects_them() {
    let input = DriveProfileInput {
        max_completion_details: 5,
        ..profile_input()
    };

    assert!(matches!(
        DriveProfile::try_from(input),
        Err(ValidationError::InvalidValue {
            field: "max completion details"
        })
    ));
}

#[test]
fn given_finish_before_stop_when_constructing_then_validation_rejects_the_ordering() {
    let input = DriveProfileInput {
        stop_claiming_after: Duration::from_secs(5),
        finish_after: Duration::from_secs(4),
        ..profile_input()
    };

    assert!(matches!(
        DriveProfile::try_from(input),
        Err(ValidationError::Ordering {
            field: "drive durations"
        })
    ));
}

#[test]
fn given_an_oversized_duration_when_constructing_then_validation_rejects_the_overflow() {
    let input = DriveProfileInput {
        stop_claiming_after: Duration::from_secs(u64::MAX),
        ..profile_input()
    };

    assert!(matches!(
        DriveProfile::try_from(input),
        Err(ValidationError::Overflow {
            field: "stop claiming duration"
        })
    ));
}

#[test]
fn given_a_clock_near_the_deadline_limit_when_requesting_then_overflow_is_rejected() {
    let profile = DriveProfile::try_from(profile_input()).expect("profile is valid");
    let now = MonotonicDeadline::from_nanos(u64::MAX - 1);

    assert!(matches!(
        profile.request_at(now),
        Err(ValidationError::Overflow {
            field: "drive deadline"
        })
    ));
}

#[test]
fn given_zero_claims_when_converting_worker_budget_then_validation_rejects_it() {
    assert_eq!(
        DriveBudget::try_from(DriveBudgetInput {
            queues: QueueSelection::all(),
            max_claims: 0,
            max_concurrency: 2,
            max_store_operations: 32,
            stop_claiming_after: Duration::from_secs(4),
            finish_after: Duration::from_secs(5),
        }),
        Err(ValidationError::InvalidValue {
            field: "max claims"
        })
    );
}
