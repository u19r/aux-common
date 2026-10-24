use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use super::clock::DriveClock;
use crate::{MonotonicDeadline, Timestamp, ValidationError};

#[test]
fn given_elapsed_monotonic_time_when_sampling_then_wall_time_and_lease_deadline_agree() {
    let nanos = Arc::new(AtomicU64::new(10));
    let sample = Arc::clone(&nanos);
    let clock = DriveClock::new(
        move || MonotonicDeadline::from_nanos(sample.load(Ordering::SeqCst)),
        Timestamp::from_millis(12000),
    );
    nanos.store(2_000_000_010, Ordering::SeqCst);
    assert_eq!(
        clock.wall_now().expect("time advances"),
        Timestamp::from_millis(14000)
    );
    assert_eq!(
        clock
            .deadline_at(Timestamp::from_millis(14000))
            .expect("deadline fits"),
        clock.now()
    );
}

#[test]
fn given_a_regressing_clock_when_sampling_wall_time_then_invalid_clock_is_rejected() {
    let nanos = Arc::new(AtomicU64::new(10));
    let sample = Arc::clone(&nanos);
    let clock = DriveClock::new(
        move || MonotonicDeadline::from_nanos(sample.load(Ordering::SeqCst)),
        Timestamp::ZERO,
    );
    nanos.store(9, Ordering::SeqCst);
    assert!(matches!(
        clock.wall_now(),
        Err(ValidationError::InvalidValue {
            field: "monotonic clock"
        })
    ));
}

#[test]
fn given_a_wall_time_overflow_when_time_advances_then_typed_overflow_is_returned() {
    let nanos = Arc::new(AtomicU64::new(0));
    let sample = Arc::clone(&nanos);
    let clock = DriveClock::new(
        move || MonotonicDeadline::from_nanos(sample.load(Ordering::SeqCst)),
        Timestamp::from_millis(i64::MAX - 1),
    );
    nanos.store(2_000_000, Ordering::SeqCst);
    assert!(matches!(
        clock.wall_now(),
        Err(ValidationError::Overflow { field: "timestamp" })
    ));
}
