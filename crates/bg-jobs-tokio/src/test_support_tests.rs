use std::time::Duration;

use bg_jobs::{Timestamp, runtime::MonotonicDeadline};

use crate::test_support::{JobClock, TestClock};

#[test]
fn given_a_virtual_clock_when_advanced_then_both_domains_move_together() {
    let clock = TestClock::new(
        Timestamp::from_millis(10),
        MonotonicDeadline::from_nanos(20),
    );

    clock.advance(Duration::from_millis(5));

    assert_eq!(clock.wall_now(), Timestamp::from_millis(15));
    assert_eq!(
        clock.monotonic_now(),
        MonotonicDeadline::from_nanos(5_000_020)
    );
}

#[test]
fn given_a_virtual_clock_when_set_then_both_domains_are_replaced() {
    let clock = TestClock::new(Timestamp::ZERO, MonotonicDeadline::ZERO);

    clock.set(
        Timestamp::from_millis(42),
        MonotonicDeadline::from_nanos(99),
    );

    assert_eq!(clock.wall_now(), Timestamp::from_millis(42));
    assert_eq!(clock.monotonic_now(), MonotonicDeadline::from_nanos(99));
}
