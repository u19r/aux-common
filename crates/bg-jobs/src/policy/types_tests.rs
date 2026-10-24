use std::{
    num::{NonZeroU16, NonZeroU32},
    time::Duration,
};

use crate::*;

fn policy_input(
    maximum_attempts: NonZeroU16,
    maximum_age: Duration,
    minimum_backoff: Duration,
    maximum_backoff: Duration,
    multiplier: u32,
) -> RetryPolicyInput {
    RetryPolicyInput {
        maximum_attempts,
        maximum_age,
        minimum_backoff,
        maximum_backoff,
        multiplier: BackoffMultiplier::try_from(multiplier).expect("test multiplier is positive"),
    }
}

#[test]
fn given_named_retry_presets_when_expanded_then_attempts_age_backoff_and_jitter_match_exactly() {
    let cases = [
        (
            RetryPreset::Interactive,
            180,
            Duration::from_secs(120),
            Duration::from_millis(100),
            Duration::from_secs(5),
        ),
        (
            RetryPreset::Network,
            180,
            Duration::from_secs(86_400),
            Duration::from_secs(1),
            Duration::from_secs(900),
        ),
        (
            RetryPreset::Maintenance,
            180,
            Duration::from_secs(604_800),
            Duration::from_secs(5),
            Duration::from_secs(21_600),
        ),
    ];

    for (preset, attempts, age, minimum, maximum) in cases {
        let policy = RetryPolicy::preset(preset);
        assert_eq!(policy.maximum_attempts().get(), attempts);
        assert_eq!(policy.maximum_age(), age);
        assert_eq!(policy.minimum_backoff(), minimum);
        assert_eq!(policy.maximum_backoff(), maximum);
        assert_eq!(policy.multiplier().get(), 2);
        assert_eq!(policy.jitter(), FullJitter);
        assert_eq!(preset.backoff_cap(NonZeroU16::MIN), minimum);
        assert_eq!(preset.backoff_cap(NonZeroU16::MAX), maximum);
    }
}

#[test]
fn given_preset_limits_when_selected_then_only_valid_tighter_limits_are_applied() {
    let selected = RetryPreset::Maintenance
        .with_limits(NonZeroU16::new(5).unwrap(), Duration::from_secs(300))
        .unwrap();
    let policy = RetryPolicy::from(selected);
    assert_eq!(policy.maximum_attempts().get(), 5);
    assert_eq!(policy.minimum_backoff(), Duration::from_secs(5));
    assert_eq!(policy.maximum_backoff(), Duration::from_secs(300));
    assert_eq!(policy.maximum_age(), Duration::from_secs(604_800));
    assert_eq!(policy.multiplier().get(), 2);
    assert_eq!(policy.jitter(), FullJitter);
    let unbounded = RetryPolicy::from(
        RetryPreset::Maintenance
            .with_limits(NonZeroU16::MAX, Duration::MAX)
            .unwrap(),
    );
    assert_eq!(unbounded, RetryPolicy::preset(RetryPreset::Maintenance));
    assert!(
        RetryPreset::Maintenance
            .with_limits(NonZeroU16::MIN, Duration::ZERO)
            .is_err()
    );
    assert!(
        RetryPreset::Maintenance
            .with_limits(NonZeroU16::MIN, Duration::from_secs(4))
            .is_err()
    );
    let delayed = RetryPreset::Maintenance
        .with_backoff(Duration::from_secs(30), Duration::from_secs(300))
        .unwrap();
    assert_eq!(
        delayed.backoff_cap(NonZeroU16::MIN),
        Duration::from_secs(30)
    );
    assert_eq!(
        delayed.backoff_cap(NonZeroU16::new(3).unwrap()),
        Duration::from_secs(120)
    );
    assert_eq!(
        delayed.backoff_cap(NonZeroU16::MAX),
        Duration::from_secs(300)
    );
    assert!(
        RetryPreset::Maintenance
            .with_backoff(Duration::ZERO, Duration::from_secs(300))
            .is_err()
    );
    assert!(
        RetryPreset::Maintenance
            .with_backoff(Duration::from_secs(30), Duration::from_secs(29))
            .is_err()
    );
}

#[test]
fn given_zero_or_contradictory_retry_limits_when_constructing_a_policy_then_validation_fails() {
    let attempts = NonZeroU16::new(1).expect("non-zero attempts");
    let valid = |age, minimum, maximum| policy_input(attempts, age, minimum, maximum, 2);

    assert!(matches!(
        RetryPolicy::try_from(valid(
            Duration::ZERO,
            Duration::from_millis(1),
            Duration::from_millis(1)
        )),
        Err(ValidationError::InvalidValue {
            field: "retry maximum age"
        })
    ));
    assert!(matches!(
        RetryPolicy::try_from(valid(
            Duration::from_secs(1),
            Duration::ZERO,
            Duration::from_millis(1)
        )),
        Err(ValidationError::InvalidValue {
            field: "retry minimum backoff"
        })
    ));
    assert!(matches!(
        RetryPolicy::try_from(valid(
            Duration::from_secs(1),
            Duration::from_millis(2),
            Duration::from_millis(1)
        )),
        Err(ValidationError::Ordering {
            field: "retry backoff"
        })
    ));
    assert!(matches!(
        RetryPolicy::try_from(valid(
            Duration::from_secs(1),
            Duration::from_millis(1),
            Duration::ZERO
        )),
        Err(ValidationError::InvalidValue {
            field: "retry maximum backoff"
        })
    ));
    assert!(NonZeroU16::new(0).is_none());
    assert!(NonZeroU32::new(0).is_none());
}

#[test]
fn given_retry_durations_beyond_persisted_nanos_when_constructing_a_policy_then_overflow_fails_closed()
 {
    let attempts = NonZeroU16::new(1).expect("non-zero attempts");
    let overflowing = Duration::new(u64::MAX, 999_999_999);
    let input = policy_input(
        attempts,
        Duration::from_secs(1),
        Duration::from_millis(1),
        overflowing,
        2,
    );

    assert!(matches!(
        RetryPolicy::try_from(input),
        Err(ValidationError::Overflow {
            field: "retry duration"
        })
    ));
}

#[test]
fn given_full_jitter_backoff_windows_when_calculating_caps_then_caps_stay_inside_the_declared_window()
 {
    let policy = RetryPolicy::try_from(policy_input(
        NonZeroU16::new(8).expect("non-zero attempts"),
        Duration::from_secs(60),
        Duration::from_millis(100),
        Duration::from_millis(500),
        2,
    ))
    .expect("policy is valid");

    for attempt in 1..=8 {
        let attempt = NonZeroU16::new(attempt).expect("loop starts at one");
        let cap = policy.backoff_cap(attempt);
        assert!(cap >= policy.minimum_backoff());
        assert!(cap <= policy.maximum_backoff());
    }
    assert_eq!(
        policy.backoff_cap(NonZeroU16::new(1).unwrap()),
        Duration::from_millis(100)
    );
    assert_eq!(
        policy.backoff_cap(NonZeroU16::new(3).unwrap()),
        Duration::from_millis(400)
    );
    assert_eq!(
        policy.backoff_cap(NonZeroU16::new(4).unwrap()),
        Duration::from_millis(500)
    );
}
