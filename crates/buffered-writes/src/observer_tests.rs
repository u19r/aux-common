use jiff::Timestamp;

use super::{Clock as _, TestClock, utc_millis};

#[test]
fn given_fractional_epoch_times_when_converted_then_milliseconds_round_down() {
    for (input, expected) in [
        ("1969-12-31T23:59:59.999999999Z", -1),
        ("1969-12-31T23:59:59.998999999Z", -2),
        ("1969-12-31T23:59:59.999Z", -1),
        ("1970-01-01T00:00:00Z", 0),
        ("1970-01-01T00:00:00.000999999Z", 0),
        ("1970-01-01T00:00:00.001Z", 1),
    ] {
        assert_eq!(utc_millis(input.parse::<Timestamp>().unwrap()), expected);
    }
}

#[test]
fn given_millisecond_test_clock_when_read_then_persisted_time_is_unchanged() {
    for millis in [-1_000_001, -1, 0, 1, 1_761_000_000_000] {
        assert_eq!(
            utc_millis(TestClock::with_utc_millis(millis).now_utc()),
            millis
        );
    }
}
