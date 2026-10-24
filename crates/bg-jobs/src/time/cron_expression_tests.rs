use chrono::{TimeZone, Utc};

use crate::{
    error::ValidationError,
    time::{CronExpression, Timestamp},
};

fn timestamp(year: i32, month: u32, day: u32, hour: u32, minute: u32) -> Timestamp {
    Timestamp::from_millis(
        Utc.with_ymd_and_hms(year, month, day, hour, minute, 0)
            .single()
            .expect("test date is valid")
            .timestamp_millis(),
    )
}

#[test]
fn given_whitespace_around_a_five_field_expression_when_parsing_then_utc_fields_are_canonical() {
    let expression = CronExpression::try_new("  0   5 * * 1  ").expect("portable cron parses");

    assert_eq!(expression.as_str(), "0 5 * * 1");
    assert_eq!(
        expression
            .next_at_or_after(timestamp(2024, 1, 1, 5, 0))
            .expect("next occurrence computes"),
        Some(timestamp(2024, 1, 1, 5, 0))
    );
}

#[test]
fn given_non_portable_cron_forms_when_parsing_then_validation_rejects_before_evaluation() {
    for expression in [
        "0 0 * *",          // four fields
        "0 0 0 * * *",      // seconds field
        "0 0 * * * 2026",   // year field
        "@daily",           // alias
        "0 0 * * ?",        // provider wildcard
        "0 0 L * *",        // last-day extension
        "0 0 1W * *",       // nearest-weekday extension
        "0 0 * * 1#2",      // nth-weekday extension
        "TZ=UTC 0 0 * * *", // timezone prefix
    ] {
        assert!(
            CronExpression::try_new(expression).is_err(),
            "expression should be rejected: {expression}"
        );
    }
}

#[test]
fn given_calendar_edges_when_calculating_occurrences_then_utc_leap_days_and_month_lengths_hold() {
    let leap_day = CronExpression::try_new("0 0 29 2 *").expect("leap-day cron parses");
    assert_eq!(
        leap_day
            .next_at_or_after(timestamp(2020, 1, 1, 0, 0))
            .expect("leap-day occurrence computes"),
        Some(timestamp(2020, 2, 29, 0, 0))
    );
    assert_eq!(
        leap_day
            .next_after(timestamp(2020, 2, 29, 0, 0))
            .expect("next leap-day occurrence computes"),
        Some(timestamp(2024, 2, 29, 0, 0))
    );

    let month_end = CronExpression::try_new("0 0 31 * *").expect("month-end cron parses");
    assert_eq!(
        month_end
            .next_at_or_after(timestamp(2024, 4, 1, 0, 0))
            .expect("month-end occurrence computes"),
        Some(timestamp(2024, 5, 31, 0, 0))
    );
}

#[test]
fn given_posix_weekday_ranges_when_calculating_occurrences_then_sunday_zero_and_seven_are_equivalent()
 {
    let zero_range = CronExpression::try_new("0 0 * * 0-7").expect("weekday range parses");
    let seven_range = CronExpression::try_new("0 0 * * 1-7").expect("weekday range parses");
    let monday = timestamp(2024, 1, 1, 0, 0);
    let tuesday = timestamp(2024, 1, 2, 0, 0);

    assert_eq!(zero_range.next_at_or_after(monday), Ok(Some(monday)));
    assert_eq!(zero_range.next_after(monday), Ok(Some(tuesday)));
    assert_eq!(seven_range.next_at_or_after(monday), Ok(Some(monday)));
    assert_eq!(seven_range.next_after(monday), Ok(Some(tuesday)));
}

#[test]
fn given_an_exact_boundary_when_requesting_next_occurrences_then_at_or_after_is_inclusive() {
    let expression = CronExpression::try_new("*/15 * * * *").expect("quarter-hour cron parses");
    let boundary = timestamp(2024, 2, 29, 12, 30);

    assert_eq!(
        expression
            .next_at_or_after(boundary)
            .expect("inclusive occurrence computes"),
        Some(boundary)
    );
    assert_eq!(
        expression
            .next_after(boundary)
            .expect("strict occurrence computes"),
        Some(timestamp(2024, 2, 29, 12, 45))
    );
}

#[test]
fn given_an_oversized_cron_input_when_parsing_then_the_parser_is_not_reached() {
    let expression = "x".repeat(CronExpression::MAX_INPUT_BYTES + 1);

    assert_eq!(
        CronExpression::try_new(expression),
        Err(ValidationError::TooLong {
            field: "cron expression",
            maximum: CronExpression::MAX_INPUT_BYTES,
            actual: CronExpression::MAX_INPUT_BYTES + 1,
        })
    );
}

#[test]
fn given_an_oversized_cron_field_when_parsing_then_the_parser_is_not_reached() {
    let expression = format!(
        "{} 0 * * *",
        "1".repeat(CronExpression::MAX_FIELD_BYTES + 1)
    );

    assert!(matches!(
        CronExpression::try_new(expression),
        Err(ValidationError::TooLong {
            field: "cron field",
            maximum: CronExpression::MAX_FIELD_BYTES,
            ..
        })
    ));
}

#[test]
fn given_too_many_cron_segments_when_parsing_then_the_parser_is_not_reached() {
    let segments = std::iter::repeat_n("1", CronExpression::MAX_SEGMENTS + 1)
        .collect::<Vec<_>>()
        .join(",");
    let expression = format!("{segments} 0 * * *");

    assert!(matches!(
        CronExpression::try_new(expression),
        Err(ValidationError::TooLong {
            field: "cron segments",
            maximum: CronExpression::MAX_SEGMENTS,
            ..
        })
    ));
}
