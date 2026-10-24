use std::time::Duration;

/// Conservative persisted UTC age. A future timestamp has unknown age, so it
/// must not postpone eligible writes or extend a finite replay horizon.
pub(crate) fn conservative_age(first_item_time_ms: i64, now_utc_ms: i64) -> Duration {
    if now_utc_ms < first_item_time_ms {
        Duration::MAX
    } else {
        Duration::from_millis(now_utc_ms.abs_diff(first_item_time_ms))
    }
}

/// Retry backoff cannot strand retained work when persisted UTC moves backward.
/// Lease expiry remains a separate provider-time check.
pub(crate) fn retry_is_due(scheduled_at_ms: i64, retry_at_ms: i64, now_ms: i64) -> bool {
    retry_at_ms <= now_ms || scheduled_at_ms > now_ms
}
