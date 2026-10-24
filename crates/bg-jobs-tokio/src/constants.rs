use std::time::Duration;

pub(crate) const DRIVE_RECOVERY_WAKE: Duration = Duration::from_secs(5);

pub(crate) const MINIMUM_QUEUE_RECEIVE_RETRY: Duration = Duration::from_millis(1);
pub(crate) const MINIMUM_LEASE_RENEWAL_INTERVAL: Duration = Duration::from_millis(1);
