use core::fmt;
use std::time::Duration;

use crate::error::ValidationError;

/// Signed Unix epoch milliseconds used for persisted scheduling state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Timestamp(i64);

impl Timestamp {
    pub const ZERO: Self = Self(0);

    pub const fn from_millis(milliseconds: i64) -> Self {
        Self(milliseconds)
    }

    pub const fn as_millis(self) -> i64 {
        self.0
    }

    pub fn checked_add(self, duration: Duration) -> Result<Self, ValidationError> {
        let millis =
            i64::try_from(duration.as_millis()).map_err(|_| ValidationError::Overflow {
                field: "timestamp duration",
            })?;
        let value = self
            .0
            .checked_add(millis)
            .ok_or(ValidationError::Overflow { field: "timestamp" })?;
        Ok(Self(value))
    }

    pub fn checked_sub(self, duration: Duration) -> Result<Self, ValidationError> {
        let millis =
            i64::try_from(duration.as_millis()).map_err(|_| ValidationError::Overflow {
                field: "timestamp duration",
            })?;
        let value = self
            .0
            .checked_sub(millis)
            .ok_or(ValidationError::Overflow { field: "timestamp" })?;
        Ok(Self(value))
    }

    pub fn duration_since(self, earlier: Self) -> Result<Duration, ValidationError> {
        let millis = self
            .0
            .checked_sub(earlier.0)
            .ok_or(ValidationError::Overflow { field: "timestamp" })?;
        if millis < 0 {
            return Err(ValidationError::Ordering { field: "timestamp" });
        }
        Ok(Duration::from_millis(millis as u64))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Runtime-neutral monotonic deadline. A runtime maps its monotonic clock to
/// this value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct MonotonicDeadline(u64);

impl MonotonicDeadline {
    pub const ZERO: Self = Self(0);

    pub const fn from_nanos(nanoseconds: u64) -> Self {
        Self(nanoseconds)
    }

    pub fn from_duration(duration: Duration) -> Option<Self> {
        match u64::try_from(duration.as_nanos()) {
            Ok(nanoseconds) => Some(Self(nanoseconds)),
            Err(_) => None,
        }
    }

    pub(crate) fn checked_add(
        self,
        duration: Duration,
        field: &'static str,
    ) -> Result<Self, ValidationError> {
        let delta =
            u64::try_from(duration.as_nanos()).map_err(|_| ValidationError::Overflow { field })?;
        let value = self
            .0
            .checked_add(delta)
            .ok_or(ValidationError::Overflow { field })?;
        Ok(Self(value))
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub const fn is_before(self, other: Self) -> bool {
        self.0 < other.0
    }

    pub const fn is_at_or_before(self, other: Self) -> bool {
        self.0 <= other.0
    }

    pub fn remaining_until(self, now: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(now.0))
    }
}
