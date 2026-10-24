use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::Duration,
};

use super::{DriveRequest, DriveRequestInput, QueueSelection};
use crate::{error::ValidationError, time::MonotonicDeadline};

/// Named bounded-drive presets used by routine consumers.
///
/// The wrapped profile stays private so callers choose a deployment-shaped
/// budget instead of assembling deadlines and operation limits at every
/// runtime call site. Test and conformance adapters can construct an explicit
/// profile through the optional `test-support` feature when their contract
/// requires it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveBudget(DriveProfile);

/// Inputs for a bounded worker budget with safe payload and completion
/// defaults. Conversion into [`DriveBudget`] validates every throughput and
/// time bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveBudgetInput {
    pub queues: QueueSelection,
    pub max_claims: u32,
    pub max_concurrency: u16,
    pub max_store_operations: u32,
    pub stop_claiming_after: Duration,
    pub finish_after: Duration,
}

/// Runtime-independent inputs for a reusable bounded drive profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveProfileInput {
    pub queues: QueueSelection,
    pub max_claims: u32,
    pub max_concurrency: u16,
    pub max_payload_bytes_in_flight: usize,
    pub max_completion_details: u32,
    pub max_store_operations: u32,
    pub stop_claiming_after: Duration,
    pub finish_after: Duration,
}

/// Validated static budgets used to construct caller-clocked drive requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveProfile {
    queues: QueueSelection,
    max_claims: NonZeroU32,
    max_concurrency: NonZeroU16,
    max_payload_bytes_in_flight: NonZeroUsize,
    max_completion_details: u32,
    max_store_operations: NonZeroU32,
    stop_claiming_after: Duration,
    finish_after: Duration,
}

impl TryFrom<DriveProfileInput> for DriveProfile {
    type Error = ValidationError;

    fn try_from(input: DriveProfileInput) -> Result<Self, Self::Error> {
        let max_claims =
            NonZeroU32::new(input.max_claims).ok_or(ValidationError::InvalidValue {
                field: "max claims",
            })?;
        let max_concurrency =
            NonZeroU16::new(input.max_concurrency).ok_or(ValidationError::InvalidValue {
                field: "max concurrency",
            })?;
        let max_payload_bytes_in_flight = NonZeroUsize::new(input.max_payload_bytes_in_flight)
            .ok_or(ValidationError::InvalidValue {
                field: "max payload bytes in flight",
            })?;
        let max_store_operations =
            NonZeroU32::new(input.max_store_operations).ok_or(ValidationError::InvalidValue {
                field: "max store operations",
            })?;
        if input.max_completion_details > max_claims.get() {
            return Err(ValidationError::InvalidValue {
                field: "max completion details",
            });
        }
        validate_duration("stop claiming duration", input.stop_claiming_after)?;
        validate_duration("finish duration", input.finish_after)?;
        if input.finish_after < input.stop_claiming_after {
            return Err(ValidationError::Ordering {
                field: "drive durations",
            });
        }
        Ok(Self {
            queues: input.queues,
            max_claims,
            max_concurrency,
            max_payload_bytes_in_flight,
            max_completion_details: input.max_completion_details,
            max_store_operations,
            stop_claiming_after: input.stop_claiming_after,
            finish_after: input.finish_after,
        })
    }
}

impl DriveProfile {
    /// Builds one bounded request from a caller-owned monotonic clock value.
    pub fn request_at(&self, now: MonotonicDeadline) -> Result<DriveRequest, ValidationError> {
        let stop_claiming_at = now.checked_add(self.stop_claiming_after, "drive deadline")?;
        let finish_by = now.checked_add(self.finish_after, "drive deadline")?;
        DriveRequest::try_from(DriveRequestInput {
            queues: self.queues.clone(),
            max_claims: self.max_claims,
            max_concurrency: self.max_concurrency,
            max_payload_bytes_in_flight: self.max_payload_bytes_in_flight,
            max_completion_details: self.max_completion_details,
            max_store_operations: self.max_store_operations,
            stop_claiming_at,
            finish_by,
        })
    }
}

impl TryFrom<DriveBudgetInput> for DriveBudget {
    type Error = ValidationError;

    fn try_from(input: DriveBudgetInput) -> Result<Self, Self::Error> {
        Self::try_from(DriveProfileInput {
            queues: input.queues,
            max_claims: input.max_claims,
            max_concurrency: input.max_concurrency,
            max_payload_bytes_in_flight: crate::model::MAX_INLINE_PAYLOAD_BYTES,
            max_completion_details: input.max_claims,
            max_store_operations: input.max_store_operations,
            stop_claiming_after: input.stop_claiming_after,
            finish_after: input.finish_after,
        })
    }
}

impl TryFrom<DriveProfileInput> for DriveBudget {
    type Error = ValidationError;

    fn try_from(input: DriveProfileInput) -> Result<Self, Self::Error> {
        DriveProfile::try_from(input).map(Self)
    }
}

impl DriveBudget {
    /// Small bounded work profile suitable for low-volume workers and tests.
    pub fn try_tiny(queues: QueueSelection) -> Result<Self, ValidationError> {
        Self::try_from(DriveProfileInput {
            queues,
            max_claims: 8,
            max_concurrency: 2,
            max_payload_bytes_in_flight: crate::policy::TINY_MAX_PAYLOAD_BYTES_IN_FLIGHT,
            max_completion_details: crate::policy::TINY_MAX_COMPLETION_DETAILS,
            max_store_operations: 32,
            stop_claiming_after: Duration::from_millis(250),
            finish_after: Duration::from_millis(500),
        })
    }

    /// Resident-service profile with a larger bounded claim and memory window.
    pub fn try_resident(queues: QueueSelection) -> Result<Self, ValidationError> {
        Self::try_from(DriveProfileInput {
            queues,
            max_claims: 32,
            max_concurrency: 8,
            max_payload_bytes_in_flight: 1024 * 1024,
            max_completion_details: 32,
            max_store_operations: 128,
            stop_claiming_after: Duration::from_secs(4),
            finish_after: Duration::from_secs(5),
        })
    }

    /// Serverless/invocation profile with a bounded long-running window.
    pub fn try_serverless(queues: QueueSelection) -> Result<Self, ValidationError> {
        Self::try_from(DriveProfileInput {
            queues,
            max_claims: 16,
            max_concurrency: 4,
            max_payload_bytes_in_flight: 64 * 1024,
            max_completion_details: 16,
            max_store_operations: 128,
            stop_claiming_after: Duration::from_secs(20),
            finish_after: Duration::from_secs(25),
        })
    }

    /// Builds a request from the caller-owned monotonic clock value.
    pub fn request_at(&self, now: MonotonicDeadline) -> Result<DriveRequest, ValidationError> {
        self.0.request_at(now)
    }
}

impl From<DriveProfile> for DriveBudget {
    fn from(profile: DriveProfile) -> Self {
        Self(profile)
    }
}

fn validate_duration(field: &'static str, duration: Duration) -> Result<(), ValidationError> {
    if duration.is_zero() {
        return Err(ValidationError::InvalidValue { field });
    }
    u64::try_from(duration.as_nanos()).map_err(|_| ValidationError::Overflow { field })?;
    Ok(())
}
