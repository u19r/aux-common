use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;

use super::constants::{
    MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS, MAX_ACCESS_ASSIGNMENT_EXPLANATION_BYTES,
    MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS,
};
use crate::ValidationError;

/// A bounded, whole-second assignment duration owned by the server.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ToSchema, schemars::JsonSchema,
)]
#[schema(value_type = u32, example = 3600)]
pub struct AccessAssignmentDurationSeconds(u32);

impl AccessAssignmentDurationSeconds {
    pub fn try_new(value: u32) -> Result<Self, ValidationError> {
        if !(MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS..=MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS)
            .contains(&value)
        {
            return Err(ValidationError::OutOfRange {
                field: "duration_seconds",
                message: format!(
                    "must be between {MIN_ACCESS_ASSIGNMENT_DURATION_SECONDS} and \
                     {MAX_ACCESS_ASSIGNMENT_DURATION_SECONDS} seconds"
                ),
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Compute the expiry from the trusted server timestamp in epoch
    /// milliseconds.
    pub fn checked_expires_at_millis(self, now_millis: i64) -> Result<i64, ValidationError> {
        let duration_millis =
            i64::from(self.0)
                .checked_mul(1_000)
                .ok_or(ValidationError::OutOfRange {
                    field: "duration_seconds",
                    message: "duration arithmetic overflowed".to_string(),
                })?;
        now_millis
            .checked_add(duration_millis)
            .ok_or(ValidationError::OutOfRange {
                field: "duration_seconds",
                message: "expiry arithmetic overflowed".to_string(),
            })
    }
}

impl Serialize for AccessAssignmentDurationSeconds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for AccessAssignmentDurationSeconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let value = u32::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

/// A normalized human explanation retained in restricted audit data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToSchema, schemars::JsonSchema)]
#[schema(value_type = String, example = "INC-4832")]
pub struct AccessAssignmentExplanation(String);

impl AccessAssignmentExplanation {
    pub fn try_new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::RequiredFieldMissing("explanation"));
        }
        if trimmed.len() > MAX_ACCESS_ASSIGNMENT_EXPLANATION_BYTES {
            return Err(ValidationError::OutOfRange {
                field: "explanation",
                message: format!(
                    "maximum length is {MAX_ACCESS_ASSIGNMENT_EXPLANATION_BYTES} bytes"
                ),
            });
        }
        if trimmed.chars().any(char::is_control) {
            return Err(ValidationError::InvalidFormat {
                field: "explanation",
                message: "control characters are not permitted".to_string(),
            });
        }
        Ok(Self(trimmed.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for AccessAssignmentExplanation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AccessAssignmentExplanation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let value = String::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

/// Whether a target allows permanent assignments.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessAssignmentMode {
    PermanentOrTemporary,
    TemporaryRequired,
}

/// Customer-configured assignment policy for an assignable target.
///
/// Revision and update provenance are server-owned fields on the persisted
/// target policy and are intentionally absent from this desired specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessAssignmentPolicySpec {
    pub assignment_mode: AccessAssignmentMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = true)]
    pub maximum_duration_seconds: Option<AccessAssignmentDurationSeconds>,
}

impl AccessAssignmentPolicySpec {
    pub fn try_new(
        assignment_mode: AccessAssignmentMode,
        maximum_duration_seconds: Option<AccessAssignmentDurationSeconds>,
    ) -> Result<Self, ValidationError> {
        let spec = Self {
            assignment_mode,
            maximum_duration_seconds,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if matches!(
            self.assignment_mode,
            AccessAssignmentMode::TemporaryRequired
        ) && self.maximum_duration_seconds.is_none()
        {
            return Err(ValidationError::RequiredFieldMissing(
                "maximum_duration_seconds",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AccessAssignmentPolicySpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawPolicySpec {
            assignment_mode: AccessAssignmentMode,
            maximum_duration_seconds: Option<AccessAssignmentDurationSeconds>,
        }

        let raw = RawPolicySpec::deserialize(deserializer)?;
        Self::try_new(raw.assignment_mode, raw.maximum_duration_seconds)
            .map_err(serde::de::Error::custom)
    }
}

/// Policy embedded directly on an assignable target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessAssignmentPolicy {
    pub assignment_mode: AccessAssignmentMode,
    #[schema(nullable = true)]
    pub maximum_duration_seconds: Option<AccessAssignmentDurationSeconds>,
    #[schema(minimum = 1)]
    pub revision: u64,
    #[schema(format = "int64")]
    pub updated_at_ms: i64,
    #[schema(nullable = true)]
    pub updated_by: Option<String>,
}

impl<'de> Deserialize<'de> for AccessAssignmentPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawPolicy {
            assignment_mode: AccessAssignmentMode,
            maximum_duration_seconds: Option<AccessAssignmentDurationSeconds>,
            revision: u64,
            updated_at_ms: i64,
            updated_by: Option<String>,
        }

        let raw = RawPolicy::deserialize(deserializer)?;
        Self::try_new(
            raw.assignment_mode,
            raw.maximum_duration_seconds,
            raw.revision,
            raw.updated_at_ms,
            raw.updated_by,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl AccessAssignmentPolicy {
    pub fn from_spec(
        spec: &AccessAssignmentPolicySpec,
        updated_at_ms: i64,
        updated_by: String,
    ) -> Result<Self, ValidationError> {
        spec.validate()?;
        Self::try_new(
            spec.assignment_mode,
            spec.maximum_duration_seconds,
            1,
            updated_at_ms,
            Some(updated_by),
        )
    }

    pub fn updated_for_spec(
        &self,
        spec: &AccessAssignmentPolicySpec,
        updated_at_ms: i64,
        updated_by: String,
    ) -> Result<Self, ValidationError> {
        spec.validate()?;
        if self.matches_spec(spec) {
            return Ok(self.clone());
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(ValidationError::OutOfRange {
                field: "revision",
                message: "revision arithmetic overflowed".to_string(),
            })?;
        Self::try_new(
            spec.assignment_mode,
            spec.maximum_duration_seconds,
            revision,
            updated_at_ms,
            Some(updated_by),
        )
    }

    #[must_use]
    pub fn matches_spec(&self, spec: &AccessAssignmentPolicySpec) -> bool {
        self.assignment_mode == spec.assignment_mode
            && self.maximum_duration_seconds == spec.maximum_duration_seconds
    }

    pub fn try_new(
        assignment_mode: AccessAssignmentMode,
        maximum_duration_seconds: Option<AccessAssignmentDurationSeconds>,
        revision: u64,
        updated_at_ms: i64,
        updated_by: Option<String>,
    ) -> Result<Self, ValidationError> {
        if matches!(assignment_mode, AccessAssignmentMode::TemporaryRequired)
            && maximum_duration_seconds.is_none()
        {
            return Err(ValidationError::RequiredFieldMissing(
                "maximum_duration_seconds",
            ));
        }
        if revision == 0 {
            return Err(ValidationError::OutOfRange {
                field: "revision",
                message: "must be greater than zero".to_string(),
            });
        }
        Ok(Self {
            assignment_mode,
            maximum_duration_seconds,
            revision,
            updated_at_ms,
            updated_by,
        })
    }

    pub fn validate_duration(
        &self,
        duration_seconds: Option<AccessAssignmentDurationSeconds>,
    ) -> Result<(), ValidationError> {
        if duration_seconds.is_none()
            && matches!(
                self.assignment_mode,
                AccessAssignmentMode::TemporaryRequired
            )
        {
            return Err(ValidationError::InvalidFormat {
                field: "duration_seconds",
                message: "temporary_required targets require a bounded duration".to_string(),
            });
        }
        if let (Some(requested), Some(maximum)) = (duration_seconds, self.maximum_duration_seconds)
            && requested > maximum
        {
            return Err(ValidationError::OutOfRange {
                field: "duration_seconds",
                message: format!("must not exceed {} seconds", maximum.get()),
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if matches!(
            self.assignment_mode,
            AccessAssignmentMode::TemporaryRequired
        ) && self.maximum_duration_seconds.is_none()
        {
            return Err(ValidationError::RequiredFieldMissing(
                "maximum_duration_seconds",
            ));
        }
        if self.revision == 0 {
            return Err(ValidationError::OutOfRange {
                field: "revision",
                message: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

/// Lifecycle state for a canonical assignment.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessAssignmentStatus {
    Active,
    Expired,
    Revoked,
}

/// Why a canonical assignment became terminal.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessAssignmentRemovalCause {
    Expired,
    Manual,
    TargetDeleted,
    PrincipalDeleted,
}

/// The boundary that performed a removal transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessAssignmentRemovalSource {
    ExpiryWorker,
    Api,
    Cascade,
}

/// Stable resource identity used by assignment capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AccessAssignmentTarget {
    Role { id: String },
    OrgGroup { id: String },
    AccessProfile { id: String },
}

impl AccessAssignmentTarget {
    #[must_use]
    pub fn resource_id(&self) -> String {
        match self {
            Self::Role { id } => format!("role:{id}"),
            Self::OrgGroup { id } => format!("group:{id}"),
            Self::AccessProfile { id } => format!("access_profile:{id}"),
        }
    }
}
