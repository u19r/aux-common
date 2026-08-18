use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::{
    DEFAULT_RESERVATION_TTL_SECONDS, MAX_IDENTIFIER_LEN, MAX_PUBLIC_SAFE_INTEGER,
    MAX_RESERVATION_TTL_SECONDS, PermissionId, Scope, ValidationError,
};

/// Validated role identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, ToSchema)]
#[schema(
    value_type = String,
    example = "repo_admin"
)]
pub struct RoleId(String);

impl RoleId {
    pub const MAX_LENGTH: usize = 58;

    pub fn new(s: impl Into<String>) -> Result<Self, ValidationError> {
        let s = s.into();
        if s.is_empty() {
            return Err(ValidationError::InvalidFormat {
                field: "role_id",
                message: "cannot be empty".to_string(),
            });
        }
        if s.len() > Self::MAX_LENGTH {
            return Err(ValidationError::OutOfRange {
                field: "role_id",
                message: format!("max length is {}", Self::MAX_LENGTH),
            });
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RoleId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A permission entry with scope restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RolePermission {
    /// Permission identifier attached to this role.
    #[schema(value_type = String, example = "repo:read")]
    pub permission_id: PermissionId,
    /// Scope restrictions for this permission grant.
    #[schema(max_items = 100)]
    pub scopes: Vec<Scope>,
}

macro_rules! role_limit_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, ToSchema)]
        #[serde(transparent)]
        #[schema(value_type = String)]
        pub struct $name(String);

        impl $name {
            pub fn try_new(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(ValidationError::InvalidFormat {
                        field: $field,
                        message: "cannot be empty".to_string(),
                    });
                }
                if value.len() > MAX_IDENTIFIER_LEN {
                    return Err(ValidationError::OutOfRange {
                        field: $field,
                        message: format!("max length is {MAX_IDENTIFIER_LEN}"),
                    });
                }
                if value.trim() != value || value.chars().any(char::is_control) {
                    return Err(ValidationError::InvalidFormat {
                        field: $field,
                        message: "must not contain surrounding whitespace or control characters"
                            .to_string(),
                    });
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = String::deserialize(deserializer)?;
                Self::try_new(value).map_err(serde::de::Error::custom)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

role_limit_identifier!(RoleLimitKey, "limit.key");
role_limit_identifier!(RoleLimitUnit, "limit.unit");

/// A non-negative role-action allowance restricted to the public JSON integer
/// range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = u64)]
pub struct RoleLimitAmount(u64);

impl RoleLimitAmount {
    pub fn try_new(value: u64) -> Result<Self, ValidationError> {
        if value > MAX_PUBLIC_SAFE_INTEGER {
            return Err(ValidationError::OutOfRange {
                field: "limit.amount",
                message: format!("maximum is {MAX_PUBLIC_SAFE_INTEGER}"),
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for RoleLimitAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let value = u64::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

/// A server-owned, non-renewable reservation lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(transparent)]
#[schema(value_type = u32)]
pub struct RoleLimitReservationTtlSeconds(u32);

impl RoleLimitReservationTtlSeconds {
    pub fn try_new(value: u32) -> Result<Self, ValidationError> {
        if !(1..=MAX_RESERVATION_TTL_SECONDS).contains(&value) {
            return Err(ValidationError::OutOfRange {
                field: "limit.reservation_ttl_seconds",
                message: format!("must be between 1 and {MAX_RESERVATION_TTL_SECONDS} seconds"),
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for RoleLimitReservationTtlSeconds {
    fn default() -> Self {
        Self(DEFAULT_RESERVATION_TTL_SECONDS)
    }
}

impl<'de> Deserialize<'de> for RoleLimitReservationTtlSeconds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let value = u32::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

/// Optional utilization crossings emitted by a capacity transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleLimitThresholds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(minimum = 1, maximum = 99, nullable = true)]
    low_percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(minimum = 1, maximum = 99, nullable = true)]
    critical_percent: Option<u8>,
}

impl Default for RoleLimitThresholds {
    fn default() -> Self {
        Self {
            low_percent: Some(80),
            critical_percent: Some(90),
        }
    }
}

impl RoleLimitThresholds {
    #[must_use]
    pub const fn low_percent(&self) -> Option<u8> {
        self.low_percent
    }

    #[must_use]
    pub const fn critical_percent(&self) -> Option<u8> {
        self.critical_percent
    }

    pub fn try_new(
        low_percent: Option<u8>,
        critical_percent: Option<u8>,
    ) -> Result<Self, ValidationError> {
        for (field, value) in [
            ("limit.thresholds.low_percent", low_percent),
            ("limit.thresholds.critical_percent", critical_percent),
        ] {
            if value.is_some_and(|percent| percent == 0 || percent >= 100) {
                return Err(ValidationError::OutOfRange {
                    field,
                    message: "must be between 1 and 99".to_string(),
                });
            }
        }
        if let (Some(low), Some(critical)) = (low_percent, critical_percent)
            && low >= critical
        {
            return Err(ValidationError::InvalidFormat {
                field: "limit.thresholds",
                message: "low_percent must be below critical_percent".to_string(),
            });
        }
        Ok(Self {
            low_percent,
            critical_percent,
        })
    }
}

impl<'de> Deserialize<'de> for RoleLimitThresholds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawThresholds {
            #[serde(default)]
            low_percent: Option<u8>,
            #[serde(default)]
            critical_percent: Option<u8>,
        }

        let raw = RawThresholds::deserialize(deserializer)?;
        Self::try_new(raw.low_percent, raw.critical_percent).map_err(serde::de::Error::custom)
    }
}

/// The finite scope over which a role-action limit counts occupancy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RoleLimitCountScope {
    Tenant,
    Organization,
    Subject,
    ResourceParent,
}

/// The source of the count used by a role-action limit.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RoleLimitCountSource {
    Capacity,
    CustomerSupplied,
}

/// Whether AuxFn strictly admits a role-action operation or only reports
/// advice.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RoleLimitEnforcementMode {
    Hard,
    Advisory,
}

/// A typed default allowance attached to one direct role action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleActionLimit {
    pub key: RoleLimitKey,
    pub amount: RoleLimitAmount,
    pub unit: RoleLimitUnit,
    pub count_scope: RoleLimitCountScope,
    pub count_source: RoleLimitCountSource,
    pub enforcement_mode: RoleLimitEnforcementMode,
    #[serde(default = "RoleLimitReservationTtlSeconds::default")]
    pub reservation_ttl_seconds: RoleLimitReservationTtlSeconds,
    #[serde(default)]
    pub thresholds: RoleLimitThresholds,
}

impl RoleActionLimit {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        key: impl Into<String>,
        amount: u64,
        unit: impl Into<String>,
        count_scope: RoleLimitCountScope,
        count_source: RoleLimitCountSource,
        enforcement_mode: RoleLimitEnforcementMode,
        reservation_ttl_seconds: u32,
        thresholds: RoleLimitThresholds,
    ) -> Result<Self, ValidationError> {
        let limit = Self {
            key: RoleLimitKey::try_new(key)?,
            amount: RoleLimitAmount::try_new(amount)?,
            unit: RoleLimitUnit::try_new(unit)?,
            count_scope,
            count_source,
            enforcement_mode,
            reservation_ttl_seconds: RoleLimitReservationTtlSeconds::try_new(
                reservation_ttl_seconds,
            )?,
            thresholds,
        };
        limit.validate()?;
        Ok(limit)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        RoleLimitThresholds::try_new(
            self.thresholds.low_percent,
            self.thresholds.critical_percent,
        )?;
        match (self.count_source, self.enforcement_mode) {
            (RoleLimitCountSource::Capacity, RoleLimitEnforcementMode::Hard)
            | (RoleLimitCountSource::CustomerSupplied, RoleLimitEnforcementMode::Advisory) => {
                Ok(())
            }
            (RoleLimitCountSource::Capacity, RoleLimitEnforcementMode::Advisory)
            | (RoleLimitCountSource::CustomerSupplied, RoleLimitEnforcementMode::Hard) => {
                Err(ValidationError::InvalidFormat {
                    field: "limit.enforcement_mode",
                    message: "capacity limits are hard and customer-supplied limits are advisory"
                        .to_string(),
                })
            }
        }
    }
}

impl<'de> Deserialize<'de> for RoleActionLimit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawRoleActionLimit {
            key: RoleLimitKey,
            amount: RoleLimitAmount,
            unit: RoleLimitUnit,
            count_scope: RoleLimitCountScope,
            count_source: RoleLimitCountSource,
            enforcement_mode: RoleLimitEnforcementMode,
            #[serde(default)]
            reservation_ttl_seconds: RoleLimitReservationTtlSeconds,
            #[serde(default)]
            thresholds: RoleLimitThresholds,
        }

        let raw = RawRoleActionLimit::deserialize(deserializer)?;
        let limit = Self {
            key: raw.key,
            amount: raw.amount,
            unit: raw.unit,
            count_scope: raw.count_scope,
            count_source: raw.count_source,
            enforcement_mode: raw.enforcement_mode,
            reservation_ttl_seconds: raw.reservation_ttl_seconds,
            thresholds: raw.thresholds,
        };
        limit.validate().map_err(serde::de::Error::custom)?;
        Ok(limit)
    }
}

/// A direct action entry with scope restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct RoleActionRef {
    /// Resource type referenced by this role action.
    #[schema(example = "document", min_length = 1, max_length = 58)]
    pub resource_type: String,
    /// Action name referenced by this role action.
    #[schema(example = "read", min_length = 1, max_length = 58)]
    pub action_name: String,
    #[schema(max_items = 100)]
    pub scopes: Vec<Scope>,
    /// Optional typed default capacity policy for this direct action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<RoleActionLimit>,
}

/// A role groups permissions with optional scope restrictions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct Role {
    /// Role identifier.
    #[schema(example = "repo:admin", min_length = 1, max_length = 58)]
    pub id: String,
    /// Customer-supplied stable role name.
    #[schema(example = "repo_admin", min_length = 1, max_length = 58)]
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional human-readable role description.
    #[schema(
        min_length = 1,
        max_length = 250,
        nullable = true,
        example = "Full administrative access to repositories"
    )]
    pub description: Option<String>,
    #[schema(max_items = 1024)] // Keep in sync with MAX_PERMISSIONS.
    pub permissions: Vec<RolePermission>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500)]
    pub actions: Vec<RoleActionRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(max_items = 500)]
    pub not_actions: Vec<RoleActionRef>,
}
