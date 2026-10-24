use core::fmt;
use std::{
    num::{NonZeroU16, NonZeroU32},
    time::Duration,
};

use super::constants::DEFAULT_MAXIMUM_ATTEMPTS;
use crate::{
    error::ValidationError,
    ids::FairnessKey,
    time::{CronExpression, Timestamp},
};

/// Hierarchical fairness scope used for high-volume work.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FairnessPath {
    /// The required top-level fairness scope.
    pub primary: FairnessKey,
    /// An optional child scope within `primary`.
    pub secondary: Option<FairnessKey>,
}

impl FairnessPath {
    pub fn new(primary: FairnessKey, secondary: Option<FairnessKey>) -> Self {
        Self { primary, secondary }
    }
}

/// Fairness is either scoped by opaque keys or explicitly low volume.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FairnessClass {
    Scoped(FairnessPath),
    /// The aggregate unscoped lane for low-throughput work. It permits one
    /// unresolved service at a time; a later drive restores eligibility after
    /// reconciling the preceding durable lifecycle result.
    LowVolume,
}

impl FairnessClass {
    pub const fn low_volume() -> Self {
        Self::LowVolume
    }
}

impl From<FairnessPath> for FairnessClass {
    fn from(path: FairnessPath) -> Self {
        Self::Scoped(path)
    }
}

/// Closed priority lanes. Their default service weights are 8:4:1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Priority {
    Critical,
    #[default]
    Default,
    Bulk,
}

impl Priority {
    pub const fn default_weight(self) -> u16 {
        match self {
            Self::Critical => 8,
            Self::Default => 4,
            Self::Bulk => 1,
        }
    }
}

/// Effect safety declaration supplied by a trusted handler registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EffectMode {
    ReadOnly,
    Idempotent,
    AtLeastOnce,
    Fenced,
}

/// A positive bounded backoff multiplier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BackoffMultiplier(NonZeroU32);

impl BackoffMultiplier {
    pub const MAX: u32 = 32;

    fn try_from_value(value: u32) -> Result<Self, ValidationError> {
        let value = NonZeroU32::new(value).ok_or(ValidationError::InvalidValue {
            field: "retry multiplier",
        })?;
        if value.get() > Self::MAX {
            return Err(ValidationError::TooLong {
                field: "retry multiplier",
                maximum: Self::MAX as usize,
                actual: value.get() as usize,
            });
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for BackoffMultiplier {
    type Error = ValidationError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::try_from_value(value)
    }
}

/// The only jitter mode in the v1 retry contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FullJitter;

/// Validated retry policy with bounded attempts, age, and backoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetryPolicy {
    maximum_attempts: NonZeroU16,
    maximum_age: Duration,
    minimum_backoff: Duration,
    maximum_backoff: Duration,
    multiplier: BackoffMultiplier,
    jitter: FullJitter,
}

/// Inputs for constructing a retry policy without an unstructured parameter
/// bag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetryPolicyInput {
    pub maximum_attempts: NonZeroU16,
    pub maximum_age: Duration,
    pub minimum_backoff: Duration,
    pub maximum_backoff: Duration,
    pub multiplier: BackoffMultiplier,
}

impl RetryPolicy {
    fn try_from_input(input: RetryPolicyInput) -> Result<Self, ValidationError> {
        if input.maximum_age.is_zero() {
            return Err(ValidationError::InvalidValue {
                field: "retry maximum age",
            });
        }
        if input.minimum_backoff.is_zero() {
            return Err(ValidationError::InvalidValue {
                field: "retry minimum backoff",
            });
        }
        if input.maximum_backoff.is_zero() {
            return Err(ValidationError::InvalidValue {
                field: "retry maximum backoff",
            });
        }
        if input.minimum_backoff > input.maximum_backoff {
            return Err(ValidationError::Ordering {
                field: "retry backoff",
            });
        }
        if input.maximum_age.as_nanos() > u64::MAX as u128
            || input.minimum_backoff.as_nanos() > u64::MAX as u128
            || input.maximum_backoff.as_nanos() > u64::MAX as u128
        {
            return Err(ValidationError::Overflow {
                field: "retry duration",
            });
        }
        Ok(Self {
            maximum_attempts: input.maximum_attempts,
            maximum_age: input.maximum_age,
            minimum_backoff: input.minimum_backoff,
            maximum_backoff: input.maximum_backoff,
            multiplier: input.multiplier,
            jitter: FullJitter,
        })
    }

    pub fn preset(preset: RetryPreset) -> Self {
        match preset {
            RetryPreset::Interactive => {
                Self::preset_values(DEFAULT_MAXIMUM_ATTEMPTS, 120, 100, 5_000)
            }
            RetryPreset::Network => {
                Self::preset_values(DEFAULT_MAXIMUM_ATTEMPTS, 86_400, 1_000, 900_000)
            }
            RetryPreset::Maintenance => {
                Self::preset_values(DEFAULT_MAXIMUM_ATTEMPTS, 604_800, 5_000, 21_600_000)
            }
        }
    }

    fn preset_values(
        attempts: u16,
        age_seconds: u64,
        minimum_millis: u64,
        maximum_millis: u64,
    ) -> Self {
        let maximum_attempts = match NonZeroU16::new(attempts) {
            Some(value) => value,
            None => NonZeroU16::MIN,
        };
        let multiplier = match NonZeroU32::new(2) {
            Some(value) => BackoffMultiplier(value),
            None => BackoffMultiplier(NonZeroU32::MIN),
        };
        Self {
            maximum_attempts,
            maximum_age: Duration::from_secs(age_seconds),
            minimum_backoff: Duration::from_millis(minimum_millis),
            maximum_backoff: Duration::from_millis(maximum_millis),
            multiplier,
            jitter: FullJitter,
        }
    }

    pub const fn maximum_attempts(self) -> NonZeroU16 {
        self.maximum_attempts
    }

    pub const fn maximum_age(self) -> Duration {
        self.maximum_age
    }

    pub const fn minimum_backoff(self) -> Duration {
        self.minimum_backoff
    }

    pub const fn maximum_backoff(self) -> Duration {
        self.maximum_backoff
    }

    pub const fn multiplier(self) -> BackoffMultiplier {
        self.multiplier
    }

    pub const fn jitter(self) -> FullJitter {
        self.jitter
    }

    pub fn backoff_cap(self, attempt: NonZeroU16) -> Duration {
        let mut value = self.minimum_backoff;
        for _ in 1..attempt.get() {
            value = match value.checked_mul(self.multiplier.get()) {
                Some(value) => value,
                None => self.maximum_backoff,
            };
            if value >= self.maximum_backoff {
                return self.maximum_backoff;
            }
        }
        value.min(self.maximum_backoff)
    }
}

impl TryFrom<RetryPolicyInput> for RetryPolicy {
    type Error = ValidationError;

    fn try_from(input: RetryPolicyInput) -> Result<Self, Self::Error> {
        Self::try_from_input(input)
    }
}

/// Named exact retry presets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetryPreset {
    Interactive,
    Network,
    Maintenance,
}

impl RetryPreset {
    /// Maximum delay before jitter for a one-based durable attempt.
    pub fn backoff_cap(self, attempt: NonZeroU16) -> Duration {
        RetryPolicy::preset(self).backoff_cap(attempt)
    }

    /// Applies tighter attempt and backoff limits while preserving the preset's
    /// age, multiplier, minimum delay, and shared jitter policy.
    pub fn with_limits(
        self,
        maximum_attempts: NonZeroU16,
        maximum_backoff: Duration,
    ) -> Result<RetrySelection, ValidationError> {
        let preset = RetryPolicy::preset(self);
        let policy = RetryPolicy::try_from(RetryPolicyInput {
            maximum_attempts: maximum_attempts.min(preset.maximum_attempts),
            maximum_age: preset.maximum_age,
            minimum_backoff: preset.minimum_backoff,
            maximum_backoff: maximum_backoff.min(preset.maximum_backoff),
            multiplier: preset.multiplier,
        })?;
        Ok(RetrySelection::Custom(policy))
    }

    /// Uses application-required delay bounds with the preset's attempt budget,
    /// maximum age, multiplier, and shared jitter policy.
    pub fn with_backoff(
        self,
        minimum_backoff: Duration,
        maximum_backoff: Duration,
    ) -> Result<RetrySelection, ValidationError> {
        let preset = RetryPolicy::preset(self);
        let policy = RetryPolicy::try_from(RetryPolicyInput {
            maximum_attempts: preset.maximum_attempts,
            maximum_age: preset.maximum_age,
            minimum_backoff,
            maximum_backoff,
            multiplier: preset.multiplier,
        })?;
        Ok(RetrySelection::Custom(policy))
    }
}

/// Registration-time retry selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetrySelection {
    Preset(RetryPreset),
    Custom(RetryPolicy),
}

impl RetrySelection {
    /// Maximum delay before jitter for a one-based durable attempt.
    pub fn backoff_cap(self, attempt: NonZeroU16) -> Duration {
        RetryPolicy::from(self).backoff_cap(attempt)
    }
}

impl From<RetrySelection> for RetryPolicy {
    fn from(selection: RetrySelection) -> Self {
        match selection {
            RetrySelection::Preset(preset) => RetryPolicy::preset(preset),
            RetrySelection::Custom(policy) => policy,
        }
    }
}

/// Handler outcome classes that consume the engine retry budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetryClass {
    Transient,
    Throttled,
    AmbiguousEffect,
}

/// Bounded machine-readable outcome code.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OutcomeCode(String);

impl OutcomeCode {
    pub const MAX_BYTES: usize = 64;

    pub fn try_new(code: impl AsRef<str>) -> Result<Self, ValidationError> {
        let value = code.as_ref();
        if value.is_empty() {
            return Err(ValidationError::Empty {
                field: "outcome code",
            });
        }
        if value.len() > Self::MAX_BYTES {
            return Err(ValidationError::TooLong {
                field: "outcome code",
                maximum: Self::MAX_BYTES,
                actual: value.len(),
            });
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        }) {
            return Err(ValidationError::InvalidText {
                field: "outcome code",
            });
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OutcomeCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Trigger-neutral recurring cadence.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Cadence {
    CronUtc(CronExpression),
}

/// Bounded handling of missed recurring occurrences.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MisfirePolicy {
    Skip,
    FireOnce,
    CatchUp { maximum_occurrences: NonZeroU16 },
}

/// Whether recurring occurrences may overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OverlapPolicy {
    Allow,
    Forbid,
}

/// Trusted registration fairness policy. Product identity remains outside this
/// crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FairnessPolicy {
    Scoped {
        weight: NonZeroU16,
    },
    /// The aggregate unscoped lane for low-throughput handlers. It permits one
    /// unresolved service at a time and becomes eligible again after durable
    /// reconciliation. Use scoped fairness for tenant-heavy work; global
    /// controllers do not need to invent a scope merely to recur.
    LowVolume,
}

impl FairnessPolicy {
    pub const fn low_volume() -> Self {
        Self::LowVolume
    }
}

impl From<NonZeroU16> for FairnessPolicy {
    fn from(weight: NonZeroU16) -> Self {
        Self::Scoped { weight }
    }
}

/// Optional enqueue deduplication retention request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Deduplication {
    key: crate::ids::DeduplicationKey,
    retain_until: Timestamp,
}

impl Deduplication {
    pub fn try_new(
        key: crate::ids::DeduplicationKey,
        retain_until: Timestamp,
    ) -> Result<Self, ValidationError> {
        if retain_until < Timestamp::ZERO {
            return Err(ValidationError::InvalidValue {
                field: "deduplication retention",
            });
        }
        Ok(Self { key, retain_until })
    }

    pub fn key(&self) -> &crate::ids::DeduplicationKey {
        &self.key
    }

    pub const fn retain_until(&self) -> Timestamp {
        self.retain_until
    }
}
