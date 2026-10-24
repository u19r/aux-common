use core::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::{
    error::ValidationError,
    ids::constants::{
        MAX_DEDUPE_KEY_BYTES, MAX_FAIRNESS_KEY_BYTES, MAX_NAME_BYTES, MAX_NAMESPACE_BYTES,
        MAX_ORDERING_KEY_BYTES, OPAQUE_ID_BYTES,
    },
    time::Timestamp,
};

/// Errors from fixed-size or bounded opaque identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifierError {
    InvalidLength {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
    Empty {
        kind: &'static str,
    },
    TooLong {
        kind: &'static str,
        maximum: usize,
        actual: usize,
    },
    EntropyUnavailable,
    InvalidText {
        kind: &'static str,
    },
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                kind,
                expected,
                actual,
            } => write!(formatter, "{kind} requires {expected} bytes, got {actual}"),
            Self::Empty { kind } => write!(formatter, "{kind} must not be empty"),
            Self::TooLong {
                kind,
                maximum,
                actual,
            } => write!(formatter, "{kind} exceeds {maximum} bytes: {actual}"),
            Self::EntropyUnavailable => {
                formatter.write_str("secure identifier entropy unavailable")
            }
            Self::InvalidText { kind } => write!(formatter, "{kind} is not valid text"),
        }
    }
}

impl std::error::Error for IdentifierError {}

macro_rules! fixed_identifier {
    ($name:ident, $label:literal, $debug_label:literal, $redacted:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
        pub struct $name([u8; OPAQUE_ID_BYTES]);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                if $redacted {
                    formatter.write_str(concat!($debug_label, "(redacted)"))
                } else {
                    formatter.debug_tuple($debug_label).field(&self.0).finish()
                }
            }
        }

        impl $name {
            pub const BYTE_LENGTH: usize = OPAQUE_ID_BYTES;

            pub fn try_from_slice(bytes: &[u8]) -> Result<Self, IdentifierError> {
                let array = bytes
                    .try_into()
                    .map_err(|_| IdentifierError::InvalidLength {
                        kind: $label,
                        expected: OPAQUE_ID_BYTES,
                        actual: bytes.len(),
                    })?;
                Ok(Self(array))
            }

            pub fn generate() -> Result<Self, IdentifierError> {
                let mut bytes = [0; OPAQUE_ID_BYTES];
                getrandom::fill(&mut bytes).map_err(|_| IdentifierError::EntropyUnavailable)?;
                Ok(Self(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; OPAQUE_ID_BYTES] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; OPAQUE_ID_BYTES] {
                self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = IdentifierError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::try_from_slice(bytes)
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = IdentifierError;

            fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from_slice(&bytes)
            }
        }

        impl From<[u8; OPAQUE_ID_BYTES]> for $name {
            fn from(bytes: [u8; OPAQUE_ID_BYTES]) -> Self {
                Self(bytes)
            }
        }
    };
}

fixed_identifier!(JobId, "job ID", "JobId", false);
fixed_identifier!(ScheduleId, "schedule ID", "ScheduleId", false);
fixed_identifier!(OccurrenceId, "occurrence ID", "OccurrenceId", false);
fixed_identifier!(ExecutionId, "execution ID", "ExecutionId", false);
fixed_identifier!(AttemptId, "attempt ID", "AttemptId", false);
fixed_identifier!(LeaseToken, "lease token", "LeaseToken", true);
fixed_identifier!(OperationId, "operation ID", "OperationId", false);
fixed_identifier!(
    CommitOperationId,
    "commit operation ID",
    "CommitOperationId",
    false
);
fixed_identifier!(OwnerId, "owner ID", "OwnerId", false);

impl OccurrenceId {
    /// Derives the stable logical job identity for one intended UTC time.
    pub fn derive(schedule_id: &ScheduleId, intended_at: Timestamp) -> Self {
        let mut digest = Sha256::new();
        digest.update(schedule_id.as_bytes());
        digest.update(intended_at.as_millis().to_be_bytes());
        let digest = digest.finalize();
        let mut bytes = [0; Self::BYTE_LENGTH];
        bytes.copy_from_slice(&digest[..Self::BYTE_LENGTH]);
        Self::from(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
struct OpaqueBytes<const MAX: usize> {
    bytes: Vec<u8>,
}

impl<const MAX: usize> OpaqueBytes<MAX> {
    fn try_new(kind: &'static str, bytes: &[u8]) -> Result<Self, IdentifierError> {
        if bytes.is_empty() {
            return Err(IdentifierError::Empty { kind });
        }
        if bytes.len() > MAX {
            return Err(IdentifierError::TooLong {
                kind,
                maximum: MAX,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// An opaque fairness scope component. It deliberately does not implement
/// `Display`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct FairnessKey(OpaqueBytes<MAX_FAIRNESS_KEY_BYTES>);

impl FairnessKey {
    pub const MAX_BYTES: usize = MAX_FAIRNESS_KEY_BYTES;

    pub fn try_new(bytes: impl AsRef<[u8]>) -> Result<Self, IdentifierError> {
        Ok(Self(OpaqueBytes::try_new("fairness key", bytes.as_ref())?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

impl TryFrom<Vec<u8>> for FairnessKey {
    type Error = IdentifierError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

impl TryFrom<&[u8]> for FairnessKey {
    type Error = IdentifierError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

/// An opaque ordering-group component. It deliberately does not implement
/// `Display`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OrderingKey(OpaqueBytes<MAX_ORDERING_KEY_BYTES>);

impl OrderingKey {
    pub const MAX_BYTES: usize = MAX_ORDERING_KEY_BYTES;

    pub fn try_new(bytes: impl AsRef<[u8]>) -> Result<Self, IdentifierError> {
        Ok(Self(OpaqueBytes::try_new("ordering key", bytes.as_ref())?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

impl TryFrom<Vec<u8>> for OrderingKey {
    type Error = IdentifierError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

/// A bounded opaque producer deduplication key. It deliberately does not
/// implement `Display`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct DeduplicationKey(OpaqueBytes<MAX_DEDUPE_KEY_BYTES>);

impl DeduplicationKey {
    pub const MAX_BYTES: usize = MAX_DEDUPE_KEY_BYTES;

    pub fn try_new(bytes: impl AsRef<[u8]>) -> Result<Self, IdentifierError> {
        Ok(Self(OpaqueBytes::try_new(
            "deduplication key",
            bytes.as_ref(),
        )?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }
}

impl TryFrom<Vec<u8>> for DeduplicationKey {
    type Error = IdentifierError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
struct ValidatedText {
    value: Arc<str>,
}

impl ValidatedText {
    fn try_new(kind: &'static str, value: &str, maximum: usize) -> Result<Self, IdentifierError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return Err(IdentifierError::Empty { kind });
        }
        if bytes.len() > maximum {
            return Err(IdentifierError::TooLong {
                kind,
                maximum,
                actual: bytes.len(),
            });
        }
        if value.chars().any(char::is_control) {
            return Err(IdentifierError::InvalidText { kind });
        }
        Ok(Self {
            value: Arc::from(value),
        })
    }

    fn as_str(&self) -> &str {
        &self.value
    }
}

/// A caller-selected job kind. Unlike product enums, this remains an extensible
/// validated name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct JobKind(ValidatedText);

impl JobKind {
    pub const MAX_BYTES: usize = MAX_NAME_BYTES;

    pub fn try_new(value: impl AsRef<str>) -> Result<Self, IdentifierError> {
        Ok(Self(ValidatedText::try_new(
            "job kind",
            value.as_ref(),
            MAX_NAME_BYTES,
        )?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for JobKind {
    type Error = IdentifierError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl TryFrom<&str> for JobKind {
    type Error = IdentifierError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl fmt::Display for JobKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A caller-selected queue name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct QueueName(ValidatedText);

impl QueueName {
    pub const MAX_BYTES: usize = MAX_NAME_BYTES;

    pub fn try_new(value: impl AsRef<str>) -> Result<Self, IdentifierError> {
        Ok(Self(ValidatedText::try_new(
            "queue name",
            value.as_ref(),
            MAX_NAME_BYTES,
        )?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for QueueName {
    type Error = IdentifierError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl TryFrom<&str> for QueueName {
    type Error = IdentifierError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl fmt::Display for QueueName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A namespace prefix supplied by the store adapter or application boundary.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Namespace(OpaqueBytes<MAX_NAMESPACE_BYTES>);

impl Namespace {
    pub const MAX_BYTES: usize = MAX_NAMESPACE_BYTES;

    pub fn try_new(bytes: impl AsRef<[u8]>) -> Result<Self, IdentifierError> {
        Ok(Self(OpaqueBytes::try_new("namespace", bytes.as_ref())?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<Vec<u8>> for Namespace {
    type Error = IdentifierError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_new(bytes)
    }
}

impl From<IdentifierError> for ValidationError {
    fn from(error: IdentifierError) -> Self {
        match error {
            IdentifierError::Empty { kind } => Self::Empty { field: kind },
            IdentifierError::TooLong {
                kind,
                maximum,
                actual,
            } => Self::TooLong {
                field: kind,
                maximum,
                actual,
            },
            IdentifierError::InvalidText { kind } => Self::InvalidText { field: kind },
            IdentifierError::InvalidLength { kind, .. } => Self::InvalidValue { field: kind },
            IdentifierError::EntropyUnavailable => Self::InvalidValue {
                field: "secure entropy",
            },
        }
    }
}
