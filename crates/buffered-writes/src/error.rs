use crate::configuration::OperationId;

/// Safe encoding and decoding failures without customer payload contents.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("record serialization failed")]
    SerializationFailed,
    #[error("record deserialization failed")]
    DeserializationFailed,
    #[error("encoded payload requires at least {size} bytes; limit is {limit} bytes")]
    PayloadTooLarge { size: usize, limit: usize },
    #[error("invalid record input: {reason}")]
    InvalidInput { reason: &'static str },
    #[error("unsupported record codec version")]
    UnsupportedCodecVersion,
}

impl EncodeError {
    #[must_use]
    pub const fn invalid_input(reason: &'static str) -> Self {
        Self::InvalidInput { reason }
    }
}

/// Safe batch preparation failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PrepareError {
    #[error("batch preparation encoding failed: {0}")]
    Encode(#[from] EncodeError),
    #[error("prepared batch requires at least {size} bytes; limit is {limit} bytes")]
    CandidateTooLarge { size: usize, limit: usize },
    #[error("prepared batch of {count} operations exceeds limit of {limit} operations")]
    TooManyOperations { count: usize, limit: usize },
    #[error("prepared batch produced zero operations")]
    EmptyOperations,
    #[error("prepared batch contains duplicate operation identity")]
    DuplicateOperationId,
    #[error("prepared batch contains invalid operation identity")]
    InvalidOperationId,
    #[error("batch preparation failed permanently: {reason}")]
    Permanent { reason: &'static str },
}

impl PrepareError {
    #[must_use]
    pub const fn permanent(reason: &'static str) -> Self {
        Self::Permanent { reason }
    }
}

/// Safe configuration validation errors rejected before accepting writes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigurationError {
    #[error("codec or strategy version is invalid")]
    InvalidVersion,
    #[error("batch identity must be an RFC 4122 UUIDv7")]
    InvalidBatchId,
    #[error("writer namespace must not be empty")]
    EmptyNamespace,
    #[error("writer namespace exceeds maximum byte length")]
    NamespaceTooLong,
    #[error("writer namespace contains invalid characters")]
    InvalidNamespace,
    #[error("buffer namespace does not match the writer namespace")]
    NamespaceMismatch,
    #[error(
        "retained buffer needs {retained_items} items/{retained_bytes} bytes; configured limits \
         are {item_limit} items/{byte_limit} bytes; drain using the previous configuration"
    )]
    InsufficientRecoveryCapacity {
        retained_items: usize,
        retained_bytes: usize,
        item_limit: usize,
        byte_limit: usize,
    },
    #[error(
        "retained preparation credit {reserved} bytes is below the current requirement {required} \
         bytes; drain using the previous configuration"
    )]
    InsufficientPreparationCredit { reserved: usize, required: usize },
    #[error("configuration field {field} must be greater than zero")]
    ZeroCapacity { field: &'static str },
    #[error("invalid sink limits: {reason}")]
    InvalidSinkLimits { reason: &'static str },
    #[error("sink replay guarantee is unsupported for buffered recovery")]
    UnsupportedReplayGuarantee,
    #[error("incompatible retention and replay configuration: {reason}")]
    IncompatibleRetentionAndReplay { reason: &'static str },
    #[error("invalid timing relationship: {reason}")]
    InvalidTimingRelationship { reason: &'static str },
    #[error("invalid endpoint configuration: {reason}")]
    InvalidEndpoint { reason: &'static str },
    #[error("invalid disk journal path: {reason}")]
    InvalidDiskPath { reason: &'static str },
    #[error("invalid fallback queue configuration: {reason}")]
    InvalidQueueConfiguration { reason: &'static str },
}

/// Safe destination write failures classified for retry, breaker, and
/// quarantine policy.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SinkError {
    #[error("retryable sink failure: {reason}")]
    Retryable { reason: &'static str },
    #[error("permanent sink failure: {reason}")]
    Permanent { reason: &'static str },
    #[error("sink batch identity conflict: existing receipt has a different digest")]
    IdentityConflict,
    #[error("sink commit outcome is unknown: {reason}")]
    UnknownOutcome { reason: &'static str },
    #[error("sink returned invalid operation outcome: {reason}")]
    InvalidOutcome { reason: &'static str },
}

impl SinkError {
    #[must_use]
    pub const fn retryable(reason: &'static str) -> Self {
        Self::Retryable { reason }
    }

    #[must_use]
    pub const fn permanent(reason: &'static str) -> Self {
        Self::Permanent { reason }
    }

    #[must_use]
    pub const fn identity_conflict() -> Self {
        Self::IdentityConflict
    }

    #[must_use]
    pub const fn unknown_outcome(reason: &'static str) -> Self {
        Self::UnknownOutcome { reason }
    }

    #[must_use]
    pub const fn invalid_outcome(reason: &'static str) -> Self {
        Self::InvalidOutcome { reason }
    }

    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable { .. } | Self::UnknownOutcome { .. })
    }

    #[must_use]
    pub const fn is_unknown_outcome(&self) -> bool {
        matches!(self, Self::UnknownOutcome { .. })
    }
}

/// Safe retention provider failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BufferError {
    #[error("buffer configuration is incompatible with retained writes: {0}")]
    Configuration(#[from] ConfigurationError),
    #[error("persisted buffer namespace does not match the provider namespace")]
    NamespaceMismatch,
    #[error("invalid buffer request: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("write buffer capacity is full")]
    Full,
    #[error("write buffer is closed for admission")]
    Closed,
    #[error("admission operation identity conflict")]
    DuplicateIdentityConflict { operation_id: OperationId },
    #[error("encoded write item requires at least {size} bytes; limit is {limit} bytes")]
    OversizedItem { size: usize, limit: usize },
    #[error("stale buffer fencing token for generation {generation}")]
    StaleFence { generation: u64 },
    #[error("buffer claim lease has expired")]
    LeaseExpired,
    #[error("sealed batch was not found in buffer")]
    BatchNotFound,
    #[error("buffer storage is corrupt: {reason}")]
    CorruptStorage { reason: &'static str },
    #[error("unsupported persisted codec or strategy version")]
    UnsupportedVersion,
    #[error("buffer storage is unavailable: {reason}")]
    StorageUnavailable { reason: &'static str },
    #[error("buffer operation deadline exceeded")]
    DeadlineExceeded,
    #[error("buffer admission outcome is ambiguous")]
    AmbiguousAdmission { operation_id: OperationId },
}

/// Safe fallback and replay queue failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QueueError {
    #[error("sealed envelope of {size} bytes exceeds queue limit of {limit} bytes")]
    EnvelopeTooLarge { size: usize, limit: usize },
    #[error("fallback queue is unavailable: {reason}")]
    Unavailable { reason: &'static str },
    #[error("fallback queue rejected request permanently: {reason}")]
    Permanent { reason: &'static str },
    #[error("fallback queue publication outcome is ambiguous")]
    AmbiguousPublish,
    #[error("fallback queue operation deadline exceeded")]
    DeadlineExceeded,
    #[error("fallback queue receipt handle is invalid")]
    InvalidReceipt,
    #[error("replay envelope is poisoned: {reason}")]
    PoisonEnvelope { reason: &'static str },
}

/// Safe lifecycle adapter failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleError {
    #[error("lifecycle source is unavailable: {reason}")]
    SourceUnavailable { reason: &'static str },
    #[error("a lifecycle driver is already attached to this writer")]
    DriverAlreadyStarted,
    #[error("invalid lifecycle configuration: {reason}")]
    InvalidConfiguration { reason: &'static str },
    #[error("lifecycle IPC is unavailable: {reason}")]
    IpcUnavailable { reason: &'static str },
    #[error("lifecycle IPC protocol violation: {reason}")]
    IpcProtocolViolation { reason: &'static str },
    #[error("lifecycle operation deadline exceeded")]
    DeadlineExceeded,
    #[error("lifecycle shutdown failed: {reason}")]
    ShutdownFailed { reason: &'static str },
}

/// Safe caller-visible write admission and synchronous delivery errors.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WriteError {
    #[error("invalid writer configuration: {0}")]
    Configuration(#[from] ConfigurationError),
    #[error("record encoding failed: {0}")]
    Encode(#[from] EncodeError),
    #[error("write buffer capacity is full")]
    Full,
    #[error("writer admission is closed")]
    Closed,
    #[error("encoded write item requires at least {size} bytes; limit is {limit} bytes")]
    OversizedItem { size: usize, limit: usize },
    #[error("invalid tenant scope: {reason}")]
    InvalidScope { reason: &'static str },
    #[error("operation identity was already used with different payload bytes")]
    IdentityConflict { operation_id: OperationId },
    #[error("write item was rejected: {reason}")]
    Rejected { reason: &'static str },
    #[error("write destination is unavailable (accepted={accepted})")]
    Unavailable {
        operation_id: Option<OperationId>,
        accepted: bool,
    },
    #[error("write deadline exceeded (accepted={accepted})")]
    DeadlineExceeded {
        operation_id: Option<OperationId>,
        accepted: bool,
    },
    #[error("write admission or commit outcome is ambiguous")]
    Ambiguous { operation_id: OperationId },
    #[error("write buffer is corrupt: {reason}")]
    CorruptBuffer { reason: &'static str },
}

impl WriteError {
    #[must_use]
    pub fn operation_id(&self) -> Option<&OperationId> {
        match self {
            Self::IdentityConflict { operation_id } | Self::Ambiguous { operation_id } => {
                Some(operation_id)
            }
            Self::Unavailable { operation_id, .. }
            | Self::DeadlineExceeded { operation_id, .. } => operation_id.as_ref(),
            Self::Configuration(_)
            | Self::Encode(_)
            | Self::Full
            | Self::Closed
            | Self::OversizedItem { .. }
            | Self::InvalidScope { .. }
            | Self::Rejected { .. }
            | Self::CorruptBuffer { .. } => None,
        }
    }

    #[must_use]
    pub const fn is_definitely_rejected(&self) -> bool {
        match self {
            Self::Configuration(_)
            | Self::Encode(_)
            | Self::Full
            | Self::Closed
            | Self::OversizedItem { .. }
            | Self::InvalidScope { .. }
            | Self::IdentityConflict { .. }
            | Self::Rejected { .. }
            | Self::CorruptBuffer { .. } => true,
            Self::Unavailable { accepted, .. } | Self::DeadlineExceeded { accepted, .. } => {
                !*accepted
            }
            Self::Ambiguous { .. } => false,
        }
    }

    #[must_use]
    pub const fn is_ambiguous_or_accepted(&self) -> bool {
        !self.is_definitely_rejected()
    }
}
