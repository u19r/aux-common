use core::fmt;

/// Validation failures at a public job boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    Empty {
        field: &'static str,
    },
    TooLong {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    TooShort {
        field: &'static str,
        minimum: usize,
        actual: usize,
    },
    InvalidText {
        field: &'static str,
    },
    InvalidValue {
        field: &'static str,
    },
    Overflow {
        field: &'static str,
    },
    Ordering {
        field: &'static str,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(formatter, "{field} must not be empty"),
            Self::TooLong {
                field,
                maximum,
                actual,
            } => write!(formatter, "{field} exceeds {maximum} bytes: {actual}"),
            Self::TooShort {
                field,
                minimum,
                actual,
            } => write!(formatter, "{field} requires {minimum} bytes: {actual}"),
            Self::InvalidText { field } => write!(formatter, "{field} is not valid text"),
            Self::InvalidValue { field } => write!(formatter, "{field} has an invalid value"),
            Self::Overflow { field } => write!(formatter, "{field} overflows its bound"),
            Self::Ordering { field } => write!(formatter, "{field} has an invalid ordering"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Fail-closed errors from the versioned persisted-value codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreDataError {
    UnknownVersion(u8),
    UnknownTag(u8),
    Truncated,
    Malformed(&'static str),
    InvalidLength {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    LengthOverflow,
    TrailingBytes,
}

impl fmt::Display for StoreDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVersion(version) => write!(formatter, "unknown value version {version}"),
            Self::UnknownTag(tag) => write!(formatter, "unknown value tag {tag}"),
            Self::Truncated => formatter.write_str("truncated persisted value"),
            Self::Malformed(reason) => write!(formatter, "malformed persisted value: {reason}"),
            Self::InvalidLength {
                field,
                actual,
                maximum,
            } => write!(formatter, "{field} length {actual} exceeds {maximum}"),
            Self::LengthOverflow => formatter.write_str("persisted length overflows"),
            Self::TrailingBytes => formatter.write_str("persisted value has trailing bytes"),
        }
    }
}

impl std::error::Error for StoreDataError {}

impl From<crate::ids::IdentifierError> for StoreDataError {
    fn from(_: crate::ids::IdentifierError) -> Self {
        Self::Malformed("identifier")
    }
}

impl From<ValidationError> for StoreDataError {
    fn from(_: ValidationError) -> Self {
        Self::Malformed("validated value")
    }
}

/// Typed categories for a backend operation failure.
#[derive(Clone, PartialEq, Eq)]
pub enum StoreFailure {
    Unavailable,
    Timeout,
    Permanent,
    Corrupt(StoreDataError),
    Unsupported,
}

impl fmt::Debug for StoreFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("Unavailable"),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::Permanent => formatter.write_str("Permanent"),
            Self::Corrupt(_) => formatter.write_str("Corrupt(<redacted>)"),
            Self::Unsupported => formatter.write_str("Unsupported"),
        }
    }
}

impl fmt::Display for StoreFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("store unavailable"),
            Self::Timeout => formatter.write_str("store operation timed out"),
            Self::Permanent => formatter.write_str("permanent store failure"),
            Self::Corrupt(_) => formatter.write_str("corrupt store data"),
            Self::Unsupported => formatter.write_str("store capability is unsupported"),
        }
    }
}

impl std::error::Error for StoreFailure {}

/// Errors returned while validating the store contract or its transaction
/// limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreContractError {
    Validation(ValidationError),
    CapabilityExceeded(&'static str),
    DuplicateTransactionKey(&'static str),
    FalseDistributedClaim,
    EmptyTransaction,
}

impl fmt::Display for StoreContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => error.fmt(formatter),
            Self::CapabilityExceeded(field) => {
                write!(formatter, "store capability exceeded: {field}")
            }
            Self::DuplicateTransactionKey(section) => {
                write!(formatter, "store transaction has a duplicate {section} key")
            }
            Self::FalseDistributedClaim => {
                formatter.write_str("store does not satisfy distributed semantics")
            }
            Self::EmptyTransaction => formatter.write_str("store transaction is empty"),
        }
    }
}

impl std::error::Error for StoreContractError {}

impl From<ValidationError> for StoreContractError {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}

/// Errors returned by the runtime-neutral lifecycle engine.
/// The adapter error in [`Self::Store`] remains available to typed callers by
/// matching the public variant. Safe formatting intentionally projects it to
/// a fixed category and does not call its `Display` or `Debug` implementation.
pub enum JobSystemError<E> {
    Validation(ValidationError),
    StoreContract(StoreContractError),
    StoreData(StoreDataError),
    Store(E),
    WakeScheduler(crate::model::WakeSchedulerError),
    UnregisteredHandler,
    JobIdConflict,
    NotFound,
    LeaseConflict,
    LeaseLost,
    PayloadCorrupt,
    /// The source lease committed, but remote publication was not acknowledged.
    /// No usable claim was exposed; ordinary lease expiry/reclaim remains safe.
    ClaimPublicationUnacknowledged,
    UnsupportedOutcome,
    UnknownCommit,
    EntropyUnavailable,
}

impl<E> fmt::Debug for JobSystemError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => formatter.debug_tuple("Validation").field(error).finish(),
            Self::StoreContract(error) => {
                formatter.debug_tuple("StoreContract").field(error).finish()
            }
            Self::StoreData(error) => formatter.debug_tuple("StoreData").field(error).finish(),
            Self::Store(_) => formatter.write_str("Store(<redacted>)"),
            Self::WakeScheduler(error) => {
                formatter.debug_tuple("WakeScheduler").field(error).finish()
            }
            Self::UnregisteredHandler => formatter.write_str("UnregisteredHandler"),
            Self::JobIdConflict => formatter.write_str("JobIdConflict"),
            Self::NotFound => formatter.write_str("NotFound"),
            Self::LeaseConflict => formatter.write_str("LeaseConflict"),
            Self::LeaseLost => formatter.write_str("LeaseLost"),
            Self::PayloadCorrupt => formatter.write_str("PayloadCorrupt"),
            Self::ClaimPublicationUnacknowledged => {
                formatter.write_str("ClaimPublicationUnacknowledged")
            }
            Self::UnsupportedOutcome => formatter.write_str("UnsupportedOutcome"),
            Self::UnknownCommit => formatter.write_str("UnknownCommit"),
            Self::EntropyUnavailable => formatter.write_str("EntropyUnavailable"),
        }
    }
}

impl<E> fmt::Display for JobSystemError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => error.fmt(formatter),
            Self::StoreContract(error) => error.fmt(formatter),
            Self::StoreData(error) => error.fmt(formatter),
            Self::Store(_) => formatter.write_str("job store failure"),
            Self::WakeScheduler(error) => write!(formatter, "wake scheduler failure: {error}"),
            Self::UnregisteredHandler => formatter.write_str("job handler is not registered"),
            Self::JobIdConflict => {
                formatter.write_str("job ID already has different immutable data")
            }
            Self::NotFound => formatter.write_str("job was not found"),
            Self::LeaseConflict => formatter.write_str("job claim conflicted"),
            Self::LeaseLost => formatter.write_str("job lease authority was lost"),
            Self::PayloadCorrupt => formatter.write_str("job payload is corrupt or incomplete"),
            Self::ClaimPublicationUnacknowledged => {
                formatter.write_str("job claim publication was not acknowledged")
            }
            Self::UnsupportedOutcome => {
                formatter.write_str("job outcome is outside this lifecycle slice")
            }
            Self::UnknownCommit => formatter.write_str("store commit outcome is unresolved"),
            Self::EntropyUnavailable => formatter.write_str("secure job entropy unavailable"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display + 'static> std::error::Error for JobSystemError<E> {}

impl<E> From<ValidationError> for JobSystemError<E> {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}

impl<E> From<StoreContractError> for JobSystemError<E> {
    fn from(error: StoreContractError) -> Self {
        Self::StoreContract(error)
    }
}

impl<E> From<StoreDataError> for JobSystemError<E> {
    fn from(error: StoreDataError) -> Self {
        Self::StoreData(error)
    }
}

/// Result alias for lifecycle operations over a particular store error type.
pub type JobResult<T, E> = Result<T, JobSystemError<E>>;
