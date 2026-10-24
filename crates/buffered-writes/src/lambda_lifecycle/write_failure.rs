use serde::{Deserialize, Serialize};

use crate::{OperationId, WriteError};

#[derive(Serialize, Deserialize)]
pub(super) enum WriteFailure {
    Full,
    Closed,
    Oversized { size: usize, limit: usize },
    IdentityConflict,
    Unavailable { accepted: bool },
    Deadline { accepted: bool },
    Ambiguous,
    InvalidScope,
    Corrupt,
    Rejected,
}

impl From<WriteError> for WriteFailure {
    fn from(error: WriteError) -> Self {
        match error {
            WriteError::Full => Self::Full,
            WriteError::Closed => Self::Closed,
            WriteError::OversizedItem { size, limit } => Self::Oversized { size, limit },
            WriteError::IdentityConflict { .. } => Self::IdentityConflict,
            WriteError::Unavailable { accepted, .. } => Self::Unavailable { accepted },
            WriteError::DeadlineExceeded { accepted, .. } => Self::Deadline { accepted },
            WriteError::Ambiguous { .. } => Self::Ambiguous,
            WriteError::InvalidScope { .. } => Self::InvalidScope,
            WriteError::CorruptBuffer { .. } => Self::Corrupt,
            WriteError::Configuration(_) | WriteError::Encode(_) | WriteError::Rejected { .. } => {
                Self::Rejected
            }
        }
    }
}

impl WriteFailure {
    pub(super) fn into_error(self, operation_id: OperationId) -> WriteError {
        match self {
            Self::Full => WriteError::Full,
            Self::Closed => WriteError::Closed,
            Self::Oversized { size, limit } => WriteError::OversizedItem { size, limit },
            Self::IdentityConflict => WriteError::IdentityConflict { operation_id },
            Self::Unavailable { accepted } => WriteError::Unavailable {
                operation_id: Some(operation_id),
                accepted,
            },
            Self::Deadline { accepted } => WriteError::DeadlineExceeded {
                operation_id: Some(operation_id),
                accepted,
            },
            Self::Ambiguous => WriteError::Ambiguous { operation_id },
            Self::InvalidScope => WriteError::InvalidScope {
                reason: "Lambda extension rejected the scope",
            },
            Self::Corrupt => WriteError::CorruptBuffer {
                reason: "Lambda extension buffer is corrupt",
            },
            Self::Rejected => WriteError::Rejected {
                reason: "Lambda extension rejected the write",
            },
        }
    }
}
