use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Invalid format for {field}: {message}")]
    InvalidFormat {
        field: &'static str,
        message: String,
    },

    #[error("Required field missing: {0}")]
    RequiredFieldMissing(&'static str),

    #[error("Value out of range for {field}: {message}")]
    OutOfRange {
        field: &'static str,
        message: String,
    },

    #[error("Duplicate identifier: {0}")]
    DuplicateId(String),

    #[error("Reference not found: {entity_type} '{id}'")]
    ReferenceNotFound {
        entity_type: &'static str,
        id: String,
    },

    #[error("Limit exceeded: {resource} (max: {limit}, actual: {actual})")]
    LimitExceeded {
        resource: &'static str,
        limit: usize,
        actual: usize,
    },
}
