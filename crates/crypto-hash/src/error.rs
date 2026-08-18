use thiserror::Error;

/// Errors returned by public hashing operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HashError {
    #[error("invalid password-hash encoding")]
    InvalidPasswordHash,
    #[error("password hash is outside the selected Argon2id policy")]
    PasswordPolicy,
    #[error("password hashing failed")]
    PasswordHashing,
    #[error("api-key hash encoding is invalid")]
    InvalidApiKeyEncoding,
    #[error("unsupported api-key hash algorithm")]
    UnsupportedApiKeyAlgorithm,
}
