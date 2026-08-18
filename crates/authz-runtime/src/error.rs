use thiserror::Error;

pub type AuthzRuntimeResult<T> = Result<T, AuthzRuntimeError>;

#[derive(Debug, Error)]
pub enum AuthzRuntimeError {
    #[error("policy runtime build failed: {0}")]
    Build(String),

    #[error("cedar evaluation failed: {0}")]
    Cedar(String),

    #[error("snapshot subject does not match evaluation request")]
    SubjectSnapshotMismatch,

    #[error("snapshot resource does not match evaluation request")]
    ResourceSnapshotMismatch,

    #[error("snapshot tenant does not match evaluation tenant")]
    TenantSnapshotMismatch,

    #[error("trusted authorization context does not match evaluation subject")]
    TrustedContextSubjectMismatch,

    #[error("{snapshot} snapshot timestamp is invalid")]
    SnapshotTimestampInvalid { snapshot: &'static str },

    #[error("{snapshot} snapshot is stale")]
    SnapshotStale { snapshot: &'static str },
}

impl AuthzRuntimeError {
    pub fn build(error: impl std::fmt::Display) -> Self {
        Self::Build(error.to_string())
    }

    pub fn cedar(error: impl std::fmt::Display) -> Self {
        Self::Cedar(error.to_string())
    }
}
