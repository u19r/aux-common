use thiserror::Error;

pub type AuthzRuntimeResult<T> = Result<T, AuthzRuntimeError>;

#[derive(Debug, Error)]
pub enum AuthzRuntimeError {
    #[error("policy runtime build failed")]
    Build,

    #[error("cedar evaluation failed")]
    Cedar,

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
    pub fn build(_error: impl std::fmt::Display) -> Self {
        Self::Build
    }

    pub fn cedar(_error: impl std::fmt::Display) -> Self {
        Self::Cedar
    }
}
