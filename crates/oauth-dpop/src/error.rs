/// Error categories deliberately exclude customer-controlled material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DpopError {
    #[error("invalid_dpop_proof")]
    InvalidProof,
    #[error("invalid request target")]
    InvalidTarget,
    #[error("invalid token confirmation")]
    InvalidConfirmation,
    #[error("invalid token presenter")]
    InvalidPresenter,
}

impl From<jose_core::JoseError> for DpopError {
    fn from(_: jose_core::JoseError) -> Self {
        Self::InvalidProof
    }
}
