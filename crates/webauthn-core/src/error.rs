use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("WebAuthn input is malformed")]
    Malformed,
    #[error("WebAuthn relying-party policy is invalid")]
    InvalidPolicy,
    #[error("client data is invalid")]
    ClientData,
    #[error("challenge does not match")]
    ChallengeMismatch,
    #[error("origin does not match")]
    OriginMismatch,
    #[error("RP ID hash does not match")]
    RpIdHashMismatch,
    #[error("user presence is required")]
    UserPresenceMissing,
    #[error("user verification is required")]
    UserVerificationRequired,
    #[error("unsupported WebAuthn extension data")]
    UnsupportedExtensions,
    #[error("unsupported COSE key")]
    UnsupportedCoseKey,
    #[error("unsupported attestation format")]
    UnsupportedAttestation,
    #[error("invalid WebAuthn signature")]
    InvalidSignature,
}
