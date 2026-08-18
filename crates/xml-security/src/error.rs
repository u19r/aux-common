use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum XmlSecurityError {
    #[error("xml parse error: {message}")]
    Parse { message: String },
    #[error("invalid xml shape: {message}")]
    Shape { message: String },
    #[error("unsupported xml feature: {message}")]
    Unsupported { message: String },
    #[error("namespace mismatch: {message}")]
    NamespaceMismatch { message: String },
    #[error("invalid XML signature: {message}")]
    Signature { message: String },
    #[error("XML signature verification failed")]
    SignatureVerification,
}
