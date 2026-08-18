use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SamlError {
    #[error("invalid SAML input: {0}")]
    InvalidInput(String),
    #[error("unsupported SAML feature: {0}")]
    Unsupported(String),
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("metadata certificate is not trusted by the supplied trust policy")]
    CertificateNotTrusted,
    #[error("unsupported signature or digest algorithm")]
    UnsupportedAlgorithm,
    #[error("signature verification failed")]
    SignatureVerification,
}

impl From<xml_security::XmlSecurityError> for SamlError {
    fn from(error: xml_security::XmlSecurityError) -> Self {
        match error {
            xml_security::XmlSecurityError::Unsupported { message } => Self::Unsupported(message),
            xml_security::XmlSecurityError::Signature { message } => Self::InvalidInput(message),
            xml_security::XmlSecurityError::SignatureVerification => Self::SignatureVerification,
            xml_security::XmlSecurityError::NamespaceMismatch { message }
            | xml_security::XmlSecurityError::Parse { message }
            | xml_security::XmlSecurityError::Shape { message } => Self::InvalidInput(message),
        }
    }
}
