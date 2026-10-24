mod constants;
mod document;
mod sso_binding;

pub use document::{
    CertificateDer, CertificateTrustPolicy, MetadataVerification, MetadataWarning,
    UnverifiedMetadata, VerifiedMetadata,
};
pub use sso_binding::MetadataSsoBinding;

#[cfg(test)]
mod document_tests;
