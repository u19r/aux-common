//! Strict SAML 2.0 protocol primitives with no application or tenant model.

mod bindings;
mod crypto;
mod error;
mod metadata;

pub use bindings::{
    MAX_REQUEST_B64_BYTES, build_redirect_request_url, decode_post_request,
    decode_redirect_request, encode_response, validate_redirect_destination,
};
pub use crypto::{
    DigestAlgorithm, SignatureAlgorithm, UnverifiedPublicKeyDer, compute_digest, verify_saml_xml,
    verify_signature,
};
pub use error::SamlError;
pub use metadata::{
    CertificateDer, CertificateTrustPolicy, MetadataVerification, MetadataWarning,
    UnverifiedMetadata, VerifiedMetadata,
};
pub use xml_security::{VerifiedElement, VerifiedXmlDocument};

#[cfg(test)]
mod saml2_tests;
