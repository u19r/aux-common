//! Bounded XML 1.0 parsing and the reviewed exclusive-canonicalisation subset.
//!
//! `UnverifiedElement`, `Node`, `canonicalize_unverified_xml_text`, and
//! `extract_unverified_in_response_to` are parsing helpers only and must never
//! inform trust decisions. Only [`VerifiedXmlDocument`] and [`VerifiedElement`]
//! cross the trust boundary.

mod constants;
mod error;
mod signature;
mod xml;

pub use constants::{NS_DS, SAML_ASSERTION_NS, SAML_PROTOCOL_NS};
pub use error::XmlSecurityError;
pub use signature::{EnvelopedSignature, SignatureVerifier, VerifiedElement, VerifiedXmlDocument};
pub use xml::{
    Node, UnverifiedElement, XmlLimits, canonicalize_unverified_xml_text,
    extract_unverified_in_response_to,
};
