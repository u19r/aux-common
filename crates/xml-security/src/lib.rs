//! Bounded XML 1.0 parsing and the reviewed exclusive-canonicalisation subset.

mod error;
mod signature;
mod xml;

pub use error::XmlSecurityError;
pub use signature::{EnvelopedSignature, SignatureVerifier, VerifiedElement, VerifiedXmlDocument};
#[cfg(test)]
pub(crate) use xml::{
    Element, canonicalize_exclusive, canonicalize_xml, extract_in_response_to, parse_with_limits,
    parse_xml_to_element,
};
pub use xml::{
    NS_DS, Node, SAML_ASSERTION_NS, SAML_PROTOCOL_NS, UnverifiedElement, XmlLimits,
    canonicalize_unverified_xml_text, extract_unverified_in_response_to,
};

#[cfg(test)]
mod xml_security_tests;
