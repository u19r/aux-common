mod document;

pub(crate) use document::parse_xml_to_element;
#[cfg(test)]
pub(crate) use document::{
    Element, canonicalize_exclusive, canonicalize_xml, extract_in_response_to, parse_with_limits,
};
pub use document::{
    Node, UnverifiedElement, XmlLimits, canonicalize_unverified_xml_text,
    extract_unverified_in_response_to,
};

#[cfg(test)]
pub(crate) use crate::constants::SAML_PROTOCOL_NS;

#[cfg(test)]
mod document_tests;
