use std::{
    cell::Cell,
    io::{Cursor, Read, Write},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use url::{SyntaxViolation, Url};

use crate::SamlError;

pub const MAX_XML_BYTES: usize = 512 * 1024;
pub const MAX_REQUEST_B64_BYTES: usize = MAX_XML_BYTES.div_ceil(3) * 4;

pub fn decode_post_request(encoded: &str) -> Result<String, SamlError> {
    decode_xml_payload(decode_base64(encoded)?)
}

/// Encode a bounded SAML response for the HTTP-POST form field.
///
/// Responses larger than [`MAX_XML_BYTES`] are rejected before base64
/// allocation.
pub fn encode_response(xml: &str) -> Result<String, SamlError> {
    if xml.len() > MAX_XML_BYTES {
        return Err(SamlError::InvalidInput(
            "SAML XML exceeds the configured limit".to_string(),
        ));
    }
    Ok(STANDARD.encode(xml.as_bytes()))
}

pub fn decode_redirect_request(encoded: &str) -> Result<String, SamlError> {
    let decoded = decode_base64(encoded)?;
    if looks_like_xml(&decoded) {
        return decode_xml_payload(decoded);
    }
    let decoded_len = decoded.len();
    let mut decoder = DeflateDecoder::new(Cursor::new(decoded));
    let mut inflated = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = decoder.read(&mut chunk).map_err(|_| {
            SamlError::InvalidInput("Redirect DEFLATE payload is invalid".to_string())
        })?;
        if read == 0 {
            break;
        }
        if inflated.len() + read > MAX_XML_BYTES {
            return Err(SamlError::InvalidInput(
                "Redirect inflated payload exceeds max size".to_string(),
            ));
        }
        inflated.extend_from_slice(&chunk[..read]);
    }
    if inflated.is_empty() {
        return Err(SamlError::InvalidInput(
            "Redirect payload is empty".to_string(),
        ));
    }
    if decoder.total_in() != decoded_len as u64 {
        return Err(SamlError::InvalidInput(
            "Redirect DEFLATE payload has trailing bytes".to_string(),
        ));
    }
    decode_xml_payload(inflated)
}

/// Build an HTTP-Redirect URL for a trusted IdP destination.
///
/// The destination is validated as an absolute HTTPS URL, but this crate does
/// not select or trust an IdP host. Callers must source it from verified
/// metadata or an application-owned allowlist.
pub fn build_redirect_request_url(
    destination: &str,
    xml: &str,
    relay_state: Option<&str>,
) -> Result<String, SamlError> {
    validate_redirect_destination(destination)?;
    if xml.len() > MAX_XML_BYTES {
        return Err(SamlError::InvalidInput(
            "SAML XML exceeds the configured limit".to_string(),
        ));
    }
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(xml.as_bytes())
        .map_err(|_| SamlError::InvalidInput("SAML XML compression failed".to_string()))?;
    let compressed = encoder
        .finish()
        .map_err(|_| SamlError::InvalidInput("SAML XML compression failed".to_string()))?;
    let separator = if destination.contains('?') { '&' } else { '?' };
    let mut result = format!(
        "{destination}{separator}SAMLRequest={}",
        percent_encode(&STANDARD.encode(compressed))
    );
    if let Some(relay_state) = relay_state {
        result.push_str("&RelayState=");
        result.push_str(&percent_encode(relay_state));
    }
    Ok(result)
}

/// Validate the transport and URL shape of a SAML destination.
///
/// This helper deliberately does not establish trust in a host: federated SAML
/// deployments choose their IdP hosts through application-owned metadata and
/// allowlists. Callers must apply that trust policy before passing an
/// attacker-controlled or otherwise untrusted destination here.
pub fn validate_redirect_destination(destination: &str) -> Result<(), SamlError> {
    let malformed_syntax = Cell::new(false);
    let url = Url::options()
        .syntax_violation_callback(Some(&|violation| {
            if matches!(
                violation,
                SyntaxViolation::Backslash
                    | SyntaxViolation::C0SpaceIgnored
                    | SyntaxViolation::ExpectedDoubleSlash
                    | SyntaxViolation::ExpectedFileDoubleSlash
                    | SyntaxViolation::PercentDecode
                    | SyntaxViolation::TabOrNewlineIgnored
                    | SyntaxViolation::UnencodedAtSign
            ) {
                malformed_syntax.set(true);
            }
        }))
        .parse(destination)
        .map_err(|_| invalid_destination())?;
    let has_non_empty_host = url.host_str().is_some_and(|host| !host.is_empty());
    if !url.scheme().eq_ignore_ascii_case("https")
        || !has_non_empty_host
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || malformed_syntax.get()
    {
        return Err(invalid_destination());
    }
    Ok(())
}

fn invalid_destination() -> SamlError {
    SamlError::InvalidInput(
        "destination must be an absolute HTTPS URL without credentials or a fragment".to_string(),
    )
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>, SamlError> {
    if encoded.is_empty() {
        return Err(SamlError::InvalidInput(
            "SAMLRequest payload is empty".to_string(),
        ));
    }
    if encoded.len() > MAX_REQUEST_B64_BYTES {
        return Err(SamlError::InvalidInput(format!(
            "SAMLRequest payload exceeds max encoded size of {MAX_REQUEST_B64_BYTES} bytes"
        )));
    }
    STANDARD
        .decode(encoded)
        .map_err(|_| SamlError::InvalidInput("SAMLRequest base64 decode failed".to_string()))
}

fn decode_xml_payload(decoded: Vec<u8>) -> Result<String, SamlError> {
    if decoded.len() > MAX_XML_BYTES {
        return Err(SamlError::InvalidInput(format!(
            "SAMLRequest XML exceeds max decoded size of {MAX_XML_BYTES} bytes"
        )));
    }
    let xml = String::from_utf8(decoded)
        .map_err(|_| SamlError::InvalidInput("SAML XML is not UTF-8".to_string()))?;
    if !xml.trim_start().starts_with('<') {
        return Err(SamlError::InvalidInput(
            "SAMLRequest must decode to XML text".to_string(),
        ));
    }
    Ok(xml)
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|value| value.trim_start().starts_with('<'))
}

fn percent_encode(input: &str) -> String {
    input
        .bytes()
        .fold(String::with_capacity(input.len()), |mut output, byte| {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    output.push(byte as char)
                }
                _ => {
                    output.push('%');
                    output.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                    output.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
                }
            }
            output
        })
}
