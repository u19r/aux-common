use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use sha2::{Digest as _, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::SamlError;

/// DER-encoded subject-public-key bytes parsed from a certificate.
///
/// Parsing proves only that the certificate is structurally valid. It does
/// not establish that the key is trusted for any identity or XML document;
/// callers should prefer [`crate::verify_saml_xml`] with an independently
/// trusted certificate list.
#[derive(Clone, PartialEq, Eq)]
pub struct UnverifiedPublicKeyDer(Vec<u8>);

impl std::fmt::Debug for UnverifiedPublicKeyDer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UnverifiedPublicKeyDer([redacted])")
    }
}

impl UnverifiedPublicKeyDer {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Parse a PEM or base64-encoded X.509 certificate into an unverified
    /// subject-public-key representation.
    pub fn parse_unverified(input: &str) -> Result<Self, SamlError> {
        Self::try_from(input)
    }

    /// Construct an explicitly unverified key representation from raw DER
    /// bytes. This does not parse a certificate or establish trust.
    #[must_use]
    pub fn from_unverified_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for UnverifiedPublicKeyDer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

const MAX_CERTIFICATE_INPUT_BYTES: usize = 128 * 1024;
const MAX_PUBLIC_KEY_BYTES: usize = 8 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    RsaSha256,
}

impl SignatureAlgorithm {
    pub const RSA_SHA256_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    #[must_use]
    pub const fn as_uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => Self::RSA_SHA256_URI,
        }
    }
}

impl TryFrom<&str> for SignatureAlgorithm {
    type Error = SamlError;

    fn try_from(uri: &str) -> Result<Self, Self::Error> {
        (uri == Self::RSA_SHA256_URI)
            .then_some(Self::RsaSha256)
            .ok_or(SamlError::UnsupportedAlgorithm)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
}

impl DigestAlgorithm {
    pub const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

    #[must_use]
    pub const fn as_uri(self) -> &'static str {
        match self {
            Self::Sha256 => Self::SHA256_URI,
        }
    }
}

impl TryFrom<&str> for DigestAlgorithm {
    type Error = SamlError;

    fn try_from(uri: &str) -> Result<Self, Self::Error> {
        (uri == Self::SHA256_URI)
            .then_some(Self::Sha256)
            .ok_or(SamlError::UnsupportedAlgorithm)
    }
}

/// Verify raw RSA-SHA256 bytes.
///
/// This primitive does not parse XML, resolve a reference, remove an
/// enveloped signature, or establish which application element is trusted.
/// XML callers should use [`crate::verify_saml_xml`] instead.
pub fn verify_signature(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
    algorithm: SignatureAlgorithm,
) -> Result<(), SamlError> {
    if public_key.is_empty()
        || public_key.len() > MAX_PUBLIC_KEY_BYTES
        || signature.is_empty()
        || signature.len() > MAX_SIGNATURE_BYTES
    {
        return Err(SamlError::SignatureVerification);
    }
    match algorithm {
        SignatureAlgorithm::RsaSha256 => {
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key)
                .verify(data, signature)
                .map_err(|_| SamlError::SignatureVerification)
        }
    }
}

#[must_use]
pub fn compute_digest(data: &[u8], algorithm: DigestAlgorithm) -> Vec<u8> {
    match algorithm {
        DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
    }
}

impl TryFrom<&str> for UnverifiedPublicKeyDer {
    type Error = SamlError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        if input.len() > MAX_CERTIFICATE_INPUT_BYTES {
            return Err(SamlError::InvalidCertificate);
        }
        let bytes = if input.trim().contains("BEGIN CERTIFICATE") {
            let pem_text = input.trim();
            let pems = pem::parse_many(pem_text).map_err(|_| SamlError::InvalidCertificate)?;
            if pems.len() != 1 || !pem_text.ends_with("-----END CERTIFICATE-----") {
                return Err(SamlError::InvalidCertificate);
            }
            let pem = pems
                .into_iter()
                .next()
                .ok_or(SamlError::InvalidCertificate)?;
            if pem.tag() != "CERTIFICATE" {
                return Err(SamlError::InvalidCertificate);
            }
            pem.into_contents()
        } else {
            let normalized = input.split_whitespace().collect::<String>();
            STANDARD
                .decode(&normalized)
                .or_else(|_| STANDARD_NO_PAD.decode(&normalized))
                .map_err(|_| SamlError::InvalidCertificate)?
        };
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(SamlError::InvalidCertificate);
        }
        let (remainder, certificate) =
            X509Certificate::from_der(&bytes).map_err(|_| SamlError::InvalidCertificate)?;
        if !remainder.is_empty() {
            return Err(SamlError::InvalidCertificate);
        }
        Ok(Self(certificate.tbs_certificate.subject_pki.raw.to_vec()))
    }
}

impl TryFrom<&String> for UnverifiedPublicKeyDer {
    type Error = SamlError;

    fn try_from(input: &String) -> Result<Self, Self::Error> {
        Self::try_from(input.as_str())
    }
}

/// Verify a signed SAML XML document against caller-supplied, independently
/// trusted certificates in one operation.
///
/// The XMLDSig profile is intentionally strict: a direct root signature or a
/// single nested signed element, a unique `ID` reference to that element,
/// enveloped-signature followed by exclusive canonicalisation, and
/// RSA-SHA256/SHA-256 only. Embedded KeyInfo is never used as a trust source.
/// The returned element is the signature-covered subtree with all XMLDSig
/// signature nodes removed.
pub fn verify_saml_xml<C: AsRef<str>>(
    xml: &str,
    trusted_certificates: &[C],
) -> Result<xml_security::VerifiedXmlDocument, SamlError> {
    if trusted_certificates.is_empty() {
        return Err(SamlError::InvalidCertificate);
    }
    let public_keys = trusted_certificates
        .iter()
        .map(|certificate| UnverifiedPublicKeyDer::try_from(certificate.as_ref()))
        .collect::<Result<Vec<_>, _>>()?;
    xml_security::VerifiedXmlDocument::verify_enveloped(xml, &public_keys).map_err(SamlError::from)
}
