use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{SamlError, bindings::validate_redirect_destination};

const SAML_METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const SAML_BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const NS_DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const NS_XINCLUDE: &str = "http://www.w3.org/2001/XInclude";
const NS_XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataWarning {
    MultipleSigningCertificates,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CertificateDer(Vec<u8>);

impl std::fmt::Debug for CertificateDer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CertificateDer([redacted])")
    }
}

impl CertificateDer {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Exact SHA-256 certificate pins selected by the application trust policy.
///
/// Metadata parsing only establishes that a certificate is well-formed. It
/// never establishes identity-provider trust. Callers must build this policy
/// from an independently trusted configuration source and validate the parsed
/// metadata before retaining or using its certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateTrustPolicy {
    fingerprints: Vec<[u8; 32]>,
}

impl CertificateTrustPolicy {
    /// Build a policy from one or more exact SHA-256 DER certificate
    /// fingerprints. Empty policies are rejected so an omitted trust source
    /// cannot accidentally become an allow-all policy.
    pub fn from_sha256_fingerprints(mut fingerprints: Vec<[u8; 32]>) -> Result<Self, SamlError> {
        if fingerprints.is_empty() {
            return Err(SamlError::InvalidInput(
                "at least one trusted certificate fingerprint is required".to_string(),
            ));
        }
        fingerprints.sort_unstable();
        fingerprints.dedup();
        Ok(Self { fingerprints })
    }

    fn accepts_der(&self, der: &[u8]) -> bool {
        let fingerprint: [u8; 32] = Sha256::digest(der).into();
        self.fingerprints.binary_search(&fingerprint).is_ok()
    }
}

/// Metadata parsed from XML without authenticating the XML document.
///
/// The values are bounded and structurally validated, but the document can
/// still have been supplied by an attacker. Use
/// [`VerifiedMetadata::try_from`] when metadata authenticity is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedMetadata {
    entity_id: String,
    sso_url: String,
    certificates: Vec<CertificateDer>,
    warnings: Vec<MetadataWarning>,
}

impl UnverifiedMetadata {
    /// Parse metadata without verifying an XML signature.
    ///
    /// The returned value is structurally validated but remains attacker
    /// controlled. Use [`VerifiedMetadata::try_from`] when metadata
    /// authenticity is required.
    pub fn parse_unverified(xml: &str, now: DateTime<Utc>) -> Result<Self, SamlError> {
        let root = xml_security::UnverifiedElement::try_from(xml)?;
        Self::from_unverified_element(&root, now)
    }

    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    #[must_use]
    pub fn sso_url(&self) -> &str {
        &self.sso_url
    }

    #[must_use]
    pub fn certificates(&self) -> &[CertificateDer] {
        &self.certificates
    }

    #[must_use]
    pub fn warnings(&self) -> &[MetadataWarning] {
        &self.warnings
    }

    /// Require every signing certificate in this document to match the
    /// caller-supplied exact pin set.
    pub fn validate_trust(&self, policy: &CertificateTrustPolicy) -> Result<(), SamlError> {
        if self
            .certificates
            .iter()
            .all(|certificate| policy.accepts_der(certificate.as_bytes()))
        {
            Ok(())
        } else {
            Err(SamlError::CertificateNotTrusted)
        }
    }
}

impl UnverifiedMetadata {
    fn from_unverified_element(
        root: &xml_security::UnverifiedElement,
        now: DateTime<Utc>,
    ) -> Result<Self, SamlError> {
        if contains_namespace(root, NS_XINCLUDE) {
            return Err(SamlError::Unsupported(
                "XInclude is not supported in metadata".to_string(),
            ));
        }
        if contains_namespace(root, NS_XMLENC) {
            return Err(SamlError::Unsupported(
                "XML Encryption is not supported in metadata".to_string(),
            ));
        }
        if contains_element(root, NS_DS, "Signature") {
            return Err(SamlError::Unsupported(
                "signed metadata is not supported without caller verification".to_string(),
            ));
        }
        validate_valid_until(root, now, "metadata")?;
        let entity = find_entity_descriptor(root)?;
        if !std::ptr::eq(entity, root) {
            validate_valid_until(entity, now, "EntityDescriptor")?;
        }
        let entity_id = entity
            .attr("entityID")
            .ok_or_else(|| SamlError::InvalidInput("metadata entityID is required".to_string()))?
            .to_string();
        if entity_id.trim().is_empty() {
            return Err(SamlError::InvalidInput(
                "metadata entityID must not be empty".to_string(),
            ));
        }
        let mut idp_descriptors = entity.child_elements().filter(|child| {
            child.name() == "IDPSSODescriptor" && child.namespace() == Some(SAML_METADATA_NS)
        });
        let idp = idp_descriptors
            .next()
            .ok_or_else(|| SamlError::InvalidInput("IDPSSODescriptor is required".to_string()))?;
        if idp_descriptors.next().is_some() {
            return Err(SamlError::Unsupported(
                "multiple IDPSSODescriptor values are not supported".to_string(),
            ));
        }
        let endpoints = idp
            .child_elements()
            .filter(|child| {
                child.name() == "SingleSignOnService"
                    && child.namespace() == Some(SAML_METADATA_NS)
                    && child.attr("Binding") == Some(SAML_BINDING_HTTP_POST)
            })
            .collect::<Vec<_>>();
        if endpoints.is_empty() {
            return Err(SamlError::InvalidInput(
                "HTTP-POST SingleSignOnService is required".to_string(),
            ));
        }
        let mut warnings = Vec::new();
        if endpoints.len() > 1 {
            return Err(SamlError::Unsupported(
                "multiple HTTP-POST SingleSignOnService values are not supported".to_string(),
            ));
        }
        let sso_url = endpoints[0]
            .attr("Location")
            .ok_or_else(|| {
                SamlError::InvalidInput("SingleSignOnService Location is required".to_string())
            })?
            .to_string();
        validate_redirect_destination(&sso_url)?;
        let certificates = extract_certificates(idp, &mut warnings)?;
        Ok(UnverifiedMetadata {
            entity_id,
            sso_url,
            certificates,
            warnings,
        })
    }
}

/// Metadata whose XML document was verified against caller-supplied signing
/// certificates and whose advertised signing certificates match the supplied
/// trust policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMetadata(UnverifiedMetadata);

/// Input to [`VerifiedMetadata::try_from`].
pub struct MetadataVerification<'a, C> {
    xml: &'a str,
    trusted_signing_certificates: &'a [C],
    trust_policy: &'a CertificateTrustPolicy,
    now: DateTime<Utc>,
}

impl<'a, C> MetadataVerification<'a, C> {
    #[must_use]
    pub const fn new(
        xml: &'a str,
        trusted_signing_certificates: &'a [C],
        trust_policy: &'a CertificateTrustPolicy,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            xml,
            trusted_signing_certificates,
            trust_policy,
            now,
        }
    }
}

impl VerifiedMetadata {
    #[must_use]
    pub fn entity_id(&self) -> &str {
        self.0.entity_id()
    }

    #[must_use]
    pub fn sso_url(&self) -> &str {
        self.0.sso_url()
    }

    #[must_use]
    pub fn certificates(&self) -> &[CertificateDer] {
        self.0.certificates()
    }

    #[must_use]
    pub fn warnings(&self) -> &[MetadataWarning] {
        self.0.warnings()
    }
}

impl<C: AsRef<str>> TryFrom<MetadataVerification<'_, C>> for VerifiedMetadata {
    type Error = SamlError;

    fn try_from(input: MetadataVerification<'_, C>) -> Result<Self, Self::Error> {
        let verified =
            crate::crypto::verify_saml_xml(input.xml, input.trusted_signing_certificates)?;
        let parsed = UnverifiedMetadata::from_unverified_element(
            verified.signed_element().as_unverified(),
            input.now,
        )?;
        parsed.validate_trust(input.trust_policy)?;
        Ok(Self(parsed))
    }
}

fn validate_valid_until(
    element: &xml_security::UnverifiedElement,
    now: DateTime<Utc>,
    element_name: &str,
) -> Result<(), SamlError> {
    let valid_until = element
        .attr("validUntil")
        .ok_or_else(|| SamlError::InvalidInput(format!("{element_name} validUntil is required")))?;
    let valid_until = DateTime::parse_from_rfc3339(valid_until)
        .map_err(|_| SamlError::InvalidInput(format!("{element_name} validUntil is invalid")))?;
    if valid_until.with_timezone(&Utc) <= now {
        return Err(SamlError::InvalidInput(format!(
            "{element_name} metadata is expired"
        )));
    }
    Ok(())
}

fn find_entity_descriptor(
    root: &xml_security::UnverifiedElement,
) -> Result<&xml_security::UnverifiedElement, SamlError> {
    if root.name() == "EntityDescriptor" && root.namespace() == Some(SAML_METADATA_NS) {
        return Ok(root);
    }
    if root.name() == "EntitiesDescriptor" && root.namespace() == Some(SAML_METADATA_NS) {
        let mut entities = root.child_elements().filter(|child| {
            child.name() == "EntityDescriptor" && child.namespace() == Some(SAML_METADATA_NS)
        });
        let Some(entity) = entities.next() else {
            return Err(SamlError::InvalidInput(
                "EntityDescriptor is required".to_string(),
            ));
        };
        if entities.next().is_some() {
            return Err(SamlError::Unsupported(
                "multiple EntityDescriptor values are not supported".to_string(),
            ));
        }
        return Ok(entity);
    }
    Err(SamlError::InvalidInput(
        "EntityDescriptor is required".to_string(),
    ))
}

fn extract_certificates(
    idp: &xml_security::UnverifiedElement,
    warnings: &mut Vec<MetadataWarning>,
) -> Result<Vec<CertificateDer>, SamlError> {
    let mut signing = Vec::new();
    for descriptor in idp.child_elements().filter(|child| {
        child.name() == "KeyDescriptor" && child.namespace() == Some(SAML_METADATA_NS)
    }) {
        let target = match descriptor.attr("use") {
            Some("signing") => &mut signing,
            Some("encryption") => continue,
            Some(_) => {
                return Err(SamlError::Unsupported(
                    "unsupported KeyDescriptor use".to_string(),
                ));
            }
            None => {
                return Err(SamlError::InvalidInput(
                    "KeyDescriptor use is required".to_string(),
                ));
            }
        };
        let key_infos = descriptor
            .child_elements()
            .map(|child| {
                if child.namespace() == Some(NS_DS) && child.name() == "RetrievalMethod" {
                    return Err(SamlError::Unsupported(
                        "remote XML Signature key retrieval is not supported".to_string(),
                    ));
                }
                if child.namespace() == Some(NS_DS) && child.name() == "KeyInfo" {
                    Ok(child)
                } else {
                    Err(SamlError::Unsupported(
                        "KeyDescriptor contains an unsupported child".to_string(),
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        if key_infos.len() != 1 {
            return Err(SamlError::InvalidInput(
                "exactly one ds:KeyInfo is required for a signing KeyDescriptor".to_string(),
            ));
        }
        let key_info = key_infos[0];
        let x509_data = key_info
            .child_elements()
            .map(|child| {
                if child.namespace() == Some(NS_DS) && child.name() == "RetrievalMethod" {
                    return Err(SamlError::Unsupported(
                        "remote XML Signature key retrieval is not supported".to_string(),
                    ));
                }
                if child.namespace() == Some(NS_DS) && child.name() == "X509Data" {
                    Ok(child)
                } else {
                    Err(SamlError::Unsupported(
                        "ds:KeyInfo contains an unsupported child".to_string(),
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        if x509_data.len() != 1 {
            return Err(SamlError::InvalidInput(
                "exactly one ds:X509Data is required for a signing KeyDescriptor".to_string(),
            ));
        }
        let certificates = x509_data[0]
            .child_elements()
            .map(|element| {
                if element.namespace() != Some(NS_DS) || element.name() != "X509Certificate" {
                    return Err(SamlError::Unsupported(
                        "ds:X509Data contains an unsupported child".to_string(),
                    ));
                }
                if element.child_elements().next().is_some() {
                    return Err(SamlError::InvalidInput(
                        "X509Certificate must contain text only".to_string(),
                    ));
                }
                let text = element
                    .text_content()
                    .ok_or_else(|| SamlError::InvalidInput("empty X509Certificate".to_string()))?;
                let encoded = text.split_whitespace().collect::<String>();
                let bytes = STANDARD
                    .decode(encoded)
                    .map_err(|_| SamlError::InvalidCertificate)?;
                if bytes.is_empty() || bytes.len() > 64 * 1024 {
                    return Err(SamlError::InvalidCertificate);
                }
                let (remainder, _) =
                    X509Certificate::from_der(&bytes).map_err(|_| SamlError::InvalidCertificate)?;
                if !remainder.is_empty() {
                    return Err(SamlError::InvalidCertificate);
                }
                Ok(CertificateDer(bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if certificates.is_empty() {
            return Err(SamlError::InvalidInput(
                "at least one X509Certificate is required".to_string(),
            ));
        }
        target.extend(certificates);
    }
    let mut certificates = signing;
    if certificates.is_empty() {
        return Err(SamlError::InvalidInput(
            "at least one X509Certificate is required".to_string(),
        ));
    }
    if certificates.len() > 1 {
        warnings.push(MetadataWarning::MultipleSigningCertificates);
    }
    certificates.sort_by(|left, right| left.0.cmp(&right.0));
    certificates.dedup_by(|left, right| left.0 == right.0);
    Ok(certificates)
}

fn contains_namespace(root: &xml_security::UnverifiedElement, namespace: &str) -> bool {
    root.namespace() == Some(namespace)
        || root
            .child_elements()
            .any(|child| contains_namespace(child, namespace))
}

fn contains_element(root: &xml_security::UnverifiedElement, namespace: &str, name: &str) -> bool {
    (root.namespace() == Some(namespace) && root.name() == name)
        || root
            .child_elements()
            .any(|child| contains_element(child, namespace, name))
}
