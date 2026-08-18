use std::{collections::HashSet, ops::Deref};

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use sha2::{Digest as _, Sha256};

use crate::{
    NS_DS, XmlSecurityError,
    xml::{Node, UnverifiedElement, parse_xml_to_element},
};

const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const MAX_PUBLIC_KEY_BYTES: usize = 8 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8 * 1024;

#[derive(Debug, Default)]
struct CanonicalizationParameters {
    signed_info_inclusive_prefixes: Option<Vec<String>>,
    reference_inclusive_prefixes: Option<Vec<String>>,
}

/// Cryptographic operations used by the XML signature profile.
///
/// [`VerifiedXmlDocument::verify_enveloped`] uses the audited default
/// implementation. This trait exists for deterministic tests and for callers
/// that provide an independently reviewed hardware-backed verifier; it does
/// not change the XML signature policy or the signed-element selection rules.
pub trait SignatureVerifier {
    fn verify_rsa_sha256(
        &self,
        canonicalized_signed_info: &[u8],
        signature: &[u8],
        public_key_der: &[u8],
    ) -> Result<bool, XmlSecurityError>;

    fn sha256_digest(&self, canonicalized_element: &[u8]) -> Result<Vec<u8>, XmlSecurityError>;
}

struct DefaultSignatureVerifier;

impl SignatureVerifier for DefaultSignatureVerifier {
    fn verify_rsa_sha256(
        &self,
        canonicalized_signed_info: &[u8],
        signature: &[u8],
        public_key_der: &[u8],
    ) -> Result<bool, XmlSecurityError> {
        if public_key_der.is_empty() || public_key_der.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(XmlSecurityError::Signature {
                message: "public key is empty or exceeds the configured limit".to_string(),
            });
        }
        if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
            return Err(XmlSecurityError::Signature {
                message: "signature value is empty or exceeds the configured limit".to_string(),
            });
        }
        Ok(
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key_der)
                .verify(canonicalized_signed_info, signature)
                .is_ok(),
        )
    }

    fn sha256_digest(&self, canonicalized_element: &[u8]) -> Result<Vec<u8>, XmlSecurityError> {
        Ok(Sha256::digest(canonicalized_element).to_vec())
    }
}

/// The element after one enveloped XML signature has been verified against
/// caller-supplied trusted public keys.
///
/// All `ds:Signature` descendants are removed before the value is returned, so
/// consumers cannot accidentally interpret signature metadata as application
/// data. If the document has a root signature, the signed element is the root;
/// otherwise the document must contain exactly one nested signed element and
/// only that subtree is returned.
#[derive(Clone, Debug)]
pub struct VerifiedElement(UnverifiedElement);

impl VerifiedElement {
    #[must_use]
    pub fn as_unverified(&self) -> &UnverifiedElement {
        &self.0
    }
}

impl Deref for VerifiedElement {
    type Target = UnverifiedElement;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Result of the one-call XML signature verification API.
#[derive(Clone, Debug)]
pub struct VerifiedXmlDocument {
    signed_element: VerifiedElement,
}

impl VerifiedXmlDocument {
    #[must_use]
    pub fn signed_element(&self) -> &VerifiedElement {
        &self.signed_element
    }

    #[must_use]
    pub fn into_signed_element(self) -> VerifiedElement {
        self.signed_element
    }

    /// Verify a strict enveloped XML signature using caller-supplied trusted
    /// public keys.
    pub fn verify_enveloped<K: AsRef<[u8]>>(
        xml: &str,
        trusted_public_keys: &[K],
    ) -> Result<Self, XmlSecurityError> {
        Self::try_from(EnvelopedSignature::new(xml, trusted_public_keys))
    }

    /// Verify a strict enveloped XML signature while injecting only the
    /// cryptographic primitive. The XML policy and signed-element selection
    /// remain fixed.
    pub fn verify_enveloped_with<K: AsRef<[u8]>, V: SignatureVerifier>(
        input: EnvelopedSignature<'_, K>,
        verifier: &V,
    ) -> Result<Self, XmlSecurityError> {
        Self::verify_with(input.xml, input.trusted_public_keys, verifier)
    }

    fn verify_with<K: AsRef<[u8]>, V: SignatureVerifier>(
        xml: &str,
        trusted_public_keys: &[K],
        verifier: &V,
    ) -> Result<Self, XmlSecurityError> {
        if trusted_public_keys.is_empty() {
            return Err(XmlSecurityError::Signature {
                message: "at least one trusted public key is required".to_string(),
            });
        }
        let root = parse_xml_to_element(xml)?;
        root.validate_unique_ids()?;
        let (signed_element, signature) = root.find_signature_target()?;
        let signed_element_id = signed_element.unique_id(&root)?;
        let signed_info = signature.require_ds_child("SignedInfo")?;
        let signature_value = signature.decode_child_text("SignatureValue", MAX_SIGNATURE_BYTES)?;
        signature.validate_signature_children()?;
        let canonicalization_parameters = signed_info.validate_signed_info(&signed_element_id)?;

        let unsigned_element_for_digest = signed_element.retaining_children(|node| {
            !matches!(
                node,
                Node::Element(element)
                    if element.name() == "Signature" && element.namespace() == Some(NS_DS)
            )
        });
        let reference = signed_info.require_ds_child("Reference")?;
        let digest_value = reference.decode_child_text("DigestValue", MAX_SIGNATURE_BYTES)?;
        let reference_prefixes = canonicalization_parameters
            .reference_inclusive_prefixes
            .as_deref()
            .map(|prefixes| prefixes.iter().map(String::as_str).collect::<Vec<_>>());
        let canonicalized_unsigned_element = unsigned_element_for_digest
            .canonicalize_unverified_with_inclusive_prefixes(reference_prefixes.as_deref())?;
        let computed_digest = verifier.sha256_digest(&canonicalized_unsigned_element)?;
        if computed_digest != digest_value {
            return Err(XmlSecurityError::Signature {
                message: "reference digest does not match the signed element".to_string(),
            });
        }

        let signed_info_prefixes = canonicalization_parameters
            .signed_info_inclusive_prefixes
            .as_deref()
            .map(|prefixes| prefixes.iter().map(String::as_str).collect::<Vec<_>>());
        let canonicalized_signed_info = signed_info
            .canonicalize_unverified_with_inclusive_prefixes(signed_info_prefixes.as_deref())?;
        let mut matched = false;
        for key in trusted_public_keys {
            if verifier.verify_rsa_sha256(
                &canonicalized_signed_info,
                &signature_value,
                key.as_ref(),
            )? {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(XmlSecurityError::SignatureVerification);
        }

        Ok(Self {
            signed_element: VerifiedElement(
                unsigned_element_for_digest.without_ds_signature_nodes(),
            ),
        })
    }
}

/// The input to [`VerifiedXmlDocument::try_from`].
pub struct EnvelopedSignature<'a, K> {
    xml: &'a str,
    trusted_public_keys: &'a [K],
}

impl<'a, K> EnvelopedSignature<'a, K> {
    #[must_use]
    pub const fn new(xml: &'a str, trusted_public_keys: &'a [K]) -> Self {
        Self {
            xml,
            trusted_public_keys,
        }
    }
}

impl<K: AsRef<[u8]>> TryFrom<EnvelopedSignature<'_, K>> for VerifiedXmlDocument {
    type Error = XmlSecurityError;

    fn try_from(input: EnvelopedSignature<'_, K>) -> Result<Self, Self::Error> {
        Self::verify_with(
            input.xml,
            input.trusted_public_keys,
            &DefaultSignatureVerifier,
        )
    }
}

impl UnverifiedElement {
    fn find_signature_target(
        &self,
    ) -> Result<(&UnverifiedElement, &UnverifiedElement), XmlSecurityError> {
        if let Some(signature) = self.direct_signature()? {
            return Ok((self, signature));
        }
        let mut nested = Vec::new();
        self.collect_nested_signatures(&mut nested)?;
        match nested.as_slice() {
            [(signed_element, signature)] => Ok((*signed_element, *signature)),
            [] => Err(XmlSecurityError::Signature {
                message: "document does not contain a direct Signature element".to_string(),
            }),
            _ => Err(XmlSecurityError::Signature {
                message: "document contains multiple nested signature targets".to_string(),
            }),
        }
    }

    fn direct_signature(&self) -> Result<Option<&UnverifiedElement>, XmlSecurityError> {
        let signatures = self
            .child_elements()
            .filter(|child| child.name() == "Signature")
            .collect::<Vec<_>>();
        match signatures.as_slice() {
            [] => Ok(None),
            [signature] if signature.namespace() == Some(NS_DS) => Ok(Some(signature)),
            [signature] => Err(XmlSecurityError::NamespaceMismatch {
                message: format!(
                    "Signature element uses unexpected namespace {:?}",
                    signature.namespace()
                ),
            }),
            _ => Err(XmlSecurityError::Signature {
                message: "an element contains multiple direct Signature elements".to_string(),
            }),
        }
    }

    fn collect_nested_signatures<'a>(
        &'a self,
        nested: &mut Vec<(&'a UnverifiedElement, &'a UnverifiedElement)>,
    ) -> Result<(), XmlSecurityError> {
        for child in self.child_elements() {
            if let Some(signature) = child.direct_signature()? {
                nested.push((child, signature));
            }
            child.collect_nested_signatures(nested)?;
        }
        Ok(())
    }

    fn unique_id(&self, document: &UnverifiedElement) -> Result<String, XmlSecurityError> {
        let ids = self
            .attributes()
            .iter()
            .filter(|(name, _)| name == "ID")
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        let [id] = ids.as_slice() else {
            return Err(XmlSecurityError::Signature {
                message: "signed element must contain exactly one ID attribute".to_string(),
            });
        };
        if id.is_empty() {
            return Err(XmlSecurityError::Signature {
                message: "signed element ID must not be empty".to_string(),
            });
        }
        if document.count_id_occurrences(id) != 1 {
            return Err(XmlSecurityError::Signature {
                message: "signed element ID must be unique in the document".to_string(),
            });
        }
        Ok((*id).to_string())
    }

    fn validate_unique_ids(&self) -> Result<(), XmlSecurityError> {
        let mut seen = HashSet::new();
        self.collect_unique_ids(&mut seen)
    }

    fn collect_unique_ids(&self, seen: &mut HashSet<String>) -> Result<(), XmlSecurityError> {
        for (name, value) in self.attributes() {
            if name == "ID" && (value.is_empty() || !seen.insert(value.clone())) {
                return Err(XmlSecurityError::Signature {
                    message: if value.is_empty() {
                        "ID attributes must not be empty".to_string()
                    } else {
                        format!("ID value appears more than once: {value}")
                    },
                });
            }
        }
        for child in self.child_elements() {
            child.collect_unique_ids(seen)?;
        }
        Ok(())
    }

    fn count_id_occurrences(&self, id: &str) -> usize {
        let own = usize::from(
            self.attributes()
                .iter()
                .any(|(name, value)| name == "ID" && value == id),
        );
        own + self
            .child_elements()
            .map(|child| child.count_id_occurrences(id))
            .sum::<usize>()
    }

    fn validate_signature_children(&self) -> Result<(), XmlSecurityError> {
        let mut key_info_count = 0;
        for child in self.child_elements() {
            if child.namespace() != Some(NS_DS)
                || !matches!(child.name(), "SignedInfo" | "SignatureValue" | "KeyInfo")
            {
                return Err(XmlSecurityError::Signature {
                    message: format!("unsupported Signature child: {}", child.name()),
                });
            }
            match child.name() {
                "SignedInfo" | "SignatureValue" => {}
                "KeyInfo" => {
                    key_info_count += 1;
                    child.validate_key_info()?;
                }
                _ => {}
            }
        }
        if key_info_count > 1 {
            return Err(XmlSecurityError::Signature {
                message: "Signature must contain at most one KeyInfo".to_string(),
            });
        }
        Ok(())
    }

    fn validate_key_info(&self) -> Result<(), XmlSecurityError> {
        let children = self.child_elements().collect::<Vec<_>>();
        if children.len() != 1 {
            return Err(XmlSecurityError::Signature {
                message: "KeyInfo must contain exactly one X509Data element".to_string(),
            });
        }
        for child in children {
            if child.namespace() != Some(NS_DS) || child.name() != "X509Data" {
                return Err(XmlSecurityError::Signature {
                    message: "only ds:X509Data is accepted in KeyInfo".to_string(),
                });
            }
            let certificates = child.child_elements().collect::<Vec<_>>();
            if certificates.len() != 1
                || certificates[0].namespace() != Some(NS_DS)
                || certificates[0].name() != "X509Certificate"
            {
                return Err(XmlSecurityError::Signature {
                    message: "KeyInfo must contain exactly one ds:X509Certificate".to_string(),
                });
            }
            if certificates[0].child_elements().next().is_some() {
                return Err(XmlSecurityError::Signature {
                    message: "ds:X509Certificate must not contain child elements".to_string(),
                });
            }
        }
        Ok(())
    }

    fn validate_signed_info(
        &self,
        root_id: &str,
    ) -> Result<CanonicalizationParameters, XmlSecurityError> {
        for child in self.child_elements() {
            if child.namespace() != Some(NS_DS)
                || !matches!(
                    child.name(),
                    "CanonicalizationMethod" | "SignatureMethod" | "Reference"
                )
            {
                return Err(XmlSecurityError::Signature {
                    message: format!("unsupported SignedInfo child: {}", child.name()),
                });
            }
        }
        let canonicalization_method = self.require_ds_child("CanonicalizationMethod")?;
        if canonicalization_method.attr("Algorithm") != Some(EXCLUSIVE_C14N) {
            return Err(XmlSecurityError::Unsupported {
                message: "only exclusive XML canonicalisation is supported for signatures"
                    .to_string(),
            });
        }
        let signed_info_inclusive_prefixes =
            canonicalization_method.inclusive_namespace_prefixes(true)?;
        let signature_method = self.require_ds_child("SignatureMethod")?;
        if signature_method.attr("Algorithm") != Some(RSA_SHA256) {
            return Err(XmlSecurityError::Unsupported {
                message: "only RSA-SHA256 signatures are supported".to_string(),
            });
        }
        signature_method.require_no_child_elements("SignatureMethod")?;
        let reference = self.require_ds_child("Reference")?;
        let expected_uri = format!("#{root_id}");
        if reference.attr("URI") != Some(expected_uri.as_str()) {
            return Err(XmlSecurityError::Signature {
                message: "signature reference must point to the signed element ID".to_string(),
            });
        }
        let transforms = reference.require_ds_child("Transforms")?;
        let transforms = transforms.child_elements().collect::<Vec<_>>();
        if transforms.len() != 2
            || transforms.iter().any(|transform| {
                transform.namespace() != Some(NS_DS)
                    || transform.name() != "Transform"
                    || transform.attr("Algorithm").is_none()
            })
        {
            return Err(XmlSecurityError::Signature {
                message: "signature transform shape is invalid".to_string(),
            });
        }
        let first_transform_inclusive_prefixes =
            transforms[0].inclusive_namespace_prefixes(false)?;
        if first_transform_inclusive_prefixes.is_some() {
            return Err(XmlSecurityError::Signature {
                message: "enveloped-signature transform must not have parameters".to_string(),
            });
        }
        let reference_inclusive_prefixes = transforms[1].inclusive_namespace_prefixes(true)?;
        let Some(first_algorithm) = transforms[0].attr("Algorithm") else {
            return Err(XmlSecurityError::Signature {
                message: "signature transform algorithm is missing".to_string(),
            });
        };
        let Some(second_algorithm) = transforms[1].attr("Algorithm") else {
            return Err(XmlSecurityError::Signature {
                message: "signature transform algorithm is missing".to_string(),
            });
        };
        if ![ENVELOPED_SIGNATURE, EXCLUSIVE_C14N].contains(&first_algorithm)
            || ![ENVELOPED_SIGNATURE, EXCLUSIVE_C14N].contains(&second_algorithm)
        {
            return Err(XmlSecurityError::Unsupported {
                message: "unsupported signature transform".to_string(),
            });
        }
        if first_algorithm != ENVELOPED_SIGNATURE || second_algorithm != EXCLUSIVE_C14N {
            return Err(XmlSecurityError::Signature {
                message: "signature transforms must be enveloped-signature followed by exclusive \
                          canonicalisation"
                    .to_string(),
            });
        }
        let digest_method = reference.require_ds_child("DigestMethod")?;
        if digest_method.attr("Algorithm") != Some(SHA256) {
            return Err(XmlSecurityError::Unsupported {
                message: "only SHA-256 reference digests are supported".to_string(),
            });
        }
        digest_method.require_no_child_elements("DigestMethod")?;
        let _ = reference.require_ds_child("DigestValue")?;
        for child in reference.child_elements() {
            if child.namespace() != Some(NS_DS)
                || !matches!(child.name(), "Transforms" | "DigestMethod" | "DigestValue")
            {
                return Err(XmlSecurityError::Signature {
                    message: format!("unsupported Reference child: {}", child.name()),
                });
            }
        }
        Ok(CanonicalizationParameters {
            signed_info_inclusive_prefixes,
            reference_inclusive_prefixes,
        })
    }

    fn require_ds_child(&self, name: &str) -> Result<&UnverifiedElement, XmlSecurityError> {
        let children = self
            .child_elements()
            .filter(|child| child.name() == name)
            .collect::<Vec<_>>();
        match children.as_slice() {
            [child] if child.namespace() == Some(NS_DS) => Ok(child),
            [child] => Err(XmlSecurityError::NamespaceMismatch {
                message: format!("{name} uses unexpected namespace {:?}", child.namespace()),
            }),
            [] => Err(XmlSecurityError::Signature {
                message: format!("{name} is missing"),
            }),
            _ => Err(XmlSecurityError::Signature {
                message: format!("{name} appears more than once"),
            }),
        }
    }

    fn require_no_child_elements(&self, name: &str) -> Result<(), XmlSecurityError> {
        if self.child_elements().next().is_some() {
            return Err(XmlSecurityError::Signature {
                message: format!("{name} must not contain child elements"),
            });
        }
        Ok(())
    }

    fn inclusive_namespace_prefixes(
        &self,
        allow_parameters: bool,
    ) -> Result<Option<Vec<String>>, XmlSecurityError> {
        let children = self.child_elements().collect::<Vec<_>>();
        if children.is_empty() {
            return Ok(None);
        }
        if !allow_parameters
            || children.len() != 1
            || children[0].namespace() != Some(EXCLUSIVE_C14N)
            || children[0].name() != "InclusiveNamespaces"
        {
            return Err(XmlSecurityError::Signature {
                message: "unsupported exclusive canonicalisation parameter".to_string(),
            });
        }
        let inclusive_namespaces = children[0];
        if inclusive_namespaces
            .attributes()
            .iter()
            .any(|(name, _)| name != "PrefixList")
        {
            return Err(XmlSecurityError::Signature {
                message: "InclusiveNamespaces contains an unsupported attribute".to_string(),
            });
        }
        let Some(prefix_list) = inclusive_namespaces.attr("PrefixList") else {
            return Err(XmlSecurityError::Signature {
                message: "InclusiveNamespaces PrefixList is missing".to_string(),
            });
        };
        inclusive_namespaces.require_no_child_elements("InclusiveNamespaces")?;
        if inclusive_namespaces
            .text_content()
            .is_some_and(|text| !text.trim().is_empty())
        {
            return Err(XmlSecurityError::Signature {
                message: "InclusiveNamespaces must not contain text".to_string(),
            });
        }
        let mut prefixes = Vec::new();
        for prefix in prefix_list.split_whitespace() {
            if prefixes.iter().any(|existing| existing == prefix) {
                return Err(XmlSecurityError::NamespaceMismatch {
                    message: format!("duplicate inclusive namespace prefix: {prefix}"),
                });
            }
            prefixes.push(prefix.to_string());
        }
        Ok(Some(prefixes))
    }

    fn decode_child_text(&self, name: &str, max_bytes: usize) -> Result<Vec<u8>, XmlSecurityError> {
        let child = self.require_ds_child(name)?;
        if child.child_elements().next().is_some() {
            return Err(XmlSecurityError::Signature {
                message: format!("{name} must not contain child elements"),
            });
        }
        let text = child
            .text_content()
            .ok_or_else(|| XmlSecurityError::Signature {
                message: format!("{name} is empty"),
            })?;
        let normalized = text.split_whitespace().collect::<String>();
        if normalized.is_empty() || normalized.len() > max_bytes * 2 {
            return Err(XmlSecurityError::Signature {
                message: format!("{name} exceeds the configured size limit"),
            });
        }
        let decoded = STANDARD
            .decode(&normalized)
            .or_else(|_| STANDARD_NO_PAD.decode(&normalized))
            .map_err(|_| XmlSecurityError::Signature {
                message: format!("{name} is not valid base64"),
            })?;
        if decoded.len() > max_bytes {
            return Err(XmlSecurityError::Signature {
                message: format!("{name} exceeds the configured size limit"),
            });
        }
        Ok(decoded)
    }
}
