use std::{cell::Cell, rc::Rc};

use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{KeyPair, RSA_PKCS1_SHA256},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};

use super::SignatureVerifier;
use crate::{
    XmlSecurityError,
    xml::{Element, canonicalize_xml, parse_xml_to_element},
};

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const TEST_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const TEST_ENV: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const TEST_RSA: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const TEST_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

fn signed_test_document() -> (String, Vec<u8>) {
    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate test key");
    let public_key = key_pair
        .public_key()
        .as_der()
        .expect("encode public key")
        .as_ref()
        .to_vec();
    let unsigned = r#"<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="root"><samlp:Value>signed</samlp:Value></samlp:Request>"#;
    let unsigned_element = parse_xml_to_element(unsigned).expect("unsigned XML");
    let digest = STANDARD.encode(Sha256::digest(
        canonicalize_xml(&unsigned_element).expect("unsigned c14n"),
    ));
    let signed_info = format!(
        r##"<ds:SignedInfo xmlns:ds="{DS_NS}"><ds:CanonicalizationMethod Algorithm="{TEST_C14N}"/><ds:SignatureMethod Algorithm="{TEST_RSA}"/><ds:Reference URI="#root"><ds:Transforms><ds:Transform Algorithm="{TEST_ENV}"/><ds:Transform Algorithm="{TEST_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{TEST_SHA256}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
    );
    let placeholder = format!(
        r#"<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="{DS_NS}" ID="root"><samlp:Value>signed</samlp:Value><ds:Signature>{signed_info}<ds:SignatureValue>A</ds:SignatureValue></ds:Signature></samlp:Request>"#
    );
    let parsed_placeholder = parse_xml_to_element(&placeholder).expect("placeholder XML");
    let signed_info_element = parsed_placeholder
        .child_elements()
        .find(|child| child.name() == "Signature")
        .and_then(|signature| signature.find_child_in_namespace(Some(DS_NS), "SignedInfo"))
        .expect("SignedInfo");
    let canonicalized_signed_info = canonicalize_xml(signed_info_element).expect("SignedInfo c14n");
    let mut signature = vec![0_u8; key_pair.public_modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            &canonicalized_signed_info,
            &mut signature,
        )
        .expect("sign test XML");
    let signed = placeholder.replace(
        "<ds:SignatureValue>A</ds:SignatureValue>",
        &format!(
            "<ds:SignatureValue>{}</ds:SignatureValue>",
            STANDARD.encode(signature)
        ),
    );
    (signed, public_key)
}

fn inclusive_namespace_signed_document() -> (String, Vec<u8>) {
    const UNSIGNED: &str = r#"<Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:foo="urn:example:foo" ID="root"><Payload>signed</Payload></Envelope>"#;
    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate test key");
    let public_key = key_pair
        .public_key()
        .as_der()
        .expect("encode public key")
        .as_ref()
        .to_vec();
    let unsigned_element = parse_xml_to_element(UNSIGNED).expect("unsigned XML");
    let inclusive_prefixes = ["foo"];
    let canonicalized_unsigned = unsigned_element
        .canonicalize_unverified_with_inclusive_prefixes(Some(&inclusive_prefixes))
        .expect("unsigned XML c14n");
    assert_eq!(
        canonicalized_unsigned,
        br#"<Envelope xmlns:foo="urn:example:foo" ID="root"><Payload>signed</Payload></Envelope>"#
    );
    let digest = STANDARD.encode(Sha256::digest(&canonicalized_unsigned));
    let signed_info = format!(
        r##"<ds:SignedInfo xmlns:ds="{DS_NS}">
  <ds:CanonicalizationMethod Algorithm="{TEST_C14N}">
    <ec:InclusiveNamespaces xmlns:ec="{TEST_C14N}" PrefixList="foo"/>
  </ds:CanonicalizationMethod>
  <ds:SignatureMethod Algorithm="{TEST_RSA}"/>
  <ds:Reference URI="#root">
    <ds:Transforms>
      <ds:Transform Algorithm="{TEST_ENV}"/>
      <ds:Transform Algorithm="{TEST_C14N}">
        <ec:InclusiveNamespaces xmlns:ec="{TEST_C14N}" PrefixList="foo"/>
      </ds:Transform>
    </ds:Transforms>
    <ds:DigestMethod Algorithm="{TEST_SHA256}"/>
    <ds:DigestValue>{digest}</ds:DigestValue>
  </ds:Reference>
</ds:SignedInfo>"##
    );
    let placeholder = UNSIGNED.replace(
        "</Envelope>",
        &format!(
            r#"<ds:Signature>{signed_info}<ds:SignatureValue>A</ds:SignatureValue></ds:Signature></Envelope>"#
        ),
    );
    let placeholder_element = parse_xml_to_element(&placeholder).expect("placeholder XML");
    let signed_info_element = placeholder_element
        .find_child_in_namespace(Some(DS_NS), "Signature")
        .and_then(|signature| signature.find_child_in_namespace(Some(DS_NS), "SignedInfo"))
        .expect("SignedInfo");
    let canonicalized_signed_info = signed_info_element
        .canonicalize_unverified_with_inclusive_prefixes(Some(&inclusive_prefixes))
        .expect("SignedInfo c14n");
    let mut signature = vec![0_u8; key_pair.public_modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            &canonicalized_signed_info,
            &mut signature,
        )
        .expect("sign test XML");
    let signed = placeholder.replace(
        "<ds:SignatureValue>A</ds:SignatureValue>",
        &format!(
            "<ds:SignatureValue>{}</ds:SignatureValue>",
            STANDARD.encode(signature)
        ),
    );
    (signed, public_key)
}

fn find_element_by_id<'a>(element: &'a Element, id: &str) -> Option<&'a Element> {
    if element.attr("ID") == Some(id) {
        return Some(element);
    }
    element
        .child_elements()
        .find_map(|child| find_element_by_id(child, id))
}

fn sign_document_with_direct_signature(
    unsigned_xml: &str,
    signed_id: &str,
    insertion_closing_tag: &str,
) -> (String, Vec<u8>) {
    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate test key");
    let public_key = key_pair
        .public_key()
        .as_der()
        .expect("encode public key")
        .as_ref()
        .to_vec();
    let unsigned_element = parse_xml_to_element(unsigned_xml).expect("unsigned XML");
    let signed_element = find_element_by_id(&unsigned_element, signed_id).expect("signed element");
    let digest = STANDARD.encode(Sha256::digest(
        canonicalize_xml(signed_element).expect("unsigned c14n"),
    ));
    let signed_info = format!(
        r##"<ds:SignedInfo xmlns:ds="{DS_NS}"><ds:CanonicalizationMethod Algorithm="{TEST_C14N}"/><ds:SignatureMethod Algorithm="{TEST_RSA}"/><ds:Reference URI="#{signed_id}"><ds:Transforms><ds:Transform Algorithm="{TEST_ENV}"/><ds:Transform Algorithm="{TEST_C14N}"/></ds:Transforms><ds:DigestMethod Algorithm="{TEST_SHA256}"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
    );
    let parsed_signed_info = parse_xml_to_element(&signed_info).expect("SignedInfo");
    let canonicalized_signed_info = canonicalize_xml(&parsed_signed_info).expect("SignedInfo c14n");
    let mut signature = vec![0_u8; key_pair.public_modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            &canonicalized_signed_info,
            &mut signature,
        )
        .expect("sign test XML");
    let signature_block = format!(
        r#"<ds:Signature>{signed_info}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>"#,
        STANDARD.encode(signature)
    );
    let insertion = format!("{signature_block}{insertion_closing_tag}");
    let signed_xml = unsigned_xml.replacen(insertion_closing_tag, &insertion, 1);
    (signed_xml, public_key)
}

fn contains_ds_signature(element: &Element) -> bool {
    element.child_elements().any(|child| {
        (child.name() == "Signature" && child.namespace() == Some(DS_NS))
            || contains_ds_signature(child)
    })
}

fn replace_child_text(xml: &str, name: &str, text: &str) -> String {
    let opening = format!("<ds:{name}>");
    let closing = format!("</ds:{name}>");
    let content_start = xml.find(&opening).expect("child opening tag");
    let content_start = content_start + opening.len();
    let content_end = xml
        .get(content_start..)
        .and_then(|suffix| suffix.find(&closing).map(|offset| content_start + offset))
        .expect("child closing tag");
    let mut replaced = xml.to_string();
    replaced.replace_range(content_start..content_end, text);
    replaced
}

fn append_to_signature(xml: &str, fragment: &str) -> String {
    xml.replacen("</ds:Signature>", &format!("{fragment}</ds:Signature>"), 1)
}

type VerificationInput = (Vec<u8>, Vec<u8>, Vec<u8>);

struct TestSignatureVerifier {
    verification_results: Vec<Result<bool, XmlSecurityError>>,
    verification_calls: Cell<usize>,
    verification_inputs: Rc<std::cell::RefCell<Vec<VerificationInput>>>,
    digest_result: Option<Result<Vec<u8>, XmlSecurityError>>,
}

impl TestSignatureVerifier {
    fn new(verification_results: impl IntoIterator<Item = bool>) -> Self {
        Self {
            verification_results: verification_results.into_iter().map(Ok).collect(),
            verification_calls: Cell::new(0),
            verification_inputs: Rc::new(std::cell::RefCell::new(Vec::new())),
            digest_result: None,
        }
    }

    fn with_digest_error(
        verification_results: impl IntoIterator<Item = bool>,
        error: XmlSecurityError,
    ) -> Self {
        let mut verifier = Self::new(verification_results);
        verifier.digest_result = Some(Err(error));
        verifier
    }

    fn with_verification_error(
        verification_results: impl IntoIterator<Item = Result<bool, XmlSecurityError>>,
    ) -> Self {
        let mut verifier = Self::new([]);
        verifier.verification_results = verification_results.into_iter().collect();
        verifier
    }
}

impl SignatureVerifier for TestSignatureVerifier {
    fn verify_rsa_sha256(
        &self,
        canonicalized_signed_info: &[u8],
        signature: &[u8],
        public_key_der: &[u8],
    ) -> Result<bool, XmlSecurityError> {
        let call = self.verification_calls.get();
        self.verification_calls.set(call + 1);
        self.verification_inputs.borrow_mut().push((
            canonicalized_signed_info.to_vec(),
            signature.to_vec(),
            public_key_der.to_vec(),
        ));
        self.verification_results
            .get(call)
            .cloned()
            .unwrap_or(Ok(false))
    }

    fn sha256_digest(&self, canonicalized_element: &[u8]) -> Result<Vec<u8>, XmlSecurityError> {
        if let Some(result) = &self.digest_result {
            return result.clone();
        }
        Ok(Sha256::digest(canonicalized_element).to_vec())
    }
}

fn externally_canonicalized_document() -> (String, Vec<u8>) {
    const UNSIGNED_XML: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:sig="http://www.w3.org/2000/09/xmldsig#" xmlns:unused="urn:unused" z="z" a="a" ID="response-id" Destination="https://sp.example/acs">
  <saml:Issuer>https://idp.example</saml:Issuer>
  <saml:Assertion ID="assertion-id" IssueInstant="2026-08-18T00:00:00Z" Version="2.0">
    <saml:Issuer>https://idp.example</saml:Issuer>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;
    const EXPECTED_UNSIGNED_C14N: &[u8] = br#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://sp.example/acs" ID="response-id" a="a" z="z">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example</saml:Issuer>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="assertion-id" IssueInstant="2026-08-18T00:00:00Z" Version="2.0">
    <saml:Issuer>https://idp.example</saml:Issuer>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;

    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate test key");
    let public_key = key_pair
        .public_key()
        .as_der()
        .expect("encode public key")
        .as_ref()
        .to_vec();
    let digest = STANDARD.encode(Sha256::digest(EXPECTED_UNSIGNED_C14N));
    assert_eq!(
        canonicalize_xml(&parse_xml_to_element(UNSIGNED_XML).expect("unsigned XML"))
            .expect("unsigned c14n"),
        EXPECTED_UNSIGNED_C14N
    );
    let signed_info = format!(
        r##"<sig:SignedInfo xmlns:sig="{DS_NS}">
  <sig:CanonicalizationMethod Algorithm="{TEST_C14N}"/>
  <sig:SignatureMethod Algorithm="{TEST_RSA}"/>
  <sig:Reference URI="#response-id">
    <sig:Transforms>
      <sig:Transform Algorithm="{TEST_ENV}"/>
      <sig:Transform Algorithm="{TEST_C14N}"/>
    </sig:Transforms>
    <sig:DigestMethod Algorithm="{TEST_SHA256}"/>
    <sig:DigestValue>{digest}</sig:DigestValue>
  </sig:Reference>
</sig:SignedInfo>"##
    );
    let expected_signed_info = format!(
        r##"<sig:SignedInfo xmlns:sig="{DS_NS}">
  <sig:CanonicalizationMethod Algorithm="{TEST_C14N}"></sig:CanonicalizationMethod>
  <sig:SignatureMethod Algorithm="{TEST_RSA}"></sig:SignatureMethod>
  <sig:Reference URI="#response-id">
    <sig:Transforms>
      <sig:Transform Algorithm="{TEST_ENV}"></sig:Transform>
      <sig:Transform Algorithm="{TEST_C14N}"></sig:Transform>
    </sig:Transforms>
    <sig:DigestMethod Algorithm="{TEST_SHA256}"></sig:DigestMethod>
    <sig:DigestValue>{digest}</sig:DigestValue>
  </sig:Reference>
</sig:SignedInfo>"##
    );
    let parsed_signed_info = parse_xml_to_element(&signed_info).expect("SignedInfo");
    assert_eq!(
        canonicalize_xml(&parsed_signed_info).expect("SignedInfo c14n"),
        expected_signed_info.as_bytes()
    );
    let mut signature = vec![0_u8; key_pair.public_modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            expected_signed_info.as_bytes(),
            &mut signature,
        )
        .expect("sign external XMLDSig vector");
    let signed_xml = UNSIGNED_XML.replacen(
        "</samlp:Response>",
        &format!(
            r#"<sig:Signature>{signed_info}<sig:SignatureValue>{}</sig:SignatureValue></sig:Signature></samlp:Response>"#,
            STANDARD.encode(signature)
        ),
        1,
    );
    (signed_xml, public_key)
}

#[test]
fn given_valid_enveloped_signature_when_verifying_then_return_only_signed_root() {
    let (xml, public_key) = signed_test_document();
    let verified = super::VerifiedXmlDocument::try_from(super::EnvelopedSignature::new(
        &xml,
        std::slice::from_ref(&public_key),
    ))
    .expect("valid XML signature");
    assert_eq!(verified.signed_element().name(), "Request");
    assert_eq!(verified.signed_element().attr("ID"), Some("root"));
    assert!(
        verified
            .signed_element()
            .find_child_in_namespace(Some(DS_NS), "Signature")
            .is_none()
    );
    assert_eq!(
        verified
            .signed_element()
            .find_child_in_namespace(Some("urn:oasis:names:tc:SAML:2.0:protocol"), "Value")
            .and_then(|value| value.text_content())
            .as_deref(),
        Some("signed")
    );
}

#[test]
fn given_tampered_signed_subtree_when_verifying_then_reject_digest_mismatch() {
    let (xml, public_key) = signed_test_document();
    let tampered = xml.replace(">signed<", ">attacker<");
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&tampered, &[public_key]),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_signature_on_nested_element_when_verifying_root_then_reject() {
    let (xml, public_key) = signed_test_document();
    let nested = xml
        .replace(
            "<samlp:Value>signed</samlp:Value><ds:Signature>",
            "<samlp:Value ID=\"nested\">signed<ds:Signature>",
        )
        .replace(
            "</ds:Signature></samlp:Request>",
            "</ds:Signature></samlp:Value></samlp:Request>",
        );
    assert!(super::VerifiedXmlDocument::verify_enveloped(&nested, &[public_key]).is_err());
}

#[test]
fn given_duplicate_id_or_child_reference_when_verifying_then_reject() {
    let (xml, public_key) = signed_test_document();
    let duplicate_id = xml.replace(
        "<samlp:Value>signed</samlp:Value>",
        "<samlp:Value ID=\"root\">signed</samlp:Value>",
    );
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(
            &duplicate_id,
            std::slice::from_ref(&public_key)
        )
        .is_err()
    );

    let child_reference = xml.replace("URI=\"#root\"", "URI=\"#child\"");
    assert!(super::VerifiedXmlDocument::verify_enveloped(&child_reference, &[public_key]).is_err());
}

#[test]
fn given_untrusted_key_or_remote_key_info_when_verifying_then_reject() {
    let (xml, public_key) = signed_test_document();
    let wrong_key = RsaKeyPair::generate(KeySize::Rsa2048)
        .expect("generate wrong key")
        .public_key()
        .as_der()
        .expect("encode wrong key")
        .as_ref()
        .to_vec();
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&xml, &[wrong_key]),
        Err(XmlSecurityError::SignatureVerification)
    ));

    let with_remote_key = xml.replace(
        "</ds:Signature>",
        "<ds:KeyInfo><ds:RetrievalMethod URI=\"https://attacker.invalid/key\"/></ds:KeyInfo></ds:Signature>",
    );
    assert!(super::VerifiedXmlDocument::verify_enveloped(&with_remote_key, &[public_key]).is_err());
}

#[test]
fn given_external_exclusive_c14n_vector_when_verifying_then_interoperate() {
    let (xml, public_key) = externally_canonicalized_document();

    let verified = super::VerifiedXmlDocument::verify_enveloped(&xml, &[public_key])
        .expect("the independently canonicalized XMLDSig vector must verify");
    assert_eq!(verified.signed_element().name(), "Response");
    assert_eq!(verified.signed_element().attr("ID"), Some("response-id"));
    assert!(!contains_ds_signature(
        verified.signed_element().as_unverified()
    ));
}

#[test]
fn given_inclusive_namespace_parameters_when_verifying_then_honor_both_canonicalization_points() {
    let (xml, public_key) = inclusive_namespace_signed_document();

    let verified = super::VerifiedXmlDocument::verify_enveloped(&xml, &[public_key])
        .expect("exclusive c14n InclusiveNamespaces parameters must verify");
    assert_eq!(verified.signed_element().name(), "Envelope");
    assert_eq!(verified.signed_element().attr("ID"), Some("root"));
}

#[test]
fn given_unsupported_reference_or_canonicalization_parameters_when_verifying_then_reject() {
    let (xml, public_key) = inclusive_namespace_signed_document();
    let missing_prefix_list = xml.replace(
        r#"<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="foo"/>"#,
        r#"<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>"#,
    );
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(
            &missing_prefix_list,
            std::slice::from_ref(&public_key)
        ),
        Err(XmlSecurityError::Signature { .. })
    ));

    let extra_reference_child = xml.replace("</ds:DigestValue>", "</ds:DigestValue><ds:Unknown/>");
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&extra_reference_child, &[public_key]),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_line_wrapped_signature_value_when_verifying_then_accept_base64_interoperability() {
    let (xml, public_key) = externally_canonicalized_document();
    let signature_value = parse_xml_to_element(&xml)
        .expect("signed XML")
        .find_child_in_namespace(Some(DS_NS), "Signature")
        .and_then(|signature| signature.find_child_in_namespace(Some(DS_NS), "SignatureValue"))
        .and_then(Element::text_content)
        .expect("signature value");
    let wrapped = signature_value
        .as_bytes()
        .chunks(32)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .expect("base64 is UTF-8")
        .join("\n");
    let wrapped_xml = xml.replacen(&signature_value, &wrapped, 1);

    super::VerifiedXmlDocument::verify_enveloped(&wrapped_xml, &[public_key])
        .expect("standard line-wrapped SignatureValue must verify");
}

#[test]
fn given_nested_signed_element_when_verifying_then_return_only_signed_subtree() {
    let unsigned = r#"<Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Untrusted>attacker</Untrusted><Payload ID="payload"><Value>trusted</Value></Payload></Envelope>"#;
    let (xml, public_key) = sign_document_with_direct_signature(unsigned, "payload", "</Payload>");

    let verified = super::VerifiedXmlDocument::verify_enveloped(&xml, &[public_key])
        .expect("nested signed payload must verify");
    assert_eq!(verified.signed_element().name(), "Payload");
    assert_eq!(verified.signed_element().attr("ID"), Some("payload"));
    assert_eq!(verified.signed_element().child_elements().count(), 1);
    assert_eq!(
        verified
            .signed_element()
            .child_elements()
            .next()
            .unwrap()
            .name(),
        "Value"
    );
}

#[test]
fn given_duplicate_id_outside_nested_signed_element_when_verifying_then_reject_wrapping() {
    let unsigned = r#"<Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Untrusted ID="payload">attacker</Untrusted><Payload ID="payload"><Value>trusted</Value></Payload></Envelope>"#;
    let (xml, public_key) = sign_document_with_direct_signature(unsigned, "payload", "</Payload>");

    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&xml, &[public_key]),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_duplicate_unreferenced_ids_when_verifying_then_reject_ambiguous_document() {
    let unsigned = r#"<Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Payload ID="payload"><Value>trusted</Value></Payload><Metadata ID="metadata"/></Envelope>"#;
    let (xml, public_key) = sign_document_with_direct_signature(unsigned, "payload", "</Payload>");
    let duplicated = xml.replace("<Metadata ID=\"metadata\"/>", "<Metadata ID=\"payload\"/>");

    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&duplicated, &[public_key]),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_multiple_nested_signature_targets_when_verifying_then_reject_wrapping() {
    let first_unsigned = r#"<Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Payload ID="first"><Value>first</Value></Payload><Other ID="second"><Value>second</Value></Other></Envelope>"#;
    let (first_signed, public_key) =
        sign_document_with_direct_signature(first_unsigned, "first", "</Payload>");
    let first_signature = first_signed
        .find("<ds:Signature>")
        .and_then(|start| {
            first_signed.get(start..).and_then(|suffix| {
                suffix
                    .find("</ds:Signature>")
                    .and_then(|end| first_signed.get(start..start + end + "</ds:Signature>".len()))
            })
        })
        .expect("first signature");
    let without_first_signature = first_signed.replacen(first_signature, "", 1);
    let second_signature = first_signature.replace("#first", "#second");
    let xml =
        without_first_signature.replacen("</Other>", &format!("{second_signature}</Other>"), 1);

    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&xml, &[public_key]),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_root_signature_with_nested_signature_metadata_when_verifying_then_hide_unverified_metadata()
 {
    let unsigned = r#"<Envelope xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="envelope"><Payload ID="payload"><Value>trusted</Value><ds:Signature><ds:SignatureValue>not-verified</ds:SignatureValue></ds:Signature></Payload></Envelope>"#;
    let (xml, public_key) =
        sign_document_with_direct_signature(unsigned, "envelope", "</Envelope>");

    let verified = super::VerifiedXmlDocument::verify_enveloped(&xml, &[public_key])
        .expect("the root signature covers the nested metadata");
    assert_eq!(verified.signed_element().name(), "Envelope");
    assert!(!contains_ds_signature(
        verified.signed_element().as_unverified()
    ));
}

#[test]
fn given_nested_elements_in_signature_value_or_digest_when_verifying_then_reject_ambiguous_data() {
    let (xml, public_key) = signed_test_document();
    let nested_signature_value =
        xml.replace("<ds:SignatureValue>", "<ds:SignatureValue><ds:Nested/>");
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(
            &nested_signature_value,
            std::slice::from_ref(&public_key)
        ),
        Err(XmlSecurityError::Signature { .. })
    ));

    let nested_digest = xml.replace("<ds:DigestValue>", "<ds:DigestValue><ds:Nested/>");
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&nested_digest, &[public_key]),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_no_trusted_keys_when_verifying_then_reject_before_parsing() {
    // Given a caller that has not supplied any trust anchor.
    let trusted_keys: Vec<Vec<u8>> = Vec::new();

    // When verification is requested for otherwise irrelevant input.
    let result = super::VerifiedXmlDocument::verify_enveloped("not XML", &trusted_keys);

    // Then verification fails closed before parsing or selecting a signed
    // element.
    assert!(matches!(
        result,
        Err(XmlSecurityError::Signature { message })
            if message == "at least one trusted public key is required"
    ));
}

#[test]
fn given_injected_verifier_and_multiple_trust_anchors_when_verifying_then_return_verified_subtree()
{
    // Given a valid in-memory signature fixture and a verifier that accepts
    // only its second key.
    let (xml, _public_key) = signed_test_document();
    let trusted_keys = vec![
        b"first-trust-anchor".to_vec(),
        b"second-trust-anchor".to_vec(),
    ];
    let verifier = TestSignatureVerifier::new([false, true]);

    let parsed = parse_xml_to_element(&xml).expect("signed fixture XML");
    let signature = parsed
        .find_child_in_namespace(Some(DS_NS), "Signature")
        .expect("signature element");
    let signed_info = signature
        .find_child_in_namespace(Some(DS_NS), "SignedInfo")
        .expect("SignedInfo element");
    let expected_signed_info = canonicalize_xml(signed_info).expect("SignedInfo c14n");
    let expected_signature = STANDARD
        .decode(
            signature
                .find_child_in_namespace(Some(DS_NS), "SignatureValue")
                .and_then(Element::text_content)
                .expect("signature value"),
        )
        .expect("signature base64");

    // When the cryptographic boundary is injected without changing XML policy.
    let verified = super::VerifiedXmlDocument::verify_enveloped_with(
        super::EnvelopedSignature::new(&xml, &trusted_keys),
        &verifier,
    )
    .expect("the injected verifier should accept the second trusted key");

    // Then both trust anchors are tried and consuming the result exposes only
    // unsigned data.
    assert_eq!(verifier.verification_calls.get(), 2);
    let calls = verifier.verification_inputs.borrow();
    assert_eq!(calls.len(), 2);
    for (index, expected_key) in trusted_keys.iter().enumerate() {
        assert_eq!(calls[index].0, expected_signed_info);
        assert_eq!(calls[index].1, expected_signature);
        assert_eq!(calls[index].2, *expected_key);
    }
    let signed_element = verified.into_signed_element();
    assert_eq!(signed_element.name(), "Request");
    assert!(
        signed_element
            .as_unverified()
            .find_child_in_namespace(Some(DS_NS), "Signature")
            .is_none()
    );
}

#[test]
fn given_digest_primitive_error_when_verifying_then_propagate_without_rsa_iteration() {
    // Given a valid signature fixture and a deterministic digest failure.
    let (xml, _public_key) = signed_test_document();
    let trusted_keys = vec![
        b"first-trust-anchor".to_vec(),
        b"second-trust-anchor".to_vec(),
    ];
    let expected = XmlSecurityError::Signature {
        message: "digest primitive failed".to_string(),
    };
    let verifier = TestSignatureVerifier::with_digest_error([true, true], expected.clone());

    // When digest calculation fails before signature verification.
    let result = super::VerifiedXmlDocument::verify_enveloped_with(
        super::EnvelopedSignature::new(&xml, &trusted_keys),
        &verifier,
    );

    // Then the exact primitive error propagates and no trust anchor is tried.
    assert!(matches!(result, Err(error) if error == expected));
    assert!(verifier.verification_inputs.borrow().is_empty());
}

#[test]
fn given_rsa_primitive_error_when_trying_first_key_then_propagate_and_stop_iteration() {
    // Given a valid signature fixture and an RSA verifier that errors on key
    // one.
    let (xml, _public_key) = signed_test_document();
    let trusted_keys = vec![
        b"first-trust-anchor".to_vec(),
        b"second-trust-anchor".to_vec(),
    ];
    let expected = XmlSecurityError::Signature {
        message: "RSA primitive failed".to_string(),
    };
    let verifier =
        TestSignatureVerifier::with_verification_error([Err(expected.clone()), Ok(true)]);

    // When verification reaches the first trusted key.
    let result = super::VerifiedXmlDocument::verify_enveloped_with(
        super::EnvelopedSignature::new(&xml, &trusted_keys),
        &verifier,
    );

    // Then the exact primitive error propagates and key two is never attempted.
    assert!(matches!(result, Err(error) if error == expected));
    let calls = verifier.verification_inputs.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].2, trusted_keys[0]);
}

#[test]
fn given_verifier_that_rejects_every_trust_anchor_when_verifying_then_fail_closed() {
    // Given a valid signature whose injected verifier rejects every key.
    let (xml, _public_key) = signed_test_document();
    let trusted_keys = vec![Vec::new()];
    let verifier = TestSignatureVerifier::new([false]);

    // When verification reaches the trusted-key decision.
    let result = super::VerifiedXmlDocument::verify_enveloped_with(
        super::EnvelopedSignature::new(&xml, &trusted_keys),
        &verifier,
    );

    // Then no unverifiable document is returned.
    assert!(matches!(
        result,
        Err(XmlSecurityError::SignatureVerification)
    ));
}

#[test]
fn given_invalid_signature_target_shapes_when_verifying_then_reject_without_selecting_data() {
    // Given target shapes that would be ambiguous or fail to identify one
    // signed element.
    let cases = [
        (
            "no signature",
            r#"<root ID="root"><child/></root>"#,
            "document does not contain a direct Signature element",
        ),
        (
            "wrong signature namespace",
            r#"<root ID="root"><Signature/></root>"#,
            "Signature element uses unexpected namespace",
        ),
        (
            "multiple direct signatures",
            r#"<root ID="root"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></root>"#,
            "an element contains multiple direct Signature elements",
        ),
        (
            "multiple nested signatures",
            r#"<root><first><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></first><second><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></second></root>"#,
            "document contains multiple nested signature targets",
        ),
        (
            "empty signed element id",
            r#"<root ID=""><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></root>"#,
            "ID attributes must not be empty",
        ),
        (
            "missing signed element id",
            r#"<root><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/></root>"#,
            "signed element must contain exactly one ID attribute",
        ),
        (
            "wrong SignedInfo namespace",
            r#"<root ID="root"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SignedInfo/></ds:Signature></root>"#,
            "SignedInfo uses unexpected namespace",
        ),
    ];

    for (label, xml, expected_message) in cases {
        // When the untrusted shape is sent with one non-empty trust-anchor
        // vector.
        let result = super::VerifiedXmlDocument::verify_enveloped(xml, &[vec![1_u8]]);

        // Then selection fails closed with the rule-specific diagnostic.
        let rejected_with_expected_message = match &result {
            Err(XmlSecurityError::Signature { message })
            | Err(XmlSecurityError::NamespaceMismatch { message }) => {
                message.contains(expected_message)
            }
            _ => false,
        };
        assert!(
            rejected_with_expected_message,
            "case {label} unexpectedly verified: {result:?}"
        );
    }
}

#[test]
fn given_empty_or_oversized_trusted_key_when_verifying_then_reject_before_rsa() {
    // Given a valid XML signature and trust anchors that violate the local
    // key-size boundary.
    let (xml, _public_key) = signed_test_document();
    let cases = [
        ("empty", Vec::new()),
        ("oversized", vec![0_u8; 8 * 1024 + 1]),
    ];

    for (label, trusted_key) in cases {
        // When the default verifier is asked to use the malformed trust anchor.
        let result = super::VerifiedXmlDocument::verify_enveloped(&xml, &[trusted_key]);

        // Then the key is rejected before the cryptographic library receives
        // it.
        assert!(
            matches!(result, Err(XmlSecurityError::Signature { ref message }) if message == "public key is empty or exceeds the configured limit"),
            "case {label} unexpectedly returned a different result: {result:?}"
        );
    }
}

#[test]
fn given_malformed_key_info_shapes_when_verifying_then_reject_embedded_key_material() {
    // Given KeyInfo shapes outside the one explicit X509Data/X509Certificate
    // profile.
    let (xml, public_key) = signed_test_document();
    let valid_key_info =
        r#"<ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>"#;
    let cases = [
        (
            "empty key info",
            r#"<ds:KeyInfo/>"#,
            "KeyInfo must contain exactly one X509Data element",
        ),
        (
            "wrong key info child",
            r#"<ds:KeyInfo><Wrong/></ds:KeyInfo>"#,
            "only ds:X509Data is accepted in KeyInfo",
        ),
        (
            "missing certificate",
            r#"<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>"#,
            "KeyInfo must contain exactly one ds:X509Certificate",
        ),
        (
            "multiple certificates",
            r#"<ds:KeyInfo><ds:X509Data><ds:X509Certificate/><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>"#,
            "KeyInfo must contain exactly one ds:X509Certificate",
        ),
        (
            "nested certificate elements",
            r#"<ds:KeyInfo><ds:X509Data><ds:X509Certificate><ds:Nested/></ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#,
            "ds:X509Certificate must not contain child elements",
        ),
    ];

    for (label, key_info, expected_message) in cases {
        // When untrusted embedded metadata is appended to the otherwise valid
        // signature.
        let candidate = append_to_signature(&xml, key_info);
        let result = super::VerifiedXmlDocument::verify_enveloped(
            &candidate,
            std::slice::from_ref(&public_key),
        );

        // Then malformed embedded key material cannot bypass caller-supplied
        // trust.
        assert!(
            matches!(result, Err(XmlSecurityError::Signature { ref message }) if message == expected_message),
            "case {label} unexpectedly returned a different result: {result:?}"
        );
    }

    // Given two individually valid KeyInfo elements.
    let candidate = append_to_signature(&append_to_signature(&xml, valid_key_info), valid_key_info);

    // When the signature contains duplicate embedded key descriptions.
    let result = super::VerifiedXmlDocument::verify_enveloped(&candidate, &[public_key]);

    // Then the closed profile rejects duplicate KeyInfo elements.
    assert!(matches!(
        result,
        Err(XmlSecurityError::Signature { message })
            if message == "Signature must contain at most one KeyInfo"
    ));
}

#[test]
fn given_unsupported_signature_policy_shapes_when_verifying_then_reject_before_digest_use() {
    // Given mutations that violate one canonical XMLDSig policy rule at a time.
    let (xml, public_key) = signed_test_document();
    let unsupported_child = xml.replace("</ds:SignedInfo>", "<ds:Unknown/></ds:SignedInfo>");
    let unsupported_signature_child = append_to_signature(&xml, "<ds:Unknown/>");
    let unsupported_c14n = xml.replacen(
        &format!("Algorithm=\"{TEST_C14N}\""),
        "Algorithm=\"urn:unsupported:c14n\"",
        1,
    );
    let unsupported_rsa = xml.replacen(
        &format!("Algorithm=\"{TEST_RSA}\""),
        "Algorithm=\"urn:unsupported:rsa\"",
        1,
    );
    let nested_signature_method = xml.replace(
        &format!(r#"<ds:SignatureMethod Algorithm="{TEST_RSA}"/>"#),
        &format!(r#"<ds:SignatureMethod Algorithm="{TEST_RSA}"><ds:Nested/></ds:SignatureMethod>"#),
    );
    let malformed_transform = xml.replace(
        &format!(r#"<ds:Transform Algorithm="{TEST_ENV}"/>"#),
        r#"<ds:Transform/>"#,
    );
    let missing_transform =
        xml.replacen(&format!(r#"<ds:Transform Algorithm="{TEST_ENV}"/>"#), "", 1);
    let parameterized_enveloped_transform = xml.replace(
        &format!(r#"<ds:Transform Algorithm="{TEST_ENV}"/>"#),
        &format!(
            r#"<ds:Transform Algorithm="{TEST_ENV}"><ec:InclusiveNamespaces xmlns:ec="{TEST_C14N}" PrefixList="foo"/></ds:Transform>"#
        ),
    );
    let unsupported_transform = xml.replace(
        &format!(r#"<ds:Transform Algorithm="{TEST_ENV}"/>"#),
        r#"<ds:Transform Algorithm="urn:unsupported:transform"/>"#,
    );
    let wrong_transform_order = xml
        .replace(
            &format!(r#"<ds:Transform Algorithm="{TEST_ENV}"/>"#),
            r#"<ds:Transform Algorithm="urn:temporary:first"/>"#,
        )
        .replace(
            &format!(r#"<ds:Transform Algorithm="{TEST_C14N}"/>"#),
            &format!(r#"<ds:Transform Algorithm="{TEST_ENV}"/>"#),
        )
        .replace(
            r#"<ds:Transform Algorithm="urn:temporary:first"/>"#,
            &format!(r#"<ds:Transform Algorithm="{TEST_C14N}"/>"#),
        );
    let unsupported_digest = xml.replacen(
        &format!("Algorithm=\"{TEST_SHA256}\""),
        "Algorithm=\"urn:unsupported:digest\"",
        1,
    );
    let nested_digest_method = xml.replace(
        &format!(r#"<ds:DigestMethod Algorithm="{TEST_SHA256}"/>"#),
        &format!(r#"<ds:DigestMethod Algorithm="{TEST_SHA256}"><ds:Nested/></ds:DigestMethod>"#),
    );
    let missing_digest_method = xml.replace(
        &format!(r#"<ds:DigestMethod Algorithm="{TEST_SHA256}"/>"#),
        r#"<ds:UnknownDigest/>"#,
    );
    let duplicate_reference = xml.replace("</ds:SignedInfo>", r#"<ds:Reference/></ds:SignedInfo>"#);
    let cases = [
        (
            "unsupported SignedInfo child",
            unsupported_child,
            "unsupported SignedInfo child",
        ),
        (
            "unsupported Signature child",
            unsupported_signature_child,
            "unsupported Signature child",
        ),
        (
            "unsupported canonicalization",
            unsupported_c14n,
            "only exclusive XML canonicalisation is supported",
        ),
        (
            "unsupported signature method",
            unsupported_rsa,
            "only RSA-SHA256 signatures are supported",
        ),
        (
            "nested signature method",
            nested_signature_method,
            "SignatureMethod must not contain child elements",
        ),
        (
            "malformed transform",
            malformed_transform,
            "signature transform shape is invalid",
        ),
        (
            "missing transform",
            missing_transform,
            "signature transform shape is invalid",
        ),
        (
            "parameterized enveloped transform",
            parameterized_enveloped_transform,
            "unsupported exclusive canonicalisation parameter",
        ),
        (
            "unsupported transform",
            unsupported_transform,
            "unsupported signature transform",
        ),
        (
            "wrong transform order",
            wrong_transform_order,
            "signature transforms must be enveloped-signature followed by exclusive",
        ),
        (
            "unsupported digest method",
            unsupported_digest,
            "only SHA-256 reference digests are supported",
        ),
        (
            "nested digest method",
            nested_digest_method,
            "DigestMethod must not contain child elements",
        ),
        (
            "missing digest method",
            missing_digest_method,
            "DigestMethod is missing",
        ),
        (
            "duplicate reference",
            duplicate_reference,
            "Reference appears more than once",
        ),
    ];

    for (label, candidate, expected_message) in cases {
        // When the policy-invalid document is passed to the strict verifier.
        let result = super::VerifiedXmlDocument::verify_enveloped(
            &candidate,
            std::slice::from_ref(&public_key),
        );

        // Then unsupported or ambiguous XMLDSig semantics are rejected before
        // trust is granted.
        let rejected_with_expected_message = match &result {
            Err(XmlSecurityError::Signature { message })
            | Err(XmlSecurityError::Unsupported { message }) => message.contains(expected_message),
            _ => false,
        };
        assert!(
            rejected_with_expected_message,
            "case {label} unexpectedly returned a different result: {result:?}"
        );
    }
}

#[test]
fn given_malformed_inclusive_namespace_parameters_when_verifying_then_reject_them() {
    // Given a valid signature using the explicit InclusiveNamespaces extension
    // point.
    let (xml, public_key) = inclusive_namespace_signed_document();
    let cases = [
        (
            "unsupported attribute",
            xml.replacen(
                r#"PrefixList="foo""#,
                r#"PrefixList="foo" Other="value""#,
                1,
            ),
            "InclusiveNamespaces contains an unsupported attribute",
        ),
        (
            "missing prefix list",
            xml.replacen(r#" PrefixList="foo""#, "", 1),
            "InclusiveNamespaces PrefixList is missing",
        ),
        (
            "non-empty text",
            xml.replacen(
                r#"PrefixList="foo"/>"#,
                r#"PrefixList="foo">unexpected</ec:InclusiveNamespaces>"#,
                1,
            ),
            "InclusiveNamespaces must not contain text",
        ),
        (
            "duplicate prefixes",
            xml.replacen(r#"PrefixList="foo""#, r#"PrefixList="foo foo""#, 1),
            "duplicate inclusive namespace prefix",
        ),
    ];

    for (label, candidate, expected_message) in cases {
        // When a parameterized canonicalization method is checked.
        let result = super::VerifiedXmlDocument::verify_enveloped(
            &candidate,
            std::slice::from_ref(&public_key),
        );

        // Then every malformed parameter is rejected rather than interpreted
        // loosely.
        let rejected_with_expected_message = match &result {
            Err(XmlSecurityError::Signature { message })
            | Err(XmlSecurityError::NamespaceMismatch { message }) => {
                message.contains(expected_message)
            }
            _ => false,
        };
        assert!(
            rejected_with_expected_message,
            "case {label} unexpectedly returned a different result: {result:?}"
        );
    }
}

#[test]
fn given_invalid_or_oversized_signature_and_digest_text_when_verifying_then_reject_before_crypto() {
    // Given base64-bearing fields with whitespace-only, invalid, and over-limit
    // values.
    let (xml, public_key) = signed_test_document();
    let oversized_decoded = STANDARD.encode(vec![0_u8; 8 * 1024 + 1]);
    let cases = [
        (
            "signature whitespace",
            replace_child_text(&xml, "SignatureValue", " \n\t "),
            "SignatureValue exceeds the configured size limit",
        ),
        (
            "signature missing text",
            xml.replace("<ds:SignatureValue>", "<ds:SignatureValue/>")
                .replace("</ds:SignatureValue>", ""),
            "SignatureValue is empty",
        ),
        (
            "signature invalid base64",
            replace_child_text(&xml, "SignatureValue", "not-base64!"),
            "SignatureValue is not valid base64",
        ),
        (
            "signature oversized encoded text",
            replace_child_text(&xml, "SignatureValue", &"A".repeat(16 * 1024 + 1)),
            "SignatureValue exceeds the configured size limit",
        ),
        (
            "signature oversized decoded value",
            replace_child_text(&xml, "SignatureValue", &oversized_decoded),
            "SignatureValue exceeds the configured size limit",
        ),
        (
            "digest invalid base64",
            replace_child_text(&xml, "DigestValue", "not-base64!"),
            "DigestValue is not valid base64",
        ),
        (
            "digest missing text",
            xml.replace("<ds:DigestValue>", "<ds:DigestValue/>")
                .replace("</ds:DigestValue>", ""),
            "DigestValue is empty",
        ),
        (
            "digest oversized decoded value",
            replace_child_text(&xml, "DigestValue", &oversized_decoded),
            "DigestValue exceeds the configured size limit",
        ),
    ];

    for (label, candidate, expected_message) in cases {
        // When the strict verifier decodes the selected signature field.
        let result = super::VerifiedXmlDocument::verify_enveloped(
            &candidate,
            std::slice::from_ref(&public_key),
        );

        // Then malformed input is rejected before any signature result can be
        // trusted.
        assert!(
            matches!(result, Err(XmlSecurityError::Signature { ref message }) if message == expected_message),
            "case {label} unexpectedly returned a different result: {result:?}"
        );
    }
}

#[test]
fn given_distinct_id_sibling_beside_signed_assertion_when_verifying_then_return_only_signed_subtree()
 {
    // Given a response whose signed assertion keeps its digest while an
    // attacker-controlled assertion with a distinct ID sits beside it.
    let unsigned = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="resp"><samlp:Assertion ID="good"><samlp:Name>alice</samlp:Name></samlp:Assertion></samlp:Response>"#;
    let (xml, public_key) =
        sign_document_with_direct_signature(unsigned, "good", "</samlp:Assertion>");
    let wrapped = xml.replacen(
        "</samlp:Response>",
        "<samlp:Assertion \
         ID=\"evil\"><samlp:Name>mallory</samlp:Name></samlp:Assertion></samlp:Response>",
        1,
    );

    // When the wrapped document reaches the strict verifier.
    let verified = super::VerifiedXmlDocument::verify_enveloped(&wrapped, &[public_key])
        .expect("the signed assertion must still verify");

    // Then only the signed subtree is returned, never the attacker sibling.
    assert_eq!(verified.signed_element().name(), "Assertion");
    assert_eq!(verified.signed_element().attr("ID"), Some("good"));
}

#[test]
fn given_unsigned_wrapper_around_signed_root_when_verifying_then_exclude_wrapper_from_result() {
    // Given a valid root-signed document wrapped in an attacker element.
    let (xml, public_key) = signed_test_document();
    let wrapped = format!("<Wrapper>{xml}</Wrapper>");

    // When the wrapped document reaches the strict verifier.
    let verified = super::VerifiedXmlDocument::verify_enveloped(&wrapped, &[public_key])
        .expect("the inner signed root must still verify");

    // Then the wrapper is excluded from the returned signed element.
    assert_eq!(verified.signed_element().name(), "Request");
    assert_eq!(verified.signed_element().attr("ID"), Some("root"));
}

#[test]
fn given_second_reference_or_foreign_digest_decoy_when_verifying_then_reject_ambiguity() {
    // Given a second Reference element smuggled into SignedInfo.
    let (xml, public_key) = signed_test_document();
    let second_reference = xml.replacen("</ds:SignedInfo>", "<ds:Reference/></ds:SignedInfo>", 1);
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(
            &second_reference,
            std::slice::from_ref(&public_key)
        ),
        Err(XmlSecurityError::Signature { .. })
    ));

    // When a foreign-namespace DigestValue decoy is smuggled into the
    // reference, mimicking the CVE-2024-45409 digest-injection shape.
    let decoy = xml.replacen(
        "</ds:Reference>",
        "<DigestValue xmlns=\"urn:evil\">AA</DigestValue></ds:Reference>",
        1,
    );
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&decoy, std::slice::from_ref(&public_key)),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_lowercase_or_empty_id_on_signed_element_when_verifying_then_reject() {
    // Given a signed element that uses `Id` instead of the exact `ID` name.
    let (xml, public_key) = signed_test_document();
    let lowercase = xml.replace("ID=\"root\"", "Id=\"root\"");
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&lowercase, std::slice::from_ref(&public_key)),
        Err(XmlSecurityError::Signature { .. })
    ));

    // When the signed element carries an empty ID value.
    let empty = xml.replace("ID=\"root\"", "ID=\"\"");
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&empty, std::slice::from_ref(&public_key)),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_attacker_key_material_or_second_key_info_when_verifying_then_reject() {
    // Given KeyInfo that embeds an attacker-controlled raw key instead of
    // the pinned X509Data certificate path.
    let (xml, public_key) = signed_test_document();
    let key_value = xml.replacen(
        "</ds:Signature>",
        "<ds:KeyInfo><ds:KeyValue>AA==</ds:KeyValue></ds:KeyInfo></ds:Signature>",
        1,
    );
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&key_value, std::slice::from_ref(&public_key)),
        Err(XmlSecurityError::Signature { .. })
    ));

    // When two KeyInfo elements appear, even with well-formed shapes.
    let key_info = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>AA==</ds:X509Certificate></ds:\
                    X509Data></ds:KeyInfo>";
    let doubled = xml.replacen(
        "</ds:Signature>",
        &format!("{key_info}{key_info}</ds:Signature>"),
        1,
    );
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&doubled, std::slice::from_ref(&public_key)),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_transform_reorder_or_removal_when_verifying_then_reject() {
    // Given the enveloped and canonicalization transforms in swapped order.
    let (xml, public_key) = signed_test_document();
    let swapped = xml
        .replacen(
            &format!("<ds:Transform Algorithm=\"{TEST_ENV}\"/>"),
            "<ds:Transform Algorithm=\"urn:placeholder\"/>",
            1,
        )
        .replacen(
            &format!("<ds:Transform Algorithm=\"{TEST_C14N}\"/>"),
            &format!("<ds:Transform Algorithm=\"{TEST_ENV}\"/>"),
            1,
        )
        .replacen(
            "<ds:Transform Algorithm=\"urn:placeholder\"/>",
            &format!("<ds:Transform Algorithm=\"{TEST_C14N}\"/>"),
            1,
        );
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&swapped, std::slice::from_ref(&public_key)),
        Err(XmlSecurityError::Signature { .. })
    ));

    // When the canonicalization transform is removed entirely.
    let removed = xml.replacen(&format!("<ds:Transform Algorithm=\"{TEST_C14N}\"/>"), "", 1);
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(&removed, std::slice::from_ref(&public_key)),
        Err(XmlSecurityError::Signature { .. })
    ));
}

#[test]
fn given_signature_method_children_or_comment_in_signed_info_when_verifying_then_reject() {
    // Given a SignatureMethod element that smuggles child content.
    let (xml, public_key) = signed_test_document();
    let method_children = xml.replacen(
        &format!("<ds:SignatureMethod Algorithm=\"{TEST_RSA}\"/>"),
        &format!("<ds:SignatureMethod Algorithm=\"{TEST_RSA}\"><ds:Unknown/></ds:SignatureMethod>"),
        1,
    );
    assert!(matches!(
        super::VerifiedXmlDocument::verify_enveloped(
            &method_children,
            std::slice::from_ref(&public_key)
        ),
        Err(XmlSecurityError::Signature { .. })
    ));

    // When a comment is injected inside SignedInfo.
    let comment = xml.replacen("<ds:SignedInfo", "<!-- attacker --><ds:SignedInfo", 1);
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(&comment, std::slice::from_ref(&public_key))
            .is_err()
    );
}

#[test]
fn given_single_character_digest_tamper_when_verifying_then_reject_mismatch() {
    // Given a DigestValue whose text still decodes as base64 but no longer
    // matches the signed element.
    let (xml, public_key) = signed_test_document();
    let opening = "<ds:DigestValue>";
    let closing = "</ds:DigestValue>";
    let start = xml.find(opening).expect("digest opening") + opening.len();
    let end = xml.find(closing).expect("digest closing");
    let mut digest = xml
        .get(start..end)
        .expect("digest span on character boundaries")
        .to_string();
    let replacement = if digest.starts_with('A') { 'B' } else { 'A' };
    digest.replace_range(0..1, &replacement.to_string());
    let mut tampered = xml
        .get(..start)
        .expect("prefix on character boundaries")
        .to_string();
    tampered.push_str(&digest);
    tampered.push_str(xml.get(end..).expect("suffix on character boundaries"));

    // When the tampered document reaches the strict verifier.
    let result = super::VerifiedXmlDocument::verify_enveloped(&tampered, &[public_key]);

    // Then the mismatch fails closed instead of trusting attacker content.
    assert!(matches!(result, Err(XmlSecurityError::Signature { .. })));
}

#[test]
fn given_mutated_documents_with_accepting_crypto_when_verifying_then_policy_oracle_holds() {
    // Given a nested-signed document whose digest is real while the RSA step
    // accepts everything, isolating selection and digest policy from crypto.
    // This is the deterministic twin of the `xml_signature_mutation` fuzz
    // oracle: only the byte-identical seed may verify successfully.
    let unsigned = r#"<Response xmlns="urn:example" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="resp"><Assertion ID="a1"><Name>alice</Name></Assertion></Response>"#;
    let parsed = parse_xml_to_element(unsigned).expect("seed parses");
    let target = parsed
        .child_elements()
        .find(|child| child.attr("ID") == Some("a1"))
        .expect("seed target");
    let digest = STANDARD.encode(Sha256::digest(
        canonicalize_xml(target).expect("seed canonicalizes"),
    ));
    let seed = unsigned.replacen(
        "</Assertion>",
        &format!(
            "<ds:Signature><ds:SignedInfo xmlns:ds=\"{DS_NS}\"><ds:CanonicalizationMethod \
             Algorithm=\"{TEST_C14N}\"/><ds:SignatureMethod \
             Algorithm=\"{TEST_RSA}\"/><ds:Reference URI=\"#a1\"><ds:Transforms><ds:Transform \
             Algorithm=\"{TEST_ENV}\"/><ds:Transform \
             Algorithm=\"{TEST_C14N}\"/></ds:Transforms><ds:DigestMethod \
             Algorithm=\"{TEST_SHA256}\"/><ds:DigestValue>{digest}</ds:DigestValue></ds:\
             Reference></ds:SignedInfo><ds:SignatureValue>AA</ds:SignatureValue></ds:Signature></\
             Assertion>"
        ),
        1,
    );
    let trusted = [b"unused-trust-anchor".to_vec()];
    let verify = |xml: &str, verifier: &TestSignatureVerifier| {
        super::VerifiedXmlDocument::verify_enveloped_with(
            super::EnvelopedSignature::new(xml, &trusted),
            verifier,
        )
        .ok()
        .and_then(|verified| verified.signed_element().canonicalize_unverified().ok())
    };
    let expected = verify(&seed, &TestSignatureVerifier::new([true]))
        .expect("seed must verify under accepting crypto");

    // When an unsigned sibling is injected beside the signed content.
    let sibling = seed.replacen("</Response>", "<Evil ID=\"evil\">x</Evil></Response>", 1);
    assert_eq!(
        verify(&sibling, &TestSignatureVerifier::new([true])),
        Some(expected.clone()),
        "unsigned sibling must not perturb the verified bytes"
    );

    // Then every content, identity, or structure mutation fails closed.
    let flipped = seed.replacen("alice", "alice!", 1);
    assert!(
        verify(&flipped, &TestSignatureVerifier::new([true])).is_none(),
        "text tampering must break the digest"
    );
    let duplicated = seed.replacen("ID=\"resp\"", "ID=\"a1\"", 1);
    assert!(
        verify(&duplicated, &TestSignatureVerifier::new([true])).is_none(),
        "duplicated ID values must fail closed"
    );
    let extra_signature = seed.replacen(
        "</Assertion>",
        "<ds:Signature><ds:SignatureValue>AA</ds:SignatureValue></ds:Signature></Assertion>",
        1,
    );
    assert!(
        verify(&extra_signature, &TestSignatureVerifier::new([true])).is_none(),
        "smuggled signatures must fail closed"
    );
    let truncated = seed
        .get(..seed.len() / 2)
        .expect("seed is ASCII; midpoint is a character boundary")
        .to_string();
    assert!(
        verify(&truncated, &TestSignatureVerifier::new([true])).is_none(),
        "truncation must fail closed"
    );
}

#[test]
fn given_same_name_signature_in_foreign_namespace_when_verifying_then_reject() {
    // Given a Signature element that shares the local name but lives in an
    // attacker namespace beside the real signature.
    let (xml, public_key) = signed_test_document();
    let confused = xml.replacen(
        "</samlp:Request>",
        "<Signature xmlns=\"urn:evil\">attacker</Signature></samlp:Request>",
        1,
    );

    // When the confused document reaches the strict verifier.
    let result = super::VerifiedXmlDocument::verify_enveloped(&confused, &[public_key]);

    // Then namespace confusion fails closed instead of selecting the wrong
    // signature node.
    assert!(result.is_err());
}

#[test]
fn given_namespaced_id_pollution_when_verifying_then_reject_tampered_reference_target() {
    // The Fragile Lock: adding a second ID with the same local name must not
    // redirect verification to another element, regardless of attribute order.
    let (xml, public_key) = signed_test_document();
    for attributes in [
        r#"ID="root" samlp:ID="forged""#,
        r#"samlp:ID="forged" ID="root""#,
    ] {
        let polluted = xml.replacen("ID=\"root\"", attributes, 1);
        assert!(
            super::VerifiedXmlDocument::verify_enveloped(&polluted, &[&public_key]).is_err(),
            "polluted ID was accepted: {attributes}"
        );
    }
}

#[test]
fn given_relative_namespace_when_verifying_then_reject_void_canonicalization() {
    // The Fragile Lock: a relative URI must never make canonicalization yield
    // empty bytes and validate an unrelated SHA-256 digest.
    let (xml, public_key) = signed_test_document();
    let with_relative_namespace = xml.replacen("ID=\"root\"", "ID=\"root\" xmlns:unused=\"1\"", 1);
    let with_empty_digest = replace_child_text(
        &with_relative_namespace,
        "DigestValue",
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    );
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(&with_empty_digest, &[public_key]).is_err()
    );
}

#[test]
fn given_extension_signature_before_signed_assertion_when_verifying_then_reject_decoy() {
    // The Fragile Lock: Extensions can place a decoy Signature before the
    // authentic assertion signature in document order.
    let unsigned = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="response"><samlp:Assertion ID="assertion"><samlp:Name>alice</samlp:Name></samlp:Assertion></samlp:Response>"#;
    let (xml, public_key) =
        sign_document_with_direct_signature(unsigned, "assertion", "</samlp:Assertion>");
    for decoy in [
        "<ds:Signature><ds:SignedInfo/></ds:Signature>",
        r#"<Signature xml:xmlns="http://www.w3.org/2000/09/xmldsig#"/>"#,
    ] {
        let with_decoy = xml.replacen(
            "<samlp:Assertion",
            &format!("<samlp:Extensions>{decoy}</samlp:Extensions><samlp:Assertion"),
            1,
        );
        assert!(
            super::VerifiedXmlDocument::verify_enveloped(&with_decoy, &[&public_key]).is_err(),
            "extension decoy was accepted: {decoy}"
        );
    }
}

#[test]
fn given_reused_metadata_signature_in_response_when_verifying_then_expose_only_metadata() {
    // The Fragile Lock: a valid signature from another document type may be
    // transplanted into Extensions beside a forged assertion.
    let metadata = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="metadata"><md:Issuer>trusted</md:Issuer></md:EntityDescriptor>"#;
    let (signed_metadata, public_key) =
        sign_document_with_direct_signature(metadata, "metadata", "</md:EntityDescriptor>");
    let response = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="response"><samlp:Extensions>{signed_metadata}</samlp:Extensions><samlp:Assertion ID="forged"><samlp:Name>mallory</samlp:Name></samlp:Assertion></samlp:Response>"#
    );
    let verified = super::VerifiedXmlDocument::verify_enveloped(&response, &[public_key])
        .expect("the signed metadata subtree itself remains valid");
    assert_eq!(verified.signed_element().name(), "EntityDescriptor");
    assert_eq!(verified.signed_element().attr("ID"), Some("metadata"));
    assert!(
        verified
            .signed_element()
            .find_child_in_namespace(None, "Assertion")
            .is_none()
    );
}

#[test]
fn given_comment_inside_digest_or_name_id_when_verifying_then_reject_parser_differential() {
    let (xml, public_key) = signed_test_document();
    let digest_comment = xml.replacen(
        "<ds:DigestValue>",
        "<ds:DigestValue><!-- forged digest -->",
        1,
    );
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(&digest_comment, &[&public_key]).is_err(),
        "a comment inside DigestValue must never survive verification"
    );

    let unsigned = r#"<samlp:Assertion xmlns:samlp="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="assertion"><samlp:Subject><samlp:NameID>admin@victim.example.evil.example</samlp:NameID></samlp:Subject></samlp:Assertion>"#;
    let (xml, public_key) =
        sign_document_with_direct_signature(unsigned, "assertion", "</samlp:Assertion>");
    let name_id_comment = xml.replacen(
        "admin@victim.example.evil.example",
        "admin@victim.example<!-- attacker -->.evil.example",
        1,
    );
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(&name_id_comment, &[public_key]).is_err(),
        "a comment must not truncate a signed NameID"
    );
}

#[test]
fn given_encoded_duplicate_id_or_xml_id_when_verifying_then_reject_id_confusion() {
    let (xml, public_key) = signed_test_document();
    let encoded_duplicate = xml.replacen(
        "</samlp:Request>",
        "<samlp:Value ID=\"&#x72;oot\">forged</samlp:Value></samlp:Request>",
        1,
    );
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(&encoded_duplicate, &[&public_key]).is_err(),
        "character references must not hide duplicate IDs"
    );

    let xml_id_only = xml.replacen("ID=\"root\"", "xml:id=\"root\"", 1);
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(&xml_id_only, &[public_key]).is_err(),
        "xml:id must not substitute for the SAML ID attribute"
    );
}

#[test]
fn given_signed_assertion_moved_into_status_detail_when_verifying_then_expose_only_that_assertion()
{
    // XSW location variants place the authentic signed assertion where a
    // response consumer may skip it, with a forged assertion at the usual path.
    let unsigned = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="response"><saml:Assertion ID="authentic"><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>"#;
    let (xml, public_key) =
        sign_document_with_direct_signature(unsigned, "authentic", "</saml:Assertion>");
    let wrapped = xml
        .replacen(
            "<saml:Assertion ID=\"authentic\">",
            "<samlp:StatusDetail><saml:Assertion ID=\"authentic\">",
            1,
        )
        .replacen(
            "</saml:Assertion></samlp:Response>",
            "</saml:Assertion></samlp:StatusDetail><saml:Assertion \
             ID=\"forged\"><saml:Subject><saml:NameID>mallory</saml:NameID></saml:Subject></saml:\
             Assertion></samlp:Response>",
            1,
        );

    let verified = super::VerifiedXmlDocument::verify_enveloped(&wrapped, &[public_key])
        .expect("the authentic assertion remains signed");
    assert_eq!(verified.signed_element().name(), "Assertion");
    assert_eq!(verified.signed_element().attr("ID"), Some("authentic"));
    assert_eq!(
        verified
            .signed_element()
            .find_child_in_namespace(Some("urn:oasis:names:tc:SAML:2.0:assertion"), "Subject")
            .and_then(|subject| subject
                .find_child_in_namespace(Some("urn:oasis:names:tc:SAML:2.0:assertion"), "NameID",))
            .and_then(Element::text_content)
            .as_deref(),
        Some("alice")
    );
}

#[test]
fn given_signed_error_response_reused_with_forged_success_when_verifying_then_hide_forgery() {
    // A signed error response is easier to obtain than a valid login. Its
    // signature must not authenticate an outer forged success response.
    let error = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="error"><samlp:Status><samlp:StatusCode Value="error"/></samlp:Status></samlp:Response>"#;
    let (signed_error, public_key) =
        sign_document_with_direct_signature(error, "error", "</samlp:Response>");
    let forged = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="forged"><samlp:StatusDetail>{signed_error}</samlp:StatusDetail><samlp:Assertion ID="mallory"><samlp:NameID>mallory</samlp:NameID></samlp:Assertion></samlp:Response>"#
    );

    let verified = super::VerifiedXmlDocument::verify_enveloped(&forged, &[public_key])
        .expect("the signed error response itself remains valid");
    assert_eq!(verified.signed_element().attr("ID"), Some("error"));
    assert_eq!(verified.signed_element().name(), "Response");
    assert!(
        verified
            .signed_element()
            .find_child_in_namespace(Some("urn:oasis:names:tc:SAML:2.0:protocol"), "Assertion")
            .is_none()
    );
}

#[test]
fn given_status_detail_signature_or_signature_object_when_verifying_then_reject_wrapping() {
    // Two published XSW placement variants: a decoy before the authentic
    // assertion signature, and an assertion hidden inside ds:Object.
    let unsigned = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="response"><samlp:Assertion ID="authentic"><samlp:Name>alice</samlp:Name></samlp:Assertion></samlp:Response>"#;
    let (xml, public_key) =
        sign_document_with_direct_signature(unsigned, "authentic", "</samlp:Assertion>");
    let with_status_detail_decoy = xml.replacen(
        "<samlp:Assertion ID=\"authentic\">",
        "<samlp:Status><samlp:StatusDetail><ds:Signature><ds:SignedInfo/></ds:Signature></samlp:\
         StatusDetail></samlp:Status><samlp:Assertion ID=\"authentic\">",
        1,
    );
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(&with_status_detail_decoy, &[&public_key])
            .is_err(),
        "a StatusDetail decoy must not select or authenticate an assertion"
    );

    let object = xml.replacen(
        "</ds:Signature>",
        "<ds:Object><samlp:Assertion \
         ID=\"forged\"><samlp:Name>mallory</samlp:Name></samlp:Assertion></ds:Object></ds:\
         Signature>",
        1,
    );
    assert!(
        super::VerifiedXmlDocument::verify_enveloped(&object, &[public_key]).is_err(),
        "an enveloping ds:Object is outside the supported signature profile"
    );
}

#[test]
fn given_signed_assertion_nested_in_forged_assertion_when_verifying_then_expose_only_signed_child()
{
    // The 2012 XSW study placed the genuine signed assertion inside a forged
    // assertion that a first-assertion consumer might otherwise select.
    let original = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="authentic"><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>"#;
    let (signed_assertion, public_key) =
        sign_document_with_direct_signature(original, "authentic", "</saml:Assertion>");
    let wrapped = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="response"><saml:Assertion ID="forged"><saml:Subject><saml:NameID>mallory</saml:NameID></saml:Subject>{signed_assertion}</saml:Assertion></samlp:Response>"#
    );

    let verified = super::VerifiedXmlDocument::verify_enveloped(&wrapped, &[public_key])
        .expect("the nested genuine assertion remains signed");
    assert_eq!(verified.signed_element().attr("ID"), Some("authentic"));
    assert_eq!(verified.signed_element().name(), "Assertion");
    assert_eq!(
        verified
            .signed_element()
            .find_child_in_namespace(Some("urn:oasis:names:tc:SAML:2.0:assertion"), "Subject")
            .and_then(|subject| subject
                .find_child_in_namespace(Some("urn:oasis:names:tc:SAML:2.0:assertion"), "NameID",))
            .and_then(Element::text_content)
            .as_deref(),
        Some("alice")
    );
}
