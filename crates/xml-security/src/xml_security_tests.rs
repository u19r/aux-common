use std::fmt::Write as _;

use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{KeyPair, RSA_PKCS1_SHA256},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest as _, Sha256};

use super::{
    Element, Node, SAML_PROTOCOL_NS, XmlLimits, XmlSecurityError, canonicalize_exclusive,
    canonicalize_xml, extract_in_response_to, parse_with_limits, parse_xml_to_element,
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

fn assert_rejected(xml: &str) {
    assert!(
        parse_xml_to_element(xml).is_err(),
        "attacker-controlled XML was accepted: {xml:?}"
    );
}

fn nested_document(depth: usize) -> String {
    let mut xml = String::new();
    for index in 0..depth {
        write!(xml, "<e{index}>").expect("write to String cannot fail");
    }
    for index in (0..depth).rev() {
        write!(xml, "</e{index}>").expect("write to String cannot fail");
    }
    xml
}

#[test]
fn given_non_document_content_when_parsing_then_reject_before_tree_inspection() {
    for xml in ["text<a/>", "<a/>text", "<a/><b/>", "<a></b>", "<a>"] {
        assert_rejected(xml);
    }
}

#[test]
fn given_unsupported_xml_declaration_when_parsing_then_reject() {
    for xml in [
        r#"<?xml version="1.1" encoding="UTF-8"?><a/>"#,
        r#"<?xml version="1.0" encoding="ISO-8859-1"?><a/>"#,
        r#"<?xml version="1.0" encoding="UTF-16"?><a/>"#,
    ] {
        assert_rejected(xml);
    }
}

#[test]
fn given_external_or_internal_doctype_when_parsing_then_reject() {
    for xml in [
        r#"<!DOCTYPE a SYSTEM "https://attacker.invalid/entity"><a/>"#,
        r#"<!DOCTYPE a [<!ENTITY expansion "expanded">]><a>&expansion;</a>"#,
    ] {
        assert!(matches!(
            parse_xml_to_element(xml),
            Err(XmlSecurityError::Unsupported { .. })
        ));
    }
}

#[test]
fn given_comments_or_processing_instructions_when_parsing_then_reject() {
    for xml in [
        r#"<?xml-stylesheet type="text/xsl" href="https://attacker.invalid/a.xsl"?><a/>"#,
        "<a><!-- hidden signed content --></a>",
        "<a><?target attacker-controlled data?></a>",
    ] {
        assert!(matches!(
            parse_xml_to_element(xml),
            Err(XmlSecurityError::Unsupported { .. })
        ));
    }
}

#[test]
fn given_duplicate_attributes_when_parsing_then_reject_lexical_and_expanded_collisions() {
    for xml in [
        r#"<a id="one" id="two"/>"#,
        r#"<a xmlns:p="urn:one" xmlns:p="urn:two"/>"#,
        r#"<a xmlns:p="urn:attributes" p:id="one" p:id="two"/>"#,
        r#"<a xmlns:p="urn:attributes" xmlns:q="urn:attributes" p:id="one" q:id="two"/>"#,
    ] {
        assert!(
            matches!(
                parse_xml_to_element(xml),
                Err(XmlSecurityError::Parse { .. }) | Err(XmlSecurityError::Shape { .. })
            ),
            "duplicate attribute was accepted: {xml}"
        );
    }
}

#[test]
fn given_invalid_namespace_bindings_when_parsing_then_reject() {
    for xml in [
        "<p:unbound/>",
        r#"<a xmlns:xml="urn:not-the-xml-namespace"/>"#,
        r#"<a xmlns:xmlns="urn:not-the-xmlns-namespace"/>"#,
        r#"<a xmlns:p="relative-namespace"/>"#,
        r#"<a xmlns:p="urn:bad namespace"/>"#,
        r#"<a xmlns:p="urn:p"><p:child xmlns:p=""><p:value/></p:child></a>"#,
    ] {
        assert_rejected(xml);
    }
}

#[test]
fn given_invalid_characters_or_unclosed_structure_when_parsing_then_reject() {
    assert_rejected("<a>\u{0000}</a>");
    assert_rejected("<a><b></a></b>");
    assert_rejected("<a><b/>");
    assert_rejected("<a malformed>");
}

#[test]
fn given_namespace_text_inside_an_attribute_when_parsing_then_do_not_misclassify_it() {
    let element = parse_xml_to_element(r#"<root note="literal xmlns:p='one' xmlns:p='two'"/>"#)
        .expect("namespace-looking text in an attribute is not a declaration");
    assert_eq!(
        element.attr("note"),
        Some("literal xmlns:p='one' xmlns:p='two'")
    );
}

#[test]
fn given_size_or_depth_limit_when_parsing_then_reject_before_unbounded_allocation() {
    let oversized = "<root>123456789012345</root>";
    assert!(matches!(
        parse_with_limits(oversized, XmlLimits::try_new(16, 8).expect("valid limits")),
        Err(XmlSecurityError::Shape { .. })
    ));

    let deep = nested_document(9);
    assert!(matches!(
        parse_with_limits(&deep, XmlLimits::try_new(1024, 8).expect("valid limits")),
        Err(XmlSecurityError::Shape { .. })
    ));

    assert!(XmlLimits::try_new(0, 1).is_err());
    assert!(XmlLimits::try_new(1, 0).is_err());
}

#[test]
fn given_zero_cardinality_limit_when_constructing_limits_then_reject() {
    let base = XmlLimits::try_new(1024, 8).expect("valid byte and depth limits");
    for (elements, attributes, namespaces) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert!(
            base.try_with_cardinality(elements, attributes, namespaces)
                .is_err()
        );
    }
    for (uri_bytes, declaration_bytes, context_bytes) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert!(
            base.try_with_namespace_bytes(uri_bytes, declaration_bytes, context_bytes)
                .is_err()
        );
    }
}

#[test]
fn given_tight_cardinality_limits_when_parsing_then_reject_each_overflow() {
    let limits = XmlLimits::try_new(4096, 8)
        .expect("valid byte and depth limits")
        .try_with_cardinality(2, 1, 4)
        .expect("valid cardinality limits");

    assert!(parse_with_limits("<root><child/></root>", limits).is_ok());
    assert!(parse_with_limits("<root><first/><second/></root>", limits).is_err());
    assert!(parse_with_limits(r#"<root first="one" second="two"/>"#, limits).is_err());
    assert!(parse_with_limits(r#"<root xmlns:p="urn:p" xmlns:q="urn:q"/>"#, limits,).is_err());
}

#[test]
fn given_shallow_document_with_too_many_elements_when_parsing_then_reject() {
    let mut xml = String::from("<root>");
    for _ in 0..8_193 {
        xml.push_str("<item/>");
    }
    xml.push_str("</root>");

    assert!(matches!(
        parse_xml_to_element(&xml),
        Err(XmlSecurityError::Shape { .. })
    ));
}

#[test]
fn given_element_with_too_many_attributes_when_parsing_then_reject() {
    let mut xml = String::from("<root");
    for index in 0..129 {
        write!(xml, " a{index}=\"v\"").expect("write to String cannot fail");
    }
    xml.push_str("/>");

    assert!(matches!(
        parse_xml_to_element(&xml),
        Err(XmlSecurityError::Shape { .. }) | Err(XmlSecurityError::Parse { .. })
    ));
}

#[test]
fn given_element_with_too_many_namespace_bindings_when_parsing_then_reject() {
    let mut xml = String::from("<root");
    for index in 0..64 {
        write!(xml, " xmlns:p{index}=\"urn:p{index}\"").expect("write to String cannot fail");
    }
    xml.push_str("/>");

    assert!(matches!(
        parse_xml_to_element(&xml),
        Err(XmlSecurityError::Shape { .. })
    ));
}

#[test]
fn given_namespace_uri_over_per_binding_limit_when_parsing_then_reject_before_parser_cloning() {
    let uri = format!("urn:{}", "a".repeat(1_021));
    let xml = format!(r#"<root xmlns:p="{uri}"/>"#);

    assert!(matches!(
        parse_xml_to_element(&xml),
        Err(XmlSecurityError::Shape { .. })
    ));
}

#[test]
fn given_namespace_declarations_over_cumulative_byte_limit_when_parsing_then_reject_before_parser_cloning()
 {
    let uri = format!("urn:{}", "a".repeat(1_020));
    let mut xml = String::from("<root");
    for index in 0..17 {
        write!(xml, " xmlns:p{index}=\"{uri}\"").expect("write to String cannot fail");
    }
    xml.push_str("/>");

    assert!(xml.len() < XmlLimits::default().max_bytes());
    assert!(matches!(
        parse_xml_to_element(&xml),
        Err(XmlSecurityError::Shape { .. })
    ));
}

#[test]
fn given_inherited_namespace_context_over_resource_limit_when_parsing_then_reject_before_parser_cloning()
 {
    let uri = format!("urn:{}", "a".repeat(1_020));
    let mut xml = format!(r#"<root xmlns:p="{uri}">"#);
    for _ in 0..5_000 {
        xml.push_str("<p:item/>");
    }
    xml.push_str("</root>");

    assert!(xml.len() < XmlLimits::default().max_bytes());
    assert!(matches!(
        parse_xml_to_element(&xml),
        Err(XmlSecurityError::Shape { .. })
    ));
}

#[test]
fn given_normal_namespace_context_when_parsing_then_accept_with_namespace_resource_limits() {
    let mut xml = String::from(r#"<root xmlns:p="urn:trusted">"#);
    for _ in 0..8 {
        xml.push_str("<p:item/>");
    }
    xml.push_str("</root>");

    let limits = XmlLimits::try_new(4_096, 16)
        .expect("valid limits")
        .try_with_namespace_bytes(64, 1_024, 8_192)
        .expect("valid namespace limits");
    assert!(parse_with_limits(&xml, limits).is_ok());
}

#[test]
fn given_valid_namespaces_and_cdata_when_parsing_then_values_are_accessible_but_debug_is_redacted()
{
    let element = parse_xml_to_element(
        r#"<s:root xmlns:s="urn:root" secret="credential"><s:child><![CDATA[sensitive <a xmlns:p="urn:one" xmlns:p="urn:two"/> text]]></s:child></s:root>"#,
    )
    .expect("valid XML");
    assert_eq!(element.name(), "root");
    assert_eq!(element.namespace(), Some("urn:root"));
    assert_eq!(element.prefix(), Some("s"));
    assert_eq!(element.attr("secret"), Some("credential"));
    assert_eq!(
        element
            .find_child_in_namespace(Some("urn:root"), "child")
            .and_then(Element::text_content),
        Some("sensitive <a xmlns:p=\"urn:one\" xmlns:p=\"urn:two\"/> text".to_string())
    );
    let debug = format!("{element:?}");
    assert!(!debug.contains("credential"));
    assert!(!debug.contains("sensitive text"));
}

#[test]
fn given_same_local_name_in_untrusted_namespace_when_finding_then_select_trusted_namespace() {
    let root = parse_xml_to_element(
        r#"<root xmlns:trusted="urn:trusted" xmlns:attacker="urn:attacker"><attacker:item>evil</attacker:item><trusted:item>good</trusted:item></root>"#,
    )
    .expect("valid XML");

    let selected = root
        .find_child_in_namespace(Some("urn:trusted"), "item")
        .expect("trusted element must be selected");
    assert_eq!(selected.namespace(), Some("urn:trusted"));
    assert_eq!(selected.text_content().as_deref(), Some("good"));
}

#[test]
fn given_unqualified_and_namespaced_same_local_names_when_finding_then_none_is_exact() {
    let root = parse_xml_to_element(
        r#"<root xmlns:p="urn:p"><item>plain</item><p:item>qualified</p:item></root>"#,
    )
    .expect("valid XML");

    assert_eq!(
        root.find_child_in_namespace(None, "item")
            .and_then(Element::text_content)
            .as_deref(),
        Some("plain")
    );
    assert_eq!(
        root.find_child_in_namespace(Some("urn:p"), "item")
            .and_then(Element::text_content)
            .as_deref(),
        Some("qualified")
    );
    assert!(
        root.find_child_in_namespace(Some("urn:missing"), "item")
            .is_none()
    );
}

#[test]
fn given_child_filter_when_retaining_then_original_tree_remains_unchanged() {
    let root = parse_xml_to_element("<root><keep/><drop/></root>").expect("valid XML");
    let filtered = root.retaining_children(
        |node| matches!(node, Node::Element(element) if element.name() == "keep"),
    );
    assert_eq!(root.child_elements().count(), 2);
    assert_eq!(filtered.child_elements().count(), 1);
    assert_eq!(
        filtered
            .find_child_in_namespace(None, "keep")
            .map(Element::name),
        Some("keep")
    );
    assert!(filtered.find_child_in_namespace(None, "drop").is_none());
}

#[test]
fn given_saml_response_when_extracting_in_response_to_then_require_protocol_root() {
    let valid =
        format!(r#"<samlp:Response xmlns:samlp="{SAML_PROTOCOL_NS}" InResponseTo="request-123"/>"#);
    assert_eq!(
        extract_in_response_to(&valid).expect("valid response"),
        Some("request-123".to_string())
    );
    assert_eq!(
        extract_in_response_to(&format!(
            r#"<samlp:Response xmlns:samlp="{SAML_PROTOCOL_NS}"/>"#
        ))
        .expect("valid response"),
        None
    );
    for invalid in [
        "<Response InResponseTo=\"request-123\"/>",
        r#"<samlp:Response xmlns:samlp="urn:attacker:protocol" InResponseTo="request-123"/>"#,
        r#"<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="request-123"/>"#,
    ] {
        assert!(matches!(
            extract_in_response_to(invalid),
            Err(XmlSecurityError::NamespaceMismatch { .. })
        ));
    }
}

#[test]
fn given_xml_special_characters_when_canonicalizing_then_escape_rules_are_deterministic() {
    let element = parse_xml_to_element(
        r#"<root attr="&quot;&#x9;&#xA;&#xD;&amp;&lt;">&amp;&lt;&gt;&#xD;</root>"#,
    )
    .expect("valid XML");
    assert_eq!(
        canonicalize_xml(&element).expect("canonical XML"),
        br#"<root attr="&quot;&#x9;&#xA;&#xD;&amp;&lt;">&amp;&lt;&gt;&#xD;</root>"#
    );
}

#[test]
fn given_attribute_and_namespace_order_variations_when_canonicalizing_then_sort_by_c14n_rules() {
    let element = parse_xml_to_element(
        r#"<root xmlns:z="urn:z" xmlns:a="urn:a" z:b="z" a:a="a" plain="plain"/>"#,
    )
    .expect("valid XML");
    assert_eq!(
        canonicalize_xml(&element).expect("canonical XML"),
        br#"<root xmlns:a="urn:a" xmlns:z="urn:z" plain="plain" a:a="a" z:b="z"></root>"#
    );
}

#[test]
fn given_generic_element_name_when_canonicalizing_then_do_not_special_case_it() {
    let element = parse_xml_to_element(
        r#"<?xml version="1.0" encoding="UTF-8"?><root xmlns="urn:example"><e8 /></root>"#,
    )
    .expect("namespaced XML should parse");
    assert_eq!(
        canonicalize_xml(&element).expect("canonical XML"),
        br#"<root xmlns="urn:example"><e8></e8></root>"#
    );
}

#[test]
fn given_non_namespace_xmlns_prefixed_attribute_when_canonicalizing_then_preserve_it() {
    let element =
        parse_xml_to_element(r#"<?xml version="1.0" encoding="UTF-8"?><root xmlnsFoo="bar" />"#)
            .expect("ordinary xmlnsFoo attribute should parse");
    assert_eq!(
        canonicalize_xml(&element).expect("canonical XML"),
        br#"<root xmlnsFoo="bar"></root>"#
    );
}

#[test]
fn given_implicit_xml_namespace_when_canonicalizing_then_do_not_emit_an_empty_rebinding() {
    let element =
        parse_xml_to_element(r#"<root xml:lang="en" xml:space="preserve"/>"#).expect("valid XML");
    assert_eq!(
        canonicalize_xml(&element).expect("canonical XML"),
        br#"<root xml:lang="en" xml:space="preserve"></root>"#
    );
}

#[test]
fn given_unused_namespace_when_exclusive_canonicalizing_then_omit_it_until_used() {
    let canonical = canonicalize_exclusive(
        r#"<root xmlns:unused="urn:unused" xmlns:used="urn:used"><child used:value="v"/></root>"#,
        None,
    )
    .expect("canonical XML");
    assert_eq!(
        canonical,
        br#"<root><child xmlns:used="urn:used" used:value="v"></child></root>"#
    );
}

#[test]
fn given_inclusive_prefix_list_when_canonicalizing_then_retain_in_scope_declarations() {
    let canonical = canonicalize_exclusive(
        r#"<root xmlns:p="urn:ancestor"><child/></root>"#,
        Some(&["p"]),
    )
    .expect("canonical XML");
    assert_eq!(
        canonical,
        br#"<root xmlns:p="urn:ancestor"><child></child></root>"#
    );
}

#[test]
fn given_descendant_only_inclusive_prefix_when_canonicalizing_then_reject() {
    assert!(matches!(
        canonicalize_exclusive(
            r#"<root><child xmlns:p="urn:descendant"/></root>"#,
            Some(&["p"]),
        ),
        Err(XmlSecurityError::NamespaceMismatch { .. })
    ));
}

#[test]
fn given_descendant_only_default_namespace_when_canonicalizing_then_reject() {
    assert!(matches!(
        canonicalize_exclusive(
            r#"<root><child xmlns="urn:descendant"/></root>"#,
            Some(&["#default"]),
        ),
        Err(XmlSecurityError::NamespaceMismatch { .. })
    ));
}

#[test]
fn given_invalid_or_duplicate_inclusive_prefixes_when_canonicalizing_then_reject() {
    for prefixes in [
        &["" as &str][..],
        &["xmlns"][..],
        &["xml"][..],
        &["p", "p"][..],
    ] {
        assert!(matches!(
            canonicalize_exclusive(r#"<root xmlns:p="urn:p"/>"#, Some(prefixes)),
            Err(XmlSecurityError::NamespaceMismatch { .. })
        ));
    }
}

#[test]
fn given_root_inclusive_prefix_when_canonicalizing_then_propagate_one_binding() {
    let canonical = canonicalize_exclusive(
        r#"<root xmlns:p="urn:p"><child><p:value/></child></root>"#,
        Some(&["p"]),
    )
    .expect("root declaration is in scope");
    assert_eq!(
        canonical,
        br#"<root xmlns:p="urn:p"><child><p:value></p:value></child></root>"#
    );
}

#[test]
fn given_root_default_namespace_when_canonicalizing_then_retain_inclusive_default() {
    let canonical = canonicalize_exclusive(
        r#"<root xmlns="urn:root"><child/></root>"#,
        Some(&["#default"]),
    )
    .expect("root default declaration is in scope");
    assert_eq!(
        canonical,
        br#"<root xmlns="urn:root"><child></child></root>"#
    );
}

#[test]
fn given_prefixed_element_with_inclusive_default_namespace_when_canonicalizing_then_use_default_binding()
 {
    let canonical = canonicalize_exclusive(
        r#"<p:root xmlns="urn:default" xmlns:p="urn:prefixed"><p:child/></p:root>"#,
        Some(&["#default"]),
    )
    .expect("the in-scope default namespace must be retained");
    assert_eq!(
        canonical,
        br#"<p:root xmlns="urn:default" xmlns:p="urn:prefixed"><p:child></p:child></p:root>"#
    );
}

#[test]
fn given_default_namespace_rebinding_when_canonicalizing_then_preserve_namespace_boundaries() {
    let canonical = canonicalize_xml(
        &parse_xml_to_element(
            r#"<root xmlns="urn:root"><child/><unqualified xmlns=""><nested/></unqualified></root>"#,
        )
        .expect("valid XML"),
    )
    .expect("canonical XML");
    assert_eq!(
        canonical,
        br#"<root xmlns="urn:root"><child></child><unqualified xmlns=""><nested></nested></unqualified></root>"#
    );
}

#[test]
fn given_prefix_rebinding_when_canonicalizing_then_bind_each_visible_subtree() {
    let canonical = canonicalize_xml(
        &parse_xml_to_element(
            r#"<root xmlns:p="urn:one"><p:first/><wrapper xmlns:p="urn:two"><p:second/></wrapper></root>"#,
        )
        .expect("valid XML"),
    )
    .expect("canonical XML");
    assert_eq!(
        canonical,
        br#"<root><p:first xmlns:p="urn:one"></p:first><wrapper><p:second xmlns:p="urn:two"></p:second></wrapper></root>"#
    );
}

#[test]
fn given_missing_inclusive_prefix_or_comments_when_canonicalizing_then_reject() {
    assert!(canonicalize_exclusive("<root/>", Some(&["missing"])).is_err());
    assert!(canonicalize_exclusive("<root><!--comment--></root>", None).is_err());
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
