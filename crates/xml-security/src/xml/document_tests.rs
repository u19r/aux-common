use std::fmt::Write as _;

use proptest::prelude::*;

use super::{
    Element, Node, SAML_PROTOCOL_NS, UnverifiedElement, XmlLimits, canonicalize_exclusive,
    canonicalize_unverified_xml_text, canonicalize_xml, extract_in_response_to, parse_with_limits,
    parse_xml_to_element,
};
use crate::{VerifiedXmlDocument, XmlSecurityError};

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
fn given_published_saml_parser_differentials_when_parsing_then_reject_ambiguous_xml() {
    // SAML Roulette: a DTD default namespace can make two parsers disagree
    // about which Signature is in the XMLDSig namespace.
    let dtd_namespace = r#"<!DOCTYPE Response [<!ATTLIST Signature xmlns CDATA "http://www.w3.org/2000/09/xmldsig#">]><Response><Signature/></Response>"#;
    // XML comment truncation: one consumer can read only the first NameID
    // text node while the signature engine ignores the inserted comment.
    let name_id_comment = "<NameID>admin@victim.example<!-- attacker -->.evil.example</NameID>";
    // SAMLStorm: comment handling can make DigestValue text differ between
    // signature verification and application processing.
    let digest_comment =
        "<DigestValue><!-- forged -->47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</DigestValue>";

    for xml in [dtd_namespace, name_id_comment, digest_comment] {
        assert_rejected(xml);
    }
}

#[test]
fn given_cdata_and_character_references_when_parsing_then_preserve_full_identity_text() {
    // CDATA and predefined character references are legal XML. They must
    // produce the same identity and canonical bytes as literal text.
    let literal = parse_xml_to_element("<NameID>alice&amp;bob@example.test</NameID>")
        .expect("literal escaped identity");
    let segmented =
        parse_xml_to_element("<NameID>ali<![CDATA[ce&]]>bob&#x40;example.test</NameID>")
            .expect("segmented identity");
    assert_eq!(
        segmented.text_content().as_deref(),
        Some("alice&bob@example.test")
    );
    assert_eq!(canonicalize_xml(&literal), canonicalize_xml(&segmented));
}

#[test]
fn given_prefixed_child_resetting_default_namespace_when_canonicalizing_then_match_reference_bytes()
{
    // Exclusive C14N omits an unused default namespace reset on a prefixed
    // child. These expected bytes were checked with xmllint --exc-c14n.
    let xml = r#"<r xmlns="urn:r"><p:c xmlns:p="urn:p" xmlns=""/></r>"#;
    let canonical = canonicalize_xml(&parse_xml_to_element(xml).expect("valid XML"))
        .expect("exclusive canonicalization");
    assert_eq!(
        canonical,
        br#"<r xmlns="urn:r"><p:c xmlns:p="urn:p"></p:c></r>"#
    );
}

#[test]
fn given_dtd_entities_or_stylesheet_when_parsing_saml_then_reject_active_xml() {
    for xml in [
        r#"<!DOCTYPE samlp:Response SYSTEM "https://attacker.invalid/metadata.dtd"><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#,
        r#"<!DOCTYPE samlp:Response [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&b;</samlp:Response>"#,
        r#"<?xml-stylesheet type="text/xsl" href="https://attacker.invalid/saml.xsl"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#,
    ] {
        assert_rejected(xml);
    }
}

#[test]
fn given_xinclude_inside_saml_response_when_parsing_then_reject_active_xml() {
    // The XML security contract excludes XInclude before any later consumer
    // can interpret an included file or remote resource.
    assert_rejected(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></samlp:Response>"#,
    );
}

#[test]
fn given_encrypted_data_inside_saml_response_when_verifying_then_reject_unsupported_xml() {
    let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptedData/></samlp:Response>"#;
    let parsed = parse_xml_to_element(xml).expect("outbound encrypted XML can be canonicalized");
    parsed
        .canonicalize_unverified()
        .expect("outbound canonicalization");
    assert!(matches!(
        VerifiedXmlDocument::verify_enveloped(xml, &[b"test-key"]),
        Err(XmlSecurityError::Unsupported { .. })
    ));
}

#[test]
fn given_namespace_aliases_for_unsupported_xml_when_parsing_then_reject_them() {
    for xml in [
        r#"<Response xmlns:alias="http://www.w3.org/2001/XInclude"><alias:include href="https://attacker.invalid/identity"/></Response>"#,
        r#"<Response><include xmlns="http://www.w3.org/2001/XInclude" href="file:///etc/passwd"/></Response>"#,
    ] {
        assert!(matches!(
            parse_xml_to_element(xml),
            Err(XmlSecurityError::Unsupported { .. })
        ));
    }
}

#[test]
fn given_encrypted_namespace_aliases_when_validating_inbound_then_reject_them() {
    for xml in [
        r#"<Response xmlns:alias="http://www.w3.org/2001/04/xmlenc#"><alias:EncryptedData/></Response>"#,
        r#"<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#"/>"#,
        r#"<Response xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xenc:CipherData="opaque"/>"#,
    ] {
        let parsed = parse_xml_to_element(xml).expect("outbound encrypted XML can be parsed");
        assert!(matches!(
            parsed.reject_xml_encryption(),
            Err(XmlSecurityError::Unsupported { .. })
        ));
        assert!(matches!(
            VerifiedXmlDocument::verify_enveloped(xml, &[b"test-key"]),
            Err(XmlSecurityError::Unsupported { .. })
        ));
    }
}

#[test]
fn given_xinclude_namespaced_attribute_when_parsing_then_reject_it() {
    assert_rejected(
        r#"<Response xmlns:xi="http://www.w3.org/2001/XInclude" xi:href="file:///etc/passwd"/>"#,
    );
}

#[test]
fn given_unused_unsupported_feature_namespaces_when_parsing_then_allow_declarations() {
    let parsed = parse_xml_to_element(
        r#"<Response xmlns:xi="http://www.w3.org/2001/XInclude" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xml:lang="en"><Issuer>example</Issuer></Response>"#,
    )
    .expect("unused namespace declarations do not invoke an XML feature");
    parsed
        .reject_xml_encryption()
        .expect("unused declaration is safe");
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
fn given_public_unverified_xml_when_parsing_then_expose_bounded_tree_and_canonical_bytes() {
    // Given attacker-controlled XML with an entity-escaped attribute and a
    // namespace-qualified child.
    let source = String::from(
        r#"<root xmlns:p="urn:example:p" p:id="one" note="&quot;">text<p:child/></root>"#,
    );
    let limits = XmlLimits::try_new(1_024, 8).expect("valid XML limits");

    // When both public parse entrypoints and the public canonicalizer are used.
    let parsed = UnverifiedElement::try_from(&source).expect("valid unverified XML");
    let bounded = UnverifiedElement::parse_unverified_with_limits(&source, limits)
        .expect("valid XML within explicit limits");
    let canonical = parsed
        .canonicalize_unverified()
        .expect("canonical bytes for unverified XML");
    let canonical_from_text = canonicalize_unverified_xml_text(&source, &["p"])
        .expect("canonical bytes from public text boundary");

    // Then callers can inspect structure while canonical output remains one
    // deterministic serialization independent of the selected limits.
    assert_eq!(parsed.name(), "root");
    assert_eq!(parsed.attr("p:id"), Some("one"));
    assert_eq!(parsed.attr("note"), Some("\""));
    assert_eq!(parsed.attributes().len(), 2);
    assert_eq!(parsed.children().len(), 2);
    assert_eq!(
        canonical,
        br#"<root xmlns:p="urn:example:p" note="&quot;" p:id="one">text<p:child></p:child></root>"#
    );
    assert_eq!(canonical_from_text, canonical);
    assert_eq!(
        bounded
            .canonicalize_unverified()
            .expect("bounded canonical bytes"),
        canonical
    );
}

#[test]
fn given_malformed_namespace_declaration_lexemes_when_parsing_then_reject_before_tree_use() {
    // Given namespace-looking attributes that are missing an equals sign or a
    // quoted URI, including forms that exercise the pre-limit scanner.
    for xml in [
        r#"<root xmlns:p/>"#,
        r#"<root xmlns:p=value/>"#,
        r#"<root xmlns:p =/>"#,
        r#"<root xmlns:p="unterminated>"#,
    ] {
        // When untrusted XML reaches the parser boundary.
        let result = parse_xml_to_element(xml);

        // Then malformed namespace syntax is rejected rather than represented
        // as an incomplete or attacker-controlled namespace context.
        assert!(
            matches!(
                result,
                Err(XmlSecurityError::Parse { .. }) | Err(XmlSecurityError::Shape { .. })
            ),
            "malformed namespace declaration was accepted: {xml}"
        );
    }
}

fn element_with_attributes(pairs: &[(String, String)]) -> String {
    let mut xml = String::from("<r");
    for (name, value) in pairs {
        xml.push(' ');
        xml.push_str(name);
        xml.push_str("=\"");
        xml.push_str(value);
        xml.push('"');
    }
    xml.push_str("/>");
    xml
}

proptest! {
    #[test]
    fn given_reordered_attributes_when_canonicalizing_then_bytes_match(
        names in prop::collection::hash_set("[a-wyz][a-z]{0,3}", 1..4),
    ) {
        // Given unique attribute names that avoid the reserved `xml` prefix.
        let pairs: Vec<(String, String)> = names
            .iter()
            .map(|name| (name.clone(), format!("v{name}")))
            .collect();
        let mut reversed = pairs.clone();
        reversed.reverse();

        // When both lexical orders reach the canonicalization boundary.
        let forward = UnverifiedElement::parse_unverified(&element_with_attributes(&pairs))
            .expect("ordered attributes parse")
            .canonicalize_unverified()
            .expect("ordered attributes canonicalize");
        let backward = UnverifiedElement::parse_unverified(&element_with_attributes(&reversed))
            .expect("reordered attributes parse")
            .canonicalize_unverified()
            .expect("reordered attributes canonicalize");

        // Then attribute order never changes the canonical bytes consumed by
        // digest verification.
        prop_assert_eq!(forward, backward);
    }
}

fn xml_tag_name() -> impl Strategy<Value = String> {
    "[a-wyz][a-z]{0,5}".prop_filter("reserved xml prefix", |name| !name.starts_with("xml"))
}

fn xml_attribute_value() -> impl Strategy<Value = String> {
    "[A-Za-z0-9 ]{0,8}"
}

fn xml_text_content() -> impl Strategy<Value = String> {
    "[A-Za-z0-9 >]{0,12}"
}

fn render_element(name: &str, attrs: &[(String, String)], children: &[String]) -> String {
    let mut xml = String::from("<");
    xml.push_str(name);
    let mut ordered: Vec<&(String, String)> = attrs.iter().collect();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    for (key, value) in ordered {
        xml.push(' ');
        xml.push_str(key);
        xml.push_str("=\"");
        xml.push_str(value);
        xml.push('"');
    }
    xml.push('>');
    for child in children {
        xml.push_str(child);
    }
    xml.push_str("</");
    xml.push_str(name);
    xml.push('>');
    xml
}

fn xml_node(depth: u32) -> BoxedStrategy<String> {
    if depth == 0 {
        return xml_text_content().boxed();
    }
    let child = xml_node(depth - 1);
    (
        xml_tag_name(),
        prop::collection::hash_map(xml_tag_name(), xml_attribute_value(), 0..2),
        prop::collection::vec(child, 0..3),
    )
        .prop_map(|(name, attrs, kids)| {
            let pairs: Vec<(String, String)> = attrs.into_iter().collect();
            render_element(&name, &pairs, &kids)
        })
        .boxed()
}

fn xml_document() -> BoxedStrategy<String> {
    (
        xml_tag_name(),
        prop::collection::hash_map(xml_tag_name(), xml_attribute_value(), 0..2),
        prop::collection::vec(xml_node(2), 0..3),
    )
        .prop_map(|(name, attrs, kids)| {
            let pairs: Vec<(String, String)> = attrs.into_iter().collect();
            render_element(&name, &pairs, &kids)
        })
        .boxed()
}

fn inject_root_declaration(document: &str, prefix: &str, uri: &str) -> String {
    document.replacen('>', &format!(" xmlns:{prefix}=\"{uri}\">"), 1)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn given_generated_document_when_canonicalizing_twice_then_bytes_stable(
        document in xml_document(),
    ) {
        // Given a well-formed generated document without reserved names.
        let first = UnverifiedElement::parse_unverified(&document)
            .expect("generated document parses")
            .canonicalize_unverified()
            .expect("generated document canonicalizes");
        let first_text =
            String::from_utf8(first.clone()).expect("canonical bytes are UTF-8");

        // When the canonical form crosses the parse boundary again.
        let reparsed = UnverifiedElement::parse_unverified(&first_text)
            .expect("canonical output must always re-parse");

        // Then canonicalization is a fixed point, so digests computed at any
        // stage agree.
        prop_assert_eq!(
            reparsed.canonicalize_unverified().expect("re-canonicalizes"),
            first
        );
    }

    #[test]
    fn given_unused_namespace_declaration_when_canonicalizing_then_placement_is_irrelevant(
        prefix in "[a-wyz][a-z]{0,3}".prop_filter("reserved xml prefix", |name| !name.starts_with("xml")),
        uri in "urn:example:[a-z]{1,6}",
        document in xml_document(),
    ) {
        // Given the same document with an unused declaration on an outer
        // wrapper, on its own root, or nowhere at all.
        let declared_outer = format!("<r xmlns:{prefix}=\"{uri}\">{document}</r>");
        let declared_inner = format!("<r>{}</r>", inject_root_declaration(&document, &prefix, &uri));
        let undeclared = format!("<r>{document}</r>");
        let canonical = |xml: &str| {
            UnverifiedElement::parse_unverified(xml)
                .expect("namespace placement parses")
                .canonicalize_unverified()
                .expect("namespace placement canonicalizes")
        };

        // When each shape reaches the canonicalization boundary.
        // Then unused declarations never perturb the bytes consumed by
        // digest verification, closing the namespace-smuggling surface.
        prop_assert_eq!(canonical(&declared_outer), canonical(&undeclared));
        prop_assert_eq!(canonical(&declared_inner), canonical(&undeclared));
    }

    #[test]
    fn given_prefixed_attributes_in_either_order_when_canonicalizing_then_bytes_match(
        first_value in "[A-Za-z0-9 ]{0,8}",
        second_value in "[A-Za-z0-9 ]{0,8}",
    ) {
        // Given two namespace-qualified attributes whose lexical order and
        // declaration order both vary.
        let forward = format!(
            "<r xmlns:p=\"urn:p\" xmlns:q=\"urn:q\" p:a=\"{first_value}\" q:b=\"{second_value}\"/>"
        );
        let backward = format!(
            "<r xmlns:q=\"urn:q\" xmlns:p=\"urn:p\" q:b=\"{second_value}\" p:a=\"{first_value}\"/>"
        );
        let canonical = |xml: &str| {
            UnverifiedElement::parse_unverified(xml)
                .expect("prefixed attributes parse")
                .canonicalize_unverified()
                .expect("prefixed attributes canonicalize")
        };

        // When both orders reach the canonicalization boundary.
        // Then sorting by namespace URI and local name erases the order.
        prop_assert_eq!(canonical(&forward), canonical(&backward));
    }
}

#[test]
fn given_unsigned_sibling_inserted_beside_signed_content_when_canonicalizing_then_subtree_bytes_stable()
 {
    // Given the canonical bytes of a signed subtree before wrapping.
    let document = r#"<Response xmlns="urn:example" ID="resp"><Assertion ID="a1"><Name>alice</Name></Assertion></Response>"#;
    let parsed = UnverifiedElement::parse_unverified(document).expect("document parses");
    let assertion = parsed
        .child_elements()
        .find(|child| child.attr("ID") == Some("a1"))
        .expect("signed subtree");
    let before = assertion
        .canonicalize_unverified()
        .expect("subtree canonicalizes");

    // When an unsigned sibling is inserted beside the signed content.
    let wrapped = document.replacen(
        "</Response>",
        "<Assertion ID=\"evil\"><Name>mallory</Name></Assertion></Response>",
        1,
    );
    let reparsed = UnverifiedElement::parse_unverified(&wrapped).expect("wrapped parses");
    let after = reparsed
        .child_elements()
        .find(|child| child.attr("ID") == Some("a1"))
        .expect("signed subtree after wrapping")
        .canonicalize_unverified()
        .expect("wrapped subtree canonicalizes");

    // Then wrapping cannot perturb the bytes the digest binds.
    assert_eq!(before, after);
}

#[test]
fn given_namespaced_id_pollution_in_either_order_when_reading_id_then_use_only_unqualified_id() {
    // The Fragile Lock: an ID lookup must not depend on attribute order or
    // confuse samlp:ID with the unqualified SAML ID attribute.
    for attributes in [
        r#"ID="signed" samlp:ID="forged""#,
        r#"samlp:ID="forged" ID="signed""#,
    ] {
        let xml = format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" {attributes}/>"#
        );
        let response =
            UnverifiedElement::parse_unverified(&xml).expect("distinct attributes parse");
        assert_eq!(response.attr("ID"), Some("signed"));
        assert_eq!(response.attr("samlp:ID"), Some("forged"));
    }
}

#[test]
fn given_reserved_xml_xmlns_attribute_when_parsing_then_reject_namespace_confusion() {
    // The Fragile Lock uses xml:xmlns to make two parsers disagree on which
    // Signature is present. Reject this shape at the XML trust boundary.
    let accepted = [
        r#"<Signature xml:xmlns="http://www.w3.org/2000/09/xmldsig#"/>"#,
        r##"<Parent xmlns="http://www.w3.org/2000/09/xmldsig#"><Child xml:xmlns="#other"><Signature/></Child></Parent>"##,
    ]
        .into_iter()
        .filter(|xml| UnverifiedElement::parse_unverified(xml).is_ok())
        .collect::<Vec<_>>();
    assert!(
        accepted.is_empty(),
        "namespace confusion shapes were accepted: {accepted:?}"
    );
    UnverifiedElement::parse_unverified(r#"<Signature xml:lang="en"/>"#)
        .expect("ordinary xml attributes remain supported");
}

fn escape_text_source(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn escape_attribute_source(value: &str) -> String {
    escape_text_source(value)
        .replace('"', "&quot;")
        .replace('\t', "&#x9;")
        .replace('\n', "&#xA;")
        .replace('\r', "&#xD;")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn given_escapable_text_when_roundtripping_then_content_survives_verbatim(
        text in "[A-Za-z0-9 \t\n&<>\u{00e9}\u{4e2d}]{0,24}",
    ) {
        // Given text needing entity escaping, built so the source document
        // is always well-formed.
        let document = format!("<r>{}</r>", escape_text_source(&text));
        let parsed =
            UnverifiedElement::parse_unverified(&document).expect("escaped text parses");

        // When the canonical bytes cross the parse boundary again.
        let first = parsed.canonicalize_unverified().expect("canonicalizes");
        let first_text = String::from_utf8(first.clone()).expect("UTF-8");
        let reparsed = UnverifiedElement::parse_unverified(&first_text)
            .expect("canonical output parses");

        // Then escaping is a fixed point that preserves the text content,
        // whatever the parser's whitespace handling.
        prop_assert_eq!(
            reparsed.canonicalize_unverified().expect("re-canonicalizes"),
            first
        );
        prop_assert_eq!(reparsed.text_content(), parsed.text_content());
    }

    #[test]
    fn given_escapable_attribute_value_when_roundtripping_then_value_survives_verbatim(
        value in "[A-Za-z0-9 \t\n&<>\"]{0,16}",
    ) {
        // Given an attribute value needing entity and whitespace escaping.
        let document = format!("<r a=\"{}\"/>", escape_attribute_source(&value));
        let parsed = UnverifiedElement::parse_unverified(&document)
            .expect("escaped attribute parses");

        // When the canonical bytes cross the parse boundary again.
        let first = parsed.canonicalize_unverified().expect("canonicalizes");
        let first_text = String::from_utf8(first.clone()).expect("UTF-8");
        let reparsed = UnverifiedElement::parse_unverified(&first_text)
            .expect("canonical output parses");

        // Then normalization and escaping compose to a fixed point that
        // preserves the attribute value.
        prop_assert_eq!(
            reparsed.canonicalize_unverified().expect("re-canonicalizes"),
            first
        );
        prop_assert_eq!(reparsed.attr("a"), parsed.attr("a"));
    }
}
