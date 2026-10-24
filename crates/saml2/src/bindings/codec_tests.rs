use std::io::Write;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, write::DeflateEncoder};
use proptest::prelude::*;

use crate::{
    MAX_REQUEST_B64_BYTES,
    bindings::{
        build_redirect_request_url, decode_post_request, decode_redirect_request, encode_response,
        validate_redirect_destination,
    },
};

fn encoded_xml(xml: &str) -> String {
    STANDARD.encode(xml.as_bytes())
}

fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).expect("write compressed payload");
    encoder.finish().expect("finish compressed payload")
}

#[test]
fn given_unsafe_redirect_destination_when_validating_then_reject() {
    for value in [
        "javascript:alert(1)",
        "data:text/html,attack",
        "ftp://example.test/sso",
        "/relative/sso",
        "//example.test/sso",
        "https:///missing-host",
        "https://user@example.test/sso",
        "https://user:pass@example.test/sso",
        "https://example.test/sso#fragment",
        "https://example.test\\@evil.test/sso",
        "https://example.test/sso\x00",
        "  https://example.test/sso",
        "https://example.test/sso  ",
        "\thttps://example.test/sso",
        "https://example.test/sso\n",
    ] {
        assert!(
            validate_redirect_destination(value).is_err(),
            "unsafe destination was accepted: {value}"
        );
    }
}

#[test]
fn given_canonical_https_destination_when_validating_then_accept() {
    for value in [
        "HTTPS://example.test/sso?tenant=one",
        "https://example.test:8443/sso",
    ] {
        validate_redirect_destination(value).expect("safe destination");
    }
}

#[test]
fn given_cleartext_redirect_destination_when_building_then_reject_downgrade() {
    assert!(build_redirect_request_url("http://idp.example.test/sso", "<Request/>", None).is_err());
}

#[test]
fn given_invalid_post_payload_when_decoding_then_reject_without_parsing_attacker_bytes() {
    for payload in [
        "",
        "not-base64",
        &STANDARD.encode([0xff, 0x00]),
        &encoded_xml("plain"),
    ] {
        assert!(
            decode_post_request(payload).is_err(),
            "payload was accepted: {payload:?}"
        );
    }

    let oversized = STANDARD.encode(vec![b'x'; 512 * 1024 + 1]);
    assert!(decode_post_request(&oversized).is_err());
    assert!(decode_post_request(&"A".repeat(MAX_REQUEST_B64_BYTES + 1)).is_err());
}

#[test]
fn given_valid_post_or_raw_redirect_payload_when_decoding_then_preserve_exact_utf8() {
    let xml = "  <?xml version=\"1.0\" encoding=\"UTF-8\"?><samlp:Request \
               xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>  ";
    assert_eq!(
        decode_post_request(&encoded_xml(xml)).expect("POST XML"),
        xml
    );
    assert_eq!(
        decode_redirect_request(&encoded_xml(xml)).expect("raw Redirect XML"),
        xml
    );
}

#[test]
fn given_saml_response_when_encoding_for_post_then_preserve_exact_utf8() {
    let xml =
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">✓</samlp:Response>";
    assert_eq!(
        decode_post_request(&encode_response(xml).expect("response is within the size limit"))
            .expect("encoded response should decode"),
        xml
    );
}

#[test]
fn given_oversized_response_when_encoding_for_post_then_reject_before_allocation() {
    let xml = "x".repeat(512 * 1024 + 1);
    assert!(encode_response(&xml).is_err());
}

#[test]
fn given_invalid_or_trailing_deflate_payload_when_decoding_then_reject() {
    assert!(decode_redirect_request(&STANDARD.encode(b"not-deflate")).is_err());

    let mut trailing = deflate(b"<Request/>");
    trailing.extend_from_slice(b"attacker-trailing-bytes");
    assert!(decode_redirect_request(&STANDARD.encode(trailing)).is_err());
}

#[test]
fn given_inflated_redirect_payload_over_limit_when_decoding_then_stop_before_allocation() {
    let payload = vec![b'x'; 512 * 1024 + 1];
    assert!(decode_redirect_request(&STANDARD.encode(deflate(&payload))).is_err());
}

#[test]
fn given_redirect_builder_input_when_building_then_encode_request_and_relay_state_separately() {
    let xml = r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>"#;
    let url = build_redirect_request_url(
        "https://idp.example.test/sso?existing=1",
        xml,
        Some("relay state/?&"),
    )
    .expect("build Redirect URL");
    assert!(url.starts_with("https://idp.example.test/sso?existing=1&SAMLRequest="));
    assert!(url.contains("&RelayState=relay%20state%2F%3F%26"));

    let request = url
        .split("SAMLRequest=")
        .nth(1)
        .and_then(|value| value.split('&').next())
        .expect("SAMLRequest query value");
    let request = percent_decode(request);
    assert_eq!(
        decode_redirect_request(&request).expect("round-trip Redirect request"),
        xml
    );
}

fn percent_decode(value: &str) -> String {
    let mut bytes = Vec::with_capacity(value.len());
    let mut chars = value.as_bytes().iter().copied();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let high = chars.next().expect("hex high");
            let low = chars.next().expect("hex low");
            bytes.push((hex(high) << 4) | hex(low));
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).expect("utf8")
}

fn hex(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'A'..=b'F' => value - b'A' + 10,
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid hex"),
    }
}

proptest! {
    #[test]
    fn given_xml_payload_when_post_roundtripping_then_bytes_preserved(
        body in "<[A-Za-z]{1,8}[ -~]{0,64}",
    ) {
        // Given an XML-shaped payload within the portable size ceiling.
        let encoded = encode_response(&body).expect("bounded payload encodes");

        // When the payload crosses the POST decode boundary.
        let decoded = decode_post_request(&encoded).expect("round-trip decodes");

        // Then the codec preserves the exact bytes presented for signing.
        prop_assert_eq!(decoded, body);
    }

    #[test]
    fn given_xml_payload_when_redirect_roundtripping_then_bytes_preserved(
        body in "<[A-Za-z]{1,8}[ -~]{0,256}",
    ) {
        // Given an XML-shaped payload within the portable size ceiling.
        let url = build_redirect_request_url("https://idp.example.test/sso", &body, None)
            .expect("redirect URL builds");
        let encoded = url
            .split("SAMLRequest=")
            .nth(1)
            .expect("SAMLRequest parameter")
            .split('&')
            .next()
            .expect("SAMLRequest value");
        let percent_decoded = percent_decode(encoded);

        // When the deflated value crosses the redirect decode boundary,
        // which enforces chunked inflation limits and trailing-byte checks.
        let decoded = decode_redirect_request(&percent_decoded).expect("round-trip decodes");

        // Then compression preserves the exact bytes presented for signing.
        prop_assert_eq!(decoded, body);
    }
}
