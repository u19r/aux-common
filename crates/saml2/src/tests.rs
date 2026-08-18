use std::io::Write;

use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{KeyPair, RSA_PKCS1_SHA256},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, TimeZone, Utc};
use flate2::{Compression, write::DeflateEncoder};
use sha2::{Digest, Sha256};

use super::{
    CertificateTrustPolicy, DigestAlgorithm, MAX_REQUEST_B64_BYTES, MetadataVerification,
    MetadataWarning, SamlError, SignatureAlgorithm, UnverifiedMetadata, UnverifiedPublicKeyDer,
    VerifiedMetadata, build_redirect_request_url, compute_digest, decode_post_request,
    decode_redirect_request, encode_response, validate_redirect_destination, verify_signature,
};

const NOW: chrono::DateTime<Utc> = chrono::DateTime::UNIX_EPOCH;

// This is a generated test certificate. It is public test material and is used
// only to exercise strict DER/metadata handling; parsing it never establishes
// trust in the certificate.
const TEST_CERTIFICATE_DER_B64: &str = "MIIDCzCCAfOgAwIBAgIUQ4GH6mxaRr4BDE3ReyzQ/JTywX0wDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAwwKYXV4Zm4tdGVzdDAeFw0yNjAyMDcyMDU2MTRaFw0zNjAyMDUyMDU2MTRaMBUxEzARBgNVBAMMCmF1eGZuLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbOzlUVTDEzZ01qQpe233hB+IXYMCZRNHX9icrK+mrRRoNj7GgftvTRqBoehCYmB3IGTqSeiGB2heZRKovNka/hxGt85TDgtUU3fGT6GHj4GlZvVLw9Q1coqmghI0qHmFKlIN9wdjUKr0EcyUzLcPPCSt6N2f8Jbg/b7yaBYVGRCdk5D884c67l8kbwyiH8vxUJ4TWCVottniVZriuWO7Gk+D3GQXkd3iDLqA+1xq70B0iwzO9VVm9YBw+AWXqJRgqYLvQZUwjVwaBsNRPvUOJ5vt20jobjKFaWAj0YvtAa+hGEU58bCld/h0KdGsJhkC6Q+1HICfjZrKf4M6lOe4jAgMBAAGjUzBRMB0GA1UdDgQWBBQmzhNLM//Ik6FeXOuo9NEEQbAdYjAfBgNVHSMEGDAWgBQmzhNLM//Ik6FeXOuo9NEEQbAdYjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDBMD6da/5ZSb0Yq+566KmJi4cv0iL8FNfwAN6WPRBoc7afnhM3tJDcc4+ko5gIurtiK2qT7ZQzmCicYKRUda6stjQsBTEeF9MRktYOvAd6TUT24w+Q4N18OwmyOgs/LTU5czb8/AyzqPSoN2fq8XunUDQY9x5kRyoIX18DfDLo4mCyq5n6LwpyLBa/ZmXCxXHW6mCU6Wp/9l6IB9ykPgu4MxlhPs5U3jc+AGe4+KkYnGeoKfFclOuGrCqi3XtejAiaTrfHBnEeSVSCZU9s92vAyl1dwfyN2irS/ANceeWQe+Uq3jYfsa6TWh8zasUTdWshogKjnvObWK2lTtCrAqjP";

fn encoded_xml(xml: &str) -> String {
    STANDARD.encode(xml.as_bytes())
}

fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).expect("write compressed payload");
    encoder.finish().expect("finish compressed payload")
}

fn certificate_pem() -> String {
    format!("-----BEGIN CERTIFICATE-----\n{TEST_CERTIFICATE_DER_B64}\n-----END CERTIFICATE-----")
}

#[derive(Debug)]
struct SigningMaterial {
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

fn signing_material(data: &[u8]) -> SigningMaterial {
    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA test key");
    let public_key = key_pair
        .public_key()
        .as_der()
        .expect("encode RSA public key")
        .as_ref()
        .to_vec();
    let mut signature = vec![0_u8; key_pair.public_modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            data,
            &mut signature,
        )
        .expect("sign test message");
    SigningMaterial {
        public_key,
        signature,
    }
}

fn key_descriptor(certificate: &str, use_value: &str) -> String {
    format!(
        r#"<md:KeyDescriptor use="{use_value}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    )
}

fn metadata_xml(
    valid_until: &str,
    key_descriptors: &str,
    endpoints: &str,
    entity_id: &str,
) -> String {
    format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" validUntil="{valid_until}" entityID="{entity_id}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{key_descriptors}{endpoints}</md:IDPSSODescriptor></md:EntityDescriptor>"#
    )
}

fn valid_metadata() -> String {
    metadata_xml(
        "2030-01-01T00:00:00Z",
        &key_descriptor(TEST_CERTIFICATE_DER_B64, "signing"),
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "https://idp.example.test/metadata",
    )
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

#[test]
fn given_known_message_when_digesting_then_use_only_sha256_profile() {
    assert_eq!(
        compute_digest(b"abc", DigestAlgorithm::Sha256),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ]
    );
}

#[test]
fn given_signature_or_digest_uri_when_selecting_algorithm_then_allow_only_exact_profile() {
    assert_eq!(
        SignatureAlgorithm::try_from(SignatureAlgorithm::RSA_SHA256_URI),
        Ok(SignatureAlgorithm::RsaSha256)
    );
    assert_eq!(
        DigestAlgorithm::try_from(DigestAlgorithm::SHA256_URI),
        Ok(DigestAlgorithm::Sha256)
    );
    assert_eq!(
        SignatureAlgorithm::RsaSha256.as_uri(),
        SignatureAlgorithm::RSA_SHA256_URI
    );
    assert_eq!(
        DigestAlgorithm::Sha256.as_uri(),
        DigestAlgorithm::SHA256_URI
    );

    for unsupported in [
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 ",
        "",
    ] {
        assert_eq!(
            SignatureAlgorithm::try_from(unsupported),
            Err(SamlError::UnsupportedAlgorithm)
        );
    }
    for unsupported in ["http://www.w3.org/2000/09/xmldsig#sha1", ""] {
        assert_eq!(
            DigestAlgorithm::try_from(unsupported),
            Err(SamlError::UnsupportedAlgorithm)
        );
    }
}

#[test]
fn given_valid_rsa_signature_when_verifying_then_accept_exact_bytes() {
    let data = b"signed canonical bytes";
    let material = signing_material(data);
    verify_signature(
        data,
        &material.signature,
        &material.public_key,
        SignatureAlgorithm::RsaSha256,
    )
    .expect("valid RSA signature");
}

#[test]
fn given_tampered_message_signature_or_wrong_key_when_verifying_then_reject() {
    let data = b"signed canonical bytes";
    let material = signing_material(data);
    let wrong_key = signing_material(b"different message");

    let mut tampered_data = data.to_vec();
    tampered_data[0] ^= 1;
    assert!(
        verify_signature(
            &tampered_data,
            &material.signature,
            &material.public_key,
            SignatureAlgorithm::RsaSha256
        )
        .is_err()
    );

    let mut tampered_signature = material.signature.clone();
    tampered_signature[0] ^= 1;
    assert!(
        verify_signature(
            data,
            &tampered_signature,
            &material.public_key,
            SignatureAlgorithm::RsaSha256
        )
        .is_err()
    );
    assert!(
        verify_signature(
            data,
            &material.signature,
            &wrong_key.public_key,
            SignatureAlgorithm::RsaSha256
        )
        .is_err()
    );
}

#[test]
fn given_empty_malformed_or_oversized_signature_material_when_verifying_then_fail_closed() {
    let data = b"signed canonical bytes";
    let material = signing_material(data);
    for (signature, public_key) in [
        (Vec::new(), material.public_key.clone()),
        (material.signature.clone(), Vec::new()),
        (vec![0_u8; 8193], material.public_key.clone()),
        (material.signature.clone(), vec![0_u8; 8193]),
        (
            vec![0_u8; material.signature.len()],
            vec![0_u8; material.public_key.len()],
        ),
    ] {
        assert_eq!(
            verify_signature(data, &signature, &public_key, SignatureAlgorithm::RsaSha256),
            Err(SamlError::SignatureVerification)
        );
    }
}

#[test]
fn given_valid_certificate_in_pem_or_base64_when_parsing_then_return_same_spki() {
    let base64_key =
        UnverifiedPublicKeyDer::try_from(TEST_CERTIFICATE_DER_B64).expect("DER certificate");
    let pem_key = UnverifiedPublicKeyDer::try_from(&certificate_pem()).expect("PEM certificate");
    let spaced = format!(" {}\n", TEST_CERTIFICATE_DER_B64);
    let spaced_key = UnverifiedPublicKeyDer::try_from(&spaced).expect("whitespace around DER");
    assert_eq!(base64_key, pem_key);
    assert_eq!(base64_key, spaced_key);

    let debug = format!("{pem_key:?}");
    assert!(!debug.contains(TEST_CERTIFICATE_DER_B64));
}

#[test]
fn given_malformed_or_ambiguous_certificate_encoding_when_parsing_then_reject() {
    let mut der = STANDARD
        .decode(TEST_CERTIFICATE_DER_B64)
        .expect("fixture DER");
    der.push(0);
    let trailing = STANDARD.encode(der);
    for input in [
        "",
        "not-base64",
        &trailing,
        &format!("{}\n{}", certificate_pem(), certificate_pem()),
        &format!("{}\ntrailing attacker text", certificate_pem()),
        &certificate_pem().replace("CERTIFICATE", "PRIVATE KEY"),
    ] {
        assert_eq!(
            UnverifiedPublicKeyDer::try_from(input),
            Err(SamlError::InvalidCertificate)
        );
    }
}

#[test]
fn given_oversized_certificate_input_when_parsing_then_reject_before_decode() {
    let input = "A".repeat(128 * 1024 + 1);
    assert_eq!(
        UnverifiedPublicKeyDer::try_from(&input),
        Err(SamlError::InvalidCertificate)
    );
}

#[test]
fn given_valid_metadata_when_parsing_then_return_neutral_values_and_redact_certificate_debug() {
    let parsed =
        UnverifiedMetadata::parse_unverified(&valid_metadata(), NOW).expect("valid metadata");
    assert_eq!(parsed.entity_id(), "https://idp.example.test/metadata");
    assert_eq!(parsed.sso_url(), "https://idp.example.test/sso");
    assert_eq!(parsed.certificates().len(), 1);
    assert!(parsed.warnings().is_empty());
    let debug = format!("{parsed:?}");
    assert!(!debug.contains(TEST_CERTIFICATE_DER_B64));

    let wrapped = format!(
        r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2030-01-01T00:00:00Z">{}</md:EntitiesDescriptor>"#,
        valid_metadata()
    );
    assert_eq!(
        UnverifiedMetadata::parse_unverified(&wrapped, NOW)
            .expect("single EntityDescriptor wrapper")
            .entity_id(),
        "https://idp.example.test/metadata"
    );
}

#[test]
fn given_unsigned_metadata_when_using_verified_api_then_reject_before_returning_metadata() {
    let certificate = certificate_pem();
    let certificate_der = STANDARD
        .decode(TEST_CERTIFICATE_DER_B64)
        .expect("test certificate");
    let fingerprint: [u8; 32] = Sha256::digest(certificate_der).into();
    let policy = CertificateTrustPolicy::from_sha256_fingerprints(vec![fingerprint])
        .expect("non-empty trust policy");
    let xml = valid_metadata();

    let error = VerifiedMetadata::try_from(MetadataVerification::new(
        &xml,
        std::slice::from_ref(&certificate),
        &policy,
        NOW,
    ))
    .expect_err("unsigned metadata must not enter the verified state");

    assert!(matches!(
        error,
        SamlError::SignatureVerification | SamlError::InvalidInput(_)
    ));
}

#[test]
fn given_untrusted_metadata_certificate_when_validating_trust_then_reject() {
    let parsed = UnverifiedMetadata::parse_unverified(&valid_metadata(), NOW)
        .expect("valid metadata syntax");
    let policy = CertificateTrustPolicy::from_sha256_fingerprints(vec![[0x11; 32]])
        .expect("non-empty trust policy");

    assert_eq!(
        parsed.validate_trust(&policy),
        Err(SamlError::CertificateNotTrusted)
    );
}

#[test]
fn given_pinned_metadata_certificate_when_validating_trust_then_accept() {
    let parsed = UnverifiedMetadata::parse_unverified(&valid_metadata(), NOW)
        .expect("valid metadata syntax");
    let certificate = STANDARD
        .decode(TEST_CERTIFICATE_DER_B64)
        .expect("test certificate");
    let fingerprint: [u8; 32] = Sha256::digest(certificate).into();
    let policy = CertificateTrustPolicy::from_sha256_fingerprints(vec![fingerprint])
        .expect("non-empty trust policy");

    parsed
        .validate_trust(&policy)
        .expect("pinned certificate should be trusted");
}

#[test]
fn given_multiple_signing_certificates_when_parsing_then_warn_and_deduplicate() {
    let descriptors = format!(
        "{}{}",
        key_descriptor(TEST_CERTIFICATE_DER_B64, "signing"),
        key_descriptor(TEST_CERTIFICATE_DER_B64, "signing")
    );
    let endpoints = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/one"/>"#;
    let parsed = UnverifiedMetadata::parse_unverified(
        &metadata_xml("2030-01-01T00:00:00Z", &descriptors, endpoints, "entity"),
        NOW,
    )
    .expect("metadata with warnings");
    assert_eq!(parsed.sso_url(), "https://idp.example.test/one");
    assert_eq!(parsed.certificates().len(), 1);
    assert!(
        parsed
            .warnings()
            .contains(&MetadataWarning::MultipleSigningCertificates)
    );
}

#[test]
fn given_multiple_http_post_endpoints_when_parsing_then_reject_ambiguous_destination() {
    let descriptor = key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let endpoints = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/one"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/two"/>"#;
    let metadata = metadata_xml("2030-01-01T00:00:00Z", &descriptor, endpoints, "entity");

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_metadata_with_invalid_root_or_required_fields_when_parsing_then_reject() {
    let valid = valid_metadata();
    let cases = [
        valid.replace(
            "validUntil=\"2030-01-01T00:00:00Z\"",
            "validUntil=\"not-a-time\"",
        ),
        valid.replace("validUntil=\"2030-01-01T00:00:00Z\"", ""),
        valid.replace(
            "entityID=\"https://idp.example.test/metadata\"",
            "entityID=\"\"",
        ),
        valid.replace(
            "entityID=\"https://idp.example.test/metadata\"",
            "entityID=\"   \"",
        ),
        valid.replace("<md:EntityDescriptor", "<md:NotAnEntityDescriptor"),
        valid.replace("</md:EntityDescriptor>", "</md:NotAnEntityDescriptor>"),
        valid.replace("<md:IDPSSODescriptor", "<md:NotAnIdp"),
    ];
    for xml in cases {
        assert!(
            UnverifiedMetadata::parse_unverified(&xml, NOW).is_err(),
            "metadata was accepted: {xml}"
        );
    }
}

#[test]
fn given_expired_or_future_boundary_metadata_when_parsing_then_compare_with_caller_clock() {
    let valid = valid_metadata();
    let expiry = Utc
        .with_ymd_and_hms(2030, 1, 1, 0, 0, 0)
        .single()
        .expect("timestamp");
    assert!(UnverifiedMetadata::parse_unverified(&valid, expiry).is_err());
    assert!(
        UnverifiedMetadata::parse_unverified(&valid, expiry - Duration::nanoseconds(1)).is_ok()
    );
}

#[test]
fn given_expired_nested_entity_when_parsing_then_reject_even_with_live_wrapper() {
    let nested = valid_metadata().replace(
        "validUntil=\"2030-01-01T00:00:00Z\"",
        "validUntil=\"1960-01-01T00:00:00Z\"",
    );
    let wrapped = format!(
        r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2030-01-01T00:00:00Z">{nested}</md:EntitiesDescriptor>"#
    );

    assert!(UnverifiedMetadata::parse_unverified(&wrapped, NOW).is_err());
}

#[test]
fn given_nested_entity_without_valid_until_when_parsing_then_reject_unbounded_metadata() {
    let nested = valid_metadata().replace(" validUntil=\"2030-01-01T00:00:00Z\"", "");
    let wrapped = format!(
        r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2030-01-01T00:00:00Z">{nested}</md:EntitiesDescriptor>"#
    );

    assert!(UnverifiedMetadata::parse_unverified(&wrapped, NOW).is_err());
}

#[test]
fn given_metadata_without_http_post_endpoint_or_location_when_parsing_then_reject() {
    let descriptor = key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let no_post = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT" Location="https://idp.example.test/sso"/>"#;
    assert!(
        UnverifiedMetadata::parse_unverified(
            &metadata_xml("2030-01-01T00:00:00Z", &descriptor, no_post, "entity"),
            NOW
        )
        .is_err()
    );
    let no_location =
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>"#;
    assert!(
        UnverifiedMetadata::parse_unverified(
            &metadata_xml("2030-01-01T00:00:00Z", &descriptor, no_location, "entity"),
            NOW
        )
        .is_err()
    );
}

#[test]
fn given_metadata_with_unsafe_endpoint_when_parsing_then_reject_before_returning_it() {
    let descriptor = key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    for location in [
        "javascript:alert(1)",
        "https://user:pass@example.test/sso",
        "https://example.test/sso#fragment",
        "https:///missing-host",
        "//example.test/sso",
    ] {
        let endpoint = format!(
            r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{location}"/>"#
        );
        assert!(
            UnverifiedMetadata::parse_unverified(
                &metadata_xml("2030-01-01T00:00:00Z", &descriptor, &endpoint, "entity"),
                NOW
            )
            .is_err()
        );
    }
}

#[test]
fn given_metadata_with_non_signing_or_unknown_key_use_when_parsing_then_reject() {
    for use_value in ["encryption", "other"] {
        let descriptor = key_descriptor(TEST_CERTIFICATE_DER_B64, use_value);
        assert!(
            UnverifiedMetadata::parse_unverified(
                &metadata_xml(
                    "2030-01-01T00:00:00Z",
                    &descriptor,
                    r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
                    "entity",
                ),
                NOW,
            )
            .is_err(),
            "unsupported KeyDescriptor use was accepted: {use_value}"
        );
    }
}

#[test]
fn given_key_descriptor_without_use_when_parsing_then_reject_ambiguous_key_purpose() {
    let descriptor =
        key_descriptor(TEST_CERTIFICATE_DER_B64, "signing").replace(" use=\"signing\"", "");
    let metadata = metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "entity",
    );

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_remote_signature_key_or_embedded_signature_when_parsing_then_reject() {
    let descriptor = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:RetrievalMethod URI="https://attacker.invalid/key"/><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let remote_key_metadata = metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "entity",
    );
    assert!(UnverifiedMetadata::parse_unverified(&remote_key_metadata, NOW).is_err());

    let signed_metadata = valid_metadata().replace(
        "><md:IDPSSODescriptor",
        "><ds:Signature/><md:IDPSSODescriptor",
    );
    assert!(UnverifiedMetadata::parse_unverified(&signed_metadata, NOW).is_err());
}

#[test]
fn given_multiple_metadata_entities_when_parsing_then_reject_ambiguous_selection() {
    let first = valid_metadata();
    let second = first.replace(
        "entityID=\"https://idp.example.test/metadata\"",
        "entityID=\"https://other.example.test/metadata\"",
    );
    let entities = format!(
        r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2030-01-01T00:00:00Z">{first}{second}</md:EntitiesDescriptor>"#
    );
    assert!(UnverifiedMetadata::parse_unverified(&entities, NOW).is_err());
}

#[test]
fn given_multiple_idp_descriptors_when_parsing_then_reject_ambiguous_selection() {
    let first = valid_metadata();
    let (prefix, descriptor_and_suffix) = first
        .split_once("<md:IDPSSODescriptor")
        .expect("descriptor start");
    let (descriptor_body, suffix) = descriptor_and_suffix
        .split_once("</md:IDPSSODescriptor>")
        .expect("descriptor end");
    let descriptor = format!("<md:IDPSSODescriptor{descriptor_body}</md:IDPSSODescriptor>");
    let metadata = format!("{prefix}{descriptor}{descriptor}{suffix}");
    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_nested_certificate_content_when_parsing_then_reject_ambiguous_key_material() {
    let metadata = valid_metadata().replace(
        &format!("<ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate>"),
        &format!(
            "<ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}<ds:Unexpected/></ds:X509Certificate>"
        ),
    );
    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_certificate_nested_outside_x509_data_when_parsing_then_reject_untrusted_key_material() {
    let descriptor = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:KeyName><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyName></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let metadata = metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "entity",
    );

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_attacker_certificate_in_unrelated_key_descriptor_child_when_parsing_then_reject_wrapper() {
    let descriptor = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data><ds:KeyName><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:KeyName></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let metadata = metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "entity",
    );

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_multiple_x509_data_containers_when_parsing_then_reject_ambiguous_key_material() {
    let descriptor = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let metadata = metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "entity",
    );

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_cleartext_metadata_sso_destination_when_parsing_then_reject_downgrade() {
    let descriptor = key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let metadata = metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://idp.example.test/sso"/>"#,
        "entity",
    );

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_xml_encryption_metadata_when_parsing_then_reject_before_using_keys() {
    let encrypted = valid_metadata().replace(
        "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
        "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"",
    )
    .replace(
        "><md:IDPSSODescriptor",
        "><xenc:EncryptedData/><md:IDPSSODescriptor",
    );
    assert!(UnverifiedMetadata::parse_unverified(&encrypted, NOW).is_err());
}

#[test]
fn given_metadata_with_xinclude_or_doctype_when_parsing_then_reject_before_certificate_use() {
    let xinclude = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:xi="http://www.w3.org/2001/XInclude" validUntil="2030-01-01T00:00:00Z" entityID="entity"><xi:include href="file:///etc/passwd"/></md:EntityDescriptor>"#.to_string();
    assert!(matches!(
        UnverifiedMetadata::parse_unverified(&xinclude, NOW),
        Err(SamlError::Unsupported(_)) | Err(SamlError::InvalidInput(_))
    ));

    let doctype = "<!DOCTYPE md:EntityDescriptor [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" validUntil=\"2030-01-01T00:00:00Z\" entityID=\"entity\"/>";
    assert!(UnverifiedMetadata::parse_unverified(doctype, NOW).is_err());
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
