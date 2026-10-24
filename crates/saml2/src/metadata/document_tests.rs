use aws_lc_rs::{rand::SystemRandom, rsa::KeyPair as RsaKeyPair, signature::RSA_PKCS1_SHA256};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{Duration, TimeZone, Utc};
use sha2::{Digest, Sha256};

use crate::{
    CertificateTrustPolicy, MetadataSsoBinding, MetadataVerification, MetadataWarning, SamlError,
    UnverifiedMetadata, VerifiedMetadata,
};

const METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const HTTP_POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const NOW: chrono::DateTime<chrono::Utc> = chrono::DateTime::UNIX_EPOCH;

// This is public test material used only to exercise strict DER handling.
const TEST_CERTIFICATE_DER_B64: &str = "MIIDCzCCAfOgAwIBAgIUQ4GH6mxaRr4BDE3ReyzQ/JTywX0wDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAwwKYXV4Zm4tdGVzdDAeFw0yNjAyMDcyMDU2MTRaFw0zNjAyMDUyMDU2MTRaMBUxEzARBgNVBAMMCmF1eGZuLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbOzlUVTDEzZ01qQpe233hB+IXYMCZRNHX9icrK+mrRRoNj7GgftvTRqBoehCYmB3IGTqSeiGB2heZRKovNka/hxGt85TDgtUU3fGT6GHj4GlZvVLw9Q1coqmghI0qHmFKlIN9wdjUKr0EcyUzLcPPCSt6N2f8Jbg/b7yaBYVGRCdk5D884c67l8kbwyiH8vxUJ4TWCVottniVZriuWO7Gk+D3GQXkd3iDLqA+1xq70B0iwzO9VVm9YBw+AWXqJRgqYLvQZUwjVwaBsNRPvUOJ5vt20jobjKFaWAj0YvtAa+hGEU58bCld/h0KdGsJhkC6Q+1HICfjZrKf4M6lOe4jAgMBAAGjUzBRMB0GA1UdDgQWBBQmzhNLM//Ik6FeXOuo9NEEQbAdYjAfBgNVHSMEGDAWgBQmzhNLM//Ik6FeXOuo9NEEQbAdYjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDBMD6da/5ZSb0Yq+566KmJi4cv0iL8FNfwAN6WPRBoc7afnhM3tJDcc4+ko5gIurtiK2qT7ZQzmCicYKRUda6stjQsBTEeF9MRktYOvAd6TUT24w+Q4N18OwmyOgs/LTU5czb8/AyzqPSoN2fq8XunUDQY9x5kRyoIX18DfDLo4mCyq5n6LwpyLBa/ZmXCxXHW6mCU6Wp/9l6IB9ykPgu4MxlhPs5U3jc+AGe4+KkYnGeoKfFclOuGrCqi3XtejAiaTrfHBnEeSVSCZU9s92vAyl1dwfyN2irS/ANceeWQe+Uq3jYfsa6TWh8zasUTdWshogKjnvObWK2lTtCrAqjP";

// A second valid, distinct certificate used to prove all advertised certs
// must be trusted. Generated solely for this fixture; it has no deployed
// identity.
const SECOND_TEST_CERTIFICATE_DER_B64: &str = "MIIDCDCCAfCgAwIBAgIUCBar/bUWbhj+LxLlgHwXhr15FJIwDQYJKoZIhvcNAQELBQAwJDEiMCAGA1UEAwwZYXV4LWNvbW1vbi10ZXN0LXNlY29uZGFyeTAeFw0yNjEwMjQxNzE0MjRaFw0zNjEwMjExNzE0MjRaMCQxIjAgBgNVBAMMGWF1eC1jb21tb24tdGVzdC1zZWNvbmRhcnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCf+b2iTptxZ2z5iOflt7/AV0julFVVZNqjmPHG0ViVcQyr2GkLnKOqctjmyBxYf8AU3AyAv24Ij5iTrxqhtyg1MWzTd/JQDdwbTcW3yI0waXHuhR3jLsVAslNd48LOLq935Y9GF8JwAzH0h+3YG8DXZvaYa9MYfi4nFf/wygvcjXuoE3raj5GhCYPvt1kDD37bNFtPbPEYg0PIsaYRzuReOK0iBLV/TtIsbafVZ8g7IeG7GancrL+2TPUttrIGqujsnxhbQVuACs9l1y6jpxDUqRA3NKTcxauQAgGjC792Z3swS0H8fOQfFrKEJmR0jr5Af6pthEwx62uAja2Y7ZXbAgMBAAGjMjAwMB0GA1UdDgQWBBRBvo6l5tsRFixZu7W0orx6gWqlBjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAjw4qIAhOd66NHOt7w32gaHXK8Tl4FDRKHqjcDTPSMIX5J2EIjbQASrmi4IbohW7C7wS1P4bMk9AhELVz+ByV8++2Q9pMeuuLpLytS6Kp+MZVmfBYaLFCgfi5Z1FXFqcHKg7yD5Ylt3uhki7ReKxUerAtqntjReMOpdCr2Dr+Ismd05+9jrU1c/YcR8AGbNHJjMuFgVkFZd4PB+WHgZDtnr71oSHqD9YCWTC7jt9V/y2iwkTtS3Teb2pNRTLPnYSzmNHMZ3tXWkP+C9Al5ZIvHNNHr7TJ4tW0sbimSTjmQl6H+aoTbbFzo71duhqsOM9WkinbFEgIYSePIosILa1nW";

// This key is paired with the public test certificate above and is not used
// outside deterministic XML-signature fixtures.
const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbOzlUVTDEzZ01
qQpe233hB+IXYMCZRNHX9icrK+mrRRoNj7GgftvTRqBoehCYmB3IGTqSeiGB2heZ
RKovNka/hxGt85TDgtUU3fGT6GHj4GlZvVLw9Q1coqmghI0qHmFKlIN9wdjUKr0E
cyUzLcPPCSt6N2f8Jbg/b7yaBYVGRCdk5D884c67l8kbwyiH8vxUJ4TWCVottniV
ZriuWO7Gk+D3GQXkd3iDLqA+1xq70B0iwzO9VVm9YBw+AWXqJRgqYLvQZUwjVwaB
sNRPvUOJ5vt20jobjKFaWAj0YvtAa+hGEU58bCld/h0KdGsJhkC6Q+1HICfjZrKf
4M6lOe4jAgMBAAECggEAAThtrnCrolTWB1/xslXSIr1lU/r9EigGFl0vmk0Wx8DN
OdPEdIpwP9dYpOw/s7xuYgLzRrB5B5zcB8WQQE4INnW9Mp+KAvfzUWKWPzFf0Mxw
LwiKRylzZxdyuUreRvnp/GfM6Zd5f7OIiiyiluEuLLS2MhUlNjahiseHoGs1HY8t
7jX42EvFUTSyvbvESVvC/ugsBvVfbj/tYUi3py8PHbo/guw7bKphIsTb4jw0yUxU
ZKE6WiSJMVvnUkeErg/BZVHOFTuF5t1pspnD04pKFoIuoTFIEoTuc6nRF51CmLD0
9TA6Zbu1AYqrWpv+idhXTKEqHk8HuBz+baLM8BZe0QKBgQDydtbiOQCXmA7zdKjh
5ERqYra2fvEG8YlNiQFoC6JfvQfl91X3DULQOg4qYknOxgqmaaNYlEtURezVFJRp
dZ7aYJ2/6K4TlT7SAjgEG5JEm9NQ5sqXKFNbAsGrg7HeYFm1aApCSfh1FGtgRwaw
Ea/70Th/y5YOnHIWpRQlSvgssQKBgQDneFqCmfXV+JqH7hWzbjPgagOBaeCAaHuM
q0KgHORtCcJPjL9sPLzOxkPn0fam8VzlCK5tyZIl0W7TBUjCvl048Mxohhs8BnKP
8SwHikcXKcPPfUNx+Le3XVz/dkrAhSovfaYJiM20HOSOuVxReffZVqaPpnjjQ2oc
/+bOYwutEwKBgQCROPaploSxR4Uk8mm4qrUDl05ibhPFGeQoCXhLLjS57QmPBp55
k3rCJxOW9TnJ3DpCxCDvDBs2RY99bI8bvzQ/DgFOEXo6BnkS5ftREoaAC2j9Gs6a
zK9oYnVHWmCtlb4FdmQ2ogFrdqh9iO0LhfyG8iBKAtFEvRVkVMmFMKsGcQKBgBIx
XHPNZAwYSRUL+nqq27r0uifOyY1uKN/KiicJfk6vqK0V8+mu8GwUGzw6PXermtCJ
mSQZ5rnAN0SwsqJT0gHqszY37CYQn6p+myZQkPvaFYDWaJmpoc7wsKGHi6KMFN+8
sXMoZHqWlsQ8/2uL+ZYEgHzj6bZ7EvkKh/qKwF0vAoGAOZIdYwZn2lVc8PYU/Wrs
3Rj1BWrJJnMwLMYIREhBXmt3S9s9un6o7GURBA5N1AB4mpjcUV3VvEsu2dJt2kKN
2/vzO1ADerx0Y1ZGqTk+NeGikKfMxhWrKpyjA5kh2XJr3ubhqHdLdM1KuGhRxd0w
+qGhk+hC7HdFP9GbxN7yrXM=
-----END PRIVATE KEY-----";

fn metadata_xml(key_descriptors: &str) -> String {
    format!(
        r#"<md:EntityDescriptor xmlns:md="{METADATA_NS}" xmlns:ds="{DS_NS}" validUntil="2030-01-01T00:00:00Z" entityID="https://idp.example.test/metadata"><md:IDPSSODescriptor>{key_descriptors}<md:SingleSignOnService Binding="{HTTP_POST_BINDING}" Location="https://idp.example.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
    )
}

fn metadata_with_key_info(key_info: &str) -> String {
    metadata_xml(&format!(
        r#"<md:KeyDescriptor use="signing">{key_info}</md:KeyDescriptor>"#
    ))
}

fn certificate_pem() -> String {
    format!("-----BEGIN CERTIFICATE-----\n{TEST_CERTIFICATE_DER_B64}\n-----END CERTIFICATE-----")
}

fn signed_metadata() -> (String, String) {
    let descriptor = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let unsigned = metadata_xml(&descriptor).replace(
        "entityID=\"https://idp.example.test/metadata\"",
        "ID=\"metadata\" entityID=\"https://idp.example.test/metadata\"",
    );
    signed_metadata_from_unsigned(unsigned)
}

fn signed_metadata_without_sso_endpoint() -> (String, String) {
    let descriptor = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let endpoint = format!(
        r#"<md:SingleSignOnService Binding="{HTTP_POST_BINDING}" Location="https://idp.example.test/sso"/>"#
    );
    let unsigned = metadata_xml(&descriptor).replace(&endpoint, "").replace(
        "entityID=\"https://idp.example.test/metadata\"",
        "ID=\"metadata\" entityID=\"https://idp.example.test/metadata\"",
    );
    signed_metadata_from_unsigned(unsigned)
}

fn signed_metadata_from_unsigned(unsigned: String) -> (String, String) {
    let key_pair = RsaKeyPair::from_pkcs8(
        pem::parse(TEST_RSA_PRIVATE_KEY_PEM)
            .expect("test private key PEM")
            .contents(),
    )
    .expect("test private key DER");
    let certificate = certificate_pem();
    let unsigned_element = xml_security::UnverifiedElement::try_from(unsigned.as_str())
        .expect("unsigned metadata XML");
    let digest = STANDARD.encode(Sha256::digest(
        unsigned_element
            .canonicalize_unverified()
            .expect("unsigned metadata canonicalization"),
    ));
    let signed_info = format!(
        r##"<ds:SignedInfo xmlns:ds="{DS_NS}"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#metadata"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##
    );
    let signed_info_element =
        xml_security::UnverifiedElement::try_from(signed_info.as_str()).expect("signed info XML");
    let canonicalized_signed_info = signed_info_element
        .canonicalize_unverified()
        .expect("signed info canonicalization");
    let mut signature = vec![0_u8; key_pair.public_modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            &canonicalized_signed_info,
            &mut signature,
        )
        .expect("sign metadata");
    let signature_block = format!(
        r#"<ds:Signature>{signed_info}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature>"#,
        STANDARD.encode(signature)
    );
    let signed = unsigned.replace(
        "</md:EntityDescriptor>",
        &format!("{signature_block}</md:EntityDescriptor>"),
    );
    (signed, certificate)
}

#[test]
fn given_empty_fingerprint_set_when_building_trust_policy_then_reject_allow_all_policy() {
    // Given no independently trusted certificate pins.
    // When the caller constructs the metadata trust policy.
    let error = CertificateTrustPolicy::from_sha256_fingerprints(Vec::new())
        .expect_err("an empty trust source must not become allow-all");

    // Then metadata cannot be accepted without an explicit trust anchor.
    assert_eq!(
        error,
        SamlError::InvalidInput(
            "at least one trusted certificate fingerprint is required".to_string()
        )
    );
}

#[test]
fn given_two_distinct_valid_signing_certificates_when_only_one_is_pinned_then_reject_all() {
    // Given two valid advertised signing certificates and a pin for only one.
    let key_descriptors = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate><ds:X509Certificate>{SECOND_TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let metadata = UnverifiedMetadata::parse_unverified(&metadata_xml(&key_descriptors), NOW)
        .expect("both certificate DER values should parse");
    let first_der = STANDARD
        .decode(TEST_CERTIFICATE_DER_B64)
        .expect("first certificate fixture");
    let first_fingerprint: [u8; 32] = Sha256::digest(first_der).into();
    let policy = CertificateTrustPolicy::from_sha256_fingerprints(vec![first_fingerprint])
        .expect("one explicit pin should build");

    // When the caller validates the complete advertised certificate set.
    let error = metadata
        .validate_trust(&policy)
        .expect_err("an unpinned signing certificate must not be ignored");

    // Then trust requires every certificate, not merely any matching
    // certificate.
    assert_eq!(error, SamlError::CertificateNotTrusted);
}

#[test]
fn given_signed_pinned_metadata_when_verifying_then_return_verified_projection() {
    // Given a signed metadata document and an independently pinned certificate.
    let (xml, certificate) = signed_metadata();
    let der = STANDARD
        .decode(TEST_CERTIFICATE_DER_B64)
        .expect("test certificate fixture");
    let fingerprint: [u8; 32] = Sha256::digest(&der).into();
    let policy = CertificateTrustPolicy::from_sha256_fingerprints(vec![fingerprint])
        .expect("non-empty trust policy");
    let trusted_certificates = [certificate];

    // When the verified metadata API checks the XML signature and metadata pin.
    let verified = VerifiedMetadata::try_from(MetadataVerification::new(
        &xml,
        &trusted_certificates,
        &policy,
        NOW,
    ))
    .expect("signed metadata should verify");

    // Then callers receive only the signed, structurally validated projection.
    assert_eq!(verified.entity_id(), "https://idp.example.test/metadata");
    assert_eq!(verified.sso_url(), "https://idp.example.test/sso");
    assert_eq!(verified.certificates().len(), 1);
    assert!(verified.warnings().is_empty());
}

#[test]
fn given_signed_metadata_without_sso_endpoint_when_verifying_then_reject_structure() {
    // Given a validly signed document whose signed content lacks a required
    // endpoint.
    let (xml, certificate) = signed_metadata_without_sso_endpoint();
    let der = STANDARD
        .decode(TEST_CERTIFICATE_DER_B64)
        .expect("test certificate fixture");
    let fingerprint: [u8; 32] = Sha256::digest(&der).into();
    let policy = CertificateTrustPolicy::from_sha256_fingerprints(vec![fingerprint])
        .expect("non-empty trust policy");
    let trusted_certificates = [certificate];

    // When signature verification succeeds but structural metadata parsing
    // runs.
    let error = VerifiedMetadata::try_from(MetadataVerification::new(
        &xml,
        &trusted_certificates,
        &policy,
        NOW,
    ))
    .expect_err("signed metadata without an endpoint must be rejected");

    // Then the verified API preserves the structural boundary after
    // authentication.
    assert_eq!(
        error,
        SamlError::InvalidInput("HTTP-POST SingleSignOnService is required".to_string())
    );
}

#[test]
fn given_empty_entities_descriptor_when_parsing_then_reject_missing_entity() {
    // Given a bounded wrapper with no selectable EntityDescriptor.
    let xml = format!(
        r#"<md:EntitiesDescriptor xmlns:md="{METADATA_NS}" validUntil="2030-01-01T00:00:00Z"/>"#
    );

    // When metadata selection runs.
    let error = UnverifiedMetadata::parse_unverified(&xml, NOW)
        .expect_err("a wrapper without an entity must be rejected");

    // Then callers receive a structural error instead of an arbitrary choice.
    assert_eq!(
        error,
        SamlError::InvalidInput("EntityDescriptor is required".to_string())
    );
}

#[test]
fn given_non_metadata_root_when_parsing_then_reject_without_selecting_entity() {
    // Given an XML root outside the SAML metadata vocabulary.
    let xml =
        format!(r#"<md:Metadata xmlns:md="{METADATA_NS}" validUntil="2030-01-01T00:00:00Z"/>"#);

    // When metadata selection runs.
    let error = UnverifiedMetadata::parse_unverified(&xml, NOW)
        .expect_err("an unrelated root must not be treated as an entity");

    // Then the parser fails closed on the missing EntityDescriptor.
    assert_eq!(
        error,
        SamlError::InvalidInput("EntityDescriptor is required".to_string())
    );
}

#[test]
fn given_remote_key_retrieval_in_key_info_when_parsing_then_reject_without_network() {
    // Given a signing key that asks the parser to fetch remote material.
    let key_info =
        r#"<ds:KeyInfo><ds:RetrievalMethod URI="https://attacker.invalid/key"/></ds:KeyInfo>"#;

    // When the metadata key is parsed.
    let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(key_info), NOW)
        .expect_err("remote key retrieval must not be attempted");

    // Then the unsupported remote reference is rejected at the metadata
    // boundary.
    assert_eq!(
        error,
        SamlError::Unsupported("remote XML Signature key retrieval is not supported".to_string())
    );
}

#[test]
fn given_remote_key_retrieval_as_key_descriptor_child_when_parsing_then_reject_without_network() {
    // Given a signing descriptor that asks the parser to fetch remote material.
    let key_info = r#"<ds:RetrievalMethod URI="https://attacker.invalid/key"/>"#;

    // When the metadata key is parsed.
    let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(key_info), NOW)
        .expect_err("remote key retrieval must not be attempted");

    // Then the unsupported remote reference is rejected at the descriptor
    // boundary.
    assert_eq!(
        error,
        SamlError::Unsupported("remote XML Signature key retrieval is not supported".to_string())
    );
}

#[test]
fn given_unexpected_key_descriptor_child_when_parsing_then_reject_ambiguous_key_material() {
    // Given a signing descriptor with a child outside the supported ds:KeyInfo
    // shape.
    let key_info = r#"<md:Unexpected/>"#;

    // When the metadata key is parsed.
    let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(key_info), NOW)
        .expect_err("unsupported key children must not be ignored");

    // Then only the exact supported key structure remains admissible.
    assert_eq!(
        error,
        SamlError::Unsupported("KeyDescriptor contains an unsupported child".to_string())
    );
}

#[test]
fn given_zero_or_multiple_key_info_children_when_parsing_then_reject_ambiguous_key_material() {
    for key_info in ["", r#"<ds:KeyInfo/><ds:KeyInfo/>"#] {
        // Given a signing descriptor whose KeyInfo cardinality is not exactly
        // one.
        let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(key_info), NOW)
            .expect_err("ambiguous KeyInfo cardinality must be rejected");

        // Then callers cannot accidentally select attacker-controlled key
        // material.
        assert_eq!(
            error,
            SamlError::InvalidInput(
                "exactly one ds:KeyInfo is required for a signing KeyDescriptor".to_string()
            )
        );
    }
}

#[test]
fn given_unexpected_x509_data_retrieval_when_parsing_then_reject_without_network() {
    // Given X509Data that contains a remote retrieval request instead of a
    // certificate.
    let key_info = r#"<ds:KeyInfo><ds:X509Data><ds:RetrievalMethod URI="https://attacker.invalid/key"/></ds:X509Data></ds:KeyInfo>"#;

    // When the metadata key is parsed.
    let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(key_info), NOW)
        .expect_err("remote X509Data retrieval must not be attempted");

    // Then the nested reference is rejected as unsupported before any network
    // use.
    assert_eq!(
        error,
        SamlError::Unsupported("ds:X509Data contains an unsupported child".to_string())
    );
}

#[test]
fn given_unexpected_x509_data_child_when_parsing_then_reject_unsupported_certificate_source() {
    // Given X509Data with a child that is not an X509Certificate.
    let key_info =
        r#"<ds:KeyInfo><ds:X509Data><ds:KeyName>alias</ds:KeyName></ds:X509Data></ds:KeyInfo>"#;

    // When the metadata key is parsed.
    let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(key_info), NOW)
        .expect_err("unsupported X509Data children must not be accepted");

    // Then certificate extraction remains restricted to the explicit element.
    assert_eq!(
        error,
        SamlError::Unsupported("ds:X509Data contains an unsupported child".to_string())
    );
}

#[test]
fn given_empty_x509_data_when_parsing_then_reject_missing_signing_certificate() {
    // Given one KeyInfo whose X509Data has no certificate elements.
    let key_info = r#"<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>"#;

    // When signing certificates are extracted.
    let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(key_info), NOW)
        .expect_err("a signing descriptor without certificates must be rejected");

    // Then metadata cannot proceed without an advertised signing certificate.
    assert_eq!(
        error,
        SamlError::InvalidInput("at least one X509Certificate is required".to_string())
    );
}

#[test]
fn given_empty_x509_certificate_text_when_parsing_then_reject_invalid_der() {
    // Given an X509Certificate whose whitespace decodes to zero bytes.
    let key_info = concat!(
        r#"<ds:KeyInfo><ds:X509Data><ds:X509Certificate> "#,
        r#"
        </ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#,
    );

    // When the certificate bytes are decoded.
    let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(key_info), NOW)
        .expect_err("empty certificate bytes must be rejected");

    // Then no empty DER value can enter the parsed metadata.
    assert_eq!(error, SamlError::InvalidCertificate);
}

#[test]
fn given_trailing_certificate_der_when_parsing_then_reject_noncanonical_certificate() {
    // Given a valid certificate followed by attacker-controlled trailing bytes.
    let mut der = STANDARD
        .decode(TEST_CERTIFICATE_DER_B64)
        .expect("test certificate fixture");
    der.push(0);
    let encoded = STANDARD.encode(der);
    let key_info = format!(
        r#"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{encoded}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"#
    );

    // When the metadata certificate is parsed as strict DER.
    let error = UnverifiedMetadata::parse_unverified(&metadata_with_key_info(&key_info), NOW)
        .expect_err("trailing DER must not be accepted");

    // Then the certificate parser fails closed before trust evaluation.
    assert_eq!(error, SamlError::InvalidCertificate);
}

fn protocol_key_descriptor(certificate: &str, use_value: &str) -> String {
    format!(
        r#"<md:KeyDescriptor use="{use_value}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    )
}

fn protocol_metadata_xml(
    valid_until: &str,
    key_descriptors: &str,
    endpoints: &str,
    entity_id: &str,
) -> String {
    format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" validUntil="{valid_until}" entityID="{entity_id}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{key_descriptors}{endpoints}</md:IDPSSODescriptor></md:EntityDescriptor>"#
    )
}

fn protocol_valid_metadata() -> String {
    protocol_metadata_xml(
        "2030-01-01T00:00:00Z",
        &protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing"),
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "https://idp.example.test/metadata",
    )
}
#[test]
fn given_valid_metadata_when_parsing_then_return_neutral_values_and_redact_certificate_debug() {
    let parsed = UnverifiedMetadata::parse_unverified(&protocol_valid_metadata(), NOW)
        .expect("valid metadata");
    assert_eq!(parsed.entity_id(), "https://idp.example.test/metadata");
    assert_eq!(parsed.sso_url(), "https://idp.example.test/sso");
    assert_eq!(parsed.certificates().len(), 1);
    assert!(parsed.warnings().is_empty());
    let debug = format!("{parsed:?}");
    assert!(!debug.contains(TEST_CERTIFICATE_DER_B64));

    let wrapped = format!(
        r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2030-01-01T00:00:00Z">{}</md:EntitiesDescriptor>"#,
        protocol_valid_metadata()
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
    let xml = protocol_valid_metadata();

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
    let parsed = UnverifiedMetadata::parse_unverified(&protocol_valid_metadata(), NOW)
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
    let parsed = UnverifiedMetadata::parse_unverified(&protocol_valid_metadata(), NOW)
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
        protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing"),
        protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing")
    );
    let endpoints = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/one"/>"#;
    let parsed = UnverifiedMetadata::parse_unverified(
        &protocol_metadata_xml("2030-01-01T00:00:00Z", &descriptors, endpoints, "entity"),
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
    let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let endpoints = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/one"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/two"/>"#;
    let metadata = protocol_metadata_xml("2030-01-01T00:00:00Z", &descriptor, endpoints, "entity");

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_metadata_with_invalid_root_or_required_fields_when_parsing_then_reject() {
    let valid = protocol_valid_metadata();
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
    let valid = protocol_valid_metadata();
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
    let nested = protocol_valid_metadata().replace(
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
    let nested = protocol_valid_metadata().replace(" validUntil=\"2030-01-01T00:00:00Z\"", "");
    let wrapped = format!(
        r#"<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2030-01-01T00:00:00Z">{nested}</md:EntitiesDescriptor>"#
    );

    assert!(UnverifiedMetadata::parse_unverified(&wrapped, NOW).is_err());
}

#[test]
fn given_metadata_without_http_post_endpoint_or_location_when_parsing_then_reject() {
    let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let no_post = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT" Location="https://idp.example.test/sso"/>"#;
    assert!(
        UnverifiedMetadata::parse_unverified(
            &protocol_metadata_xml("2030-01-01T00:00:00Z", &descriptor, no_post, "entity"),
            NOW
        )
        .is_err()
    );
    let no_location =
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>"#;
    assert!(
        UnverifiedMetadata::parse_unverified(
            &protocol_metadata_xml("2030-01-01T00:00:00Z", &descriptor, no_location, "entity"),
            NOW
        )
        .is_err()
    );
}

#[test]
fn given_metadata_with_unsafe_endpoint_when_parsing_then_reject_before_returning_it() {
    let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
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
                &protocol_metadata_xml("2030-01-01T00:00:00Z", &descriptor, &endpoint, "entity"),
                NOW
            )
            .is_err()
        );
    }
}

#[test]
fn given_metadata_with_non_signing_or_unknown_key_use_when_parsing_then_reject() {
    for use_value in ["encryption", "other"] {
        let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, use_value);
        assert!(
            UnverifiedMetadata::parse_unverified(
                &protocol_metadata_xml(
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
    let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing")
        .replace(" use=\"signing\"", "");
    let metadata = protocol_metadata_xml(
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
    let remote_key_metadata = protocol_metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "entity",
    );
    assert!(UnverifiedMetadata::parse_unverified(&remote_key_metadata, NOW).is_err());

    let signed_metadata = protocol_valid_metadata().replace(
        "><md:IDPSSODescriptor",
        "><ds:Signature/><md:IDPSSODescriptor",
    );
    assert!(UnverifiedMetadata::parse_unverified(&signed_metadata, NOW).is_err());
}

#[test]
fn given_multiple_metadata_entities_when_parsing_then_reject_ambiguous_selection() {
    let first = protocol_valid_metadata();
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
    let first = protocol_valid_metadata();
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
    let metadata = protocol_valid_metadata().replace(
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
    let metadata = protocol_metadata_xml(
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
    let metadata = protocol_metadata_xml(
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
    let metadata = protocol_metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/sso"/>"#,
        "entity",
    );

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_cleartext_metadata_sso_destination_when_parsing_then_reject_downgrade() {
    let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let metadata = protocol_metadata_xml(
        "2030-01-01T00:00:00Z",
        &descriptor,
        r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://idp.example.test/sso"/>"#,
        "entity",
    );

    assert!(UnverifiedMetadata::parse_unverified(&metadata, NOW).is_err());
}

#[test]
fn given_xml_encryption_metadata_when_parsing_then_reject_before_using_keys() {
    let encrypted = protocol_valid_metadata().replace(
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
fn given_encrypted_namespace_attribute_in_metadata_when_parsing_then_reject_it() {
    let encrypted = protocol_valid_metadata().replace(
        "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
        "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xenc:CipherData=\"opaque\"",
    );
    assert!(matches!(
        UnverifiedMetadata::parse_unverified(&encrypted, NOW),
        Err(SamlError::Unsupported(_))
    ));
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

#[test]
fn given_expired_metadata_when_parsing_then_reject_even_with_valid_shape() {
    // Given a structurally valid document whose validity window has closed
    // relative to the caller's clock.
    let key_descriptors = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let xml = metadata_xml(&key_descriptors);
    let after_expiry = chrono::DateTime::from_timestamp(1924982400, 0).expect("2031 timestamp");

    // When parsing runs after expiry.
    // Then replay of stale federation metadata fails closed.
    assert!(UnverifiedMetadata::parse_unverified(&xml, after_expiry).is_err());
}

#[test]
fn given_multiple_entity_descriptors_when_parsing_then_reject_ambiguity() {
    // Given a wrapper selecting between two live entity descriptors, so no
    // single trust root or endpoint set can be selected.
    let wrapped = format!(
        r#"<md:EntitiesDescriptor xmlns:md="{METADATA_NS}" validUntil="2030-01-01T00:00:00Z"><md:EntityDescriptor xmlns:md="{METADATA_NS}" validUntil="2030-01-01T00:00:00Z" entityID="https://idp.example.test/metadata"><md:IDPSSODescriptor><md:SingleSignOnService Binding="{HTTP_POST_BINDING}" Location="https://idp.example.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor><md:EntityDescriptor xmlns:md="{METADATA_NS}" validUntil="2030-01-01T00:00:00Z" entityID="https://evil.example.test/metadata"><md:IDPSSODescriptor><md:SingleSignOnService Binding="{HTTP_POST_BINDING}" Location="https://evil.example.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor></md:EntitiesDescriptor>"#
    );

    // When selection runs over the ambiguous wrapper.
    // Then no entity is silently preferred over the other.
    assert!(UnverifiedMetadata::parse_unverified(&wrapped, NOW).is_err());
}

#[test]
fn given_encryption_only_certificate_when_parsing_then_reject_before_trust() {
    // Given metadata advertising only an encryption-use certificate, with no
    // signing-use certificate at all.
    let key_descriptors = format!(
        r#"<md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    );

    // When parsing runs, an encryption key must never become selectable
    // signing trust, so the document fails before trust validation.
    assert!(UnverifiedMetadata::parse_unverified(&metadata_xml(&key_descriptors), NOW).is_err());
}

#[test]
fn given_wrong_certificate_pin_when_verifying_signed_metadata_then_reject() {
    // Given validly signed metadata while the caller pins an unrelated
    // certificate.
    let (xml, certificate) = signed_metadata();
    let other_der = STANDARD
        .decode(SECOND_TEST_CERTIFICATE_DER_B64)
        .expect("second certificate fixture");
    let other_fingerprint: [u8; 32] = Sha256::digest(other_der).into();
    let policy = CertificateTrustPolicy::from_sha256_fingerprints(vec![other_fingerprint])
        .expect("pin builds");
    let trusted_certificates = [certificate];

    // When verification runs against the wrong pin.
    let error = VerifiedMetadata::try_from(MetadataVerification::new(
        &xml,
        &trusted_certificates,
        &policy,
        NOW,
    ))
    .expect_err("wrong pin must fail");

    // Then the mismatch fails as untrusted rather than verifying.
    assert_eq!(error, SamlError::CertificateNotTrusted);
}

#[test]
fn given_unsigned_metadata_when_verifying_then_reject_without_trust() {
    // Given structurally valid but unsigned metadata.
    let key_descriptors = format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{TEST_CERTIFICATE_DER_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    );
    let xml = metadata_xml(&key_descriptors);
    let der = STANDARD
        .decode(TEST_CERTIFICATE_DER_B64)
        .expect("test certificate fixture");
    let fingerprint: [u8; 32] = Sha256::digest(&der).into();
    let policy =
        CertificateTrustPolicy::from_sha256_fingerprints(vec![fingerprint]).expect("pin builds");
    let trusted_certificates = [certificate_pem()];

    // When the verified API processes the unsigned document.
    // Then no signature means no trust, however well pinned the bytes are.
    assert!(
        VerifiedMetadata::try_from(MetadataVerification::new(
            &xml,
            &trusted_certificates,
            &policy,
            NOW
        ))
        .is_err()
    );
}

#[test]
fn given_post_and_redirect_metadata_when_binding_is_selected_then_matching_endpoint_is_returned() {
    let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let endpoints = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/post"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/redirect"/>"#;
    let xml = protocol_metadata_xml("2030-01-01T00:00:00Z", &descriptor, endpoints, "entity");
    for (binding, expected) in [
        (
            MetadataSsoBinding::HttpPost,
            "https://idp.example.test/post",
        ),
        (
            MetadataSsoBinding::HttpRedirect,
            "https://idp.example.test/redirect",
        ),
    ] {
        let parsed = UnverifiedMetadata::parse_unverified_for_binding(&xml, NOW, binding)
            .expect("selected endpoint");
        assert_eq!(parsed.sso_url(), expected);
    }
    assert_eq!(
        UnverifiedMetadata::parse_unverified(&xml, NOW)
            .expect("compatibility POST")
            .sso_url(),
        "https://idp.example.test/post"
    );
}

#[test]
fn given_redirect_only_metadata_when_redirect_is_selected_then_parse_succeeds_without_post_fallback()
 {
    let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let endpoints = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/redirect"/>"#;
    let xml = protocol_metadata_xml("2030-01-01T00:00:00Z", &descriptor, endpoints, "entity");
    let parsed = UnverifiedMetadata::parse_unverified_for_binding(
        &xml,
        NOW,
        MetadataSsoBinding::HttpRedirect,
    )
    .expect("redirect metadata");
    assert_eq!(parsed.sso_url(), "https://idp.example.test/redirect");
    assert!(UnverifiedMetadata::parse_unverified(&xml, NOW).is_err());
    let post_only = xml.replace("bindings:HTTP-Redirect", "bindings:HTTP-POST");
    assert!(
        UnverifiedMetadata::parse_unverified_for_binding(
            &post_only,
            NOW,
            MetadataSsoBinding::HttpRedirect
        )
        .is_err()
    );
}

#[test]
fn given_ambiguous_or_unsafe_redirect_endpoints_when_parsing_then_metadata_is_rejected() {
    let descriptor = protocol_key_descriptor(TEST_CERTIFICATE_DER_B64, "signing");
    let one = r#"<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/redirect"/>"#;
    for endpoints in [
        format!("{one}{one}"),
        one.replace(
            "https://idp.example.test/redirect",
            "http://idp.example.test/redirect",
        ),
        one.replace(
            "https://idp.example.test/redirect",
            "https://user:password@idp.example.test/redirect",
        ),
    ] {
        let xml = protocol_metadata_xml("2030-01-01T00:00:00Z", &descriptor, &endpoints, "entity");
        assert!(
            UnverifiedMetadata::parse_unverified_for_binding(
                &xml,
                NOW,
                MetadataSsoBinding::HttpRedirect
            )
            .is_err()
        );
    }
}
