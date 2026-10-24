use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{KeyPair, RSA_PKCS1_SHA256},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{
    DigestAlgorithm, SamlError, SignatureAlgorithm, UnverifiedPublicKeyDer, compute_digest,
    crypto::verify_signature,
};

// This is a generated test certificate. It is public test material and is used
// only to exercise strict DER/metadata handling; parsing it never establishes
// trust in the certificate.
const TEST_CERTIFICATE_DER_B64: &str = "MIIDCzCCAfOgAwIBAgIUQ4GH6mxaRr4BDE3ReyzQ/JTywX0wDQYJKoZIhvcNAQELBQAwFTETMBEGA1UEAwwKYXV4Zm4tdGVzdDAeFw0yNjAyMDcyMDU2MTRaFw0zNjAyMDUyMDU2MTRaMBUxEzARBgNVBAMMCmF1eGZuLXRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbOzlUVTDEzZ01qQpe233hB+IXYMCZRNHX9icrK+mrRRoNj7GgftvTRqBoehCYmB3IGTqSeiGB2heZRKovNka/hxGt85TDgtUU3fGT6GHj4GlZvVLw9Q1coqmghI0qHmFKlIN9wdjUKr0EcyUzLcPPCSt6N2f8Jbg/b7yaBYVGRCdk5D884c67l8kbwyiH8vxUJ4TWCVottniVZriuWO7Gk+D3GQXkd3iDLqA+1xq70B0iwzO9VVm9YBw+AWXqJRgqYLvQZUwjVwaBsNRPvUOJ5vt20jobjKFaWAj0YvtAa+hGEU58bCld/h0KdGsJhkC6Q+1HICfjZrKf4M6lOe4jAgMBAAGjUzBRMB0GA1UdDgQWBBQmzhNLM//Ik6FeXOuo9NEEQbAdYjAfBgNVHSMEGDAWgBQmzhNLM//Ik6FeXOuo9NEEQbAdYjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDBMD6da/5ZSb0Yq+566KmJi4cv0iL8FNfwAN6WPRBoc7afnhM3tJDcc4+ko5gIurtiK2qT7ZQzmCicYKRUda6stjQsBTEeF9MRktYOvAd6TUT24w+Q4N18OwmyOgs/LTU5czb8/AyzqPSoN2fq8XunUDQY9x5kRyoIX18DfDLo4mCyq5n6LwpyLBa/ZmXCxXHW6mCU6Wp/9l6IB9ykPgu4MxlhPs5U3jc+AGe4+KkYnGeoKfFclOuGrCqi3XtejAiaTrfHBnEeSVSCZU9s92vAyl1dwfyN2irS/ANceeWQe+Uq3jYfsa6TWh8zasUTdWshogKjnvObWK2lTtCrAqjP";

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
