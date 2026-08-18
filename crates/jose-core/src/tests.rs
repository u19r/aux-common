use aws_lc_rs::{
    encoding::AsDer,
    signature::{Ed25519KeyPair, KeyPair},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::{
    CompactJws, JwsAlgorithm, PreparedVerifier, ProtectedHeader, PublicJwk, PublicJwks,
    PublicKeyComponents,
};

#[test]
fn given_header_when_encoding_then_fields_are_canonical_and_roundtrip() {
    let header = ProtectedHeader::new(JwsAlgorithm::EdDsa, "key-1", Some("JWT")).expect("header");
    let encoded = header.encode().expect("encoding");
    assert_eq!(ProtectedHeader::decode(&encoded).expect("decode"), header);
}

#[test]
fn given_duplicate_or_unknown_header_members_when_decoding_then_reject() {
    let duplicate = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"a","kid":"b"}"#);
    assert!(ProtectedHeader::decode(&duplicate).is_err());
    let unknown = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"a","extra":true}"#);
    assert!(ProtectedHeader::decode(&unknown).is_err());
}

#[test]
fn given_compact_jws_when_preparing_then_only_canonical_three_part_shape_is_emitted() {
    let header =
        ProtectedHeader::new(JwsAlgorithm::EdDsa, "key-1", None::<String>).expect("header");
    let prepared = CompactJws::prepare(&header, br#"{"sub":"user"}"#).expect("prepare");
    let compact = prepared.finish(&[1, 2, 3]);
    let decoded = CompactJws::decode(&compact).expect("decode");
    assert_eq!(decoded.payload, br#"{"sub":"user"}"#);
    assert_eq!(decoded.signature, vec![1, 2, 3]);
}

#[test]
fn given_invalid_public_key_when_preparing_verifier_then_reject() {
    assert!(PreparedVerifier::try_new(JwsAlgorithm::EdDsa, &[0; 31]).is_err());
    assert!(CompactJws::decode("one.two").is_err());
}

#[test]
fn given_ed25519_spki_when_preparing_then_algorithm_and_der_shape_are_bound() {
    let key_pair = Ed25519KeyPair::generate().expect("generate key");
    let public_key = key_pair.public_key().as_der().expect("encode public key");
    let verifier = PreparedVerifier::try_new(JwsAlgorithm::EdDsa, public_key.as_ref())
        .expect("prepare Ed25519 verifier");
    let message = b"jose-core-test";
    let signature = key_pair.sign(message);
    verifier
        .verify(message, signature.as_ref())
        .expect("verify signature");
    assert!(PreparedVerifier::try_new(JwsAlgorithm::Rs256, public_key.as_ref()).is_err());

    let mut trailing = public_key.as_ref().to_vec();
    trailing.push(0);
    assert!(PreparedVerifier::try_new(JwsAlgorithm::EdDsa, &trailing).is_err());
    assert!(PublicJwk::from_spki(JwsAlgorithm::EdDsa, "ed", public_key.as_ref()).is_ok());
}

#[test]
fn given_low_order_ed25519_point_when_verifying_forged_signature_then_rejects() {
    let mut point = [0_u8; 32];
    point[0] = 1;
    let public_key = ed25519_spki(point);
    assert!(PreparedVerifier::try_new(JwsAlgorithm::EdDsa, &public_key).is_err());
    assert!(
        PublicJwk::from_components(
            JwsAlgorithm::EdDsa,
            "low-order",
            PublicKeyComponents::Ed25519 { x: point.to_vec() },
        )
        .is_err()
    );
}

#[test]
fn given_low_order_ed25519_signature_r_when_verifying_then_rejects() {
    let key_pair = Ed25519KeyPair::generate().expect("generate key");
    let public_key = key_pair.public_key().as_der().expect("encode public key");
    let verifier = PreparedVerifier::try_new(JwsAlgorithm::EdDsa, public_key.as_ref())
        .expect("prepare Ed25519 verifier");
    let mut signature = [0_u8; 64];
    signature[0] = 1;

    assert!(verifier.verify(b"forged", &signature).is_err());
}

fn ed25519_spki(point: [u8; 32]) -> Vec<u8> {
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(&point);
    spki
}

#[test]
fn given_jwk_components_when_building_jwks_then_output_is_stable_and_validated() {
    let (x, y) = valid_p256_generator();
    let jwk = PublicJwk::from_components(
        JwsAlgorithm::Es256,
        "b",
        PublicKeyComponents::Ec {
            curve: "P-256",
            x: x.to_vec(),
            y: y.to_vec(),
        },
    )
    .expect("jwk");
    let other = PublicJwk::from_components(
        JwsAlgorithm::Es256,
        "a",
        PublicKeyComponents::Ec {
            curve: "P-256",
            x: x.to_vec(),
            y: y.to_vec(),
        },
    )
    .expect("jwk");
    assert_eq!(
        PublicJwks::try_new(vec![jwk, other])
            .expect("unique key ids")
            .keys()[0]
            .kid(),
        "a"
    );
    assert!(
        PublicJwk::from_components(
            JwsAlgorithm::Es256,
            "bad",
            PublicKeyComponents::Ec {
                curve: "P-384",
                x: vec![1; 48],
                y: vec![2; 48]
            },
        )
        .is_err()
    );
}

#[test]
fn given_rsa_modulus_below_bit_profile_when_building_jwk_then_rejects_and_keeps_boundary() {
    let exponent = vec![1, 0, 1];
    let mut undersized = vec![0xff; 256];
    undersized[0] = 0x7f;
    assert!(
        PublicJwk::from_components(
            JwsAlgorithm::Rs256,
            "undersized",
            PublicKeyComponents::Rsa {
                modulus: undersized,
                exponent: exponent.clone(),
            },
        )
        .is_err(),
        "a 2047-bit modulus must not pass the 2048-bit profile"
    );

    let mut valid = vec![0xff; 256];
    valid[0] = 0x80;
    assert!(
        PublicJwk::from_components(
            JwsAlgorithm::Rs256,
            "valid",
            PublicKeyComponents::Rsa {
                modulus: valid,
                exponent,
            },
        )
        .is_ok(),
        "a modulus with 2048 significant bits remains supported"
    );
}

fn valid_p256_generator() -> ([u8; 32], [u8; 32]) {
    (
        [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ],
        [
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ],
    )
}
