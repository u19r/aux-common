use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType, Jwk,
    OctetKeyPairParameters, OctetKeyPairType, OctetKeyParameters, OctetKeyType, RSAKeyParameters,
    RSAKeyType,
};

use super::KeyPolicy;
use crate::{JwtDecodeErrorKind, SignatureAlgorithm};

fn rsa_jwk(modulus_bytes: usize) -> Jwk {
    Jwk {
        common: Default::default(),
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: URL_SAFE_NO_PAD.encode(vec![0xff; modulus_bytes]),
            e: "AQAB".to_string(),
        }),
    }
}

fn ec_jwk(curve: EllipticCurve) -> Jwk {
    let coordinate_bytes = match curve {
        EllipticCurve::P256 => 32,
        EllipticCurve::P384 => 48,
        _ => 1,
    };
    Jwk {
        common: Default::default(),
        algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
            key_type: EllipticCurveKeyType::EC,
            curve,
            x: URL_SAFE_NO_PAD.encode(vec![0x01; coordinate_bytes]),
            y: URL_SAFE_NO_PAD.encode(vec![0x01; coordinate_bytes]),
        }),
    }
}

fn okp_jwk(curve: EllipticCurve) -> Jwk {
    okp_jwk_with_coordinate_len(curve, 32)
}

fn hmac_jwk(bytes: usize) -> Jwk {
    Jwk {
        common: Default::default(),
        algorithm: AlgorithmParameters::OctetKey(OctetKeyParameters {
            key_type: OctetKeyType::Octet,
            value: URL_SAFE_NO_PAD.encode(vec![0x42; bytes]),
        }),
    }
}

#[test]
fn undersized_rsa_modulus_is_rejected_before_backend_selection() {
    let error = KeyPolicy::new(&rsa_jwk(128), SignatureAlgorithm::RS256, false)
        .validate()
        .expect_err("RSA keys below 2048 bits must be rejected");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[test]
fn two_thousand_forty_eight_bit_rsa_modulus_passes_size_policy() {
    KeyPolicy::new(&rsa_jwk(256), SignatureAlgorithm::RS256, false)
        .validate()
        .expect("2048-bit RSA keys should pass the size policy");
}

#[test]
fn given_2040_bit_rsa_modulus_when_validating_key_policy_then_rejects() {
    let error = KeyPolicy::new(&rsa_jwk(255), SignatureAlgorithm::RS256, false)
        .validate()
        .expect_err("2040-bit RSA keys must be rejected");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[test]
fn given_ec_curve_mismatch_when_validating_key_policy_then_rejects() {
    let error = KeyPolicy::new(
        &ec_jwk(EllipticCurve::P384),
        SignatureAlgorithm::ES256,
        false,
    )
    .validate()
    .expect_err("ES256 must not consume a P-384 key");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    KeyPolicy::new(
        &ec_jwk(EllipticCurve::P256),
        SignatureAlgorithm::ES256,
        false,
    )
    .validate()
    .expect("the matching P-256 curve remains supported");
}

#[test]
fn given_okp_curve_mismatch_when_validating_key_policy_then_rejects() {
    let error = KeyPolicy::new(
        &okp_jwk(EllipticCurve::P256),
        SignatureAlgorithm::EdDSA,
        false,
    )
    .validate()
    .expect_err("EdDSA must only consume Ed25519 keys");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    KeyPolicy::new(
        &okp_jwk(EllipticCurve::Ed25519),
        SignatureAlgorithm::EdDSA,
        false,
    )
    .validate()
    .expect("the matching Ed25519 curve remains supported");
}

#[test]
fn given_short_hmac_jwk_when_validating_key_policy_then_rejects() {
    let error = KeyPolicy::new(&hmac_jwk(31), SignatureAlgorithm::HS256, true)
        .validate()
        .expect_err("HS256 JWKs must contain at least 256 bits");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
    KeyPolicy::new(&hmac_jwk(32), SignatureAlgorithm::HS256, true)
        .validate()
        .expect("a 256-bit HMAC JWK remains supported");
}

#[test]
fn given_oversized_rsa_modulus_when_validating_key_policy_then_rejects() {
    let error = KeyPolicy::new(&rsa_jwk(1025), SignatureAlgorithm::RS256, false)
        .validate()
        .expect_err("RSA modulus material above the supported profile must be rejected");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[test]
fn given_oversized_ec_coordinate_when_validating_key_policy_then_rejects() {
    let mut jwk = ec_jwk(EllipticCurve::P256);
    if let AlgorithmParameters::EllipticCurve(parameters) = &mut jwk.algorithm {
        parameters.x = URL_SAFE_NO_PAD.encode(vec![0x42; 49]);
    }
    let error = KeyPolicy::new(&jwk, SignatureAlgorithm::ES256, false)
        .validate()
        .expect_err("EC coordinates above the selected curve width must be rejected");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[test]
fn given_oversized_okp_coordinate_when_validating_key_policy_then_rejects() {
    let error = KeyPolicy::new(
        &okp_jwk_with_coordinate_len(EllipticCurve::Ed25519, 33),
        SignatureAlgorithm::EdDSA,
        false,
    )
    .validate()
    .expect_err("Ed25519 public keys must have exactly 32 bytes");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[test]
fn given_low_order_okp_key_when_validating_key_policy_then_rejects() {
    let mut point = [0_u8; 32];
    point[0] = 1;
    let jwk = okp_jwk_with_coordinate(URL_SAFE_NO_PAD.encode(point));
    let error = KeyPolicy::new(&jwk, SignatureAlgorithm::EdDSA, false)
        .validate()
        .expect_err("Ed25519 low-order public points must be rejected");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

#[test]
fn given_oversized_hmac_jwk_when_validating_key_policy_then_rejects() {
    let error = KeyPolicy::new(&hmac_jwk(65), SignatureAlgorithm::HS512, true)
        .validate()
        .expect_err("HMAC material above the supported profile must be rejected");

    assert_eq!(error.kind(), &JwtDecodeErrorKind::InvalidKey);
}

fn okp_jwk_with_coordinate_len(curve: EllipticCurve, bytes: usize) -> Jwk {
    okp_jwk_with_coordinate_for_curve(curve, URL_SAFE_NO_PAD.encode(vec![0x01; bytes]))
}

fn okp_jwk_with_coordinate(coordinate: String) -> Jwk {
    okp_jwk_with_coordinate_for_curve(EllipticCurve::Ed25519, coordinate)
}

fn okp_jwk_with_coordinate_for_curve(curve: EllipticCurve, coordinate: String) -> Jwk {
    Jwk {
        common: Default::default(),
        algorithm: AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve,
            x: coordinate,
        }),
    }
}
