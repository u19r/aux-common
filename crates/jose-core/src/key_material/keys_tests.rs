use aws_lc_rs::{
    encoding::AsDer,
    rand::SystemRandom,
    rsa::{KeyPair as RsaKeyPair, KeySize},
    signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
        RSA_PKCS1_SHA256, RSA_PKCS1_SHA384,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

use crate::{
    CompactJws, EmbeddedEs256Key, JoseError, JwsAlgorithm, PreparedVerifier, ProtectedHeader,
    PublicJwk, PublicJwks, PublicKeyComponents,
};

#[test]
fn given_rsa_2048_spki_when_preparing_rs256_then_signature_and_jwk_are_valid() {
    // Given a complete 2048-bit RSA SubjectPublicKeyInfo and a matching
    // signature.
    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA-2048 test key");
    let public_key = key_pair
        .public_key()
        .as_der()
        .expect("encode RSA public key")
        .as_ref()
        .to_vec();
    let message = b"jose-core-rs256";
    let mut signature = vec![0_u8; key_pair.public_modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            message,
            &mut signature,
        )
        .expect("sign RSA-256 test message");

    // When the key is prepared for RS256 and converted to a public JWK.
    let verifier = PreparedVerifier::try_new(JwsAlgorithm::Rs256, &public_key)
        .expect("prepare RS256 verifier");
    let jwk =
        PublicJwk::from_spki(JwsAlgorithm::Rs256, "rsa-2048", &public_key).expect("build RSA JWK");

    // Then verification succeeds and the JWK exposes only RSA members.
    assert_eq!(verifier.algorithm(), JwsAlgorithm::Rs256);
    verifier
        .verify(message, &signature)
        .expect("verify RSA-256 signature");
    assert_eq!(jwk.kty(), "RSA");
    assert_eq!(jwk.kid(), "rsa-2048");
    assert_eq!(jwk.use_(), "sig");
    assert_eq!(jwk.alg(), "RS256");
    assert!(jwk.n().is_some());
    assert!(jwk.e().is_some());
    assert_eq!(jwk.crv(), None);
    assert_eq!(jwk.x(), None);
    assert_eq!(jwk.y(), None);
    assert_eq!(
        format!("{verifier:?}"),
        "PreparedVerifier { algorithm: Rs256, .. }"
    );
}

#[test]
fn given_deterministic_components_when_serializing_jwk_set_then_json_and_decoded_members_match() {
    // Given deterministic RSA and P-256 public components.
    let modulus = vec![0xff; 256];
    let exponent = vec![1, 0, 1];
    let x = vec![
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ];
    let y = vec![
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ];
    let rsa = PublicJwk::from_components(
        JwsAlgorithm::Rs256,
        "rsa-fixture",
        PublicKeyComponents::Rsa {
            modulus: modulus.clone(),
            exponent: exponent.clone(),
        },
    )
    .expect("build deterministic RSA JWK");
    let ec = PublicJwk::from_components(
        JwsAlgorithm::Es256,
        "ec-fixture",
        PublicKeyComponents::Ec {
            curve: "P-256",
            x: x.clone(),
            y: y.clone(),
        },
    )
    .expect("build deterministic EC JWK");

    // When the public keys and sorted set are serialized.
    let rsa_json = serde_json::to_string(&rsa).expect("serialize RSA JWK");
    let ec_json = serde_json::to_string(&ec).expect("serialize EC JWK");
    let jwks_json = serde_json::to_string(
        &PublicJwks::try_new(vec![rsa.clone(), ec.clone()]).expect("build deterministic JWKS"),
    )
    .expect("serialize JWKS");

    // Then wire shape is exact and each encoded component decodes to its
    // fixture bytes.
    assert_eq!(
        rsa_json,
        concat!(
            r#"{"kty":"RSA","kid":"rsa-fixture","use":"sig","alg":"RS256","n":""#,
            "_____________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________w",
            r#"","e":"AQAB"}"#
        )
    );
    assert_eq!(
        ec_json,
        r#"{"kty":"EC","kid":"ec-fixture","use":"sig","alg":"ES256","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}"#
    );
    assert_eq!(jwks_json, format!(r#"{{"keys":[{ec_json},{rsa_json}]}}"#));
    let rsa_value: serde_json::Value = serde_json::from_str(&rsa_json).expect("decode RSA JSON");
    let ec_value: serde_json::Value = serde_json::from_str(&ec_json).expect("decode EC JSON");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(rsa_value["n"].as_str().expect("RSA modulus"))
            .expect("decode RSA modulus"),
        modulus
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(rsa_value["e"].as_str().expect("RSA exponent"))
            .expect("decode RSA exponent"),
        exponent
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(ec_value["x"].as_str().expect("EC x"))
            .expect("decode EC x"),
        x
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(ec_value["y"].as_str().expect("EC y"))
            .expect("decode EC y"),
        y
    );
}

#[test]
fn given_rsa_3072_spki_when_preparing_rs384_then_signature_and_jwk_are_valid() {
    // Given a complete 3072-bit RSA SubjectPublicKeyInfo and a SHA-384
    // signature.
    let key_pair = RsaKeyPair::generate(KeySize::Rsa3072).expect("generate RSA-3072 test key");
    let public_key = key_pair
        .public_key()
        .as_der()
        .expect("encode RSA public key")
        .as_ref()
        .to_vec();
    let message = b"jose-core-rs384";
    let mut signature = vec![0_u8; key_pair.public_modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA384,
            &SystemRandom::new(),
            message,
            &mut signature,
        )
        .expect("sign RSA-384 test message");

    // When the key is prepared for RS384 and converted to a public JWK.
    let verifier = PreparedVerifier::try_new(JwsAlgorithm::Rs384, &public_key)
        .expect("prepare RS384 verifier");
    let jwk =
        PublicJwk::from_spki(JwsAlgorithm::Rs384, "rsa-3072", &public_key).expect("build RSA JWK");

    // Then the SHA-384 verifier accepts the matching signature and preserves
    // the algorithm.
    assert_eq!(verifier.algorithm(), JwsAlgorithm::Rs384);
    verifier
        .verify(message, &signature)
        .expect("verify RSA-384 signature");
    assert_eq!(jwk.alg(), "RS384");
    assert_eq!(jwk.kty(), "RSA");
    assert!(jwk.n().is_some());
    assert!(jwk.e().is_some());
}

#[test]
fn given_ecdsa_spkis_when_preparing_verifiers_then_es256_and_es384_verify() {
    // Given valid P-256 and P-384 SPKIs with fixed-format ECDSA signatures.
    let p256_pair =
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("generate P-256 test key");
    let p256_public_key = p256_pair
        .public_key()
        .as_der()
        .expect("encode P-256 public key")
        .as_ref()
        .to_vec();
    let p384_pair =
        EcdsaKeyPair::generate(&ECDSA_P384_SHA384_FIXED_SIGNING).expect("generate P-384 test key");
    let p384_public_key = p384_pair
        .public_key()
        .as_der()
        .expect("encode P-384 public key")
        .as_ref()
        .to_vec();
    let p256_message = b"jose-core-es256";
    let p384_message = b"jose-core-es384";
    let p256_signature = p256_pair
        .sign(&SystemRandom::new(), p256_message)
        .expect("sign P-256 test message");
    let p384_signature = p384_pair
        .sign(&SystemRandom::new(), p384_message)
        .expect("sign P-384 test message");

    // When each SPKI is prepared for its matching JWS algorithm.
    let p256_verifier = PreparedVerifier::try_new(JwsAlgorithm::Es256, &p256_public_key)
        .expect("prepare ES256 verifier");
    let p384_verifier = PreparedVerifier::try_new(JwsAlgorithm::Es384, &p384_public_key)
        .expect("prepare ES384 verifier");
    let p256_jwk = PublicJwk::from_spki(JwsAlgorithm::Es256, "p256", &p256_public_key)
        .expect("build P-256 JWK");
    let p384_jwk = PublicJwk::from_spki(JwsAlgorithm::Es384, "p384", &p384_public_key)
        .expect("build P-384 JWK");

    // Then both curves verify and expose their curve-specific coordinates.
    assert_eq!(p256_verifier.algorithm(), JwsAlgorithm::Es256);
    assert_eq!(p384_verifier.algorithm(), JwsAlgorithm::Es384);
    p256_verifier
        .verify(p256_message, p256_signature.as_ref())
        .expect("verify P-256 signature");
    p384_verifier
        .verify(p384_message, p384_signature.as_ref())
        .expect("verify P-384 signature");
    assert_eq!(p256_jwk.kty(), "EC");
    assert_eq!(p256_jwk.crv(), Some("P-256"));
    assert_eq!(p256_jwk.alg(), "ES256");
    assert!(p256_jwk.x().is_some() && p256_jwk.y().is_some());
    assert_eq!(p384_jwk.kty(), "EC");
    assert_eq!(p384_jwk.crv(), Some("P-384"));
    assert_eq!(p384_jwk.alg(), "ES384");
    assert!(p384_jwk.x().is_some() && p384_jwk.y().is_some());
    assert_eq!(p384_jwk.n(), None);
    assert_eq!(p384_jwk.e(), None);
}

#[test]
fn given_invalid_components_when_building_jwk_then_reject_without_cross_algorithm_coercion() {
    // Given RSA components that are valid only for the 2048-bit profile.
    let modulus = vec![0xff; 256];
    let exponent = vec![1, 0, 1];
    let mut invalid_point = vec![0_u8; 32];
    invalid_point[0] = 2;

    // When components are empty, malformed, or paired with another algorithm.
    assert_eq!(
        PublicJwk::from_components(
            JwsAlgorithm::Rs256,
            "",
            PublicKeyComponents::Rsa {
                modulus: modulus.clone(),
                exponent: exponent.clone(),
            },
        ),
        Err(JoseError::EmptyKeyId)
    );
    assert_eq!(
        PublicJwk::from_components(
            JwsAlgorithm::Rs256,
            "even-exponent",
            PublicKeyComponents::Rsa {
                modulus: modulus.clone(),
                exponent: vec![2],
            },
        ),
        Err(JoseError::InvalidJwk)
    );
    assert_eq!(
        PublicJwk::from_components(
            JwsAlgorithm::Rs256,
            "oversized-modulus",
            PublicKeyComponents::Rsa {
                modulus: vec![0xff; 258],
                exponent: exponent.clone(),
            },
        ),
        Err(JoseError::InvalidJwk)
    );
    assert_eq!(
        PublicJwk::from_components(
            JwsAlgorithm::Rs256,
            "wrong-shape",
            PublicKeyComponents::Ec {
                curve: "P-256",
                x: vec![1; 32],
                y: vec![2; 32],
            },
        ),
        Err(JoseError::InvalidJwk)
    );
    assert_eq!(
        PublicJwk::from_components(
            JwsAlgorithm::EdDsa,
            "invalid-point",
            PublicKeyComponents::Ed25519 { x: invalid_point },
        ),
        Err(JoseError::InvalidJwk)
    );

    // Then malformed material cannot be coerced into a JWK for another
    // algorithm.
    assert_eq!(
        PublicJwk::from_components(
            JwsAlgorithm::Es384,
            "wrong-curve",
            PublicKeyComponents::Ec {
                curve: "P-256",
                x: vec![1; 32],
                y: vec![2; 32],
            },
        ),
        Err(JoseError::InvalidJwk)
    );
}

#[test]
fn given_duplicate_key_ids_when_building_jwks_then_reject_collision_after_sorting() {
    // Given two valid public JWKs with the same key identifier.
    let modulus = vec![0xff; 256];
    let jwk = PublicJwk::from_components(
        JwsAlgorithm::Rs256,
        "duplicate",
        PublicKeyComponents::Rsa {
            modulus,
            exponent: vec![1, 0, 1],
        },
    )
    .expect("build duplicate-test JWK");

    // When both entries are assembled into a JWKS.
    let result = PublicJwks::try_new(vec![jwk.clone(), jwk]);

    // Then the duplicate identifier is rejected instead of silently selecting
    // one key.
    assert_eq!(result, Err(JoseError::InvalidJwk));
}

#[test]
fn given_malformed_spki_when_preparing_verifier_then_reject_empty_oversized_and_trailing_bytes() {
    // Given key byte strings that violate the bounded, complete-DER contract.
    let oversized = vec![0_u8; 8 * 1024 + 1];
    let mut trailing = ed25519_spki([0; 32]);
    trailing.push(0);

    // When each malformed input is offered to the verifier.
    let empty = PreparedVerifier::try_new(JwsAlgorithm::EdDsa, &[]);
    let too_large = PreparedVerifier::try_new(JwsAlgorithm::EdDsa, &oversized);
    let with_trailing = PreparedVerifier::try_new(JwsAlgorithm::EdDsa, &trailing);

    // Then all forms are rejected before a verifier can be constructed.
    assert!(matches!(empty, Err(JoseError::InvalidPublicKey)));
    assert!(matches!(too_large, Err(JoseError::InvalidPublicKey)));
    assert!(matches!(with_trailing, Err(JoseError::InvalidPublicKey)));
}

#[test]
fn given_ed25519_verifier_when_signature_r_is_not_a_strict_point_then_reject() {
    // Given a valid Ed25519 verifier and a forged signature with a
    // non-canonical R point.
    let key_pair =
        aws_lc_rs::signature::Ed25519KeyPair::generate().expect("generate Ed25519 test key");
    let public_key = key_pair
        .public_key()
        .as_der()
        .expect("encode Ed25519 public key")
        .as_ref()
        .to_vec();
    let verifier = PreparedVerifier::try_new(JwsAlgorithm::EdDsa, &public_key)
        .expect("prepare EdDSA verifier");
    let mut signature = [0_u8; 64];
    signature[0] = 0xff;

    // When the signature is verified.
    let result = verifier.verify(b"forged", &signature);

    // Then strict point validation rejects it before generic verification.
    assert_eq!(result, Err(JoseError::InvalidSignature));
}

fn ed25519_spki(point: [u8; 32]) -> Vec<u8> {
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(&point);
    spki
}

#[test]
fn given_invalid_public_key_when_preparing_verifier_then_reject() {
    assert!(PreparedVerifier::try_new(JwsAlgorithm::EdDsa, &[0; 31]).is_err());
    assert!(CompactJws::decode("one.two").is_err());
}

#[test]
fn given_ed25519_spki_when_preparing_then_algorithm_and_der_shape_are_bound() {
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate().expect("generate key");
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
    let key_pair = aws_lc_rs::signature::Ed25519KeyPair::generate().expect("generate key");
    let public_key = key_pair.public_key().as_der().expect("encode public key");
    let verifier = PreparedVerifier::try_new(JwsAlgorithm::EdDsa, public_key.as_ref())
        .expect("prepare Ed25519 verifier");
    let mut signature = [0_u8; 64];
    signature[0] = 1;
    assert!(verifier.verify(b"forged", &signature).is_err());
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
                y: vec![2; 48],
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

#[test]
fn given_cross_family_key_material_when_preparing_verifier_then_reject() {
    // Given an RSA key presented for ECDSA and an ECDSA key presented for
    // RSA, the classic key-confusion shapes.
    let rsa_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA test key");
    let rsa_spki = rsa_pair
        .public_key()
        .as_der()
        .expect("encode RSA public key")
        .as_ref()
        .to_vec();
    let ec_pair =
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("generate P-256 test key");
    let ec_spki = ec_pair
        .public_key()
        .as_der()
        .expect("encode EC public key")
        .as_ref()
        .to_vec();

    // When each key crosses into the other family.
    // Then family binding fails before any signature is trusted.
    assert!(PreparedVerifier::try_new(JwsAlgorithm::Es256, &rsa_spki).is_err());
    assert!(PreparedVerifier::try_new(JwsAlgorithm::Rs256, &ec_spki).is_err());
    assert!(PublicJwk::from_spki(JwsAlgorithm::Es256, "confused", &rsa_spki).is_err());
    assert!(PublicJwk::from_spki(JwsAlgorithm::Rs256, "confused", &ec_spki).is_err());
}

#[test]
fn given_even_exponent_rsa_key_when_preparing_verifier_then_reject() {
    // Given a DER-valid RSA key whose public exponent is even, which no
    // RSA verification equation can use securely.
    let key_pair = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA test key");
    let mut spki = key_pair
        .public_key()
        .as_der()
        .expect("encode RSA public key")
        .as_ref()
        .to_vec();
    let last = spki.len() - 1;
    assert_eq!(spki[last], 0x01, "test key uses exponent 65537");
    spki[last] = 0x00;

    // When the even-exponent key reaches verifier preparation.
    // Then parity validation fails instead of trusting weak key material.
    assert!(PreparedVerifier::try_new(JwsAlgorithm::Rs256, &spki).is_err());
}

/// ECDSA P-256 signature malleability: the high-S (`n - s`) form of a
/// signature must produce identical verification outcomes to the low-S
/// form, because the verification boundary normalizes `s` to the lower
/// half of the group order before dispatching to the backend verifier.
///
/// Without normalization, the two byte-encodings of one logical signature
/// can produce distinct observable outcomes: replay dedupe, forensic
/// identification, and signature-hash rate limiting all see two different
/// inputs for what is cryptographically the same signature.
fn malleability_signing_key() -> SigningKey {
    SigningKey::from_slice(&[9u8; 32]).expect("test key")
}

fn malleability_spki(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_sec1_point(false);
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(point.x().unwrap());
    sec1.extend_from_slice(point.y().unwrap());
    let algorithm = [
        0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    ];
    let bit_string_len = sec1.len() + 1;
    let inner_len = algorithm.len() + 2 + bit_string_len;
    let mut spki = Vec::with_capacity(inner_len + 2);
    spki.push(0x30);
    spki.push(inner_len as u8);
    spki.extend_from_slice(&algorithm);
    spki.push(0x03);
    spki.push(bit_string_len as u8);
    spki.push(0x00);
    spki.extend_from_slice(&sec1);
    spki
}

fn flipped_s(signature: &Signature) -> Signature {
    use crate::constants::P256_ORDER;
    let mut bytes = signature.to_bytes();
    let s = &mut bytes[32..64];
    let mut borrow = 0u16;
    for index in (0..32).rev() {
        let value = u16::from(P256_ORDER[index]).checked_sub(u16::from(s[index]) + borrow);
        match value {
            Some(difference) => {
                s[index] = u8::try_from(difference).expect("in-range byte");
                borrow = 0;
            }
            None => {
                s[index] = u8::try_from(
                    u16::from(P256_ORDER[index]) + 0x100 - u16::from(s[index]) - borrow,
                )
                .expect("wrapped byte");
                borrow = 1;
            }
        }
    }
    Signature::from_slice(&bytes).expect("flipped signature")
}

fn malleability_seed_token(key: &SigningKey) -> String {
    let header = ProtectedHeader::new(JwsAlgorithm::Es256, "malleability-key", None::<String>)
        .expect("header");
    let prepared = CompactJws::prepare(&header, br#"{\"sub\":\"subject\"}"#).expect("prepare");
    let signature: Signature = key.sign(prepared.as_str().as_bytes());
    prepared.finish(&signature.to_bytes())
}

#[test]
fn given_high_s_and_low_s_forms_when_verified_then_outcomes_are_identical() {
    let key = malleability_signing_key();
    let token = malleability_seed_token(&key);

    let prepared =
        PreparedVerifier::try_new(JwsAlgorithm::Es256, &malleability_spki(&key)).expect("prepared");

    let (x, y) = {
        let point = key.verifying_key().to_sec1_point(false);
        (
            URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        )
    };
    let jwk = serde_json::json!({"kty":"EC","crv":"P-256","x":x,"y":y});
    let embedded = EmbeddedEs256Key::try_from(&jwk).expect("embedded key");

    let parts: Vec<&str> = token.split('.').collect();
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("signature decodes");
    let malleated = flipped_s(&Signature::from_slice(&signature_bytes).expect("signature"));
    let malleated_token = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(malleated.to_bytes())
    );

    let low_prepared = CompactJws::decode(&token)
        .expect("decode low-S")
        .verify(&prepared);
    let high_prepared = CompactJws::decode(&malleated_token)
        .expect("decode high-S")
        .verify(&prepared);
    assert_eq!(
        low_prepared.is_ok(),
        high_prepared.is_ok(),
        "PreparedVerifier outcomes differ between low-S and high-S forms"
    );
    assert!(low_prepared.is_ok(), "low-S form must verify");

    let low_signing_input = format!("{}.{}", parts[0], parts[1]);
    let low_sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("signature bytes");
    let low_embedded = embedded.verify(low_signing_input.as_bytes(), &low_sig_bytes);

    let high_parts: Vec<&str> = malleated_token.split('.').collect();
    let high_signing_input = format!("{}.{}", high_parts[0], high_parts[1]);
    let high_sig_bytes = URL_SAFE_NO_PAD
        .decode(high_parts[2])
        .expect("signature bytes");
    let high_embedded = embedded.verify(high_signing_input.as_bytes(), &high_sig_bytes);
    assert_eq!(
        low_embedded.is_ok(),
        high_embedded.is_ok(),
        "EmbeddedEs256Key outcomes differ between low-S and high-S forms"
    );
    assert!(low_embedded.is_ok(), "low-S form must verify on embedded");
}

#[test]
fn given_high_s_signature_when_normalized_then_produces_low_s_canonical_form() {
    use p256::ecdsa::signature::Signer as _;

    use crate::constants::{P256_HALF_ORDER, normalize_low_s};
    let key = malleability_signing_key();
    let signature: Signature = key.sign(b"normalization probe");
    let raw = signature.to_bytes();
    let malleated = flipped_s(&signature);

    let low_normalized = normalize_low_s(raw.as_slice()).expect("64 bytes");
    let high_normalized = normalize_low_s(malleated.to_bytes().as_slice()).expect("64 bytes");

    assert_eq!(
        low_normalized, high_normalized,
        "normalization must produce the same canonical bytes for both forms"
    );
    assert!(
        low_normalized[32..64] <= P256_HALF_ORDER[..],
        "normalized s must be in the lower half of the order"
    );
}

#[test]
fn given_low_s_signature_when_normalized_then_identity() {
    use p256::ecdsa::signature::Signer as _;

    use crate::constants::normalize_low_s;
    let key = malleability_signing_key();
    let signature: Signature = key.sign(b"identity probe");
    let raw = signature.to_bytes();
    // Skip keys whose signature happens to be high-S; the invariant under
    // test is identity for already-low-S inputs.
    if raw[32..64] > crate::constants::P256_HALF_ORDER[..] {
        return;
    }
    let normalized = normalize_low_s(raw.as_slice()).expect("64 bytes");
    assert_eq!(normalized[..], raw[..], "low-S input must be unchanged");
}
