use super::parse_cose_key;
use crate::{WebAuthnError, assertion::cose_key};

#[test]
fn given_trailing_cbor_when_parsing_cose_then_reject() {
    let mut input = vec![0xa4, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    input.extend_from_slice(&[0; 32]);
    input.push(0);
    assert!(matches!(
        parse_cose_key(&input),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_arbitrary_short_bytes_when_parsing_cose_then_never_panic() {
    for length in 0..=64 {
        let input = (0..length).map(|value| value as u8).collect::<Vec<_>>();
        let result = std::panic::catch_unwind(|| parse_cose_key(&input));

        assert!(result.is_ok(), "parser panicked for length {length}");
    }
}

#[test]
fn given_indefinite_cbor_container_when_parsing_cose_then_reject() {
    assert!(matches!(
        parse_cose_key(&[0x9f, 0xff]),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_truncated_cbor_length_when_parsing_cose_then_reject() {
    assert!(matches!(
        parse_cose_key(&[0x58]),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_noncanonical_integer_encoding_when_parsing_cose_then_reject() {
    // The map itself is canonical; label 1 is deliberately encoded with an
    // unnecessarily wide integer argument.
    let mut encoded = vec![
        0xa5, 0x18, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    encoded.extend_from_slice(&[1; 32]);
    encoded.push(0x22);
    encoded.push(0x58);
    encoded.push(0x20);
    encoded.extend_from_slice(&[2; 32]);

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_tagged_cose_value_when_parsing_then_reject() {
    let mut encoded = vec![
        0xd8, 0x18, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    encoded.extend_from_slice(&[1; 32]);
    encoded.extend_from_slice(&[0x22, 0x58, 0x20]);
    encoded.extend_from_slice(&[2; 32]);

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::UnsupportedCoseKey | WebAuthnError::Malformed)
    ));
}

#[test]
fn given_oversized_cose_input_when_parsing_then_reject_before_decode() {
    let input = vec![0_u8; crate::constants::MAX_COSE_KEY_BYTES + 1];

    assert!(matches!(
        parse_cose_key(&input),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_non_integer_or_unknown_cose_label_when_parsing_then_reject() {
    use ciborium::value::Value;

    for key in [Value::Text("kty".into()), Value::Integer(4_i64.into())] {
        let value = Value::Map(vec![
            (key, Value::Integer(2_i64.into())),
            (
                Value::Integer(3_i64.into()),
                Value::Integer((-7_i64).into()),
            ),
            (
                Value::Integer((-1_i64).into()),
                Value::Integer(1_i64.into()),
            ),
            (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
            (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).expect("encode unsupported COSE label");

        assert!(matches!(
            parse_cose_key(&encoded),
            Err(WebAuthnError::UnsupportedCoseKey | WebAuthnError::Malformed)
        ));
    }
}

#[test]
fn given_invalid_es256_profile_when_parsing_then_reject() {
    use ciborium::value::Value;

    for (kty, alg, curve) in [(3_i64, -7_i64, 1_i64), (2, -8, 1), (2, -7, 2)] {
        let value = Value::Map(vec![
            (Value::Integer(1_i64.into()), Value::Integer(kty.into())),
            (Value::Integer(3_i64.into()), Value::Integer(alg.into())),
            (
                Value::Integer((-1_i64).into()),
                Value::Integer(curve.into()),
            ),
            (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
            (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).expect("encode unsupported COSE profile");

        assert!(matches!(
            parse_cose_key(&encoded),
            Err(WebAuthnError::UnsupportedCoseKey)
        ));
    }
}

#[test]
fn given_off_curve_coordinates_when_parsing_then_reject() {
    let input = cose_key(&[0; 32], &[0; 32]);

    assert!(matches!(
        parse_cose_key(&input),
        Err(WebAuthnError::UnsupportedCoseKey)
    ));
}

#[test]
fn given_deeply_nested_cbor_tags_when_parsing_cose_then_reject() {
    let mut encoded = vec![0xc1; 20];
    encoded.push(0);

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_wrong_curve_or_coordinate_size_when_parsing_cose_then_reject() {
    let value = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x02, 0x21, 0x58, 0x20];
    assert!(parse_cose_key(&value).is_err());
}

#[test]
fn given_duplicate_cose_member_when_parsing_then_reject() {
    use ciborium::value::Value;

    let value = Value::Map(vec![
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
        (
            Value::Integer(3_i64.into()),
            Value::Integer((-7_i64).into()),
        ),
        (
            Value::Integer((-1_i64).into()),
            Value::Integer(1_i64.into()),
        ),
        (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
        (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode duplicate COSE key");

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_noncanonical_cose_member_order_when_parsing_then_reject() {
    use ciborium::value::Value;

    let value = Value::Map(vec![
        (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
        (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
        (
            Value::Integer((-1_i64).into()),
            Value::Integer(1_i64.into()),
        ),
        (
            Value::Integer(3_i64.into()),
            Value::Integer((-7_i64).into()),
        ),
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode noncanonical COSE key");

    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_ctap_major_type_order_when_validating_map_then_accept_and_reject_inverse() {
    use ciborium::value::Value;

    let canonical = vec![
        (Value::Integer(24_i64.into()), Value::Null),
        (Value::Text(String::new()), Value::Null),
    ];
    assert!(super::validate_canonical_map_order(&canonical).is_ok());

    let noncanonical = vec![
        (Value::Text(String::new()), Value::Null),
        (Value::Integer(24_i64.into()), Value::Null),
    ];
    assert!(matches!(
        super::validate_canonical_map_order(&noncanonical),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_oversized_unknown_cose_member_when_parsing_then_reject_before_decoding_it() {
    use ciborium::value::Value;

    let value = Value::Map(vec![
        (Value::Integer(1_i64.into()), Value::Integer(2_i64.into())),
        (
            Value::Integer(3_i64.into()),
            Value::Integer((-7_i64).into()),
        ),
        (
            Value::Integer((-1_i64).into()),
            Value::Integer(1_i64.into()),
        ),
        (Value::Integer((-2_i64).into()), Value::Bytes(vec![1; 32])),
        (Value::Integer((-3_i64).into()), Value::Bytes(vec![2; 32])),
        (Value::Integer(4_i64.into()), Value::Bytes(vec![0; 1024])),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded).expect("encode COSE key");
    assert!(matches!(
        parse_cose_key(&encoded),
        Err(WebAuthnError::Malformed)
    ));
}

#[test]
fn given_mutated_cose_key_when_parsing_then_key_confusion_oracle_holds() {
    // Given a well-formed seed key. This is the deterministic twin of the
    // `cbor_key` fuzz oracle: only the byte-identical seed may parse to the
    // seed key, and any accepted key keeps the ES256 profile.
    use p256::ecdsa::SigningKey;
    let signing_key = SigningKey::from_bytes((&[42_u8; 32]).into()).expect("test key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let seed = cose_key(
        point.x().expect("x").as_slice(),
        point.y().expect("y").as_slice(),
    );
    let seed_key = parse_cose_key(&seed).expect("seed parses");
    let mut relabeled = seed.clone();
    if let Some(index) = relabeled.iter().position(|byte| *byte == 0x26) {
        relabeled[index] = 0x22;
        relabeled.insert(index, 0x38);
    }
    let mut swapped = seed.clone();
    if swapped.len() == 77 {
        let mut reordered = swapped[..7].to_vec();
        reordered.extend_from_slice(&swapped[42..77]);
        reordered.extend_from_slice(&swapped[7..42]);
        swapped = reordered;
    }
    let mut duplicated = seed.clone();
    duplicated.splice(1..1, seed[1..7].iter().copied());
    let mut flipped = seed.clone();
    flipped[10] ^= 0x01;
    let mutated = [
        relabeled,
        swapped,
        duplicated,
        flipped,
        seed[..seed.len() / 2].to_vec(),
        Vec::new(),
    ];

    // When each mutated encoding reaches the parser.
    for candidate in mutated {
        if candidate == seed {
            continue;
        }
        // Then parsing either fails or keeps the ES256 profile on a key
        // that differs from the seed, never relabeling attacker bytes.
        match parse_cose_key(&candidate) {
            Err(_) => {}
            Ok(key) => {
                assert_eq!(key.algorithm, -7);
                assert_eq!(key.curve, 1);
                assert_ne!(key, seed_key, "distinct bytes decoded to the seed key");
            }
        }
    }
}
