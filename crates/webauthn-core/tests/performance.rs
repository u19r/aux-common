#![cfg(not(target_arch = "wasm32"))]

use std::hint::black_box;

use alloc_counter::AllocationGuard;
use ciborium::value::Value;
use p256::ecdsa::SigningKey;
use webauthn_core::parse_cose_key;

#[test]
fn performance_parse_cose_reports_valid_and_bounded_invalid_paths() {
    let signing_key = SigningKey::from_bytes((&[42_u8; 32]).into()).expect("signing key");
    let point = signing_key.verifying_key().to_sec1_point(false);
    let valid = cose_key(
        point.x().expect("x coordinate"),
        point.y().expect("y coordinate"),
    );
    let oversized = vec![0_u8; 1025];

    let valid_guard = AllocationGuard::start(
        module_path!(),
        "performance_parse_cose_reports_valid_and_bounded_invalid_paths",
        file!(),
        line!(),
        Some("valid_cose"),
    );
    let valid_result = black_box(parse_cose_key(&valid)).expect("valid COSE key");
    let valid_report = valid_guard.finish();
    alloc_counter::emit_report(&valid_report);

    let invalid_guard = AllocationGuard::start(
        module_path!(),
        "performance_parse_cose_reports_valid_and_bounded_invalid_paths",
        file!(),
        line!(),
        Some("oversized_cose"),
    );
    let invalid_result = black_box(parse_cose_key(&oversized));
    let invalid_report = invalid_guard.finish();
    alloc_counter::emit_report(&invalid_report);

    assert_eq!(valid_result.algorithm, -7);
    assert!(invalid_result.is_err());
}

fn cose_key(x: &[u8], y: &[u8]) -> Vec<u8> {
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
        (Value::Integer((-2_i64).into()), Value::Bytes(x.to_vec())),
        (Value::Integer((-3_i64).into()), Value::Bytes(y.to_vec())),
    ]);
    let mut output = Vec::new();
    ciborium::ser::into_writer(&value, &mut output).expect("encode COSE key");
    output
}
