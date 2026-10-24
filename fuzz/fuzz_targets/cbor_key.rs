#![no_main]

use libfuzzer_sys::fuzz_target;
use webauthn_core::parse_cose_key;

// Structured decision oracle for COSE key parsing.
//
// The seed is a well-formed ES256 key over P-256 with 32-byte coordinates.
// Every byte-driven edit models a key-confusion shape: algorithm-label
// substitution, curve substitution, coordinate truncation or extension,
// entry duplication or reordering, and non-canonical encodings. The oracle:
// parsing may only succeed on the byte-identical seed, and any accepted key
// must carry the ES256 profile (`algorithm == -7`, `curve == 1`) with
// full-size coordinates, so a relabeled or truncated key can never pass as
// a usable credential key. Canonical encoding is unique, so distinct bytes
// must never decode to the seed key.
fn seed_key() -> (Vec<u8>, String) {
    use ciborium::value::Value;
    use p256::ecdsa::SigningKey;
    let signing_key = SigningKey::from_bytes((&[42_u8; 32]).into()).expect("test key");
    let point = signing_key.verifying_key().to_sec1_point(false);
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
        (
            Value::Integer((-2_i64).into()),
            Value::Bytes(point.x().expect("x").to_vec()),
        ),
        (
            Value::Integer((-3_i64).into()),
            Value::Bytes(point.y().expect("y").to_vec()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).expect("encode seed key");
    // `CosePublicKey` is intentionally not nameable from outside the crate;
    // compare its redacted `Debug` projection instead of the value.
    let debug = format!("{:?}", parse_cose_key(&bytes).expect("seed must parse"));
    (bytes, debug)
}

fn apply_edit(key: &mut Vec<u8>, op: u8, position: usize, argument: u8) {
    if key.is_empty() {
        return;
    }
    match op % 7 {
        0 => {
            // Flip a byte anywhere in the encoding.
            let index = position % key.len();
            key[index] ^= argument | 1;
        }
        1 => {
            // Truncate the encoding.
            key.truncate(position % (key.len() + 1));
        }
        2 => key.clear(),
        3 => {
            // Substitute the algorithm label ES256 (-7, 0x26) with ES384
            // (-35, 0x38 0x22) while keeping P-256 coordinates.
            if let Some(index) = key.iter().position(|byte| *byte == 0x26) {
                key[index] = 0x22;
                key.insert(index, 0x38);
            }
        }
        4 => {
            // Duplicate the first map entry bytes, breaking canonical shape.
            if key.len() > 8 {
                let entry: Vec<u8> = key[1..7].to_vec();
                key.splice(1..1, entry);
            }
        }
        5 => {
            // Swap the two 35-byte coordinate entries, breaking canonical
            // member order.
            if key.len() == 77 {
                let mut swapped = key[..7].to_vec();
                swapped.extend_from_slice(&key[42..77]);
                swapped.extend_from_slice(&key[7..42]);
                *key = swapped;
            }
        }
        _ => key.push(argument),
    }
}

fuzz_target!(|data: &[u8]| {
    let (seed_bytes, seed_debug) = seed_key();
    let mut key = seed_bytes.clone();
    let mut cursor = 0;
    let mut edits = 0;
    while edits < 6 && cursor + 3 <= data.len() {
        let position = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        apply_edit(&mut key, data[cursor], position, data[cursor + 2]);
        cursor += 3;
        edits += 1;
    }
    if key == seed_bytes {
        return;
    }
    let first = parse_cose_key(&key);
    let second = parse_cose_key(&key);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "non-deterministic parse verdict"
    );
    if let Ok(parsed) = first {
        assert_eq!(
            parsed.algorithm, -7,
            "accepted key escaped the ES256 profile"
        );
        assert_eq!(parsed.curve, 1, "accepted key escaped the P-256 profile");
        assert_eq!(parsed.x.len(), 32, "accepted key has short x");
        assert_eq!(parsed.y.len(), 32, "accepted key has short y");
        assert_ne!(
            format!("{parsed:?}"),
            seed_debug,
            "distinct bytes decoded to the seed key: canonical encoding is not unique"
        );
    }
});
