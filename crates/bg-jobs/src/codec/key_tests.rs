//! Key codec behavior and persisted-byte tests.

use crate::{
    codec::{KeyCodec, KeyTag},
    error::StoreDataError,
    ids::{JobId, Namespace, QueueName},
    store::StoreKey,
};

fn namespace() -> Namespace {
    Namespace::try_new(b"jobs").expect("test namespace is non-empty")
}

const KEY_COMPONENTS: [&[u8]; 2] = [b"job", b"42"];
// Hand-maintained v1 key bytes: version, namespace, tag, then length-delimited
// components.
const KEY_VECTORS: &[(KeyTag, &str)] = &[
    (
        KeyTag::Job,
        "01000000046a6f62734a000000036a6f62000000023432",
    ),
    (
        KeyTag::PayloadChunk,
        "01000000046a6f627350000000036a6f62000000023432",
    ),
    (
        KeyTag::Due,
        "01000000046a6f627344000000036a6f62000000023432",
    ),
    (
        KeyTag::FairReady,
        "01000000046a6f627346000000036a6f62000000023432",
    ),
    (
        KeyTag::Lease,
        "01000000046a6f62734c000000036a6f62000000023432",
    ),
    (
        KeyTag::DeadLetter,
        "01000000046a6f627358000000036a6f62000000023432",
    ),
    (
        KeyTag::Schedule,
        "01000000046a6f627353000000036a6f62000000023432",
    ),
    (
        KeyTag::Dedupe,
        "01000000046a6f627355000000036a6f62000000023432",
    ),
    (
        KeyTag::Wake,
        "01000000046a6f627357000000036a6f62000000023432",
    ),
    (
        KeyTag::Permit,
        "01000000046a6f627352000000036a6f62000000023432",
    ),
    (
        KeyTag::Operation,
        "01000000046a6f62734f000000036a6f62000000023432",
    ),
    (
        KeyTag::Cancellation,
        "01000000046a6f627343000000036a6f62000000023432",
    ),
];

fn hex_bytes(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex literal has odd length");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("hex digit")
        })
        .collect()
}

const ACTIVE_JOB_ID_BYTES: [u8; 16] = [0x11; 16];
const ACTIVE_OPERATION_KEY: &str = "01000000046a6f62734f0000001011111111111111111111111111111111";
const ACTIVE_CANCELLATION_KEY: &str =
    "01000000046a6f6273430000001011111111111111111111111111111111";

#[test]
fn given_hand_maintained_v1_key_vectors_when_decoding_then_framing_and_mutations_are_stable() {
    let namespace = namespace();
    let components = KEY_COMPONENTS
        .iter()
        .map(|component| component.to_vec())
        .collect::<Vec<_>>();
    for &(tag, literal) in KEY_VECTORS {
        let expected = hex_bytes(literal);
        let key = StoreKey::try_from(expected.as_slice()).expect("literal key is non-empty");
        let decoded = KeyCodec::decode(&namespace, &key).expect("literal key decodes");

        assert_eq!(decoded.tag, tag);
        assert_eq!(decoded.components, components);
        assert_eq!(
            KeyCodec::encode(&namespace, tag, &KEY_COMPONENTS)
                .expect("key re-encodes")
                .as_bytes(),
            expected.as_slice()
        );
    }

    let job_id = JobId::from(ACTIVE_JOB_ID_BYTES);
    let operation = crate::keys::operation_key(&namespace, &job_id).expect("operation key");
    let cancellation =
        crate::keys::cancellation_key(&namespace, &job_id).expect("cancellation key");

    for (tag, key, literal) in [
        (KeyTag::Operation, operation, ACTIVE_OPERATION_KEY),
        (KeyTag::Cancellation, cancellation, ACTIVE_CANCELLATION_KEY),
    ] {
        let expected = hex_bytes(literal);
        let decoded = KeyCodec::decode(&namespace, &key).expect("active key decodes");
        assert_eq!(decoded.tag, tag);
        assert_eq!(decoded.components, vec![job_id.as_bytes().to_vec()]);
        assert_eq!(key.as_bytes(), expected.as_slice());
        assert_eq!(
            KeyCodec::encode(&namespace, tag, &[job_id.as_bytes()])
                .expect("active key re-encodes")
                .as_bytes(),
            expected.as_slice()
        );
    }

    let literal = hex_bytes(KEY_VECTORS[0].1);
    let assert_error = |mut bytes: Vec<u8>, offset: usize, replacement: &[u8], expected| {
        bytes[offset..offset + replacement.len()].copy_from_slice(replacement);
        assert_eq!(
            KeyCodec::decode(
                &namespace,
                &StoreKey::try_from(bytes).expect("key remains non-empty")
            ),
            Err(expected)
        );
    };

    assert_error(
        literal.clone(),
        0,
        &[0x7f],
        StoreDataError::UnknownVersion(0x7f),
    );
    assert_error(literal.clone(), 9, b"?", StoreDataError::UnknownTag(b'?'));
    assert_error(
        literal.clone(),
        10,
        &u32::MAX.to_be_bytes(),
        StoreDataError::Truncated,
    );
    assert_eq!(
        KeyCodec::decode(
            &namespace,
            &StoreKey::try_from(&literal[..literal.len() - 1]).expect("key remains non-empty")
        ),
        Err(StoreDataError::Truncated)
    );
}

#[test]
fn given_a_key_prefix_when_calculating_its_end_then_all_prefixed_keys_are_before_the_end() {
    let namespace = namespace();
    let prefix = KeyCodec::encode(&namespace, KeyTag::PayloadChunk, &[]).expect("prefix is valid");
    let child_components: [&[u8]; 2] = [b"payload", &[0xff]];
    let child = KeyCodec::encode(&namespace, KeyTag::PayloadChunk, &child_components)
        .expect("child is valid");
    let end = KeyCodec::prefix_end(&prefix).expect("prefix has an end");

    assert!(prefix < child);
    assert!(child < end);
    assert!(
        KeyCodec::prefix_end(&StoreKey::try_from(&[u8::MAX][..]).expect("key is non-empty"))
            .is_none()
    );
}

#[test]
fn given_component_boundaries_when_encoding_keys_then_component_concatenation_cannot_collide() {
    let namespace = namespace();
    let first_components: [&[u8]; 2] = [b"a", b"bc"];
    let first =
        KeyCodec::encode(&namespace, KeyTag::Job, &first_components).expect("first tuple is valid");
    let second_components: [&[u8]; 2] = [b"ab", b"c"];
    let second = KeyCodec::encode(&namespace, KeyTag::Job, &second_components)
        .expect("second tuple is valid");
    let empty =
        KeyCodec::encode(&namespace, KeyTag::Job, &[b"abc"]).expect("single component is valid");

    assert_ne!(first, second);
    assert_ne!(first, empty);
    assert_ne!(second, empty);
    assert_eq!(
        KeyCodec::decode(&namespace, &first)
            .expect("first decodes")
            .components,
        vec![b"a".to_vec(), b"bc".to_vec()]
    );
}

#[test]
fn given_a_queue_when_building_lease_authority_keys_then_the_queue_prefix_is_canonical() {
    let namespace = namespace();
    let queue = QueueName::try_new("mail").expect("queue is valid");
    let job_id = JobId::from([0x42; 16]);
    let key = crate::keys::lease_key(&namespace, &queue, &job_id).expect("lease key is valid");
    let prefix =
        crate::keys::lease_queue_prefix(&namespace, &queue).expect("lease queue prefix is valid");
    let end = KeyCodec::prefix_end(&prefix).expect("lease queue prefix has an end");

    assert!(key.as_bytes().starts_with(prefix.as_bytes()));
    assert!(prefix < key);
    assert!(key < end);
    assert_eq!(
        KeyCodec::decode(&namespace, &key)
            .expect("lease key decodes")
            .components,
        vec![
            queue.as_str().as_bytes().to_vec(),
            job_id.as_bytes().to_vec()
        ]
    );
    let old_shape = KeyCodec::encode(&namespace, KeyTag::Lease, &[job_id.as_bytes()])
        .expect("legacy-shaped key still encodes for comparison");
    assert_ne!(key, old_shape);
}

#[test]
fn given_a_key_with_another_namespace_when_decoding_then_the_prefix_is_rejected() {
    let jobs = namespace();
    let other = Namespace::try_new(b"other").expect("other namespace is valid");
    let key = KeyCodec::encode(&jobs, KeyTag::Job, &[b"id"]).expect("key is valid");

    assert!(matches!(
        KeyCodec::decode(&other, &key),
        Err(StoreDataError::Malformed("key prefix"))
    ));
}

#[test]
fn given_raw_namespace_and_tag_boundaries_when_encoding_different_namespaces_then_keys_are_disjoint()
 {
    let short = Namespace::try_new(b"a").expect("short namespace is valid");
    let colliding = Namespace::try_new([b'a', 0x01, b'J', 0, 0, 0])
        .expect("namespace containing raw key bytes is valid");
    let first = KeyCodec::encode(&short, KeyTag::Job, &[b"P"]).expect("first key is valid");
    let second =
        KeyCodec::encode(&colliding, KeyTag::PayloadChunk, &[]).expect("second key is valid");

    assert_ne!(
        first, second,
        "namespace/tag bytes must not alias a persisted key"
    );
    assert!(!first.as_bytes().starts_with(second.as_bytes()));
    assert!(!second.as_bytes().starts_with(first.as_bytes()));

    let prefix_namespace = Namespace::try_new(b"a").expect("prefix namespace is valid");
    let child_namespace = Namespace::try_new([b'a', 0x01, b'J'])
        .expect("child namespace containing raw key bytes is valid");
    let prefix =
        KeyCodec::encode(&prefix_namespace, KeyTag::Job, &[]).expect("prefix key is valid");
    let child =
        KeyCodec::encode(&child_namespace, KeyTag::PayloadChunk, &[]).expect("child key is valid");

    assert!(!prefix.as_bytes().starts_with(child.as_bytes()));
    assert!(!child.as_bytes().starts_with(prefix.as_bytes()));
}
