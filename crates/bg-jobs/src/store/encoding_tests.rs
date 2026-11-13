use std::num::{NonZeroU32, NonZeroUsize};

use bytes::Bytes;

use super::{
    Check, CommitOperationId, EffectReceiptGroup, Mutation, StoreCapabilities,
    StoreCapabilitiesInput, StoreKey, StoreLevel, StoreTransaction, StoreTransactionInput,
    TransactionLimits,
};
use crate::{
    error::StoreDataError,
    ids::{ExecutionId, JobId, Namespace},
    test_helper::FakeStore,
};

fn transaction(payload: Bytes) -> StoreTransaction {
    let capabilities = FakeStore::new().capabilities();
    let key = |value: &'static [u8]| StoreKey::try_from(value).unwrap();
    StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([9; 16]),
        checks: vec![
            Check::Absent(key(b"absent")),
            Check::Value(key(b"checked"), Bytes::from_static(b"\0old\xff")),
        ],
        mutations: vec![
            Mutation::Put(key(b"put"), payload),
            Mutation::Delete(key(b"delete")),
        ],
        limits: TransactionLimits {
            max_checks: capabilities.max_transaction_keys(),
            max_mutations: capabilities.max_transaction_keys(),
            max_bytes: capabilities.max_transaction_bytes(),
        },
    })
    .unwrap()
}

#[test]
fn given_all_input_tags_and_binary_values_when_encoded_and_decoded_then_exact_command_content_survives()
 {
    let original = transaction(Bytes::from_static(b"\0new\xfe"));
    let decoded =
        StoreTransaction::decode_intent(&original.encode_intent(), FakeStore::new().capabilities())
            .unwrap();
    assert_eq!(decoded.operation_id(), original.operation_id());
    assert_eq!(decoded.checks(), original.checks());
    assert_eq!(decoded.mutations(), original.mutations());
    assert_eq!(decoded.binding(), original.binding());
}

#[test]
fn given_corrupt_or_truncated_recovery_input_when_decoded_then_it_is_rejected_before_application() {
    let encoded = transaction(Bytes::from_static(b"value")).encode_intent();
    let capabilities = FakeStore::new().capabilities();
    for end in 0..encoded.len() {
        assert!(StoreTransaction::decode_intent(&encoded[..end], capabilities).is_err());
    }
    for (offset, value) in [(16, 0xff), (17, 0xff), (21, 0xff), (22, 0xff)] {
        let mut changed = encoded.to_vec();
        changed[offset] = value;
        assert!(StoreTransaction::decode_intent(&changed, capabilities).is_err());
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(StoreTransaction::decode_intent(&trailing, capabilities).is_err());
}

#[test]
fn given_a_large_payload_when_recovery_input_is_encoded_then_one_payload_buffer_is_allocated() {
    let original = transaction(Bytes::from(vec![42; 512 * 1024]));
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "intent_buffer",
        file!(),
        line!(),
        None,
    );
    let encoded = std::hint::black_box(original.encode_intent());
    let report = guard.finish();
    assert!(
        report.allocated_bytes <= encoded.len() as u64 + 128,
        "encoding allocated {} bytes for {} bytes of recovery input",
        report.allocated_bytes,
        encoded.len()
    );
}

fn clear_group() -> EffectReceiptGroup {
    EffectReceiptGroup::new(
        &Namespace::try_new(b"ns").unwrap(),
        JobId::from([1; 16]),
        ExecutionId::from([2; 16]),
    )
    .unwrap()
}

fn clear_transaction() -> StoreTransaction {
    let capabilities = FakeStore::new().capabilities();
    let put_key = StoreKey::try_from(&b"put"[..]).unwrap();
    StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([9; 16]),
        checks: Vec::new(),
        mutations: vec![
            Mutation::Put(put_key, Bytes::from_static(b"v")),
            Mutation::ClearEffectReceipts(clear_group()),
        ],
        limits: TransactionLimits {
            max_checks: capabilities.max_transaction_keys(),
            max_mutations: capabilities.max_transaction_keys(),
            max_bytes: capabilities.max_transaction_bytes(),
        },
    })
    .unwrap()
}

fn capabilities_without_groups() -> StoreCapabilities {
    StoreCapabilities::try_from(StoreCapabilitiesInput {
        level: StoreLevel::Local,
        max_key_bytes: NonZeroUsize::new(1_024).unwrap(),
        max_value_bytes: NonZeroUsize::new(1_024).unwrap(),
        max_get_many_keys: NonZeroU32::new(16).unwrap(),
        max_get_many_key_bytes: NonZeroUsize::new(4_096).unwrap(),
        max_transaction_bytes: NonZeroUsize::new(4_096).unwrap(),
        max_transaction_keys: NonZeroU32::new(16).unwrap(),
        max_range_items: NonZeroU32::new(16).unwrap(),
        max_range_bytes: NonZeroUsize::new(4_096).unwrap(),
        max_transaction_duration: std::time::Duration::from_secs(5),
    })
    .unwrap()
}

/// Offset of the clear mutation's tag byte: the clear is the last entry and
/// encodes as tag, namespace length, namespace, job id, and execution id.
fn clear_tag_offset(encoded: &[u8]) -> usize {
    encoded.len() - (1 + 4 + b"ns".len() + 16 + 16)
}

#[test]
fn given_clear_when_encoding_intent_then_decoding_returns_the_same_transaction() {
    let original = clear_transaction();
    let decoded =
        StoreTransaction::decode_intent(&original.encode_intent(), FakeStore::new().capabilities())
            .unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn given_clear_intent_when_capabilities_lack_groups_then_decoding_is_malformed() {
    let encoded = clear_transaction().encode_intent();
    assert_eq!(
        StoreTransaction::decode_intent(&encoded, capabilities_without_groups()),
        Err(StoreDataError::Malformed("commit intent capacity"))
    );
}

#[test]
fn given_mutation_tag_five_when_decoding_intent_then_tag_is_malformed() {
    let mut changed = clear_transaction().encode_intent().to_vec();
    let offset = clear_tag_offset(&changed);
    assert_eq!(changed[offset], 4);
    changed[offset] = 5;
    assert_eq!(
        StoreTransaction::decode_intent(&changed, FakeStore::new().capabilities()),
        Err(StoreDataError::Malformed("commit intent mutation tag"))
    );
}
