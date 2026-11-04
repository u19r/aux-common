use bytes::Bytes;

use super::{
    Check, CommitOperationId, Mutation, StoreKey, StoreTransaction, StoreTransactionInput,
    TransactionLimits,
};
use crate::test_helper::FakeStore;

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
