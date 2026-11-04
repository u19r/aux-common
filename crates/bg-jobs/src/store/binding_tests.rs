use std::num::{NonZeroU32, NonZeroUsize};

use bytes::Bytes;

use super::{
    Check, CommitOperationId, Mutation, StoreKey, StoreTransaction, StoreTransactionInput,
    TransactionLimits,
};

fn input() -> StoreTransactionInput {
    StoreTransactionInput {
        operation_id: CommitOperationId::from([1; 16]),
        checks: vec![
            Check::Absent(key(b"absent")),
            Check::Value(key(b"checked"), Bytes::from_static(b"old")),
        ],
        mutations: vec![
            Mutation::Put(key(b"put"), Bytes::from_static(b"new")),
            Mutation::Delete(key(b"delete")),
        ],
        limits: TransactionLimits {
            max_checks: NonZeroU32::new(4).unwrap(),
            max_mutations: NonZeroU32::new(4).unwrap(),
            max_bytes: NonZeroUsize::new(1024).unwrap(),
        },
    }
}

fn key(bytes: &'static [u8]) -> StoreKey {
    StoreKey::try_from(bytes).unwrap()
}

fn binding(input: StoreTransactionInput) -> [u8; 32] {
    StoreTransaction::try_from(input).unwrap().binding()
}

#[test]
fn given_all_entry_tags_when_binding_then_the_independent_version_two_vector_matches() {
    // Vector computed independently from the documented byte grammar with
    // Python hashlib.sha256, rather than another Rust encoder.
    let actual: String = binding(input())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        actual,
        "9bb04f64bae3375778b934d48cf6e35d371ac2f5e9284e0692e3322bf798db0b"
    );
}

#[test]
fn given_changed_order_tags_keys_or_values_when_binding_then_the_binding_changes() {
    let original = input();
    let expected = binding(original.clone());
    let mut variants = Vec::new();
    let mut changed = original.clone();
    changed.checks.reverse();
    variants.push(changed);
    let mut changed = original.clone();
    changed.mutations.reverse();
    variants.push(changed);
    let mut changed = original.clone();
    changed.checks[0] = Check::Value(key(b"absent"), Bytes::new());
    variants.push(changed);
    let mut changed = original.clone();
    changed.checks[1] = Check::Value(key(b"checked"), Bytes::from_static(b"new"));
    variants.push(changed);
    let mut changed = original.clone();
    changed.mutations[0] = Mutation::Put(key(b"put"), Bytes::from_static(b"changed"));
    variants.push(changed);
    let mut changed = original;
    changed.mutations[1] = Mutation::Delete(key(b"other"));
    variants.push(changed);
    for variant in variants {
        assert_ne!(binding(variant), expected);
    }
}

#[test]
fn given_different_field_boundaries_when_binding_then_length_prefixes_disambiguate_them() {
    let mut first = input();
    first.mutations = vec![Mutation::Put(key(b"ab"), Bytes::from_static(b"c"))];
    let mut second = input();
    second.mutations = vec![Mutation::Put(key(b"a"), Bytes::from_static(b"bc"))];
    assert_ne!(binding(first), binding(second));
}

#[test]
fn given_different_ids_or_limits_when_binding_then_effect_identity_is_unchanged() {
    let original = input();
    let mut changed = original.clone();
    changed.operation_id = CommitOperationId::from([2; 16]);
    changed.limits.max_bytes = NonZeroUsize::new(2048).unwrap();
    changed.limits.max_checks = NonZeroU32::new(8).unwrap();
    assert_eq!(binding(original), binding(changed));
}

#[test]
fn given_a_large_payload_when_binding_then_hashing_allocates_no_memory() {
    let mut request = input();
    request.limits.max_bytes = NonZeroUsize::new(1024 * 1024).unwrap();
    request.mutations[0] = Mutation::Put(key(b"put"), Bytes::from(vec![42; 512 * 1024]));
    let transaction = StoreTransaction::try_from(request).unwrap();
    let guard = alloc_counter::AllocationGuard::start(
        module_path!(),
        "transaction_binding",
        file!(),
        line!(),
        None,
    );
    std::hint::black_box(transaction.binding());
    let report = guard.finish();
    assert_eq!(report.allocation_count, 0);
    assert_eq!(report.allocated_bytes, 0);
}
