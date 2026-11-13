use std::num::{NonZeroU32, NonZeroUsize};

use bytes::Bytes;

use super::{
    Check, EffectReceiptGroup, EffectReceiptKind, Mutation, StoreCapabilities,
    StoreCapabilitiesInput, StoreKey, StoreLevel, StoreTransaction, StoreTransactionInput,
    TransactionLimits,
};
use crate::{
    CommitOperationId,
    error::{StoreContractError, ValidationError},
    ids::{ExecutionId, JobId, Namespace},
};

fn key(value: &'static [u8]) -> StoreKey {
    StoreKey::try_from(value).expect("fixture key is valid")
}

fn transaction(
    checks: Vec<Check>,
    mutations: Vec<Mutation>,
) -> Result<StoreTransaction, StoreContractError> {
    StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([1; 16]),
        checks,
        mutations,
        limits: TransactionLimits {
            max_checks: NonZeroU32::new(4).expect("check limit is non-zero"),
            max_mutations: NonZeroU32::new(4).expect("mutation limit is non-zero"),
            max_bytes: NonZeroUsize::new(1_024).expect("byte limit is non-zero"),
        },
    })
}

#[test]
fn given_duplicate_checks_or_mutations_when_constructing_a_transaction_then_they_are_rejected() {
    let duplicate_check = key(b"check");
    let check_error = transaction(
        vec![
            Check::Absent(duplicate_check.clone()),
            Check::Value(duplicate_check, Bytes::from_static(b"old")),
        ],
        Vec::new(),
    )
    .expect_err("a key has one authoritative precondition");
    assert!(matches!(
        check_error,
        StoreContractError::DuplicateTransactionKey("checks")
    ));

    let duplicate_mutation = key(b"mutation");
    let mutation_error = transaction(
        Vec::new(),
        vec![
            Mutation::Put(duplicate_mutation.clone(), Bytes::from_static(b"new")),
            Mutation::Delete(duplicate_mutation),
        ],
    )
    .expect_err("a key has one final mutation");
    assert!(matches!(
        mutation_error,
        StoreContractError::DuplicateTransactionKey("mutations")
    ));
}

#[test]
fn given_one_check_and_one_mutation_for_the_same_key_when_constructing_then_cas_is_valid() {
    let key = key(b"cas");
    let transaction = transaction(
        vec![Check::Value(key.clone(), Bytes::from_static(b"old"))],
        vec![Mutation::Put(key, Bytes::from_static(b"new"))],
    )
    .expect("one check plus one mutation is an intentional compare-and-swap");

    assert_eq!(transaction.checks().len(), 1);
    assert_eq!(transaction.mutations().len(), 1);
}

fn group(execution: u8) -> EffectReceiptGroup {
    EffectReceiptGroup::new(
        &Namespace::try_new(b"ns").expect("test namespace is valid"),
        JobId::from([1; 16]),
        ExecutionId::from([execution; 16]),
    )
    .expect("test group is valid")
}

#[test]
fn given_clear_and_put_inside_its_group_when_validating_then_transaction_is_rejected() {
    let group = group(2);
    let member = group
        .member_key(EffectReceiptKind::Effect, &[1; 32])
        .unwrap();
    let error = transaction(
        Vec::new(),
        vec![
            Mutation::ClearEffectReceipts(group),
            Mutation::Put(member, Bytes::from_static(b"x")),
        ],
    )
    .expect_err("a clear and a write in one group are contradictory");
    assert!(matches!(
        error,
        StoreContractError::Validation(ValidationError::InvalidValue {
            field: "effect receipt clear overlaps a mutation"
        })
    ));
}

#[test]
fn given_clear_and_put_outside_its_group_when_validating_then_transaction_is_accepted() {
    let other_member = group(3)
        .member_key(EffectReceiptKind::Effect, &[1; 32])
        .unwrap();
    transaction(
        Vec::new(),
        vec![
            Mutation::ClearEffectReceipts(group(2)),
            Mutation::Put(other_member, Bytes::from_static(b"x")),
        ],
    )
    .expect("another execution's group does not overlap");
}

#[test]
fn given_two_clears_of_one_group_when_validating_then_duplicate_key_is_rejected() {
    let error = transaction(
        Vec::new(),
        vec![
            Mutation::ClearEffectReceipts(group(2)),
            Mutation::ClearEffectReceipts(group(2)),
        ],
    )
    .expect_err("one group is cleared once");
    assert!(matches!(
        error,
        StoreContractError::DuplicateTransactionKey("mutations")
    ));
}

#[test]
fn given_clear_when_measuring_then_it_counts_one_mutation_and_prefix_bytes() {
    let group = group(2);
    let prefix_bytes = group.prefix().as_bytes().len();
    let transaction = transaction(Vec::new(), vec![Mutation::ClearEffectReceipts(group)]).unwrap();
    assert_eq!(transaction.mutations().len(), 1);
    assert_eq!(transaction.encoded_bytes(), prefix_bytes);
}

#[test]
fn given_capabilities_without_effect_receipt_groups_when_validating_clear_then_capability_is_exceeded()
 {
    let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
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
    .unwrap();
    let transaction =
        transaction(Vec::new(), vec![Mutation::ClearEffectReceipts(group(2))]).unwrap();
    assert!(matches!(
        capabilities.validate_transaction(&transaction),
        Err(StoreContractError::CapabilityExceeded(
            "effect receipt groups"
        ))
    ));
    assert!(
        capabilities
            .with_effect_receipt_groups()
            .validate_transaction(&transaction)
            .is_ok()
    );
}
