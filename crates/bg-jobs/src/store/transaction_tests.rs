use std::num::{NonZeroU32, NonZeroUsize};

use bytes::Bytes;

use super::{
    Check, Mutation, StoreKey, StoreTransaction, StoreTransactionInput, TransactionLimits,
};
use crate::{CommitOperationId, error::StoreContractError};

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
