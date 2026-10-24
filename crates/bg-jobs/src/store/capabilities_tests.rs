//! Store capability contract tests.

use std::{
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

use bytes::Bytes;

use crate::{
    CommitOperationId,
    error::{StoreContractError, ValidationError},
    store::{
        Check, Mutation, RangeDirection, RangeRequest, RangeRequestInput, StoreCapabilities,
        StoreCapabilitiesInput, StoreKey, StoreLevel, StoreTransaction, StoreTransactionInput,
        TransactionLimits,
    },
};

fn capabilities(level: StoreLevel) -> StoreCapabilities {
    StoreCapabilities::try_from(StoreCapabilitiesInput {
        level,
        max_key_bytes: NonZeroUsize::new(8).expect("key limit is non-zero"),
        max_value_bytes: NonZeroUsize::new(8).expect("value limit is non-zero"),
        max_get_many_keys: NonZeroU32::new(3).expect("get-many limit is non-zero"),
        max_get_many_key_bytes: NonZeroUsize::new(16).expect("get-many byte limit is non-zero"),
        max_transaction_bytes: NonZeroUsize::new(32).expect("transaction limit is non-zero"),
        max_transaction_keys: NonZeroU32::new(4).expect("transaction key limit is non-zero"),
        max_range_items: NonZeroU32::new(2).expect("range item limit is non-zero"),
        max_range_bytes: NonZeroUsize::new(16).expect("range byte limit is non-zero"),
        max_transaction_duration: Duration::from_millis(1),
    })
    .expect("capability values are coherent")
}

fn limits() -> TransactionLimits {
    TransactionLimits {
        max_checks: NonZeroU32::new(4).expect("check limit is non-zero"),
        max_mutations: NonZeroU32::new(4).expect("mutation limit is non-zero"),
        max_bytes: NonZeroUsize::new(64).expect("byte limit is non-zero"),
    }
}

fn range(start: Option<StoreKey>, end: Option<StoreKey>, items: u32, bytes: usize) -> RangeRequest {
    RangeRequest::try_from(RangeRequestInput {
        start,
        end,
        direction: RangeDirection::Forward,
        item_limit: NonZeroU32::new(items).expect("range item limit is non-zero"),
        byte_limit: NonZeroUsize::new(bytes).expect("range byte limit is non-zero"),
        continuation: None,
    })
    .expect("range request is ordered")
}

#[test]
fn given_store_capabilities_when_reading_their_limits_then_every_declared_limit_is_preserved() {
    let store = capabilities(StoreLevel::Local);

    assert_eq!(store.max_key_bytes().get(), 8);
    assert_eq!(store.max_value_bytes().get(), 8);
    assert_eq!(store.max_get_many_keys().get(), 3);
    assert_eq!(store.max_get_many_key_bytes().get(), 16);
    assert_eq!(store.max_transaction_bytes().get(), 32);
    assert_eq!(store.max_transaction_keys().get(), 4);
    assert_eq!(store.max_range_items().get(), 2);
    assert_eq!(store.max_range_bytes().get(), 16);
    assert_eq!(store.max_transaction_duration(), Duration::from_millis(1));
}

#[test]
fn given_get_many_limits_when_validating_then_empty_count_and_key_bytes_are_explicit() {
    let store = capabilities(StoreLevel::Local);
    let key = |value: &[u8]| StoreKey::try_from(value).expect("key is non-empty");

    assert!(store.validate_get_many(&[]).is_ok());
    assert!(matches!(
        store.validate_get_many(&[key(b"a"), key(b"b"), key(b"c"), key(b"d"),]),
        Err(StoreContractError::CapabilityExceeded("get-many keys"))
    ));
    assert!(matches!(
        store.validate_get_many(&[key(b"12345678"), key(b"abcdefgh"), key(b"x"),]),
        Err(StoreContractError::CapabilityExceeded("get-many key bytes"))
    ));
}

#[test]
fn given_a_transaction_over_key_or_value_limits_when_validating_it_then_the_capability_rejects_it()
{
    let store = capabilities(StoreLevel::Local);
    let long_key = StoreKey::try_from(&[0u8; 9][..]).expect("key is non-empty");
    let key = StoreKey::try_from(&b"key"[..]).expect("key is valid");

    let too_many_keys = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([1; 16]),
        checks: vec![
            Check::Absent(key.clone()),
            Check::Absent(StoreKey::try_from(&b"key2"[..]).expect("key is valid")),
        ],
        mutations: vec![
            Mutation::Delete(StoreKey::try_from(&b"key3"[..]).expect("key is valid")),
            Mutation::Delete(StoreKey::try_from(&b"key4"[..]).expect("key is valid")),
            Mutation::Delete(StoreKey::try_from(&b"key5"[..]).expect("key is valid")),
        ],
        limits: limits(),
    })
    .expect("transaction builder permits this test transaction");
    assert!(matches!(
        store.validate_transaction(&too_many_keys),
        Err(StoreContractError::CapabilityExceeded("transaction keys"))
    ));

    let too_long_key = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([2; 16]),
        checks: vec![Check::Absent(long_key)],
        mutations: Vec::new(),
        limits: limits(),
    })
    .expect("transaction builder permits the long key");
    assert!(matches!(
        store.validate_transaction(&too_long_key),
        Err(StoreContractError::CapabilityExceeded("key bytes"))
    ));

    let too_long_value = StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([3; 16]),
        checks: vec![Check::Value(key, Bytes::from(vec![0; 9]))],
        mutations: Vec::new(),
        limits: limits(),
    })
    .expect("transaction builder permits the long value");
    assert!(matches!(
        store.validate_transaction(&too_long_value),
        Err(StoreContractError::CapabilityExceeded("value bytes"))
    ));
}

#[test]
fn given_range_limits_when_validating_a_request_then_item_byte_and_key_bounds_are_enforced() {
    let store = capabilities(StoreLevel::Local);
    let key = |value: &[u8]| StoreKey::try_from(value).expect("key is non-empty");

    assert!(matches!(
        store.validate_range(&range(None, None, 3, 1)),
        Err(StoreContractError::CapabilityExceeded("range items"))
    ));
    assert!(matches!(
        store.validate_range(&range(None, None, 1, 17)),
        Err(StoreContractError::CapabilityExceeded("range bytes"))
    ));
    assert!(matches!(
        store.validate_range(&range(Some(key(&[0; 9])), None, 1, 1)),
        Err(StoreContractError::CapabilityExceeded("range key bytes"))
    ));
}

#[test]
fn given_local_and_distributed_markers_when_querying_the_level_then_only_distributed_claims_multi_node_safety()
 {
    let local = capabilities(StoreLevel::Local);
    let distributed = capabilities(StoreLevel::Distributed);

    assert!(!local.is_distributed());
    assert_eq!(local.level(), StoreLevel::Local);
    assert!(distributed.is_distributed());
    assert_eq!(distributed.level(), StoreLevel::Distributed);
}

#[test]
fn given_zero_transaction_duration_or_reversed_byte_limits_when_constructing_capabilities_then_validation_fails()
 {
    let mut input = StoreCapabilitiesInput {
        level: StoreLevel::Local,
        max_key_bytes: NonZeroUsize::new(8).expect("key limit is non-zero"),
        max_value_bytes: NonZeroUsize::new(8).expect("value limit is non-zero"),
        max_get_many_keys: NonZeroU32::new(1).expect("get-many limit is non-zero"),
        max_get_many_key_bytes: NonZeroUsize::new(8).expect("get-many byte limit is non-zero"),
        max_transaction_bytes: NonZeroUsize::new(7).expect("transaction limit is non-zero"),
        max_transaction_keys: NonZeroU32::new(1).expect("key limit is non-zero"),
        max_range_items: NonZeroU32::new(1).expect("range item limit is non-zero"),
        max_range_bytes: NonZeroUsize::new(8).expect("range byte limit is non-zero"),
        max_transaction_duration: Duration::ZERO,
    };
    assert!(matches!(
        StoreCapabilities::try_from(input),
        Err(StoreContractError::Validation(
            ValidationError::InvalidValue {
                field: "transaction duration"
            }
        ))
    ));

    input.max_transaction_duration = Duration::from_millis(1);
    assert!(matches!(
        StoreCapabilities::try_from(input),
        Err(StoreContractError::Validation(ValidationError::Ordering {
            field: "transaction/key bytes"
        }))
    ));
}
