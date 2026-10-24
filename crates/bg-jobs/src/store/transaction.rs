use std::{
    collections::BTreeSet,
    num::{NonZeroU32, NonZeroUsize},
};

use bytes::Bytes;

use crate::{error::StoreContractError, ids::CommitOperationId, store::StoreKey};

/// A conditional value check evaluated atomically by a store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Check {
    Absent(StoreKey),
    Value(StoreKey, Bytes),
}

impl Check {
    pub fn key(&self) -> &StoreKey {
        match self {
            Self::Absent(key) | Self::Value(key, _) => key,
        }
    }

    pub fn encoded_bytes(&self) -> usize {
        self.key().as_bytes().len()
            + match self {
                Self::Absent(_) => 0,
                Self::Value(_, expected) => expected.len(),
            }
    }
}

/// An atomic key/value mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mutation {
    Put(StoreKey, Bytes),
    Delete(StoreKey),
}

impl Mutation {
    pub fn key(&self) -> &StoreKey {
        match self {
            Self::Put(key, _) | Self::Delete(key) => key,
        }
    }

    pub fn encoded_bytes(&self) -> usize {
        self.key().as_bytes().len()
            + match self {
                Self::Put(_, value) => value.len(),
                Self::Delete(_) => 0,
            }
    }
}

/// Non-zero per-transaction bounds supplied by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionLimits {
    pub max_checks: NonZeroU32,
    pub max_mutations: NonZeroU32,
    pub max_bytes: NonZeroUsize,
}

/// An atomic conditional multi-key transaction and its stable commit identity.
///
/// A key may appear at most once among checks and at most once among
/// mutations. The same key may appear once in each section; that is the
/// canonical compare-and-swap shape. Rejecting ambiguous duplicate checks or
/// final mutations gives every adapter one portable interpretation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreTransaction {
    operation_id: CommitOperationId,
    checks: Vec<Check>,
    mutations: Vec<Mutation>,
    limits: TransactionLimits,
    encoded_bytes: usize,
    max_key_bytes: usize,
    max_value_bytes: usize,
}

/// Inputs for constructing a checked transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreTransactionInput {
    /// Stable identity for this one logical commit and all of its retries.
    pub operation_id: CommitOperationId,
    pub checks: Vec<Check>,
    pub mutations: Vec<Mutation>,
    pub limits: TransactionLimits,
}

impl TryFrom<StoreTransactionInput> for StoreTransaction {
    type Error = StoreContractError;

    fn try_from(input: StoreTransactionInput) -> Result<Self, Self::Error> {
        validate_counts(&input)?;
        let encoded_bytes = encoded_bytes(&input);
        if encoded_bytes > input.limits.max_bytes.get() {
            return Err(StoreContractError::CapabilityExceeded("transaction bytes"));
        }
        Ok(Self {
            operation_id: input.operation_id,
            max_key_bytes: max_key_bytes(&input),
            max_value_bytes: max_value_bytes(&input),
            checks: input.checks,
            mutations: input.mutations,
            limits: input.limits,
            encoded_bytes,
        })
    }
}

impl StoreTransaction {
    /// Stable identity that adapters use to replay an established outcome.
    pub const fn operation_id(&self) -> CommitOperationId {
        self.operation_id
    }

    pub fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    pub fn checks(&self) -> &[Check] {
        &self.checks
    }

    pub fn mutations(&self) -> &[Mutation] {
        &self.mutations
    }

    pub const fn limits(&self) -> TransactionLimits {
        self.limits
    }

    pub(super) const fn max_key_bytes(&self) -> usize {
        self.max_key_bytes
    }

    pub(super) const fn max_value_bytes(&self) -> usize {
        self.max_value_bytes
    }
}

fn validate_counts(input: &StoreTransactionInput) -> Result<(), StoreContractError> {
    if input.checks.is_empty() && input.mutations.is_empty() {
        return Err(StoreContractError::EmptyTransaction);
    }
    if input.checks.len() > input.limits.max_checks.get() as usize {
        return Err(StoreContractError::CapabilityExceeded("transaction checks"));
    }
    if input.mutations.len() > input.limits.max_mutations.get() as usize {
        return Err(StoreContractError::CapabilityExceeded(
            "transaction mutations",
        ));
    }
    validate_unique_keys(&input.checks, Check::key, "checks")?;
    validate_unique_keys(&input.mutations, Mutation::key, "mutations")?;
    Ok(())
}

fn validate_unique_keys<T>(
    values: &[T],
    key: impl Fn(&T) -> &StoreKey,
    section: &'static str,
) -> Result<(), StoreContractError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(key(value))) {
        return Err(StoreContractError::DuplicateTransactionKey(section));
    }
    Ok(())
}

fn encoded_bytes(input: &StoreTransactionInput) -> usize {
    input
        .checks
        .iter()
        .map(Check::encoded_bytes)
        .chain(input.mutations.iter().map(Mutation::encoded_bytes))
        .sum()
}

fn max_key_bytes(input: &StoreTransactionInput) -> usize {
    input
        .checks
        .iter()
        .map(|check| check.key().as_bytes().len())
        .chain(
            input
                .mutations
                .iter()
                .map(|mutation| mutation.key().as_bytes().len()),
        )
        .max()
        .unwrap_or_default()
}

fn max_value_bytes(input: &StoreTransactionInput) -> usize {
    input
        .checks
        .iter()
        .filter_map(|check| match check {
            Check::Absent(_) => None,
            Check::Value(_, value) => Some(value.len()),
        })
        .chain(
            input
                .mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    Mutation::Delete(_) => None,
                    Mutation::Put(_, value) => Some(value.len()),
                }),
        )
        .max()
        .unwrap_or_default()
}
