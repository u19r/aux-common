//! Runtime-neutral ordered-store contracts and validated request values.

pub use crate::{
    error::{StoreContractError, StoreDataError, StoreFailure},
    ids::CommitOperationId,
};

mod capabilities;
mod contract;
mod key;
mod range;
mod transaction;
#[cfg(test)]
mod transaction_tests;

#[cfg(test)]
mod capabilities_tests;

pub use capabilities::{StoreCapabilities, StoreCapabilitiesInput, StoreLevel};
pub use contract::{CommitOutcome, JobStore};
pub use key::StoreKey;
pub use range::{RangeDirection, RangeEntry, RangePage, RangeRequest, RangeRequestInput};
pub use transaction::{
    Check, Mutation, StoreTransaction, StoreTransactionInput, TransactionLimits,
};

mod observation;
pub(crate) use observation::ObservedStore;
