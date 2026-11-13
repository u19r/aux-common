//! Runtime-neutral ordered-store contracts and validated request values.

pub use crate::{
    error::{StoreContractError, StoreDataError, StoreFailure},
    ids::CommitOperationId,
};

mod binding;
#[cfg(test)]
mod binding_tests;
mod capabilities;
mod constants;
mod contract;
mod effect_receipt;
#[cfg(test)]
mod effect_receipt_tests;
mod encoding;
#[cfg(test)]
mod encoding_tests;
mod key;
mod range;
mod transaction;
#[cfg(test)]
mod transaction_tests;

#[cfg(test)]
mod capabilities_tests;

pub use capabilities::{StoreCapabilities, StoreCapabilitiesInput, StoreLevel};
pub use contract::{CommitOutcome, JobStore};
pub(crate) use effect_receipt::member_key as effect_receipt_member_key;
pub use effect_receipt::{EffectReceiptGroup, EffectReceiptKind};
pub use key::StoreKey;
pub use range::{RangeDirection, RangeEntry, RangePage, RangeRequest, RangeRequestInput};
pub use transaction::{
    Check, Mutation, StoreTransaction, StoreTransactionInput, TransactionLimits,
};

mod observation;
pub(crate) use observation::ObservedStore;
