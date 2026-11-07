//! Reusable proof support for consumer-provided [`bg_jobs::JobStore`]
//! implementations.
//!
//! This crate deliberately contains fake/reference test infrastructure, fault
//! and operation-counting wrappers, and executable contract helpers. It does
//! not provide a production persistence adapter.
//! `bg_jobs::test_support::FakeStore` and the models in this crate are for
//! aux-common tests and conformance runs only; each library consumer supplies
//! its own production `JobStore` implementation and backend adapter, then runs
//! these helpers against that adapter.

#![deny(unsafe_code)]

mod constants;
mod fault_store;
mod fault_suite;
mod lifecycle_growth;
#[cfg(all(test, not(target_arch = "wasm32")))]
mod lifecycle_growth_tests;
mod model;
mod recovery_fixture;
mod recovery_store;
mod recovery_suite;
mod suite;

pub use fault_store::{
    CommitFaultKind, CountingStore, FaultOperation, FaultStore, FaultStoreError, OperationCounts,
    ReadFaultKind,
};
pub use fault_suite::run_faults;
pub use lifecycle_growth::{
    LifecycleGrowthReport, RetainedJobStorage, run_deduplication_growth, run_lifecycle_growth,
};
pub use model::{
    RepairAction, RepairBudget, RepairEntry, RepairPlan, RepairReason, StoreModel, StoreModelError,
};
pub use recovery_suite::{RecoveryReport, run_recovery};
pub use suite::{
    ConformanceConfig, ConformanceConfigError, ConformanceError, ConformanceReport,
    OperationProfile, run_basic, run_operation_profile,
};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod quint_store_protocol;
