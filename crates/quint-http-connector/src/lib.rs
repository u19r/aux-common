//! Workspace-private Quint connector support for background-job HTTP tests.
//!
//! The package is a test-only boundary shared by the HTTP and AWS adapters. It
//! is not a customer-facing runtime dependency or production persistence API.
#![deny(unsafe_code)]

mod quint;

pub use quint::{
    AuthResult, AuthorityInput, BatchResult, Command, CommandResult, ConnectorConfig,
    ConnectorDriver, HttpOutcome, HttpStatus, Item, JobId, LastTransition, Meta, Node, OperationId,
    RequestDiagnostic, ResultClass, RetryOwner, StateProjection, TransportResult,
};
