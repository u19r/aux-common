//! Internal optimization-loop instrumentation probe.
//!
//! This crate is dev/diagnostic tooling, not a supported downstream API.
#![doc(hidden)]

mod constants;
mod probe;

#[cfg(test)]
mod probe_tests;

pub use crate::probe::{
    HotspotRecord, ProbeAllocator, ProbeSample, estimate_json_bytes, force_flush, is_enabled,
    measure_future, record_analytics_call, record_bg_job_call, record_pubsub_call,
    record_queue_call, record_storage_call, reset,
};
