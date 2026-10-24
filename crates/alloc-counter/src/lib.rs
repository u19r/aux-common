#![doc(hidden)]
#![cfg_attr(not(test), deny(clippy::print_stderr, clippy::print_stdout))]

mod allocation_counter;
mod constants;

pub use alloc_counter_macros::count_allocations;

pub use crate::{
    allocation_counter::{
        AllocationGuard, AllocationReport, AllocationReportError, emit_report, report_json,
    },
    constants::REPORT_PATH_ENV,
};
