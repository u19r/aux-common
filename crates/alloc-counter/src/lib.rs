#![doc(hidden)]

mod allocation_counter;
mod constants;

pub use alloc_counter_macros::count_allocations;

pub use crate::{allocation_counter::*, constants::REPORT_PATH_ENV};
