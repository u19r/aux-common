//! Bounded route discovery and authoritative record loading.

mod budget;
mod records;
mod runner;
mod scan;

pub(in crate::drive) use runner::{Discovery, discover, queue_selected};
