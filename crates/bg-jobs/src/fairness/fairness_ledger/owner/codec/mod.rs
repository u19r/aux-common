//! Versioned durable fair-owner codec wiring.

mod constants;
mod decode;
mod encode;
mod wire;

#[cfg(test)]
pub(super) use wire::{Reader, read_scope};
