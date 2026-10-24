#[cfg(not(target_family = "wasm"))]
mod fair_dispatch;
#[cfg(not(target_arch = "wasm32"))]
mod lifecycle;
#[cfg(not(target_arch = "wasm32"))]
mod schedule_wake;
