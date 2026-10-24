#![cfg(not(target_arch = "wasm32"))]

use std::{fmt, future::Future};

use cucumber::World;

mod common;

mod steps;

#[derive(Default, cucumber::World)]
pub struct BddWorld {
    pub(crate) http: Option<steps::HttpEvidence>,
    pub(crate) backend: Option<steps::BackendEvidence>,
    pub(crate) profile: Option<steps::ProfileEvidence>,
}

impl fmt::Debug for BddWorld {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("BddWorld").finish_non_exhaustive()
    }
}

pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => panic!("failed to build BDD Tokio runtime: {error}"),
    };
    runtime.block_on(future)
}

fn main() {
    block_on(
        BddWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
