//! Real-store fair-dispatch connector and boundary tests.

use super::driver::FairDispatchDriver;

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-fair-dispatch-mbt.qnt",
    main = "job_fair_dispatch_mbt",
    init = "mbtInit",
    step = "mbtNondetStep",
    max_samples = 1,
    max_steps = 20,
    seed = "0x3d"
)]
fn quint_fair_dispatch_real_owner_matches_public_boundaries() -> impl quint_connect::Driver {
    FairDispatchDriver::default()
}
