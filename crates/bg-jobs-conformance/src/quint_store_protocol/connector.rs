use super::driver::StoreProtocolDriver;

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-store-protocol-mbt.qnt",
    main = "job_store_protocol_mbt",
    init = "mbtInit",
    step = "mbtNondetStep",
    max_samples = 64,
    max_steps = 80,
    seed = "0x10e"
)]
fn quint_store_protocol_full_state_matches_fake_store() -> impl quint_connect::Driver {
    StoreProtocolDriver::for_command_coverage()
}
