//! Full-state Quint connector for the durable lifecycle boundary.
//!
//! The driver dispatches every connected command through `JobSystem` or the
//! owning admin/repair boundary, then rebuilds the complete model projection
//! from the `FakeStore` snapshot and returned transition evidence.

use super::driver::LifecycleDriver;

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedZeroAdvanceTrace",
    max_samples = 1,
    max_steps = 2,
    seed = "0x101"
)]
fn quint_lifecycle_zero_advance_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedConflictTrace",
    max_samples = 1,
    max_steps = 1,
    seed = "0x102"
)]
fn quint_lifecycle_conflict_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedUnknownReconcileTrace",
    max_samples = 1,
    max_steps = 2,
    seed = "0x103"
)]
fn quint_lifecycle_unknown_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedUnknownAfterTrace",
    max_samples = 1,
    max_steps = 1,
    seed = "0x112"
)]
fn quint_lifecycle_unknown_after_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleRetryReclaimTrace",
    max_samples = 1,
    max_steps = 5,
    seed = "0x110"
)]
fn quint_lifecycle_handler_retry_reclaim_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleExpiryReclaimTrace",
    max_samples = 1,
    max_steps = 5,
    seed = "0x111"
)]
fn quint_lifecycle_expiry_reclaim_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedCancellationExpiryTrace",
    max_samples = 1,
    max_steps = 3,
    seed = "0x113"
)]
fn quint_lifecycle_cancellation_expiry_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedCommandCoverageTrace",
    max_samples = 1,
    max_steps = 22,
    seed = "0x10f"
)]
fn quint_lifecycle_deterministic_commands_match_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::for_deterministic_command_coverage()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedScopedRepairTrace",
    max_samples = 1,
    max_steps = 4,
    seed = "0x104"
)]
fn quint_lifecycle_scoped_repair_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedQuarantinedRepairTrace",
    max_samples = 1,
    max_steps = 3,
    seed = "0x105"
)]
fn quint_lifecycle_quarantined_repair_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedStaleRepairTrace",
    max_samples = 1,
    max_steps = 3,
    seed = "0x106"
)]
fn quint_lifecycle_stale_repair_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleRedriveTrace",
    max_samples = 1,
    max_steps = 3,
    seed = "0x107"
)]
fn quint_lifecycle_redrive_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleStaleRedriveTrace",
    max_samples = 1,
    max_steps = 3,
    seed = "0x108"
)]
fn quint_lifecycle_stale_redrive_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleWrongOperationRedriveTrace",
    max_samples = 1,
    max_steps = 3,
    seed = "0x109"
)]
fn quint_lifecycle_wrong_operation_redrive_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleDuplicateRedriveTrace",
    max_samples = 1,
    max_steps = 4,
    seed = "0x10a"
)]
fn quint_lifecycle_duplicate_redrive_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleNonterminalRedriveTrace",
    max_samples = 1,
    max_steps = 2,
    seed = "0x10b"
)]
fn quint_lifecycle_nonterminal_redrive_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleQuarantinedRedriveTrace",
    max_samples = 1,
    max_steps = 3,
    seed = "0x10c"
)]
fn quint_lifecycle_quarantined_redrive_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "fixedLifecycleCorruptRedriveTrace",
    max_samples = 1,
    max_steps = 3,
    seed = "0x10d"
)]
fn quint_lifecycle_corrupt_redrive_matches_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::default()
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-lifecycle-mbt.qnt",
    main = "job_lifecycle_mbt",
    init = "mbtInit",
    step = "mbtNondetStep",
    max_samples = 64,
    max_steps = 80,
    seed = "0x10e"
)]
fn quint_lifecycle_nondeterministic_commands_match_public_state() -> impl quint_connect::Driver {
    LifecycleDriver::for_command_coverage()
}
