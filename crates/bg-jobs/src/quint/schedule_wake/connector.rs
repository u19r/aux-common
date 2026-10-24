//! Full-state connector for the schedule and wake boundary.
//!
//! The connector keeps the caller-owned schedule cursor and constructs wake
//! candidates through the public boundary.  It never stores a second schedule
//! reducer: every action is sent through the public `JobSystem`, schedule,
//! cursor, drive, or wake APIs and the projection is rebuilt from those values
//! and the `FakeStore` snapshot.

use super::driver::ScheduleWakeDriver;

#[::quint_connect_guard::quint_run(
    spec = "../../quint/job-schedule-wake-mbt.qnt",
    main = "job_schedule_wake_mbt",
    init = "mbtInit",
    step = "mbtNondetStep",
    max_samples = 1,
    max_steps = 20,
    seed = "0x2b"
)]
fn quint_schedule_wake_full_state_matches_public_boundaries() -> impl quint_connect::Driver {
    ScheduleWakeDriver::default()
}
