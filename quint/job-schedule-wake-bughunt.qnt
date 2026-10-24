/// Recovery-focused exploration wrapper for schedule and wake state.
///
/// A recovered pulse starts again with an explicit bounded budget.  Ordinary
/// imported steps then explore lost, duplicate, stale, pause, and materialize
/// outcomes without fabricating a durable job.
module job_schedule_wake_bughunt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_schedule_wake.* from "./job-schedule-wake"

  action restartPulse = all {
    state' = state.with("activePulses", 1).with("pulseActions", 0)
      .with("pulseExited", false).with("lastDrive", DriveNoWork),
  }

  action bughuntStep = any { step, restartPulse }
}
