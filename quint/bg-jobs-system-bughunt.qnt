/// Composite recovery exploration wrapper for the synchronized system.
///
/// A recovered scheduler advances its logical clock while preserving every
/// imported authoritative field.  The real product steps then explore lease
/// expiry, retry, reconciliation, recurrence, repair, and pulse exits.
module bg_jobs_system_bughunt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import bg_jobs_system.* from "./bg-jobs-system"

  action recoveredClockJump = all {
    system' = system.with("now", system.now + OCCURRENCE_STEP)
      .with("activePulses", 0),
  }

  action bughuntStep = any { step, recoveredClockJump }
}
