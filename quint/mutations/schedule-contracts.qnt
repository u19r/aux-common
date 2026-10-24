/// Focused schedule mutants for global identity, bounded catch-up, advisory wakes, and pulse exit.
module schedule_contract_mutations {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_schedule_wake.* from "../job-schedule-wake"

  action unsafe_qnt_017 = all { state' = state.with("emitted",
    update(update(state.emitted, Occ1, true), Occ2, true)).with("emissionCount", 2)
    .with("occurrenceIdentity", update(update(state.occurrenceIdentity, Occ1, 7), Occ2, 7))
    .with("lastMaterializeNode", NodeB) }
  val qnt_017_occurrence_identity_is_global = OCCURRENCES.forall(first =>
    OCCURRENCES.forall(second => first == second or not(state.emitted.get(first))
      or not(state.emitted.get(second))
      or state.occurrenceIdentity.get(first) != state.occurrenceIdentity.get(second)))
  val qnt_017_siblings = inv_occurrence_sets and inv_revision

  action unsafe_qnt_018 = all { state' = state.with("misfire", CatchUp)
    .with("emissionCount", MAX_OCCURRENCES + 1).with("lastBacklog", MAX_OCCURRENCES + 1) }
  val qnt_018_catchup_is_bounded = state.emissionCount <= MAX_OCCURRENCES
  val qnt_018_siblings = inv_revision and inv_wake

  action unsafe_qnt_019 = all { state' = state.with("wakePending", true)
    .with("wakeRevision", state.wakeRevision + 1).with("durableRoute", falseOccurrences)
    .with("jobState", update(state.jobState, JobA, Scheduled))
    .with("jobDueRoute", update(state.jobDueRoute, JobA, true))
    .with("jobFairRoute", update(state.jobFairRoute, JobA, true))
    .with("jobWakeRoute", update(state.jobWakeRoute, JobA, true)) }
  val qnt_019_wake_is_not_durable_authority = state.jobState.get(JobA) != Scheduled
    or OCCURRENCES.exists(occurrence => state.materialized.get(occurrence)
      and state.occurrenceJob.get(occurrence) == JobA)
  val qnt_019_siblings = inv_occurrence_identity and inv_revision

  action unsafe_qnt_020 = all { state' = state.with("misfire", FireOnce)
    .with("activePulses", 1).with("pulseExited", false)
    .with("pulseActions", state.pulseActions + 1).with("lastDriveBranch", KernelNoWork) }
  val qnt_020_one_shot_pulse_exits = state.lastDriveBranch != KernelNoWork
    or state.activePulses == 0
  val qnt_020_siblings = inv_occurrence_identity and inv_revision
}
