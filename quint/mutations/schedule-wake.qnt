/// Mutation wrapper over the real schedule occurrence identity invariant.
///
/// The unsafe transition emits two CatchUp occurrences but erases the second
/// identity.  The imported occurrence property must fail on that actual
/// schedule state rather than on a disconnected duplicate fixture.
module schedule_wake_mutation {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_schedule_wake.* from "../job-schedule-wake"

  action unsafe = all {
    state' = state.with("emitted", update(update(state.emitted, Occ1, true), Occ2, true))
      .with("emissionCount", 2)
      .with("occurrenceIdentity", update(update(state.occurrenceIdentity, Occ1, 5), Occ2, 0)),
  }

  val inv_mutation_siblings = inv_except_occurrence_identity
}
