/// Focused composite mutant for bypassing a family admission predicate.
module system_contract_mutations {
  import bg_jobs_types.* from "../bg-jobs-types"
  import bg_jobs_system.* from "../bg-jobs-system"

  action unsafe_qnt_024 = {
    val current = system.jobs.get(JobA)
    all { system' = system.with("jobs", update(system.jobs, JobA,
      current.with("state", Leased).with("revision", current.revision + 1)
        .with("generation", current.generation + 1).with("fence", current.fence + 2)
        .with("token", current.token + 3).with("leaseUntil", system.now + 3)
        .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false)
        .with("leaseRoute", true).with("attempts", current.attempts + 1)
        .with("attemptId", current.attemptId + 1)))
      .with("fairPermits", update(system.fairPermits, JobA, 0))
      .with("lastOutcome", ClaimCommitted) }
  }
  val qnt_024_composite_obeys_family_admission = system.lastOutcome != ClaimCommitted
    or system.fairPermits.get(JobA) > 0
  val qnt_024_siblings = inv_routes and inv_authority and inv_evidence
}
