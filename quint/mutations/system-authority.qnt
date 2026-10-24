/// Mutation wrapper over the real composite lease authority invariant.
///
/// The unsafe transition changes JobA's lease authority to zero while keeping
/// the record leased.  The imported authority property must reject the actual
/// synchronized product state.
module system_authority_mutation {
  import bg_jobs_types.* from "../bg-jobs-types"
  import bg_jobs_system.* from "../bg-jobs-system"

  val inv_mutation_siblings = inv_except_authority

  action unsafe = {
    val current = system.jobs.get(JobA)
    val broken = current.with("state", Leased).with("leaseRoute", true)
      .with("payload", true).with("dueRoute", false).with("fairRoute", false)
      .with("wakeRoute", false).with("leaseUntil", 3)
      .with("generation", 0).with("fence", 0).with("token", 0)
    all {
      system' = system.with("jobs", update(system.jobs, JobA, broken))
        .with("orderInFlight", update(system.orderInFlight, OrderA, true))
        .with("orderOwner", update(system.orderOwner, OrderA, JobA)),
    }
  }
}
