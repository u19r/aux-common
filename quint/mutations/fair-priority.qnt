/// Mutation wrapper over the real fair-dispatch scopes and service invariant.
///
/// The unsafe transition performs one real Critical service after a Bulk head
/// is already due. It acquires and releases the actual scope and ordering
/// authorities while deliberately bypassing only the quiet-window guard.
module fair_priority_mutation {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_fair_dispatch.* from "../job-fair-dispatch"

  action unsafe = {
    val bulkScope = scopes.get(ScopeA1)
    val readyBulk = bulkScope.with("ready", true).with("priority", Bulk)
      .with("candidates", Set(JobC)).with("head", 1).with("order", 1)
    val bulkJob = jobs.get(JobC).with("state", Scheduled).with("payload", true)
      .with("dueRoute", true).with("fairRoute", true).with("scope", ScopeA1)
      .with("priority", Bulk).with("order", 1).with("orderHead", 1)
    val readyScopes = update(scopes, ScopeA1, readyBulk)
    val readyJobs = update(jobs, JobC, bulkJob)
    val unsafeMeta = meta.with("cycle", FAIR_QUIET_ERROR)
    // The production complete reducer sees the real registered cost 2. Only
    // its `forceBulk` safety input is changed from true to false.
    val transition = familyServiceTransition(readyScopes, readyJobs, orders,
      unsafeMeta, JobA, true, false)
    all {
      transition.allowed and readyJobs.get(JobA).cost == 2,
      scopes' = transition.scopes, jobs' = transition.jobs,
      orders' = transition.orders, meta' = transition.meta,
    }
  }

  val inv_mutation_siblings = inv_except_weighted_progress
}
