/// Fairness-focused exploration wrapper for real dispatch state.
///
/// The injected action places a Bulk head at the end of the quiet window;
/// the next imported selection must service it or reject other service that
/// would cross the bounded dwell error.
module job_fair_dispatch_bughunt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_fair_dispatch.* from "./job-fair-dispatch"

  action forceBulkAtQuietBoundary = {
    val current = scopes.get(ScopeA1)
    val group = jobs.get(JobC).ordering
    val orderState = orders.get(group)
    val candidateWindow = SCOPES.filter(scope => scopes.get(scope).ready).size()
    val readyBulk = current.with("ready", true).with("priority", Bulk)
      .with("candidates", Set(JobC)).with("head", orderState.head).with("order", orderState.head)
    val withoutOtherJobCRoutes = scopes.keys().mapBy(scope =>
      if (scope != ScopeA1 and scopes.get(scope).candidates.contains(JobC))
        scopes.get(scope).with("ready", false).with("candidates",
          scopes.get(scope).candidates.filter(job => job != JobC))
      else scopes.get(scope))
    val queued = jobs.get(JobC).with("state", Scheduled).with("payload", true)
      .with("dueRoute", true).with("fairRoute", true).with("scope", ScopeA1)
      .with("priority", Bulk).with("order", orderState.head)
      .with("orderHead", orderState.head)
    val candidateScopes = update(withoutOtherJobCRoutes, ScopeA1, readyBulk)
    val candidateJobs = update(jobs, JobC, queued)
    val bothPrimariesReady = eligibleJobsIn(candidateJobs, candidateScopes, orders)
      .exists(candidate => scopePrimary(candidateJobs.get(candidate).scope) == ScopeA)
      and eligibleJobsIn(candidateJobs, candidateScopes, orders)
        .exists(candidate => scopePrimary(candidateJobs.get(candidate).scope) == ScopeB)
    val admissionFair = not(bothPrimariesReady)
      or normalizedServiceError(candidateScopes.get(ScopeA).servedCost,
        candidateScopes.get(ScopeA).share, candidateScopes.get(ScopeB).servedCost,
        candidateScopes.get(ScopeB).share) <= FAIR_NORMALIZED_ERROR
    val allowed = (current.ready or candidateWindow < MAX_CANDIDATE_ITEMS)
      and jobs.get(JobC).state != Leased and not(orderState.inFlight) and admissionFair
    all {
      scopes' = if (allowed) candidateScopes else scopes,
      jobs' = if (allowed) candidateJobs else jobs,
      orders' = orders,
      meta' = if (allowed) meta.with("cycle", FAIR_QUIET_ERROR - 1)
        .with("lastOutcome", HeadReady) else meta,
    }
  }

  action bughuntStep = any { step, forceBulkAtQuietBoundary }
}
