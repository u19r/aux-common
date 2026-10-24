/// Focused fairness and batch mutants for progress, hierarchy, budgets, and item-local results.
module fair_contract_mutations {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_fair_dispatch.* from "../job-fair-dispatch"

  action unsafe_qnt_011 = all { scopes' = scopes, jobs' = jobs, orders' = orders,
    meta' = meta.with("lastOutcome", SelectionServed).with("selectedJob", JobA)
      .with("selectedScope", ScopeA).with("serviceTransitions", meta.serviceTransitions + 1) }
  val qnt_011_quiet_scope_progress = meta.lastOutcome != SelectionServed
    or meta.serviceTransitions <= JOBS.fold(0,
      (n, job) => n + jobs.get(job).serviceTransitions)
  val qnt_011_siblings = inv_candidate_identity and inv_dispatch_budget

  action unsafe_qnt_012 = all { scopes' = update(scopes, ScopeA1,
    scopes.get(ScopeA1).with("served", 1).with("servedCost", 1)),
    jobs' = jobs, orders' = orders, meta' = meta }
  val qnt_012_secondary_charges_primary = scopes.get(ScopeA1).servedCost
    <= scopes.get(ScopeA).servedCost
  val qnt_012_siblings = inv_candidate_identity and inv_dispatch_budget

  action unsafe_qnt_014 = all { scopes' = scopes,
    jobs' = update(jobs, JobA, jobs.get(JobA).with("block", PoisonHead)),
    orders' = orders, meta' = meta.with("lastOutcome", HeadBlocked).with("selectedJob", JobA) }
  val qnt_014_blocked_head_does_not_freeze_other_scope = meta.lastOutcome != HeadBlocked
    or not(eligibleJobs.contains(JobB))
  val qnt_014_siblings = inv_candidate_identity and inv_dispatch_budget

  action unsafe_qnt_015 = all { scopes' = scopes,
    jobs' = update(update(jobs, JobB, jobs.get(JobB).with("state", Leased)
      .with("dueRoute", false).with("fairRoute", false)), JobC,
      jobs.get(JobC).with("serviceTransitions", 1)),
    orders' = update(orders, OrderB,
      orders.get(OrderB).with("inFlight", true).with("owner", JobB)), meta' = meta }
  val qnt_015_success_cannot_ack_unresolved_successor =
    not(orders.get(OrderB).inFlight and orders.get(OrderB).owner == JobB)
      or jobs.get(JobC).serviceTransitions == 0
  val qnt_015_siblings = inv_candidate_budget and inv_dispatch_budget and inv_scratch

  action unsafe_qnt_016 = all { scopes' = update(scopes, ScopeA,
    scopes.get(ScopeA).with("permits", -1)), jobs' = jobs, orders' = orders, meta' = meta }
  val qnt_016_capacity_never_overdrawn = SCOPES.forall(scope => scopes.get(scope).permits >= 0)
  val qnt_016_siblings = inv_candidate_identity and inv_order_group_authority

  action unsafe_qnt_023 = all { scopes' = scopes,
    jobs' = update(update(jobs, JobA, jobs.get(JobA).with("state", Absent)
      .with("payload", false).with("dueRoute", false).with("fairRoute", false)), JobB,
      jobs.get(JobB).with("state", Absent).with("payload", false)
        .with("dueRoute", false).with("fairRoute", false)), orders' = orders,
    meta' = meta.with("batchActive", true).with("batchMembers", Set(JobA, JobB))
      .with("batchResults", Map(JobA -> ItemSuccess, JobB -> ItemMissing)) }
  val qnt_023_batch_success_is_item_local = not(meta.batchActive)
    or meta.batchResults.get(JobB) != ItemMissing or jobs.get(JobB).state != Absent
  val qnt_023_siblings = inv_candidate_budget and inv_dispatch_budget
}
