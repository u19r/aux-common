/// Focused lifecycle mutants for retry, reconciliation, redrive, and corrupt-claim contracts.
module lifecycle_contract_mutations {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_lifecycle.* from "../job-lifecycle"

  action unsafe_qnt_004 = {
    val current = jobs.get(JobB)
    all { jobs' = update(jobs, JobB, current.with("state", RetryWaiting)
      .with("revision", current.revision + 1).with("executionId", current.executionId + 1)
      .with("dueRoute", true).with("fairRoute", true).with("wakeRoute", true)
      .with("leaseRoute", false).with("leaseUntil", 0)), meta' = meta }
  }
  val qnt_004_retry_execution_stable = jobs.get(JobB).state != RetryWaiting
    or jobs.get(JobB).executionId == initialJobs.get(JobB).executionId
  val qnt_004_siblings = inv_route_equivalence and inv_checkpoint_bound and inv_clock

  action unsafe_qnt_005 = all { jobs' = update(jobs, JobB,
    jobs.get(JobB).with("attempts", MAX_ATTEMPTS + 1)
      .with("attemptId", MAX_ATTEMPTS + 1)), meta' = meta }
  val qnt_005_retry_is_bounded = jobs.get(JobB).attempts <= MAX_ATTEMPTS
  val qnt_005_siblings = inv_route_equivalence and inv_checkpoint_bound and inv_clock

  action unsafe_qnt_006 = all { jobs' = jobs,
    meta' = meta.with("lastOutcome", UnknownReconciled).with("lastAttemptApplied", true) }
  val qnt_006_reconcile_never_executes_handler = meta.lastOutcome != UnknownReconciled
    or not(meta.lastAttemptApplied)
  val qnt_006_siblings = inv

  action unsafe_qnt_007 = {
    val current = jobs.get(JobB)
    val redriven = current.with("state", Scheduled).with("revision", current.revision + 1)
      .with("generation", current.generation + 1).with("fence", current.fence + 2)
      .with("token", current.token + 3).with("leaseUntil", 0).with("attempts", 0)
      .with("attemptId", 0).with("dueRoute", true).with("fairRoute", true)
      .with("wakeRoute", true).with("leaseRoute", false)
    all { jobs' = update(jobs, JobB, redriven), meta' = meta.with("lastOutcome", Redriven)
      .with("presentedGeneration", current.generation - 1) }
  }
  val qnt_007_redrive_rejects_old_generation = meta.lastOutcome != Redriven
    or meta.presentedGeneration >= jobs.get(JobB).generation - 1
  val qnt_007_siblings = inv_route_equivalence and inv_authority

  action unsafe_qnt_008 = {
    val current = jobs.get(JobA)
    val claimed = current.with("record", Corrupt).with("state", Leased)
      .with("revision", current.revision + 1).with("generation", 1)
      .with("fence", 2).with("token", 3).with("leaseUntil", 3)
      .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false)
      .with("leaseRoute", true).with("attempts", 1).with("attemptId", 1)
    all { jobs' = update(jobs, JobA, claimed), meta' = meta }
  }
  val qnt_008_invalid_records_unclaimable = JOBS.forall(job =>
    jobs.get(job).record == Valid or jobs.get(job).state != Leased)
  val qnt_008_siblings = inv_checkpoint_bound and inv_retry_bound and inv_clock
}
