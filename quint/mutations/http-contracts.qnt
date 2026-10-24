/// Focused HTTP mutant for single-owner retry policy.
module http_contract_mutations {
  import bg_jobs_types.* from "../bg-jobs-types"
  import http_job.* from "../http-job"

  action unsafe_qnt_021 = all { items' = update(items, JobA,
    items.get(JobA).with("member", true).with("retryOwner", EngineOwnsRetry)
      .with("result", ItemRetry)), meta' = meta.with("batchMembers", Set(JobA))
      .with("batchResults", Map(JobA -> ItemRetry)).with("engineRetries", 1)
      .with("transportRetries", 1) }
  val qnt_021_exactly_one_retry_owner = meta.engineRetries == 0
    or meta.transportRetries == 0
  val qnt_021_siblings = inv_batch_membership and inv_bounds
}
