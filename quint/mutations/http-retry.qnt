/// Mutation wrapper over the real HTTP identity and secret-projection invariants.
///
/// The unsafe transition preserves JobA's stable execution identity while
/// making the observable diagnostic receipt claim to include body contents.
/// It preserves all unrelated state so the secret-projection property is the
/// only failure under test; the separate QNT-021 mutation owns idempotency.
module http_retry_mutation {
  import bg_jobs_types.* from "../bg-jobs-types"
  import http_job.* from "../http-job"

  action unsafe = {
    val current = items.get(JobA)
    val broken = current.with("member", true).with("idempotencyHeader", current.executionId)
    val brokenProjection = meta.lastProjection.with("includesBody", true)
    all {
      items' = update(items, JobA, broken),
      meta' = meta.with("batchMembers", Set(JobA))
        .with("batchResults", update(meta.batchResults, JobA, broken.result))
        .with("lastProjection", brokenProjection),
    }
  }

  val inv_mutation_siblings = inv_except_http_safety
}
