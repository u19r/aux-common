/// Batch-delivery exploration wrapper for the HTTP adapter model.
///
/// The injected action records a duplicate delivery for one real item.  The
/// imported batch result and attempt identities remain visible while ordinary
/// steps explore transport, authorization, projection, and retry outcomes.
module http_job_bughunt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import http_job.* from "./http-job"

  action duplicateDeliveryCrashPoint = {
    nondet job = unresolvedItems.oneOf()
    val current = items.get(job)
    all {
      items' = update(items, job, current.with("duplicate", true)),
      meta' = meta.with("lastItem", job).with("lastOutcome", DuplicateDelivered),
    }
  }

  action bughuntStep = any { step, duplicateDeliveryCrashPoint }
}
