/// Recovery-focused exploration wrapper for the lifecycle transitions.
///
/// A recovered worker may observe a large clock jump.  The injected action
/// preserves the imported authoritative state while exercising expiry,
/// retry, unknown acknowledgement, and repair paths in the same model.
module job_lifecycle_bughunt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_lifecycle.* from "./job-lifecycle"

  action clockJumpAfterRecovery = all {
    jobs' = jobs,
    meta' = meta.with("now", meta.now + MAX_JOB_AGE_TICKS),
  }

  action bughuntStep = any { step, clockJumpAfterRecovery }
}
