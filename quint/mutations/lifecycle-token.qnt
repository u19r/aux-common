/// Mutation wrapper over the real lifecycle completion-authority invariant.
///
/// The unsafe transition performs the real terminal deletion for leased JobB
/// while presenting the complete authority tuple with a wrong token. It
/// deliberately bypasses exactAuthority; only the authority property fails.
module lifecycle_token_mutation {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_lifecycle.* from "../job-lifecycle"

  action unsafe = {
    val job = JobB
    val current = jobs.get(job)
    val terminal = terminalKernel(current.revision, false, completionReceiptCount,
      current.state == Leased)
    val deleted = current.with("state", Absent).with("revision", terminal.nextRevision)
      .with("payload", terminal.keepPayload).with("dueRoute", terminal.dueRoute)
      .with("fairRoute", terminal.fairRoute).with("leaseRoute", terminal.leaseRoute)
      .with("wakeRoute", terminal.wakeRoute).with("leaseUntil", 0)
      .with("checkpointBytes", 0).with("completionReceipt", false)
    all {
      jobs' = update(jobs, job, deleted),
      meta' = meta.with("completionPending", true).with("completionJob", job)
        .with("completionOperation", current.operationId)
        .with("completionRevision", terminal.nextRevision)
        .with("completionGeneration", current.generation)
        .with("completionDetail", NoCompletionDetail)
        .with("committedTerminalJobs", meta.committedTerminalJobs.union(Set(job)))
        .with("completionAuthorityRecorded", true)
        .with("completionAuthorityNow", meta.now)
        .with("completionNode", current.node).with("completionFence", current.fence)
        .with("completionToken", current.token)
        .with("completionLeaseUntil", current.leaseUntil)
        .with("completionPresentedNode", current.node)
        .with("completionPresentedRevision", current.revision)
        .with("completionPresentedGeneration", current.generation)
        .with("completionPresentedFence", current.fence)
        .with("completionPresentedToken", current.token + 1)
        .with("completionPresentedLeaseUntil", current.leaseUntil)
        .with("completionPresentedOperation", current.operationId)
        .with("staleNode", current.node).with("staleRevision", current.revision)
        .with("staleGeneration", current.generation).with("staleFence", current.fence)
        .with("staleToken", current.token).with("staleLeaseUntil", current.leaseUntil)
        .with("staleOperation", current.operationId).with("presentedNode", current.node)
        .with("lastAttemptRevision", current.revision)
        .with("presentedGeneration", current.generation)
        .with("presentedFence", current.fence).with("presentedToken", current.token + 1)
        .with("presentedLeaseUntil", current.leaseUntil)
        .with("lastAttemptOperation", current.operationId)
        .with("lastAttemptJob", job).with("lastAttemptApplied", true)
        .with("lastResult", Committed).with("lastOutcome", CompletionDeleted),
    }
  }

  val inv_mutation_siblings = inv_except_authority
}
