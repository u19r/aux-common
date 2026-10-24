/// Failure-surface exploration wrapper for the ordered store transitions.
///
/// The injected action records an ambiguous acknowledgement for one concrete
/// job and its operation identity.  The imported scoped-unknown invariant
/// keeps the crash point local while ordinary steps explore repair and purge.
module job_store_protocol_bughunt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_store_protocol.* from "./job-store-protocol"

  action unknownAcknowledgement = {
    val current = records.get(JobB)
    all {
      not(meta.unknownPending) and current.exists and current.leased,
      records' = records,
      meta' = meta.with("unknownPending", true).with("unknownJob", JobB)
        .with("unknownOperation", current.operationId).with("unknownNode", current.node)
        .with("unknownRevision", current.revision).with("unknownGeneration", current.generation)
        .with("unknownFence", current.fence).with("unknownToken", current.token)
        .with("unknownLeaseUntil", current.leaseUntil).with("unknownReadback", Conflict)
        .with("completionDetail", NoCompletionDetail).with("completionDetailJob", JobB)
        .with("lastResult", Unknown).with("lastOutcome", UnknownCommitRequiresReconcile),
    }
  }

  action bughuntStep = any { step, unknownAcknowledgement }
}
