/// Mutation wrapper over the real store completion/wake equivalence.
///
/// The unsafe transition leaves every authoritative record absent while
/// retaining the aggregate wake watermark.  The imported equivalence must
/// reject this phantom wake state.
module store_empty_wake_mutation {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_store_protocol.* from "../job-store-protocol"

  action unsafe = all {
    records' = Map(
      JobA -> makeRecord(false, Valid, 2, false, false, false, false, false, false),
      JobB -> makeRecord(false, Valid, 2, false, false, false, false, false, false),
      JobC -> makeRecord(false, Valid, 0, false, false, false, false, false, false),
    ),
    meta' = meta.with("wakeWatermark", true),
  }

  val inv_mutation_siblings = inv_except_completion_clears_watermark
}
