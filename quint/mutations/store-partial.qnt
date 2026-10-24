/// Mutation wrapper over the real store record and atomic-publication rule.
///
/// The unsafe transition retains JobA's authoritative record but removes its
/// due route.  The imported route-equivalence invariant must reject exactly
/// this partial publication.
module store_partial_mutation {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_store_protocol.* from "../job-store-protocol"

  action unsafe = {
    val current = records.get(JobA)
    val broken = current.with("exists", true).with("payload", true)
      .with("dueRoute", false).with("fairRoute", true).with("wakeRoute", true)
    all {
      records' = update(records, JobA, broken),
      meta' = meta,
    }
  }

  val inv_mutation_siblings = inv_except_route_equivalence
}
