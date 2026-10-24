/// Focused store mutants for terminal visibility, atomic publication, and revision-checked purge.
module store_contract_mutations {
  import bg_jobs_types.* from "../bg-jobs-types"
  import job_store_protocol.* from "../job-store-protocol"

  action unsafe_qnt_003 = all { records' = records,
    meta' = meta.with("completionReceipts", 1)
      .with("completionDetail", CompletionDetailReturned)
      .with("completionDetailJob", JobA)
      .with("committedTerminalJobs", Set(JobA)) }
  val qnt_003_detail_after_delete = meta.completionDetail != CompletionDetailReturned
    or not(records.get(meta.completionDetailJob).exists)
  val qnt_003_siblings = inv

  action unsafe_qnt_009 = all { records' = update(records, JobA,
    records.get(JobA).with("revision", records.get(JobA).revision + 1)),
    meta' = meta.with("lastResult", Rejected).with("lastOutcome", PartialTransactionRejected)
      .with("transactionChecks", 1).with("transactionMutations", 1) }
  val qnt_009_transactions_are_atomic = meta.lastOutcome != PartialTransactionRejected
    or records == initialRecords
  val qnt_009_siblings = inv

  action unsafe_qnt_010 = all { records' = update(records, JobC,
    records.get(JobC).with("revision", records.get(JobC).revision + 1)) ,
    meta' = meta.with("lastOutcome", DanglingIndexPurged).with("repairSteps", 1)
      .with("transactionChecks", 0) }
  val qnt_010_purge_checks_revision = meta.lastOutcome != DanglingIndexPurged
    or meta.transactionChecks > 0
  val qnt_010_siblings = inv
}
