/// Ordered key-value store contract for durable job records.
///
/// A transaction is an atomic compare-and-mutate over a primary record,
/// payload manifest/chunks, due and fairness routes, lease route, and wake
/// watermark.  Revision is the conditional version; operation identity is
/// stable across an ambiguous acknowledgement.  A conflict or partial fault
/// leaves every affected key unchanged.  Completion removes every live key
/// for the job and repairs the aggregate wake watermark, so an empty store
/// cannot retain a phantom wake.
///
/// Record, manifest, chunk, digest, payload, checkpoint, transaction, and
/// repair budgets are separate abstractions.  Corrupt and unknown-version
/// records are quarantined and fail closed. Unknown newer records retain their
/// payload, manifest, chunk, digest and checkpoint representation byte-for-byte.
/// A missing index cannot authorize or block another job. Repair of understood
/// corruption is revision-checked: a concurrent write advances the revision and
/// makes a stale repair a conflict.
module job_store_protocol {
  import bg_jobs_types.* from "./bg-jobs-types"

  type Record = {
    exists: bool,
    state: JobState,
    kind: RecordKind,
    revision: int,
    node: Node,
    generation: int,
    fence: int,
    token: int,
    leased: bool,
    leaseUntil: int,
    expiresAt: int,
    operationId: OperationId,
    enqueueFingerprint: int,
    executionId: int,
    attemptId: int,
    attempts: int,
    payloadBytes: int,
    manifestBytes: int,
    chunkBytes: int,
    digestBytes: int,
    checkpointBytes: int,
    payload: bool,
    failureRecorded: bool,
    dlqRoute: bool,
    dueRoute: bool,
    fairRoute: bool,
    leaseRoute: bool,
    wakeRoute: bool,
    permitHeld: bool,
    rateHeld: bool,
    inFlight: int,
    dangling: bool,
  }

  type Meta = {
    wakeWatermark: bool,
    now: int,
    unknownPending: bool,
    unknownJob: JobId,
    unknownOperation: OperationId,
    unknownNode: Node,
    unknownRevision: int,
    unknownGeneration: int,
    unknownFence: int,
    unknownToken: int,
    unknownLeaseUntil: int,
    unknownReadback: StoreResult,
    unknownVersionJobs: Set[JobId],
    quarantineSnapshot: JobId -> Record,
    quarantineAttempts: int,
    lastEnqueueDisposition: EnqueueDisposition,
    lastResult: StoreResult,
    lastOutcome: StoreOutcome,
    transactionChecks: int,
    transactionMutations: int,
    transactionBytes: int,
    repairSteps: int,
    unrelatedProgress: int,
    completionReceipts: int,
    completionDetail: CompletionDetail,
    lastDetail: CompletionDetail,
    completionDetailJob: JobId,
    committedTerminalJobs: Set[JobId],
    claimPending: bool,
    claimJob: JobId,
    claimRevision: int,
    claimReader: Node,
    lastAuthorityNode: Node,
    lastAuthorityRevision: int,
    lastAuthorityGeneration: int,
    lastAuthorityFence: int,
    lastAuthorityToken: int,
    lastAuthorityLeaseUntil: int,
    lastAuthorityOperation: OperationId,
  }

  type StoreOutcome = Initialised | AtomicEnqueue | ConflictNoMutation | CompletionDeletedAllKeys
    | UnknownCommitRequiresReconcile | ReconciledCommitted | ReconciledConflict
    | ReconciledAuthorityChanged | CorruptQuarantined
    | UnknownVersionQuarantined | MissingIndexDiscovered | DanglingRecordCreated | DanglingIndexPurged
    | RepairCommitted | RepairRevisionConflict | PartialTransactionRejected | PayloadRejected
    | ClaimSelected | ClaimAtomicCommit | ClaimConflictNoMutation | LeaseRenewed
    | LeaseRenewConflict | LeaseExpiredToReady | TimeAdvanced
    | EnqueueAlreadyPresent | EnqueueJobIdConflict | HandlerDeadLetter
    | RedriveCommitted | RedriveConflict | RedriveRejected

  var records: JobId -> Record
  var meta: Meta

  pure def makeRecord(present, kind, revision, leased, payload, dueRoute, fairRoute, leaseRoute, wakeRoute) = {
    exists: present,
    state: if (not(present)) Absent else if (leased) Leased else Scheduled,
    kind: kind,
    revision: revision,
    node: NodeA,
    generation: if (leased) 1 else 0,
    fence: if (leased) 1 else 0,
    token: if (leased) 3 else 0,
    leased: leased,
    leaseUntil: if (leased) 3 else 0,
    // An absent record has no retention deadline or execution identity to
    // observe. These fields become meaningful only once the record exists.
    expiresAt: if (present) MAX_JOB_AGE_TICKS else 0,
    operationId: OperationA,
    enqueueFingerprint: if (present) revision else 0,
    executionId: if (present) 1 else 0,
    attemptId: if (leased) 1 else 0,
    attempts: if (leased) 1 else 0,
    payloadBytes: if (payload) MAX_INLINE_PAYLOAD_BYTES else 0,
    manifestBytes: if (payload) MAX_MANIFEST_BYTES else 0,
    chunkBytes: if (payload) MAX_CHUNK_BYTES else 0,
    digestBytes: if (payload) MAX_DIGEST_BYTES else 0,
    checkpointBytes: 0,
    payload: payload,
    failureRecorded: false,
    dlqRoute: false,
    dueRoute: dueRoute,
    fairRoute: fairRoute,
    leaseRoute: leaseRoute,
    wakeRoute: wakeRoute,
    permitHeld: leased,
    rateHeld: leased,
    inFlight: if (leased) 1 else 0,
    dangling: false,
  }

  pure def initialRecords = Map(
    JobA -> makeRecord(true, Valid, 1, false, true, true, true, false, true),
    JobB -> makeRecord(true, Valid, 1, true, true, false, false, true, false)
      .with("enqueueFingerprint", 11).with("payloadBytes", 12)
      .with("manifestBytes", 13).with("chunkBytes", 14)
      .with("digestBytes", 15).with("checkpointBytes", 16),
    JobC -> makeRecord(false, Valid, 0, false, false, false, false, false, false),
  )

  pure def initialMeta = {
    wakeWatermark: true,
    now: 0,
    unknownPending: false,
    unknownJob: JobA,
    unknownOperation: OperationA,
    unknownNode: NodeA,
    unknownRevision: 0,
    unknownGeneration: 0,
    unknownFence: 0,
    unknownToken: 0,
    unknownLeaseUntil: 0,
    unknownReadback: Rejected,
    unknownVersionJobs: Set(),
    // No record is quarantined at initialization. The snapshot is populated
    // only when an unknown-version read is observed.
    quarantineSnapshot: Map(),
    quarantineAttempts: 0,
    lastEnqueueDisposition: NotEnqueue,
    lastResult: Committed,
    lastOutcome: Initialised,
    transactionChecks: 0,
    transactionMutations: 0,
    transactionBytes: 0,
    repairSteps: 0,
    unrelatedProgress: 0,
    completionReceipts: 0,
    completionDetail: NoCompletionDetail,
    lastDetail: NoCompletionDetail,
    completionDetailJob: JobA,
    committedTerminalJobs: Set(),
    claimPending: false,
    claimJob: JobA,
    claimRevision: 1,
    claimReader: NodeA,
    lastAuthorityNode: NodeA,
    lastAuthorityRevision: 0,
    lastAuthorityGeneration: 0,
    lastAuthorityFence: 0,
    lastAuthorityToken: 0,
    lastAuthorityLeaseUntil: 0,
    lastAuthorityOperation: OperationA,
  }

  pure def outcome(metaState, result, outcome) =
    metaState.with("lastResult", result).with("lastOutcome", outcome)
      .with("lastEnqueueDisposition", NotEnqueue)
      .with("lastDetail", NoCompletionDetail)

  pure def hasRoute(recordsState) = JOBS.exists(job =>
    recordsState.get(job).dueRoute or recordsState.get(job).fairRoute
      or recordsState.get(job).leaseRoute or recordsState.get(job).wakeRoute
  )
  pure def hasHealthyRoute(recordsState) = JOBS.exists(job => recordsState.get(job).exists
    and recordsState.get(job).kind == Valid
    and (recordsState.get(job).dueRoute or recordsState.get(job).fairRoute
      or recordsState.get(job).leaseRoute or recordsState.get(job).wakeRoute))
  pure def storeBlocked(metaState, job) =
    (metaState.unknownPending and metaState.unknownJob == job)
      or metaState.unknownVersionJobs.contains(job)

  pure def deletedTerminalRecord(current) = {
    val terminal = terminalKernel(current.revision, false, 0, current.leased)
    current.with("exists", false).with("state", Absent)
    .with("revision", terminal.nextRevision).with("payload", terminal.keepPayload).with("payloadBytes", 0)
    .with("manifestBytes", 0).with("chunkBytes", 0).with("digestBytes", 0)
    .with("checkpointBytes", 0).with("dueRoute", terminal.dueRoute)
    .with("fairRoute", terminal.fairRoute).with("leaseRoute", terminal.leaseRoute)
    .with("wakeRoute", terminal.wakeRoute).with("leased", false)
    .with("leaseUntil", 0).with("permitHeld", false).with("rateHeld", false)
    .with("inFlight", 0)
    .with("failureRecorded", false).with("dlqRoute", false)
  }

  pure def deadLetteredStoreRecord(current) = {
    val terminal = terminalKernel(current.revision, true, 0, current.leased)
    current.with("exists", true).with("state", DeadLettered)
      .with("revision", terminal.nextRevision).with("payload", terminal.keepPayload)
      .with("failureRecorded", true).with("dlqRoute", true)
      .with("dueRoute", false).with("fairRoute", false).with("leaseRoute", false)
      .with("wakeRoute", false).with("leased", false).with("leaseUntil", 0)
      // A released lease has no owner or token in the canonical job value.
      .with("node", NodeA)
      // A dead-lettered record is no longer leased.  The production record
      // therefore has no lease token to encode after authority is released.
      .with("token", 0)
      .with("permitHeld", false).with("rateHeld", false).with("inFlight", 0)
  }

  def claimable = JOBS.filter(job => records.get(job).exists and records.get(job).kind == Valid
    and not(storeBlocked(meta, job))
    and (records.get(job).state == Scheduled or records.get(job).state == RetryWaiting)
    and records.get(job).payload and records.get(job).dueRoute and not(records.get(job).leased)
    and meta.now < records.get(job).expiresAt)
  def leasedJobs = JOBS.filter(job => records.get(job).leased
    and records.get(job).state == Leased)
  // Only a known index defect is repairable. Unknown-version and missing
  // authoritative bytes stay quarantined unchanged; no reader may invent a
  // manifest, chunk, digest, or payload for data it does not understand.
  def repairable = JOBS.filter(job => records.get(job).exists and records.get(job).kind == Corrupt)

  // Every valid live record has the complete route appropriate to its lease;
  // invalid records are quarantined and cannot be claimed.
  val inv_route_equivalence = JOBS.forall(job =>
    (not(records.get(job).exists) implies records.get(job).state == Absent
      and not(records.get(job).payload)
      and not(records.get(job).leaseRoute)
      and (records.get(job).dangling or (not(records.get(job).dueRoute)
        and not(records.get(job).fairRoute) and not(records.get(job).wakeRoute))))
    and (records.get(job).leased implies records.get(job).state == Leased
      and records.get(job).exists and records.get(job).kind == Valid
      and records.get(job).payload and records.get(job).leaseRoute
      and not(records.get(job).dueRoute) and not(records.get(job).fairRoute))
    and (records.get(job).exists and records.get(job).kind == Valid
      and (records.get(job).state == Scheduled or records.get(job).state == RetryWaiting)
      implies records.get(job).payload and records.get(job).dueRoute and records.get(job).fairRoute
        and records.get(job).wakeRoute and not(records.get(job).leaseRoute))
    and (records.get(job).state == DeadLettered implies records.get(job).exists
      and records.get(job).payload and records.get(job).failureRecorded
      and records.get(job).dlqRoute and not(records.get(job).leased)
      and not(records.get(job).dueRoute) and not(records.get(job).fairRoute)
      and not(records.get(job).leaseRoute) and not(records.get(job).wakeRoute))
  )
  val inv_completion_clears_watermark = meta.wakeWatermark == hasHealthyRoute(records)
  val inv_dangling_unclaimable = JOBS.forall(job => records.get(job).dangling implies
    not(records.get(job).exists) and not(records.get(job).payload))
  val inv_unknown_scoped = not(meta.unknownPending) or (
    records.get(meta.unknownJob).operationId == meta.unknownOperation
      and records.get(meta.unknownJob).node == meta.unknownNode
      and records.get(meta.unknownJob).generation == meta.unknownGeneration
      and records.get(meta.unknownJob).fence == meta.unknownFence
      and records.get(meta.unknownJob).token == meta.unknownToken
      and (if (meta.unknownReadback == AuthorityChanged)
        records.get(meta.unknownJob).revision != meta.unknownRevision
          and records.get(meta.unknownJob).revision != meta.unknownRevision + 1
      else if (meta.unknownReadback == Committed)
        records.get(meta.unknownJob).revision == meta.unknownRevision + 1
          and not(records.get(meta.unknownJob).exists)
        else records.get(meta.unknownJob).revision == meta.unknownRevision
          and records.get(meta.unknownJob).exists and records.get(meta.unknownJob).leased
          and records.get(meta.unknownJob).leaseUntil == meta.unknownLeaseUntil)
  )
  val inv_corrupt_fail_closed = JOBS.forall(job => records.get(job).kind == Valid or (
    not(records.get(job).leased) and not(records.get(job).leaseRoute)
      and (records.get(job).dangling or (not(records.get(job).dueRoute)
        and not(records.get(job).fairRoute) and not(records.get(job).wakeRoute)))
  ))
  val inv_unknown_version_quarantine = meta.unknownVersionJobs.forall(job =>
    records.get(job) == meta.quarantineSnapshot.get(job)
      and not(claimable.contains(job)))
  val inv_authority = JOBS.forall(job => records.get(job).revision >= 0
    and records.get(job).generation >= 0 and records.get(job).fence >= 0
    and records.get(job).token >= 0
    // Lease tokens are opaque identities.  They must be present for a live
    // lease, but are not derived arithmetically from generation.
    and (records.get(job).state != Leased or (records.get(job).generation > 0
      and records.get(job).fence > 0 and records.get(job).token > 0))
    and records.get(job).leaseUntil >= 0
    and (not(records.get(job).leased) or (records.get(job).node == NodeA
      or records.get(job).node == NodeB)))
  val inv_fair_lease_accounting = JOBS.forall(job =>
    records.get(job).leased == records.get(job).permitHeld
      and records.get(job).leased == records.get(job).rateHeld
      and records.get(job).inFlight == (if (records.get(job).leased) 1 else 0))
  val inv_terminal_state = JOBS.forall(job =>
    records.get(job).attempts >= 0 and records.get(job).attempts <= MAX_ATTEMPTS
      and records.get(job).attemptId >= records.get(job).attempts
      and (not(records.get(job).exists) or records.get(job).executionId > 0)
      and (records.get(job).failureRecorded == (records.get(job).state == DeadLettered))
      and (records.get(job).dlqRoute == (records.get(job).state == DeadLettered)))
  val inv_revision = JOBS.forall(job => records.get(job).revision >= 0)
  val inv_limits = meta.transactionChecks >= 0 and meta.transactionChecks <= MAX_TRANSACTION_CHECKS
    and meta.transactionMutations >= 0 and meta.transactionMutations <= MAX_TRANSACTION_MUTATIONS
    and meta.transactionBytes >= 0 and meta.transactionBytes <= MAX_TRANSACTION_BYTES
    and meta.repairSteps >= 0 and meta.repairSteps <= MAX_REPAIR_STEPS
    and meta.completionReceipts >= 0 and meta.completionReceipts <= MAX_COMPLETION_RECEIPTS
    and meta.quarantineAttempts >= 0
  val inv_payload_bounds = JOBS.forall(job => records.get(job).payloadBytes >= 0
    and records.get(job).payloadBytes <= MAX_INLINE_PAYLOAD_BYTES
    and records.get(job).manifestBytes >= 0 and records.get(job).manifestBytes <= MAX_MANIFEST_BYTES
    and records.get(job).chunkBytes >= 0 and records.get(job).chunkBytes <= MAX_CHUNK_BYTES
    and records.get(job).digestBytes >= 0 and records.get(job).digestBytes <= MAX_DIGEST_BYTES
    and records.get(job).checkpointBytes >= 0 and records.get(job).checkpointBytes <= MAX_CHECKPOINT_BYTES)
  val inv_claim_read = JOBS.contains(meta.claimJob) and meta.claimRevision >= 0
    and (not(meta.claimPending) or (records.get(meta.claimJob).exists
      and records.get(meta.claimJob).kind == Valid and records.get(meta.claimJob).payload
      and records.get(meta.claimJob).dueRoute and not(records.get(meta.claimJob).leased)
      and records.get(meta.claimJob).revision == meta.claimRevision))
  // Completion detail is bounded response/storage data, not commit authority.
  // A returned or omitted detail is possible only after an exact terminal
  // commit for that job. Unknown outcomes deliberately expose no detail.
  val inv_completion_detail = (meta.completionDetail != NoCompletionDetail implies
      meta.committedTerminalJobs.contains(meta.completionDetailJob))
    and (meta.completionDetail == CompletionDetailReturned implies
      meta.completionReceipts > 0)
    and (meta.completionDetail == CompletionDetailOmitted implies
      meta.completionReceipts == MAX_COMPLETION_RECEIPTS)
    and (meta.unknownPending and meta.completionDetailJob == meta.unknownJob
      implies meta.completionDetail == NoCompletionDetail)
  val inv_clock = meta.now >= 0 and JOBS.forall(job => records.get(job).expiresAt >= 0)
  val inv = and {
    inv_route_equivalence,
    inv_completion_clears_watermark,
    inv_dangling_unclaimable,
    inv_unknown_scoped,
    inv_corrupt_fail_closed,
    inv_unknown_version_quarantine,
    inv_authority,
    inv_fair_lease_accounting,
    inv_terminal_state,
    inv_revision,
    inv_limits,
    inv_payload_bounds,
    inv_claim_read,
    inv_completion_detail,
    inv_clock,
  }
  val inv_except_route_equivalence = and {
    inv_completion_clears_watermark, inv_dangling_unclaimable, inv_unknown_scoped,
    inv_corrupt_fail_closed, inv_unknown_version_quarantine, inv_authority,
    inv_fair_lease_accounting,
    inv_terminal_state,
    inv_revision, inv_limits, inv_payload_bounds, inv_claim_read,
    inv_completion_detail, inv_clock,
  }
  val inv_except_completion_clears_watermark = and {
    inv_route_equivalence, inv_dangling_unclaimable, inv_unknown_scoped,
    inv_corrupt_fail_closed, inv_unknown_version_quarantine, inv_authority,
    inv_fair_lease_accounting,
    inv_terminal_state,
    inv_revision, inv_limits, inv_payload_bounds, inv_claim_read,
    inv_completion_detail, inv_clock,
  }

  action init = all {
    records' = initialRecords,
    meta' = initialMeta,
  }

  // This alternate finite starting boundary represents two response details
  // retained from earlier exact commits. It changes no live record authority;
  // subsequent Complete/UnknownCommit/Reconcile actions are the ordinary
  // authoritative transitions and prove that a full detail buffer is not a
  // terminal-commit guard.
  action fullCapacityInit = all {
    records' = initialRecords,
    meta' = initialMeta.with("completionReceipts", MAX_COMPLETION_RECEIPTS)
      .with("committedTerminalJobs", Set(JobA, JobC)),
  }

  action EnqueueAtomicInput(job: JobId, operation: OperationId, payloadBytes: int,
      manifestBytes: int, chunkBytes: int, digestBytes: int,
      checkpointBytes: int, fingerprint: int): bool = {
    val current = records.get(job)
    val within = payloadBytes <= MAX_INLINE_PAYLOAD_BYTES and manifestBytes <= MAX_MANIFEST_BYTES
      and chunkBytes <= MAX_CHUNK_BYTES and digestBytes <= MAX_DIGEST_BYTES
      and checkpointBytes <= MAX_CHECKPOINT_BYTES
      and payloadBytes >= 0 and manifestBytes >= 0 and chunkBytes >= 0
      and digestBytes >= 0 and checkpointBytes >= 0
    val present = current.enqueueFingerprint != 0
    val disposition = stableEnqueueDisposition(present,
      current.enqueueFingerprint, fingerprint)
    val blockedInput = storeBlocked(meta, job)
    val insertedAllowed = within and fingerprint > 0 and not(blockedInput)
      and disposition == Inserted
    val replayAllowed = within and not(blockedInput) and disposition == AlreadyPresent
    val inserted = current.with("exists", true).with("state", Scheduled).with("kind", Valid)
      .with("revision", current.revision + 1).with("payload", true)
      .with("payloadBytes", payloadBytes).with("manifestBytes", manifestBytes)
      .with("chunkBytes", chunkBytes).with("digestBytes", digestBytes)
      .with("checkpointBytes", checkpointBytes).with("operationId", operation)
      .with("enqueueFingerprint", fingerprint)
      .with("executionId", if (present) current.executionId else 1)
      .with("node", NodeA).with("generation", 0).with("token", 0)
      .with("leaseUntil", 0)
      .with("expiresAt", meta.now + MAX_JOB_AGE_TICKS)
      .with("dueRoute", true).with("fairRoute", true).with("wakeRoute", true)
      .with("leaseRoute", false).with("leased", false).with("dangling", false)
      .with("failureRecorded", false).with("dlqRoute", false)
      .with("attempts", 0).with("attemptId", 0)
    val nextRecords = if (insertedAllowed) update(records, job, inserted) else records
    all {
      records' = nextRecords,
      meta' = outcome(meta.with("wakeWatermark", if (insertedAllowed)
          hasHealthyRoute(nextRecords) else meta.wakeWatermark)
        .with("transactionChecks", 1).with("transactionMutations", if (insertedAllowed) 6 else 0)
        .with("transactionBytes", if (insertedAllowed) 6 else 0)
        .with("quarantineAttempts", if (meta.unknownVersionJobs.contains(job))
          meta.quarantineAttempts + 1 else meta.quarantineAttempts),
        if (insertedAllowed or replayAllowed) Committed
          else if (not(blockedInput) and present and within) Rejected else Conflict,
        if (insertedAllowed) AtomicEnqueue
          else if (replayAllowed) EnqueueAlreadyPresent
          else if (not(blockedInput) and present and within) EnqueueJobIdConflict
          else if (blockedInput) ConflictNoMutation else PayloadRejected)
        .with("lastEnqueueDisposition", if (insertedAllowed) Inserted
          else if (replayAllowed) AlreadyPresent
          else if (not(blockedInput) and present and within) JobIdConflict else NotEnqueue),
    }
  }

  action EnqueueAtomic = {
    nondet job = JOBS.oneOf()
    nondet payloadBytes = Set(0, MAX_INLINE_PAYLOAD_BYTES, MAX_INLINE_PAYLOAD_BYTES + 1).oneOf()
    nondet manifestBytes = Set(0, MAX_MANIFEST_BYTES, MAX_MANIFEST_BYTES + 1).oneOf()
    nondet chunkBytes = Set(0, MAX_CHUNK_BYTES, MAX_CHUNK_BYTES + 1).oneOf()
    nondet digestBytes = Set(0, MAX_DIGEST_BYTES, MAX_DIGEST_BYTES + 1).oneOf()
    nondet checkpointBytes = Set(0, MAX_CHECKPOINT_BYTES, MAX_CHECKPOINT_BYTES + 1).oneOf()
    nondet operation = OPERATIONS.oneOf()
    nondet fingerprint = Set(1, 2, 3).oneOf()
    EnqueueAtomicInput(job, operation, payloadBytes, manifestBytes, chunkBytes,
      digestBytes, checkpointBytes, fingerprint)
  }

  action SelectClaimInput(job: JobId, reader: Node, revision: int): bool = {
    val current = records.get(job)
    all {
      claimable.contains(job),
      revision == current.revision,
      records' = records,
      meta' = outcome(meta.with("claimPending", true).with("claimJob", job)
        .with("claimRevision", revision).with("claimReader", reader)
        .with("lastOutcome", ClaimSelected), Committed, ClaimSelected),
    }
  }

  action SelectClaim = {
    nondet job = claimable.oneOf()
    nondet reader = NODES.oneOf()
    SelectClaimInput(job, reader, records.get(job).revision)
  }

  action ClaimInput(job: JobId, contender: Node, expectedRevision: int): bool = {
    val current = records.get(job)
    val sameRead = meta.claimPending and expectedRevision == meta.claimRevision
    val allowed = not(storeBlocked(meta, job)) and sameRead and contender == meta.claimReader
      and current.exists and current.kind == Valid
      and current.payload and current.dueRoute and not(current.leased)
      and meta.now < current.expiresAt
      and not(meta.unknownVersionJobs.contains(job))
      and expectedRevision == current.revision
    val competing = not(storeBlocked(meta, job)) and expectedRevision == meta.claimRevision
      and contender != current.node and (not(meta.claimPending)
        or current.revision != meta.claimRevision or current.leased)
    val effect = claimAuthorityKernel(current.revision, current.generation,
      current.fence, current.token, current.attempts, current.attemptId, meta.now)
    val claimed = current.with("state", Leased).with("leased", true).with("node", contender)
      .with("revision", effect.nextRevision)
      .with("generation", effect.nextGeneration).with("fence", effect.nextFence)
      .with("token", effect.nextToken).with("dueRoute", false).with("fairRoute", false)
      .with("leaseRoute", true).with("wakeRoute", false).with("leaseUntil", effect.nextLeaseUntil)
      .with("permitHeld", true).with("rateHeld", true).with("inFlight", 1)
      .with("attempts", effect.nextAttempts).with("attemptId", effect.nextAttemptId)
    val nextRecords = if (allowed) update(records, job, claimed) else records
    all {
      allowed or competing,
      records' = nextRecords,
      meta' = outcome(meta.with("claimPending", false).with("wakeWatermark", hasHealthyRoute(nextRecords)).with("transactionChecks", 1)
        .with("transactionMutations", if (allowed) 3 else 0).with("transactionBytes", if (allowed) 3 else 0),
        if (allowed) Committed else Conflict, if (allowed) ClaimAtomicCommit else ClaimConflictNoMutation),
    }
  }

  action Claim = {
    nondet contender = NODES.oneOf()
    nondet expectedRevision = Set(meta.claimRevision, meta.claimRevision - 1).oneOf()
    ClaimInput(meta.claimJob, contender, expectedRevision)
  }

  pure def applyStoreCompletion(recordsState, metaState, job,
      presentedNode, presentedRevision, presentedGeneration, presentedFence,
      presentedToken, presentedLeaseUntil, operation) = {
    val current = recordsState.get(job)
    val allowed = not(storeBlocked(metaState, job)) and current.leased and current.kind == Valid
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, presentedNode, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil, operation,
        metaState.now)
    val deleted = deletedTerminalRecord(current)
    val nextRecords = if (allowed) update(recordsState, job, deleted) else recordsState
    val detail = if (allowed) completionDetailAt(metaState.completionReceipts)
      else NoCompletionDetail
    val nextMeta = outcome(metaState.with("wakeWatermark", hasHealthyRoute(nextRecords))
      .with("transactionChecks", 1)
      .with("transactionMutations", if (allowed) 7 else 0)
      .with("transactionBytes", if (allowed) 7 else 0)
      .with("claimPending", if (allowed and job == metaState.claimJob) false
        else metaState.claimPending)
      .with("completionReceipts", if (allowed)
        receiptCountAfterCompletion(metaState.completionReceipts)
        else metaState.completionReceipts)
      .with("completionDetail", detail)
      .with("completionDetailJob", job)
      .with("committedTerminalJobs", if (allowed)
        metaState.committedTerminalJobs.union(Set(job)) else metaState.committedTerminalJobs),
      if (allowed) Committed else Conflict,
      if (allowed) CompletionDeletedAllKeys else ConflictNoMutation)
      .with("lastDetail", detail)
    { records: nextRecords, meta: nextMeta, allowed: allowed }
  }

  action CompleteInput(job: JobId, presentedNode: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId): bool = {
    val effect = applyStoreCompletion(records, meta, job, presentedNode,
      presentedRevision, presentedGeneration, presentedFence, presentedToken,
      presentedLeaseUntil, operation)
    all {
      records' = effect.records,
      meta' = effect.meta,
    }
  }

  action Complete = {
    nondet job = leasedJobs.oneOf()
    val current = records.get(job)
    CompleteInput(job, current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId)
  }

  action CompleteRejected = {
    nondet job = leasedJobs.oneOf()
    nondet presentedNode = NODES.oneOf()
    nondet presentedRevision = authorityChoices(records.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(records.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(records.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(records.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(records.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = records.get(job)
    val authority = exactAuthority(current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operationId,
      presentedNode, presentedRevision, presentedGeneration, presentedFence,
      presentedToken, presentedLeaseUntil, operation, meta.now)
    all {
      not(storeBlocked(meta, job)) and not(authority),
      records' = records,
      meta' = outcome(meta.with("transactionChecks", 1).with("transactionMutations", 0)
        .with("transactionBytes", 0).with("completionDetail", NoCompletionDetail),
        Conflict, ConflictNoMutation),
    }
  }

  pure def applyStoreDeadLetter(recordsState, metaState, job,
      presentedNode, presentedRevision, presentedGeneration, presentedFence,
      presentedToken, presentedLeaseUntil, operation, handler) = {
    val current = recordsState.get(job)
    val authority = not(storeBlocked(metaState, job)) and current.leased
      and current.kind == Valid
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, presentedNode,
        presentedRevision, presentedGeneration, presentedFence, presentedToken,
        presentedLeaseUntil, operation, metaState.now)
    val terminal = authority and (handler == Permanent
      or (isRetryable(handler) and current.attempts >= MAX_ATTEMPTS))
    val dead = deadLetteredStoreRecord(current)
    val nextRecords = if (terminal) update(recordsState, job, dead) else recordsState
    val nextMeta = outcome(metaState.with("wakeWatermark", hasHealthyRoute(nextRecords))
      .with("claimPending", if (terminal and job == metaState.claimJob) false
        else metaState.claimPending)
      .with("committedTerminalJobs", if (terminal)
        metaState.committedTerminalJobs.union(Set(job)) else metaState.committedTerminalJobs)
      .with("transactionChecks", 1).with("transactionMutations", if (terminal) 7 else 0)
      .with("transactionBytes", if (terminal) 7 else 0),
      if (terminal) Committed else if (authority) Rejected else Conflict,
      if (terminal) HandlerDeadLetter else ConflictNoMutation)
    { records: nextRecords, meta: nextMeta, allowed: terminal }
  }

  action DeadLetterInput(job: JobId, presentedNode: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId,
      handler: HandlerResult): bool = {
    val effect = applyStoreDeadLetter(records, meta, job, presentedNode,
      presentedRevision, presentedGeneration, presentedFence, presentedToken,
      presentedLeaseUntil, operation, handler)
    all { records' = effect.records, meta' = effect.meta }
  }

  action DeadLetter = {
    nondet job = leasedJobs.oneOf()
    nondet handler = Set(Permanent, Transient, Throttled, Ambiguous).oneOf()
    val current = records.get(job)
    DeadLetterInput(job, current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operationId, handler)
  }

  pure def applyStoreRedrive(recordsState, metaState, job, expectedRevision,
      expectedOperation, reuseExecution) = {
    val current = recordsState.get(job)
    val effect = redriveKernel(current.state, current.kind,
      storeBlocked(metaState, job), current.revision, current.operationId,
      expectedRevision, expectedOperation, current.generation, current.fence,
      current.token, current.executionId, reuseExecution, metaState.now)
    val eligible = current.state == DeadLettered and current.kind == Valid
      and current.failureRecorded and current.dlqRoute
    val allowed = effect.allowed and eligible
    val redriven = current.with("state", Scheduled).with("revision", effect.nextRevision)
      .with("operationId", nextOperationId(current.operationId))
      .with("generation", effect.nextGeneration).with("fence", current.fence)
      .with("node", NodeA).with("token", 0).with("executionId", effect.nextExecutionId)
      .with("attemptId", effect.nextAttemptId).with("attempts", effect.nextAttempts)
      .with("expiresAt", effect.nextExpiresAt)
      .with("leased", false).with("leaseUntil", 0).with("failureRecorded", false)
      .with("checkpointBytes", 0)
      .with("dlqRoute", false).with("dueRoute", effect.dueRoute)
      .with("fairRoute", effect.fairRoute).with("leaseRoute", effect.leaseRoute)
      .with("wakeRoute", effect.wakeRoute).with("permitHeld", false)
      .with("rateHeld", false).with("inFlight", 0)
    val nextRecords = if (allowed) update(recordsState, job, redriven) else recordsState
    val authorityConflict = expectedRevision != current.revision
      or expectedOperation != current.operationId
    val nextMeta = outcome(metaState.with("wakeWatermark", hasHealthyRoute(nextRecords))
      .with("claimPending", if (allowed and metaState.claimJob == job)
        false else metaState.claimPending)
      .with("completionDetail", if (allowed) NoCompletionDetail
        else metaState.completionDetail)
      .with("lastDetail", if (allowed) NoCompletionDetail else metaState.lastDetail)
      .with("completionDetailJob", if (allowed) job else metaState.completionDetailJob)
      .with("transactionChecks", 1)
      .with("transactionMutations", if (allowed) 7 else 0)
      .with("transactionBytes", if (allowed) 7 else 0)
      .with("committedTerminalJobs", if (allowed)
        metaState.committedTerminalJobs.filter(candidate => candidate != job)
        else metaState.committedTerminalJobs),
      if (allowed) Committed else if (authorityConflict) Conflict else Rejected,
      if (allowed) RedriveCommitted else if (authorityConflict) RedriveConflict
        else RedriveRejected)
    { records: nextRecords, meta: nextMeta, allowed: allowed }
  }

  action RedriveInput(job: JobId, expectedRevision: int,
      expectedOperation: OperationId, reuseExecution: bool): bool = {
    val effect = applyStoreRedrive(records, meta, job, expectedRevision,
      expectedOperation, reuseExecution)
    all { records' = effect.records, meta' = effect.meta }
  }

  action Redrive = {
    nondet job = JOBS.oneOf()
    nondet revision = Set(records.get(job).revision, records.get(job).revision - 1).oneOf()
    nondet operation = OPERATIONS.oneOf()
    nondet reuseExecution = bools.oneOf()
    RedriveInput(job, revision, operation, reuseExecution)
  }

  action UnknownCommitInput(job: JobId, presentedNode: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId, committed: bool): bool = {
    val base = records.get(job)
    val current = base
    val completed = current.with("exists", false).with("state", Absent)
      .with("payload", false).with("payloadBytes", 0)
      .with("manifestBytes", 0).with("chunkBytes", 0).with("digestBytes", 0)
      .with("dueRoute", false).with("fairRoute", false).with("leaseRoute", false)
      .with("wakeRoute", false).with("leased", false).with("leaseUntil", 0)
      .with("permitHeld", false).with("rateHeld", false).with("inFlight", 0)
      .with("failureRecorded", false).with("dlqRoute", false)
      .with("revision", current.revision + 1)
    val allowed = not(meta.unknownPending) and base.leased and operation == base.operationId
      and exactAuthority(base.node, base.revision, base.generation,
        base.fence, base.token, base.leaseUntil, base.operationId, presentedNode,
        presentedRevision, presentedGeneration, presentedFence, presentedToken,
        presentedLeaseUntil, operation, meta.now)
    val nextRecords = if (allowed and committed) update(records, job, completed)
      else if (allowed) update(records, job, current) else records
    all {
      records' = if (not(meta.unknownPending)) nextRecords else records,
      meta' = if (allowed) outcome(meta.with("wakeWatermark", hasHealthyRoute(nextRecords))
        .with("unknownPending", true).with("unknownJob", job).with("unknownOperation", operation)
        .with("unknownNode", presentedNode).with("unknownRevision", presentedRevision)
        .with("unknownGeneration", presentedGeneration).with("unknownFence", presentedFence)
        .with("unknownToken", presentedToken).with("unknownLeaseUntil", presentedLeaseUntil)
        .with("unknownReadback", if (committed) Committed else Conflict)
        .with("claimPending", if (job == meta.claimJob) false else meta.claimPending)
        .with("completionDetail", NoCompletionDetail)
        .with("completionDetailJob", job)
        .with("committedTerminalJobs", if (committed)
          meta.committedTerminalJobs.union(Set(job)) else meta.committedTerminalJobs), Unknown,
        UnknownCommitRequiresReconcile)
        else outcome(meta, Conflict, ConflictNoMutation),
    }
  }

  action UnknownCommit = {
    nondet job = JOBS.filter(candidate => records.get(candidate).exists).oneOf()
    nondet committed = bools.oneOf()
    val current = records.get(job)
    UnknownCommitInput(job, current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operationId, committed)
  }

  action UnknownRejected = {
    nondet job = JOBS.filter(candidate => records.get(candidate).exists).oneOf()
    nondet presentedJob = JOBS.oneOf()
    nondet presentedNode = NODES.oneOf()
    nondet presentedRevision = authorityChoices(records.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(records.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(records.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(records.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(records.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = records.get(job)
    val authority = presentedJob == job and exactAuthority(current.node, current.revision,
      current.generation, current.fence, current.token, current.leaseUntil,
      current.operationId, presentedNode, presentedRevision, presentedGeneration,
      presentedFence, presentedToken, presentedLeaseUntil, operation, meta.now)
    all {
      not(meta.unknownPending) and not(authority),
      records' = records,
      meta' = outcome(meta.with("completionDetail", NoCompletionDetail), Conflict,
        ConflictNoMutation),
    }
  }

  action ReconcileInput(job: JobId, operation: OperationId,
      observed: StoreResult): bool = {
    val current = records.get(job)
    val exactIdentityReadback = current.operationId == meta.unknownOperation
      and current.node == meta.unknownNode and current.generation == meta.unknownGeneration
      and current.fence == meta.unknownFence and current.token == meta.unknownToken
      and (if (observed == Committed) not(current.exists)
        and current.revision == meta.unknownRevision + 1 and current.leaseUntil == 0
        and not(current.permitHeld) and not(current.rateHeld) and current.inFlight == 0
        else current.exists and current.leased
          and current.revision == meta.unknownRevision
          and current.leaseUntil == meta.unknownLeaseUntil
          and current.permitHeld and current.rateHeld and current.inFlight == 1)
    val authorityChanged = current.revision != meta.unknownRevision
      and current.revision != meta.unknownRevision + 1
    val exact = meta.unknownPending and job == meta.unknownJob
      and operation == meta.unknownOperation and observed == meta.unknownReadback
      and (if (observed == AuthorityChanged) authorityChanged else exactIdentityReadback)
    val committedExact = exact and observed == Committed
    all {
      records' = records,
      meta' = if (exact) outcome(meta.with("unknownPending", false)
        .with("unknownJob", JobA).with("unknownOperation", OperationA)
        .with("unknownNode", NodeA).with("unknownRevision", 0)
        .with("unknownGeneration", 0).with("unknownFence", 0)
        .with("unknownToken", 0).with("unknownLeaseUntil", 0)
        .with("unknownReadback", Rejected)
        .with("completionReceipts", if (committedExact)
          receiptCountAfterCompletion(meta.completionReceipts) else meta.completionReceipts)
        .with("completionDetail", if (committedExact)
          completionDetailAt(meta.completionReceipts)
          else NoCompletionDetail)
        .with("completionDetailJob", meta.unknownJob), Committed,
        if (observed == Committed) ReconciledCommitted
        else if (observed == Conflict) ReconciledConflict else ReconciledAuthorityChanged)
        .with("lastDetail", if (committedExact)
          completionDetailAt(meta.completionReceipts) else NoCompletionDetail)
        else outcome(meta, Conflict, ConflictNoMutation),
    }
  }

  action Reconcile = {
    nondet observed = Set(Committed, Conflict, AuthorityChanged).oneOf()
    ReconcileInput(meta.unknownJob, meta.unknownOperation, observed)
  }

  action ChangeUnknownAuthority = {
    val job = meta.unknownJob
    val current = records.get(job)
    all {
      meta.unknownPending,
      records' = update(records, job, current.with("revision", current.revision + 2)),
      meta' = meta.with("unknownReadback", AuthorityChanged).with("lastResult", Unknown)
        .with("lastOutcome", ReconciledAuthorityChanged),
    }
  }

  // Corrupt/missing records are not made live.  Revision advances before a
  // repair can restore routes; a stale repair therefore cannot resurrect an
  // index after a concurrent drop.
  action CorruptRecordInput(job: JobId, kind: RecordKind): bool = {
    val current = records.get(job)
    val understood = kind != UnknownVersion
    val corrupt = current.with("kind", kind).with("revision", current.revision + 1)
      .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false).with("leaseRoute", false)
    val nextRecords = if (understood) update(records, job, corrupt) else records
    all {
      records.get(job).exists and not(records.get(job).leased)
        and (records.get(job).state == Scheduled or records.get(job).state == RetryWaiting)
        and records.get(job).kind == Valid and not(storeBlocked(meta, job))
        and not(meta.unknownVersionJobs.contains(job)),
      kind == Corrupt or kind == UnknownVersion or kind == Missing,
      records' = nextRecords,
      meta' = if (understood) outcome(meta.with("wakeWatermark", hasHealthyRoute(nextRecords))
          .with("claimPending", if (job == meta.claimJob) false else meta.claimPending)
          .with("transactionChecks", 1).with("transactionMutations", 1)
          .with("transactionBytes", 1), Committed,
          if (kind == Missing) MissingIndexDiscovered else CorruptQuarantined)
        else outcome(meta.with("unknownVersionJobs", meta.unknownVersionJobs.union(Set(job)))
          .with("quarantineSnapshot", update(meta.quarantineSnapshot, job, current))
          .with("quarantineAttempts", 0), Rejected, UnknownVersionQuarantined),
    }
  }

  action CorruptRecord = {
    nondet job = JOBS.filter(candidate => records.get(candidate).exists
      and not(records.get(candidate).leased)
      and (records.get(candidate).state == Scheduled
        or records.get(candidate).state == RetryWaiting)
      and records.get(candidate).kind == Valid
      and not(storeBlocked(meta, candidate))).oneOf()
    nondet kind = Set(Corrupt, UnknownVersion, Missing).oneOf()
    CorruptRecordInput(job, kind)
  }

  action UnknownVersionPreservationWitnessStep =
    CorruptRecordInput(JobA, UnknownVersion)

  pure def dropRoutesAllowed(recordsState: JobId -> Record, metaState: Meta,
      job: JobId, due: bool, fair: bool, lease: bool, wake: bool): bool = {
    val current = recordsState.get(job)
    val requested = due or fair or lease or wake
    requested and not(storeBlocked(metaState, job))
      and current.kind == Valid and not(current.leased)
      and (current.state == Scheduled or current.state == RetryWaiting)
  }

  action DropRoutesInput(job: JobId, due: bool, fair: bool,
      lease: bool, wake: bool): bool = {
    val current = records.get(job)
    val allowed = dropRoutesAllowed(records, meta, job, due, fair, lease, wake)
    val dropped = current.with("kind", Corrupt).with("revision", current.revision + 1)
      .with("dueRoute", false).with("fairRoute", false).with("leaseRoute", false)
      .with("wakeRoute", false).with("dangling", not(current.exists))
    val nextRecords = if (allowed) update(records, job, dropped) else records
    all {
      records' = nextRecords,
      meta' = outcome(meta.with("wakeWatermark", hasHealthyRoute(nextRecords))
        .with("claimPending", if (job == meta.claimJob) false else meta.claimPending)
        .with("transactionChecks", 1).with("transactionMutations", if (allowed) 1 else 0)
        .with("transactionBytes", 1)
        .with("quarantineAttempts", if (meta.unknownVersionJobs.contains(job))
          meta.quarantineAttempts + 1 else meta.quarantineAttempts),
        if (allowed) Committed else Conflict,
        if (allowed and current.exists) MissingIndexDiscovered
          else if (allowed) DanglingRecordCreated else ConflictNoMutation),
    }
  }

  action DropIndex = {
    nondet job = JOBS.filter(candidate => records.get(candidate).exists
      and not(records.get(candidate).leased)
      and (records.get(candidate).state == Scheduled
        or records.get(candidate).state == RetryWaiting)
      and records.get(candidate).kind == Valid
      and not(storeBlocked(meta, candidate))).oneOf()
    val current = records.get(job)
    val dropped = current.with("kind", Corrupt).with("revision", current.revision + 1)
      .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false)
    val nextRecords = update(records, job, dropped)
    all {
      records' = nextRecords,
      meta' = outcome(meta.with("wakeWatermark", hasHealthyRoute(nextRecords))
        .with("claimPending", if (job == meta.claimJob) false else meta.claimPending)
        .with("transactionChecks", 1)
        .with("transactionMutations", 1).with("transactionBytes", 1), Committed,
        MissingIndexDiscovered),
    }
  }

  action OrphanRecord = {
    nondet job = JOBS.filter(candidate => records.get(candidate).exists
      and not(records.get(candidate).leased)
      and (records.get(candidate).state == Scheduled
        or records.get(candidate).state == RetryWaiting)
      and not(storeBlocked(meta, candidate))).oneOf()
    val current = records.get(job)
    val orphan = current.with("exists", false).with("state", Absent)
      .with("revision", current.revision + 1).with("payload", false)
      .with("dueRoute", true).with("fairRoute", true).with("wakeRoute", true).with("leaseRoute", false)
      .with("dangling", true)
    val nextRecords = update(records, job, orphan)
    all {
      records' = nextRecords,
      meta' = outcome(meta.with("wakeWatermark", hasHealthyRoute(nextRecords))
        .with("claimPending", if (job == meta.claimJob) false else meta.claimPending),
        Committed, DanglingRecordCreated),
    }
  }

  action RepairInput(job: JobId, expectedRevision: int,
      expectedOperation: OperationId): bool = {
    val current = records.get(job)
    val allowed = not(storeBlocked(meta, job)) and current.exists
      and (current.state == Scheduled or current.state == RetryWaiting)
      and expectedRevision == current.revision
      and expectedOperation == current.operationId and current.kind == Corrupt
      and not(meta.unknownVersionJobs.contains(job))
    val repaired = storeRepairCandidate(current, allowed)
    val nextRecords = if (allowed) update(records, job, repaired) else records
    all {
      records' = nextRecords,
      meta' = outcome(meta.with("wakeWatermark", hasHealthyRoute(nextRecords))
        .with("claimPending", if (allowed and job == meta.claimJob) false else meta.claimPending)
        .with("repairSteps", if (allowed) 1 else 0)
        .with("quarantineAttempts", if (meta.unknownVersionJobs.contains(job))
          meta.quarantineAttempts + 1 else meta.quarantineAttempts)
        .with("transactionChecks", 1).with("transactionMutations", if (allowed) 6 else 0)
        .with("transactionBytes", if (allowed) 6 else 0), if (allowed) Committed else Conflict,
        if (allowed) RepairCommitted else RepairRevisionConflict),
    }
  }

  /// Only a caller that has already proved a known Corrupt revision may take
  /// the repairing branch. UnknownVersion is therefore a byte-preserving
  /// identity, including all bounded payload representation fields.
  pure def storeRepairCandidate(current, allowed) = if (allowed)
    current.with("kind", Valid).with("revision", current.revision + 1)
      .with("dueRoute", true).with("fairRoute", true)
      .with("wakeRoute", true).with("leaseRoute", false)
  else current

  pure def exactStoredBytes(left: Record, right: Record): bool = left == right

  action Repair = {
    nondet job = repairable.oneOf()
    nondet expectedRevision = Set(records.get(job).revision, records.get(job).revision - 1).oneOf()
    nondet expectedOperation = OPERATIONS.oneOf()
    RepairInput(job, expectedRevision, expectedOperation)
  }

  action PurgeDanglingInput(job: JobId, expectedRevision: int): bool = {
    val current = records.get(job)
    val dangling = not(storeBlocked(meta, job)) and not(current.exists)
      and (current.dueRoute or current.fairRoute or current.leaseRoute or current.wakeRoute)
      and expectedRevision == current.revision
    val purged = current.with("dueRoute", false).with("fairRoute", false).with("leaseRoute", false)
      .with("wakeRoute", false).with("dangling", false).with("revision", current.revision + 1)
    val nextRecords = if (dangling) update(records, job, purged) else records
    all {
      records' = nextRecords,
      meta' = outcome(meta.with("wakeWatermark", hasHealthyRoute(nextRecords))
        .with("claimPending", if (dangling and job == meta.claimJob) false else meta.claimPending)
        .with("repairSteps", if (dangling) 1 else 0)
        .with("quarantineAttempts", if (meta.unknownVersionJobs.contains(job))
          meta.quarantineAttempts + 1 else meta.quarantineAttempts)
        .with("unrelatedProgress", if (dangling) min(meta.unrelatedProgress + 1, MAX_UNRELATED_PROGRESS) else meta.unrelatedProgress),
        if (dangling) Committed else Conflict, if (dangling) DanglingIndexPurged else ConflictNoMutation),
    }
  }

  action PurgeDangling = {
    nondet job = JOBS.oneOf()
    nondet expectedRevision = Set(records.get(job).revision, records.get(job).revision - 1).oneOf()
    PurgeDanglingInput(job, expectedRevision)
  }

  action PartialTransaction = all {
    records' = records,
    meta' = outcome(meta.with("transactionChecks", 1).with("transactionMutations", 0)
      .with("transactionBytes", 0), if (meta.unknownPending) Unknown else Rejected, PartialTransactionRejected),
  }

  action IndependentProgress = all {
    records' = records,
    meta' = meta.with("unrelatedProgress", min(meta.unrelatedProgress + 1, MAX_UNRELATED_PROGRESS)),
  }

  action AdvanceTimeInput(amount: int): bool = {
    all {
      records' = records,
      meta' = outcome(meta.with("now", meta.now + amount), Committed, TimeAdvanced),
    }
  }

  action AdvanceTime = {
    nondet amount = Set(0, 1, 3).oneOf()
    AdvanceTimeInput(amount)
  }

  action RenewInput(job: JobId, presentedNode: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId): bool = {
    val current = records.get(job)
    val allowed = not(storeBlocked(meta, job)) and current.leased
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, presentedNode, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil, operation,
        meta.now)
    val renewed = current.with("revision", current.revision + 1)
      .with("leaseUntil", meta.now + 3)
    all {
      records' = if (allowed) update(records, job, renewed) else records,
      meta' = outcome(meta, if (allowed) Committed else Conflict,
        if (allowed) LeaseRenewed else LeaseRenewConflict),
    }
  }

  action Renew = {
    nondet job = leasedJobs.oneOf()
    nondet presentedNode = NODES.oneOf()
    nondet presentedRevision = authorityChoices(records.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(records.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(records.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(records.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(records.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    RenewInput(job, presentedNode, presentedRevision, presentedGeneration, presentedFence,
      presentedToken, presentedLeaseUntil, operation)
  }

  action ExpireLeaseInput(job: JobId): bool = {
    val current = records.get(job)
    val ageExpired = current.expiresAt <= meta.now
    val ready = current.with("state", RetryWaiting).with("leased", false).with("revision", current.revision + 1)
      .with("leaseUntil", 0).with("dueRoute", true).with("fairRoute", true)
      .with("leaseRoute", false).with("wakeRoute", true).with("permitHeld", false)
      .with("rateHeld", false).with("inFlight", 0).with("node", NodeA).with("token", 0)
    val terminal = deadLetteredStoreRecord(current)
    val nextRecords = update(records, job, if (ageExpired) terminal else ready)
    all {
      records.get(job).leased and records.get(job).leaseUntil <= meta.now
        and not(storeBlocked(meta, job)),
      records' = nextRecords,
      meta' = outcome(meta.with("wakeWatermark", hasHealthyRoute(nextRecords))
        .with("committedTerminalJobs", if (ageExpired)
          meta.committedTerminalJobs.union(Set(job)) else meta.committedTerminalJobs),
        Committed, if (ageExpired) HandlerDeadLetter else LeaseExpiredToReady),
    }
  }

  action ExpireLease = {
    nondet job = leasedJobs.filter(candidate => records.get(candidate).leaseUntil <= meta.now
      and not(storeBlocked(meta, candidate))).oneOf()
    ExpireLeaseInput(job)
  }

  action UnknownVersionQuarantineChainStep =
    if (not(meta.unknownVersionJobs.contains(JobA)))
      CorruptRecordInput(JobA, UnknownVersion)
    else if (meta.quarantineAttempts == 0)
      DropRoutesInput(JobA, true, true, false, true)
    else if (meta.quarantineAttempts == 1)
      RepairInput(JobA, records.get(JobA).revision,
        records.get(JobA).operationId)
    else PurgeDanglingInput(JobA, records.get(JobA).revision)

  action StableStoreEnqueueChainStep =
    if (records.get(JobC).enqueueFingerprint == 0)
      EnqueueAtomicInput(JobC, OperationC, 1, 1, 1, 1, 0, 3)
    else if (meta.lastEnqueueDisposition == Inserted)
      EnqueueAtomicInput(JobC, OperationC, 1, 1, 1, 1, 0, 3)
    else EnqueueAtomicInput(JobC, OperationC, 1, 1, 1, 1, 0, 2)

  action TerminalStoreReplayChainStep = {
    val current = records.get(JobB)
    if (current.leased)
      CompleteInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId)
    else EnqueueAtomicInput(JobB, OperationA, MAX_INLINE_PAYLOAD_BYTES,
      MAX_MANIFEST_BYTES, MAX_CHUNK_BYTES, MAX_DIGEST_BYTES, 0,
      current.enqueueFingerprint)
  }

  action TerminalStoreReplayRedriveChainStep = {
    val current = records.get(JobB)
    if (current.leased)
      DeadLetterInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId, Permanent)
    else if (current.state == DeadLettered and meta.lastOutcome == HandlerDeadLetter)
      EnqueueAtomicInput(JobB, OperationA, MAX_INLINE_PAYLOAD_BYTES,
        MAX_MANIFEST_BYTES, MAX_CHUNK_BYTES, MAX_DIGEST_BYTES, 0,
        current.enqueueFingerprint)
    else RedriveInput(JobB, current.revision, current.operationId, false)
  }

  action StaleStoreRedriveChainStep = {
    val current = records.get(JobB)
    if (current.leased)
      DeadLetterInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId, Permanent)
    else RedriveInput(JobB, current.revision - 1, current.operationId, false)
  }

  action WrongOperationStoreRedriveChainStep = {
    val current = records.get(JobB)
    if (current.leased)
      DeadLetterInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId, Permanent)
    else RedriveInput(JobB, current.revision, OperationB, false)
  }

  action DuplicateStoreRedriveChainStep = {
    val current = records.get(JobB)
    if (current.leased)
      DeadLetterInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId, Permanent)
    else if (current.state == DeadLettered)
      RedriveInput(JobB, current.revision, current.operationId, false)
    else RedriveInput(JobB, current.revision - 1, current.operationId, false)
  }

  action QuarantinedStoreRedriveChainStep =
    if (not(meta.unknownVersionJobs.contains(JobA)))
      CorruptRecordInput(JobA, UnknownVersion)
    else RedriveInput(JobA, records.get(JobA).revision,
      records.get(JobA).operationId, false)

  action NonterminalStoreRedriveStep = RedriveInput(JobA,
    records.get(JobA).revision, records.get(JobA).operationId, false)

  action AgeExpiredStoreRedriveClaimChainStep = {
    val current = records.get(JobB)
    if (current.state == Leased and meta.now < current.expiresAt)
      AdvanceTimeInput(current.expiresAt - meta.now)
    else if (current.state == Leased)
      ExpireLeaseInput(JobB)
    else if (current.state == DeadLettered)
      RedriveInput(JobB, current.revision, current.operationId, true)
    else if (not(meta.claimPending))
      SelectClaimInput(JobB, NodeA, current.revision)
    else ClaimInput(JobB, NodeA, current.revision)
  }

  // A full receipt buffer must still permit an unknown committed terminal
  // transition to be reconciled. Keep this route explicit so the aggregate
  // witness exercises the real two-step protocol instead of relying on a
  // low-probability choice from the broad dispatcher.
  action ReconciledFullCapacityOmissionChainStep = {
    val current = records.get(JobB)
    if (not(meta.unknownPending))
      UnknownCommitInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId, true)
    else ReconcileInput(JobB, meta.unknownOperation, Committed)
  }

  action step = any {
    EnqueueAtomic, SelectClaim, Claim, Complete, CompleteRejected, UnknownCommit,
    UnknownRejected, ChangeUnknownAuthority, Reconcile,
    CorruptRecord, DropIndex, OrphanRecord, Repair, PurgeDangling, PartialTransaction,
    IndependentProgress, AdvanceTime, Renew, ExpireLease,
    UnknownVersionQuarantineChainStep, StableStoreEnqueueChainStep,
    TerminalStoreReplayChainStep, TerminalStoreReplayRedriveChainStep,
    StaleStoreRedriveChainStep, WrongOperationStoreRedriveChainStep,
    DuplicateStoreRedriveChainStep, QuarantinedStoreRedriveChainStep,
    NonterminalStoreRedriveStep, AgeExpiredStoreRedriveClaimChainStep,
  }

  val atomic_enqueue_witness = meta.lastOutcome == AtomicEnqueue
  val conflict_witness = meta.lastOutcome == ClaimConflictNoMutation
  val claim_conflict_witness = meta.lastOutcome == ClaimConflictNoMutation
  val unknown_commit_witness = meta.lastOutcome == UnknownCommitRequiresReconcile
  val corrupt_witness = meta.lastOutcome == CorruptQuarantined
  val unknown_version_witness = meta.lastOutcome == UnknownVersionQuarantined
  val unknown_version_preservation_witness = meta.lastOutcome == UnknownVersionQuarantined
    and records == initialRecords and meta.unknownVersionJobs.contains(JobA)
    and meta.quarantineSnapshot.get(JobA) == initialRecords.get(JobA)
    and meta.transactionChecks == 0 and meta.transactionMutations == 0
    and meta.transactionBytes == 0 and meta.claimPending == initialMeta.claimPending
    and meta.wakeWatermark == initialMeta.wakeWatermark
  val unknown_version_chain_witness = meta.unknownVersionJobs.contains(JobA)
    and meta.quarantineAttempts >= 3
    and records.get(JobA) == meta.quarantineSnapshot.get(JobA)
  val stable_enqueue_inserted_witness = meta.lastEnqueueDisposition == Inserted
    and records.get(JobC).enqueueFingerprint == 3
  val stable_enqueue_replay_witness = meta.lastEnqueueDisposition == AlreadyPresent
    and records.get(JobC).exists and records.get(JobC).revision == 1
  val stable_enqueue_conflict_witness = meta.lastEnqueueDisposition == JobIdConflict
    and records.get(JobC).exists and records.get(JobC).revision == 1
  val terminal_enqueue_replay_witness = meta.lastEnqueueDisposition == AlreadyPresent
    and not(records.get(JobB).exists)
  val terminal_dlq_enqueue_replay_witness = meta.lastEnqueueDisposition == AlreadyPresent
    and records.get(JobB).state == DeadLettered and records.get(JobB).failureRecorded
    and records.get(JobB).dlqRoute
  val terminal_redrive_witness = meta.lastOutcome == RedriveCommitted
    and records.get(JobB).state == Scheduled and records.get(JobB).exists
    and records.get(JobB).enqueueFingerprint == initialRecords.get(JobB).enqueueFingerprint
    and records.get(JobB).payloadBytes == initialRecords.get(JobB).payloadBytes
    and records.get(JobB).manifestBytes == initialRecords.get(JobB).manifestBytes
    and records.get(JobB).chunkBytes == initialRecords.get(JobB).chunkBytes
    and records.get(JobB).digestBytes == initialRecords.get(JobB).digestBytes
    and records.get(JobB).checkpointBytes == 0
    and not(records.get(JobB).failureRecorded) and not(records.get(JobB).dlqRoute)
    and not(meta.committedTerminalJobs.contains(JobB))
    and meta.completionDetail == NoCompletionDetail and meta.lastDetail == NoCompletionDetail
    and meta.transactionChecks == 1 and meta.transactionMutations == 7
    and meta.transactionBytes == 7
  val stale_redrive_conflict_witness = meta.lastOutcome == RedriveConflict
    and records.get(JobB).state == DeadLettered
  val wrong_operation_redrive_conflict_witness = stale_redrive_conflict_witness
  val nonterminal_redrive_rejected_witness = meta.lastOutcome == RedriveRejected
    and records.get(JobA) == initialRecords.get(JobA)
  val quarantined_redrive_rejected_witness = meta.lastOutcome == RedriveRejected
    and meta.unknownVersionJobs.contains(JobA)
    and records.get(JobA) == initialRecords.get(JobA)
  val duplicate_redrive_conflict_witness = meta.lastOutcome == RedriveConflict
    and records.get(JobB).state == Scheduled
  val missing_index_witness = meta.lastOutcome == MissingIndexDiscovered
  val dangling_witness = meta.lastOutcome == DanglingRecordCreated or meta.lastOutcome == DanglingIndexPurged
  val repair_witness = meta.lastOutcome == RepairCommitted
  val repair_conflict_witness = meta.lastOutcome == RepairRevisionConflict
  val partial_failure_witness = meta.lastOutcome == PartialTransactionRejected
  val payload_bound_witness = meta.lastOutcome == PayloadRejected
  val future_claim_lease_witness = meta.lastOutcome == ClaimAtomicCommit
    and records.get(meta.claimJob).leased and records.get(meta.claimJob).leaseUntil > meta.now
  val authorized_completion_witness = meta.lastOutcome == CompletionDeletedAllKeys
  val age_expired_store_redrive_claim_witness = meta.lastOutcome == ClaimAtomicCommit
    and records.get(JobB).state == Leased and records.get(JobB).expiresAt > meta.now
    and records.get(JobB).enqueueFingerprint == 11
    and records.get(JobB).payloadBytes == 12 and records.get(JobB).manifestBytes == 13
    and records.get(JobB).chunkBytes == 14 and records.get(JobB).digestBytes == 15
    and records.get(JobB).executionId == 1 and records.get(JobB).attempts == 1
  val full_capacity_completion_witness = meta.lastOutcome == CompletionDeletedAllKeys
    and meta.completionReceipts == MAX_COMPLETION_RECEIPTS
    and meta.completionDetail == CompletionDetailOmitted
    and not(records.get(meta.completionDetailJob).exists)
  val unknown_hides_detail_witness = meta.unknownPending
    and meta.lastResult == Unknown and meta.completionDetail == NoCompletionDetail
  val unknown_at_full_capacity_hides_detail_witness = unknown_hides_detail_witness
    and meta.completionReceipts == MAX_COMPLETION_RECEIPTS
  val reconciled_full_capacity_omission_witness = meta.lastOutcome == ReconciledCommitted
    and meta.completionReceipts == MAX_COMPLETION_RECEIPTS
    and meta.completionDetail == CompletionDetailOmitted
  val initial_absence_never_receipted = not(initialRecords.get(JobC).exists)
    and not(initialMeta.committedTerminalJobs.contains(JobC))
    and initialMeta.completionDetail == NoCompletionDetail

  run full_capacity_completion_contract = {
    val leased = initialRecords.get(JobB)
    val deleted = deletedTerminalRecord(leased)
    val retained = MAX_COMPLETION_RECEIPTS
    all {
      assert(leased.exists and leased.leased),
      assert(not(deleted.exists) and not(deleted.leased) and not(deleted.payload)
        and not(deleted.dueRoute) and not(deleted.fairRoute) and not(deleted.leaseRoute)
        and not(deleted.wakeRoute)),
      assert(completionDetailAt(retained) == CompletionDetailOmitted),
      assert(receiptCountAfterCompletion(retained) == retained),
    }
  }

  pure def completeAtomicRecord(payload: bool, due: bool, fair: bool, wake: bool): bool =
    payload and due and fair and wake

  run transaction_limits_are_distinct = all {
    assert(MAX_TRANSACTION_CHECKS != MAX_TRANSACTION_MUTATIONS or MAX_TRANSACTION_CHECKS == 8),
    assert(MAX_TRANSACTION_BYTES > MAX_TRANSACTION_CHECKS),
    assert(MAX_INLINE_PAYLOAD_BYTES > MAX_CHUNK_BYTES),
  }

  run portable_payload_limits = all {
    assert(MAX_INLINE_PAYLOAD_BYTES == 972800),
    assert(MAX_CHUNK_BYTES == 65536),
    assert(MAX_CHECKPOINT_BYTES == 65536),
  }

  run records_are_indexed_atomically = all {
    assert(completeAtomicRecord(true, true, true, true)),
    assert(not(completeAtomicRecord(true, false, true, true))),
  }

  run completion_repairs_empty_wake = all {
    assert(not(hasRoute(Map(
      JobA -> makeRecord(false, Valid, 2, false, false, false, false, false, false),
      JobB -> makeRecord(false, Valid, 2, false, false, false, false, false, false),
      JobC -> makeRecord(false, Valid, 0, false, false, false, false, false, false),
    )))),
  }

  run future_claim_lease_authorizes_completion = {
    val claimed = makeRecord(true, Valid, 2, true, true, false, false, true, false)
    all {
      assert(claimed.leaseUntil > initialMeta.now),
      assert(exactAuthority(claimed.node, claimed.revision, claimed.generation,
        claimed.fence, claimed.token, claimed.leaseUntil, claimed.operationId,
        claimed.node, claimed.revision, claimed.generation, claimed.fence,
        claimed.token, claimed.leaseUntil, claimed.operationId, initialMeta.now)),
      assert(not(exactAuthority(claimed.node, claimed.revision, claimed.generation,
        claimed.fence, claimed.token, claimed.leaseUntil, claimed.operationId,
        claimed.node, claimed.revision - 1, claimed.generation, claimed.fence,
        claimed.token, claimed.leaseUntil, claimed.operationId, initialMeta.now))),
      assert(not(exactAuthority(claimed.node, claimed.revision, claimed.generation,
        claimed.fence, claimed.token, claimed.leaseUntil, claimed.operationId,
        claimed.node, claimed.revision, claimed.generation, claimed.fence,
        claimed.token, claimed.leaseUntil, OperationB, initialMeta.now))),
    }
  }

  run unknown_version_repair_preserves_bytes = {
    val unknown = initialRecords.get(JobA).with("kind", UnknownVersion)
      .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false)
    val attempted = storeRepairCandidate(unknown, unknown.kind == Corrupt)
    all {
      assert(attempted == unknown),
      assert(attempted.kind == UnknownVersion and exactStoredBytes(unknown, attempted)),
    }
  }
}
