/// Durable lifecycle protocol for at-least-once background jobs.
///
/// A job record is authoritative.  Its state, revision, generation, fence,
/// lease token, operation identity, payload, and routing keys move together
/// through conditional transitions.  A node, generation, fence, token, and
/// unexpired lease are all required for a worker mutation; none is a substitute
/// for another.  The finite model represents a real checked compare-and-swap,
/// not a process-local boolean lock.
///
/// Enqueue publishes payload, due, fairness, and wake routes as one durable
/// result.  Claim changes due routing to a lease route.  Completion removes
/// every live route before a receipt can be exposed.  Retry keeps the logical
/// execution identity and allocates a fresh attempt identity.  Unknown commit
/// records the affected job and stable operation identity; reconciliation reads
/// that same job and operation and never invokes a handler again.  Corrupt or
/// unknown-version records fail closed and can only be restored by a revision
/// checked repair for understood corruption. Unknown newer versions remain
/// quarantined without interpretation or mutation. This abstraction does not
/// claim byte encoding, crypto, or exactly-once external effects.
module job_lifecycle {
  import bg_jobs_types.* from "./bg-jobs-types"

  type Job = {
    state: JobState,
    node: Node,
    revision: int,
    generation: int,
    fence: int,
    token: int,
    leaseUntil: int,
    dueAt: int,
    expiresAt: int,
    executionId: int,
    attemptId: int,
    attempts: int,
    record: RecordKind,
    payload: bool,
    dueRoute: bool,
    leaseRoute: bool,
    fairRoute: bool,
    wakeRoute: bool,
    checkpointBytes: int,
    failureRecorded: bool,
    completionReceipt: bool,
    cancelRequested: bool,
    operationId: OperationId,
    enqueueFingerprint: int,
  }

  type Meta = {
    now: int,
    paused: bool,
    dedupeActive: bool,
    dedupeJob: JobId,
    dedupeExpired: bool,
    // Lease tokens are opaque and absent from non-leased observations. This
    // connector-local progression keeps the next finite label explicit so a
    // lease expiry can retain identity history without inventing a token in
    // the projected scheduled record.
    tokenProgression: JobId -> int,
    unknownVersionJobs: Set[JobId],
    quarantineSnapshot: JobId -> Job,
    quarantineAttempts: int,
    unrelatedProgress: int,
    unknownPending: bool,
    unknownJob: JobId,
    unknownOperation: OperationId,
    unknownNode: Node,
    unknownRevision: int,
    unknownGeneration: int,
    unknownFence: int,
    unknownToken: int,
    unknownLeaseUntil: int,
    unknownAfterCommit: bool,
    unknownReadback: StoreResult,
    completionPending: bool,
    completionJob: JobId,
    completionOperation: OperationId,
    completionRevision: int,
    completionGeneration: int,
    completionDetail: CompletionDetail,
    completionDetailJob: JobId,
    completionOmissions: int,
    committedTerminalJobs: Set[JobId],
    claimPending: bool,
    claimJob: JobId,
    claimRevision: int,
    claimReader: Node,
    lastAttemptRevision: int,
    lastAttemptApplied: bool,
    lastAttemptOperation: OperationId,
    lastAttemptJob: JobId,
    completionAuthorityRecorded: bool,
    completionAuthorityNow: int,
    completionNode: Node,
    completionFence: int,
    completionToken: int,
    completionLeaseUntil: int,
    completionPresentedNode: Node,
    completionPresentedRevision: int,
    completionPresentedGeneration: int,
    completionPresentedFence: int,
    completionPresentedToken: int,
    completionPresentedLeaseUntil: int,
    completionPresentedOperation: OperationId,
    presentedNode: Node,
    presentedGeneration: int,
    presentedFence: int,
    presentedToken: int,
    presentedLeaseUntil: int,
    staleNode: Node,
    staleRevision: int,
    staleGeneration: int,
    staleFence: int,
    staleToken: int,
    staleLeaseUntil: int,
    staleOperation: OperationId,
    lastEnqueueDisposition: EnqueueDisposition,
    lastResult: StoreResult,
    lastOutcome: LifecycleOutcome,
  }

  type LifecycleOutcome = Initialised | EnqueueCommitted | EnqueueFutureCommitted
    | EnqueueDedupeCommitted | EnqueueDedupeConflict | EnqueueRejected
    | EnqueueAlreadyPresent | EnqueueJobIdConflict
    | ClaimSelected | ClaimCommitted | ClaimConflict | Renewed | RenewRejected | CheckpointCommitted
    | CheckpointBoundRejected | CheckpointAuthorityRejected | CompletionDeleted
    | CompletionRejected | RetryTransient | RetryThrottled | RetryAmbiguous
    | PermanentDeadLetter | LeaseExpired | CancelCommitted | CancelRequested | LeasedCancelled
    | LeasedCancelRejected
    | Redriven | RedriveConflict | RedriveRejected
    | UnknownBeforeCommit | UnknownAfterCommit | UnknownReconciled
    | UnknownConflictReconciled | UnknownAuthorityChanged | StaleWriteRejected
    | RepairCommitted | RepairConflict
    | DedupeRegistered | DedupeReplayExisting | DedupeIdConflict | DedupeRetentionExpired | DedupeNotFound
    | QueuePaused | QueueResumed | PartialCommitRejected | CorruptQuarantined
    | UnknownVersionQuarantined | ScheduledExpired
    | TimeAdvanced

  var jobs: JobId -> Job
  var meta: Meta

  pure def makeJob(state, node, revision, dueAt, leaseUntil, executionId, attemptId, attempts) = {
    state: state,
    node: node,
    revision: revision,
    generation: if (state == Leased) 1 else 0,
    // A public claim increments the semantic fence from the persisted
    // record's previous value (zero for a scheduled record).
    fence: if (state == Leased) 1 else 0,
    token: if (state == Leased) 3 else 0,
    leaseUntil: leaseUntil,
    dueAt: dueAt,
    expiresAt: if (state == Absent) 0 else MAX_JOB_AGE_TICKS,
    executionId: executionId,
    attemptId: attemptId,
    attempts: attempts,
    record: if (state == Absent) Missing else Valid,
    payload: state != Absent,
    dueRoute: state == Scheduled or state == RetryWaiting,
    leaseRoute: state == Leased,
    fairRoute: state == Scheduled or state == RetryWaiting,
    wakeRoute: state == Scheduled or state == RetryWaiting,
    checkpointBytes: 0,
    failureRecorded: state == DeadLettered,
    completionReceipt: false,
    cancelRequested: false,
    operationId: OperationA,
    // The production record does not persist a producer fingerprint.  The
    // lifecycle connector therefore projects the neutral value and checks
    // replay against the durable immutable fields instead.
    enqueueFingerprint: 0,
  }

  pure def initialJobs = Map(
    JobA -> makeJob(Scheduled, NodeA, 1, 0, 0, 1, 0, 0),
    JobB -> makeJob(Leased, NodeA, 1, 0, 3, 2, 1, 1),
    JobC -> makeJob(Absent, NodeA, 0, 0, 0, 0, 0, 0),
  )

  // Opaque execution IDs are normalized only for the finite model.  The
  // allocator derives the next model identity from the complete observed
  // job map, preserving equality for reused IDs without inspecting bytes.
  pure def nextExecutionId(currentJobs) = JOBS.fold(0,
    (highest, job) => max(highest, currentJobs.get(job).executionId)) + 1

  pure def initialMeta = {
    now: 0,
    paused: false,
    dedupeActive: false,
    dedupeJob: JobA,
    dedupeExpired: false,
    tokenProgression: Map(JobA -> 0, JobB -> 3, JobC -> 0),
    unknownVersionJobs: Set(),
    quarantineSnapshot: initialJobs,
    quarantineAttempts: 0,
    unrelatedProgress: 0,
    unknownPending: false,
    unknownJob: JobA,
    unknownOperation: OperationA,
    unknownNode: NodeA,
    unknownRevision: 0,
    unknownGeneration: 0,
    unknownFence: 0,
    unknownToken: 0,
    unknownLeaseUntil: 0,
    unknownAfterCommit: false,
    unknownReadback: Rejected,
    completionPending: false,
    completionJob: JobA,
    completionOperation: OperationA,
    completionRevision: 0,
    completionGeneration: 0,
    completionDetail: NoCompletionDetail,
    completionDetailJob: JobA,
    completionOmissions: 0,
    committedTerminalJobs: Set(),
    claimPending: false,
    claimJob: JobA,
    claimRevision: 1,
    claimReader: NodeA,
    lastAttemptRevision: 0,
    lastAttemptApplied: false,
    lastAttemptOperation: OperationA,
    lastAttemptJob: JobA,
    completionAuthorityRecorded: false,
    completionAuthorityNow: 0,
    completionNode: NodeA,
    completionFence: 0,
    completionToken: 0,
    completionLeaseUntil: 0,
    completionPresentedNode: NodeA,
    completionPresentedRevision: 0,
    completionPresentedGeneration: 0,
    completionPresentedFence: 0,
    completionPresentedToken: 0,
    completionPresentedLeaseUntil: 0,
    completionPresentedOperation: OperationA,
    presentedNode: NodeA,
    presentedGeneration: 0,
    presentedFence: 0,
    presentedToken: 0,
    presentedLeaseUntil: 0,
    staleNode: NodeA,
    staleRevision: 0,
    staleGeneration: 0,
    staleFence: 0,
    staleToken: 0,
    staleLeaseUntil: 0,
    staleOperation: OperationA,
    lastEnqueueDisposition: NotEnqueue,
    lastResult: Committed,
    lastOutcome: Initialised,
  }

  pure def result(metaState, result, outcome) =
    metaState.with("lastResult", result).with("lastOutcome", outcome)
      .with("lastEnqueueDisposition", NotEnqueue)
      .with("completionDetail", NoCompletionDetail)

  pure def terminalResult(metaState, storeResult, lifecycleOutcome) =
    metaState.with("lastResult", storeResult).with("lastOutcome", lifecycleOutcome)
      .with("lastEnqueueDisposition", NotEnqueue)

  /// Concrete successful-completion reducer shared by Complete, Handle and
  /// cross-product parity checks.
  pure def completedLifecycleJob(current, operation) = {
    val terminal = terminalKernel(current.revision, false, 0,
      current.state == Leased)
    current.with("state", Absent).with("revision", terminal.nextRevision)
      .with("payload", terminal.keepPayload).with("dueRoute", terminal.dueRoute)
      .with("fairRoute", terminal.fairRoute).with("leaseRoute", terminal.leaseRoute)
      .with("wakeRoute", terminal.wakeRoute).with("leaseUntil", 0)
      .with("dueAt", 0)
      // A successful receipt has no expiry field. The absent projection must
      // therefore use the public terminal value rather than retain the age
      // window from the leased record.
      .with("expiresAt", 0)
      .with("checkpointBytes", 0).with("failureRecorded", false)
      .with("completionReceipt", false).with("cancelRequested", false)
      .with("operationId", operation)
  }

  /// Canonical durable DLQ reducer shared by handler failure, scheduled age
  /// expiry and exhausted lease expiry. Payload/reference and failure evidence
  /// survive while every live route and lease authority is released.
  pure def deadLetteredLifecycleJob(current) = current.with("state", DeadLettered)
    .with("revision", current.revision + 1).with("payload", true)
    .with("failureRecorded", true).with("dueRoute", false)
    .with("fairRoute", false).with("leaseRoute", false).with("wakeRoute", false)
    .with("leaseUntil", 0).with("cancelRequested", false)
    // The lease route is released, but the operation marker retains the
    // fence high-water authority for a later redrive or reclaim.
    .with("token", 0)

  /// Canonical handler reducer. The action and cross-family parity both call
  /// this function, so DLQ commitment, completion detail state, checkpoint
  /// preservation, authority release, and result classification cannot drift.
  pure def applyLifecycleHandler(currentJobs, currentMeta, job, node,
      presentedRevision, presentedGeneration, presentedFence, presentedToken,
      presentedLeaseUntil, operation, handler) = {
    val current = currentJobs.get(job)
    val blockedInput = (currentMeta.unknownPending and job == currentMeta.unknownJob)
      or currentMeta.unknownVersionJobs.contains(job)
    // A committed cooperative-cancellation marker is an authority change.
    // No handler outcome may replace or clear it. Leased acknowledgement or
    // control-plane recovery after lease expiry consumes the marker.
    val authority = not(blockedInput) and not(current.cancelRequested)
      and current.state == Leased and current.record == Valid
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
        operation, currentMeta.now)
    val retry = authority and isRetryable(handler) and current.attempts < MAX_ATTEMPTS
    val dead = authority and (handler == Permanent or (isRetryable(handler) and not(retry)))
    val success = authority and handler == Success
    val updatedJob = if (success) completedLifecycleJob(current, operation)
      else if (retry)
        current.with("state", RetryWaiting).with("revision", current.revision + 1)
          .with("dueAt", currentMeta.now + 1).with("dueRoute", true)
          .with("fairRoute", true).with("wakeRoute", true).with("leaseRoute", false)
          .with("leaseUntil", 0).with("token", 0)
          .with("cancelRequested", false)
      else if (dead) deadLetteredLifecycleJob(current) else current
    val releasedTokenMeta = if (retry or dead)
      currentMeta.with("tokenProgression", update(currentMeta.tokenProgression, job, 0))
        .with("committedTerminalJobs", if (dead)
          currentMeta.committedTerminalJobs.union(Set(job))
          else currentMeta.committedTerminalJobs)
      else currentMeta
    val terminalMeta = currentMeta.with("completionPending", true)
      .with("completionJob", job).with("completionOperation", operation)
      .with("completionRevision", current.revision + 1)
      .with("completionGeneration", current.generation)
      .with("completionDetail", NoCompletionDetail)
      .with("completionAuthorityRecorded", true)
      .with("completionAuthorityNow", currentMeta.now)
      .with("completionNode", current.node).with("completionFence", current.fence)
      .with("completionToken", current.token).with("completionLeaseUntil", current.leaseUntil)
      .with("completionPresentedNode", node)
      .with("completionPresentedRevision", presentedRevision)
      .with("completionPresentedGeneration", presentedGeneration)
      .with("completionPresentedFence", presentedFence)
      .with("completionPresentedToken", presentedToken)
      .with("completionPresentedLeaseUntil", presentedLeaseUntil)
      .with("completionPresentedOperation", operation)
      .with("staleNode", current.node).with("staleRevision", current.revision)
      .with("staleGeneration", current.generation).with("staleFence", current.fence)
      .with("staleToken", current.token).with("staleLeaseUntil", current.leaseUntil)
      .with("staleOperation", current.operationId).with("presentedNode", node)
      .with("lastAttemptRevision", presentedRevision)
      .with("presentedGeneration", presentedGeneration)
      .with("presentedFence", presentedFence).with("presentedToken", presentedToken)
      .with("presentedLeaseUntil", presentedLeaseUntil)
      .with("lastAttemptOperation", operation)
      .with("committedTerminalJobs", currentMeta.committedTerminalJobs.union(Set(job)))
    val nextMeta = if (success)
      terminalResult(terminalMeta, Committed, CompletionDeleted)
      else result(releasedTokenMeta,
        if (authority) Committed else Conflict,
        if (retry and handler == Transient) RetryTransient
        else if (retry and handler == Throttled) RetryThrottled
        else if (retry) RetryAmbiguous else if (dead) PermanentDeadLetter
        else CompletionRejected)
    { jobs: if (authority) update(currentJobs, job, updatedJob) else currentJobs,
      meta: nextMeta, allowed: authority }
  }

  /// Canonical redrive reducer. Expected revision and operation are request
  /// inputs, never read back from the same current record as their own proof.
  /// A valid redrive clears only prior execution/terminal state and grants a
  /// fresh age window while preserving enqueue fingerprint and payload.
  pure def applyLifecycleRedrive(currentJobs, currentMeta, job,
      expectedRevision, expectedOperation, reuseExecution) = {
    val current = currentJobs.get(job)
    val blockedInput = (currentMeta.unknownPending and job == currentMeta.unknownJob)
      or currentMeta.unknownVersionJobs.contains(job)
    val effect = redriveKernel(current.state, current.record, blockedInput,
      current.revision, current.operationId, expectedRevision, expectedOperation,
      current.generation, current.fence, current.token, current.executionId,
      reuseExecution, currentMeta.now)
    val nextExecution = if (effect.allowed and not(reuseExecution))
      nextExecutionId(currentJobs) else effect.nextExecutionId
    val updatedJob = current.with("state", Scheduled).with("revision", effect.nextRevision)
      .with("payload", true).with("dueRoute", effect.dueRoute)
      .with("fairRoute", effect.fairRoute).with("wakeRoute", effect.wakeRoute)
      .with("leaseRoute", effect.leaseRoute).with("dueAt", currentMeta.now)
      .with("expiresAt", effect.nextExpiresAt)
      .with("attempts", effect.nextAttempts).with("attemptId", effect.nextAttemptId)
      .with("leaseUntil", 0).with("checkpointBytes", 0).with("failureRecorded", false)
      .with("cancelRequested", false).with("completionReceipt", false)
      // Redrive writes a fresh operation marker while preserving its fence
      // high-water value until the next claim advances it.
      .with("generation", effect.nextGeneration).with("fence", current.fence)
      .with("token", 0).with("executionId", nextExecution)
      .with("operationId", nextOperationId(current.operationId))
    val clearedMeta = currentMeta
      .with("tokenProgression", if (effect.allowed)
        update(currentMeta.tokenProgression, job, 0) else currentMeta.tokenProgression)
      .with("claimPending", if (effect.allowed and currentMeta.claimJob == job)
        false else currentMeta.claimPending)
      .with("completionPending", if (effect.allowed and currentMeta.completionJob == job)
        false else currentMeta.completionPending)
      .with("completionAuthorityRecorded", if (effect.allowed
        and currentMeta.completionJob == job) false else currentMeta.completionAuthorityRecorded)
      .with("completionDetail", if (effect.allowed) NoCompletionDetail
        else currentMeta.completionDetail)
      .with("completionDetailJob", if (effect.allowed) job else currentMeta.completionDetailJob)
      .with("committedTerminalJobs", if (effect.allowed)
        currentMeta.committedTerminalJobs.filter(candidate => candidate != job)
        else currentMeta.committedTerminalJobs)
    val nextResult = if (effect.allowed) Committed
      else if (effect.authorityConflict) Conflict else Rejected
    val nextOutcome = if (effect.allowed) Redriven
      else if (effect.authorityConflict) RedriveConflict else RedriveRejected
    { jobs: if (effect.allowed) update(currentJobs, job, updatedJob) else currentJobs,
      meta: result(clearedMeta, nextResult, nextOutcome), allowed: effect.allowed }
  }

  def claimableJobs = JOBS.filter(job =>
    not(meta.paused) and not(blocked(job)) and jobs.get(job).record == Valid
      and not(meta.unknownVersionJobs.contains(job))
      and (jobs.get(job).state == Scheduled or jobs.get(job).state == RetryWaiting)
      and jobs.get(job).payload and jobs.get(job).dueRoute and jobs.get(job).fairRoute
      and jobs.get(job).dueAt <= meta.now and meta.now < jobs.get(job).expiresAt
      and jobs.get(job).attempts < MAX_ATTEMPTS
  )

  def leasedJobs = JOBS.filter(job => jobs.get(job).state == Leased)
  def activeJobs = JOBS.filter(job => jobs.get(job).state != Absent)
  def terminalJobs = JOBS.filter(job => isTerminal(jobs.get(job).state))
  def blocked(job) = (meta.unknownPending and job == meta.unknownJob)
    or meta.unknownVersionJobs.contains(job)
  def completionReceiptCount = JOBS.filter(job => jobs.get(job).completionReceipt).size()

  // State-to-route equivalence is executable, so a missing route cannot make
  // an unrelated job unavailable and a stale route cannot authorize a claim.
  val inv_route_equivalence = JOBS.forall(job =>
      (jobs.get(job).state == Absent implies not(jobs.get(job).payload) and not(jobs.get(job).dueRoute)
        and not(jobs.get(job).leaseRoute) and not(jobs.get(job).fairRoute) and not(jobs.get(job).wakeRoute))
      and (jobs.get(job).state == Leased implies jobs.get(job).payload and jobs.get(job).leaseRoute
        and not(jobs.get(job).dueRoute) and not(jobs.get(job).fairRoute) and not(jobs.get(job).wakeRoute))
      and ((jobs.get(job).state == Scheduled or jobs.get(job).state == RetryWaiting)
        and jobs.get(job).record == Valid implies jobs.get(job).payload and jobs.get(job).dueRoute
        and jobs.get(job).fairRoute and jobs.get(job).wakeRoute and not(jobs.get(job).leaseRoute))
      and (isTerminal(jobs.get(job).state) implies not(jobs.get(job).dueRoute)
        and not(jobs.get(job).leaseRoute) and not(jobs.get(job).fairRoute) and not(jobs.get(job).wakeRoute))
      and (jobs.get(job).state == DeadLettered implies
        jobs.get(job).payload and jobs.get(job).failureRecorded)
  )
  // Generation and fence are semantic monotonic authority values. Lease
  // tokens are opaque identities; the connector maps each job-scoped token
  // bijectively to the finite labels tracked by tokenProgression. The labels
  // have no numeric relationship with generation.
  val inv_authority = JOBS.forall(job =>
      jobs.get(job).revision >= 0 and jobs.get(job).generation >= 0 and jobs.get(job).fence >= 0
      and jobs.get(job).token >= 0 and jobs.get(job).leaseUntil >= 0
      and (jobs.get(job).state != Leased or (
        jobs.get(job).record == Valid and jobs.get(job).generation > 0 and jobs.get(job).fence > 0
        and jobs.get(job).token > 0
          and jobs.get(job).token == meta.tokenProgression.get(job)
          and (jobs.get(job).node == NodeA or jobs.get(job).node == NodeB)
      ))
  ) and (not(meta.completionAuthorityRecorded and meta.lastOutcome == CompletionDeleted)
    or exactAuthority(meta.completionNode,
    meta.completionRevision - 1, meta.completionGeneration, meta.completionFence,
    meta.completionToken, meta.completionLeaseUntil, meta.completionOperation,
    meta.completionPresentedNode, meta.completionPresentedRevision,
    meta.completionPresentedGeneration, meta.completionPresentedFence,
    meta.completionPresentedToken, meta.completionPresentedLeaseUntil,
    meta.completionPresentedOperation,
    meta.completionAuthorityNow))
  val inv_attempt_identity = JOBS.forall(job =>
      (jobs.get(job).state == Absent or jobs.get(job).executionId > 0)
      and jobs.get(job).attempts >= 0
      and jobs.get(job).attempts <= MAX_ATTEMPTS and jobs.get(job).attemptId == jobs.get(job).attempts
  )
  val inv_retry_bound = JOBS.forall(job =>
    jobs.get(job).state != RetryWaiting or jobs.get(job).attempts < MAX_ATTEMPTS
  )
  val inv_checkpoint_bound = JOBS.forall(job =>
    jobs.get(job).checkpointBytes >= 0 and jobs.get(job).checkpointBytes <= MAX_CHECKPOINT_BYTES
  )
  val inv_invalid_fail_closed = JOBS.forall(job =>
    (jobs.get(job).record == Valid or (jobs.get(job).state != Leased
      and not(jobs.get(job).leaseRoute)))
      and (not(meta.unknownVersionJobs.contains(job))
        or jobs.get(job) == meta.quarantineSnapshot.get(job))
  )
  val inv_receipt_after_delete = JOBS.forall(job =>
    not(jobs.get(job).completionReceipt) or (
      jobs.get(job).state == Absent and not(jobs.get(job).payload) and not(jobs.get(job).dueRoute)
        and not(jobs.get(job).fairRoute) and not(jobs.get(job).leaseRoute)
        and not(jobs.get(job).wakeRoute)
    )
  )
  val inv_unknown_is_scoped = not(meta.unknownPending) or (
    jobs.get(meta.unknownJob).operationId == meta.unknownOperation
      and jobs.get(meta.unknownJob).node == meta.unknownNode
      and jobs.get(meta.unknownJob).generation == meta.unknownGeneration
      and jobs.get(meta.unknownJob).fence == meta.unknownFence
      and jobs.get(meta.unknownJob).token == meta.unknownToken
      and (if (meta.unknownReadback == AuthorityChanged)
        jobs.get(meta.unknownJob).revision != (if (meta.unknownAfterCommit)
          meta.unknownRevision + 1 else meta.unknownRevision)
        else if (meta.unknownAfterCommit) jobs.get(meta.unknownJob).state == Absent
          and jobs.get(meta.unknownJob).revision == meta.unknownRevision + 1
          and jobs.get(meta.unknownJob).leaseUntil == 0
        else jobs.get(meta.unknownJob).state == Leased
          and jobs.get(meta.unknownJob).revision == meta.unknownRevision
          and jobs.get(meta.unknownJob).leaseUntil == meta.unknownLeaseUntil)
  )
  val inv_claim_read = JOBS.contains(meta.claimJob) and meta.claimRevision >= 0
    and (not(meta.claimPending) or jobs.get(meta.claimJob).state != Absent)
  val inv_receipt_budget = completionReceiptCount >= 0
    and completionReceiptCount <= MAX_COMPLETION_RECEIPTS
  val inv_completion_detail = meta.completionOmissions >= 0
    and (meta.completionDetail != NoCompletionDetail implies
      meta.committedTerminalJobs.contains(meta.completionDetailJob))
    and (meta.completionDetail == CompletionDetailReturned implies
      jobs.get(meta.completionDetailJob).completionReceipt)
    and (meta.completionDetail == CompletionDetailOmitted implies
      completionReceiptCount == MAX_COMPLETION_RECEIPTS)
    and (meta.unknownPending and meta.completionDetailJob == meta.unknownJob implies
      meta.completionDetail == NoCompletionDetail)
  val inv_stale_rejection = meta.lastOutcome != StaleWriteRejected or (
    meta.lastResult == Conflict and not(meta.lastAttemptApplied) and meta.lastAttemptRevision == meta.staleRevision + 1
      and jobs.get(meta.lastAttemptJob).revision == meta.staleRevision
      and jobs.get(meta.lastAttemptJob).generation == meta.staleGeneration
      and jobs.get(meta.lastAttemptJob).fence == meta.staleFence
      and jobs.get(meta.lastAttemptJob).token == meta.staleToken
      and jobs.get(meta.lastAttemptJob).leaseUntil == meta.staleLeaseUntil
      and jobs.get(meta.lastAttemptJob).operationId == meta.staleOperation
  )
  val inv_clock = meta.now >= 0
  val inv_quarantine = meta.quarantineAttempts >= 0
    and meta.unknownVersionJobs.forall(job =>
      jobs.get(job) == meta.quarantineSnapshot.get(job)
        and not(claimableJobs.contains(job)))
  val inv = and {
    inv_route_equivalence,
    inv_authority,
    inv_attempt_identity,
    inv_retry_bound,
    inv_checkpoint_bound,
    inv_invalid_fail_closed,
    inv_receipt_after_delete,
    inv_unknown_is_scoped,
    inv_claim_read,
    inv_receipt_budget,
    inv_completion_detail,
    inv_stale_rejection,
    inv_quarantine,
    inv_clock,
  }
  val inv_except_authority = and {
    inv_route_equivalence, inv_attempt_identity, inv_retry_bound,
    inv_checkpoint_bound, inv_invalid_fail_closed, inv_receipt_after_delete,
    inv_unknown_is_scoped, inv_claim_read, inv_receipt_budget,
    inv_completion_detail, inv_stale_rejection, inv_quarantine, inv_clock,
  }

  action init = all {
    jobs' = initialJobs,
    meta' = initialMeta,
  }

  action EnqueueInput(job: JobId, due: int, operation: OperationId,
      withDedupe: bool, fingerprint: int): bool = {
    val current = jobs.get(job)
    // JobSystem does not accept or persist a producer fingerprint.  Replay
    // compares the durable immutable enqueue fields; this finite connector
    // exposes the scheduled timestamp and the fixed payload shape directly.
    // `fingerprint` remains in the command only as an opaque generator token.
    val present = current.state != Absent
    val identical = present and current.record == Valid and not(withDedupe)
      and due == current.dueAt
    val disposition = if (not(present)) Inserted
      else if (identical) AlreadyPresent else JobIdConflict
    val keyConflict = withDedupe and meta.dedupeActive and job != meta.dedupeJob
    val allowed = not(blocked(job)) and not(present) and not(keyConflict)
      and current.record != UnknownVersion
    val updatedJob = current
      .with("state", Scheduled)
      // A newly materialized record starts at revision zero. Existing records
      // are never replaced by enqueue, so this branch is only the new-record
      // path.
      .with("revision", 0)
      .with("dueAt", due)
      .with("expiresAt", meta.now + MAX_JOB_AGE_TICKS)
      .with("record", Valid)
      .with("payload", true)
      .with("dueRoute", true)
      .with("leaseRoute", false)
      .with("fairRoute", true)
      .with("wakeRoute", true)
      .with("checkpointBytes", 0)
      .with("failureRecorded", false)
      .with("completionReceipt", false)
      .with("cancelRequested", false)
      .with("attempts", 0)
      .with("attemptId", 0)
      .with("enqueueFingerprint", 0)
      .with("executionId", nextExecutionId(jobs))
      // Enqueue tombstones do not retain the caller's operation identity.
      .with("operationId", OperationA)
    all {
      jobs' = if (allowed) update(jobs, job, updatedJob) else jobs,
      meta' = if (allowed)
        result(meta.with("dedupeActive", withDedupe or meta.dedupeActive)
          .with("dedupeJob", if (withDedupe) job else meta.dedupeJob)
          .with("dedupeExpired", false), Committed,
          if (due > meta.now and withDedupe) EnqueueDedupeCommitted
          else if (due > meta.now) EnqueueFutureCommitted else EnqueueCommitted)
          .with("lastEnqueueDisposition", Inserted)
        else if (identical) result(meta, Committed, EnqueueAlreadyPresent)
          .with("lastEnqueueDisposition", AlreadyPresent)
        else result(meta.with("quarantineAttempts", if (meta.unknownVersionJobs.contains(job))
          meta.quarantineAttempts + 1 else meta.quarantineAttempts),
          if (blocked(job)) Conflict else if (present) Rejected else Conflict,
          if (blocked(job)) EnqueueRejected else if (present) EnqueueJobIdConflict
          else if (keyConflict) EnqueueDedupeConflict else EnqueueRejected)
          .with("lastEnqueueDisposition", if (not(blocked(job)) and present)
            JobIdConflict else NotEnqueue),
    }
  }

  action Enqueue = {
    nondet job = JOBS.oneOf()
    nondet due = Set(meta.now, meta.now + 3, meta.now + MAX_JOB_AGE_TICKS).oneOf()
    nondet operation = OPERATIONS.oneOf()
    nondet withDedupe = bools.oneOf()
    nondet fingerprint = Set(1, 2, 3).oneOf()
    EnqueueInput(job, due, operation, withDedupe, fingerprint)
  }

  action SelectClaimInput(job: JobId, reader: Node, revision: int): bool = {
    val current = jobs.get(job)
    all {
      claimableJobs.contains(job),
      revision == current.revision,
      meta' = result(meta.with("claimPending", true).with("claimJob", job)
        .with("claimRevision", revision).with("claimReader", reader),
        Committed, ClaimSelected)
        .with("lastOutcome", ClaimSelected),
      jobs' = jobs,
    }
  }

  action SelectClaim = {
    nondet job = claimableJobs.oneOf()
    nondet reader = NODES.oneOf()
    SelectClaimInput(job, reader, jobs.get(job).revision)
  }

  action ClaimInput(job: JobId, contender: Node, expectedRevision: int): bool = {
    val current = jobs.get(job)
    val sameRead = meta.claimPending and expectedRevision == meta.claimRevision
    val allowed = not(blocked(job)) and sameRead and contender == meta.claimReader
      and current.record == Valid and current.state != Leased
      and current.dueRoute and expectedRevision == current.revision
      and current.dueAt <= meta.now and current.attempts < MAX_ATTEMPTS
    val effect = claimAuthorityKernel(current.revision, current.generation,
      current.fence, meta.tokenProgression.get(job), current.attempts,
      current.attemptId, meta.now)
    val competing = not(blocked(job)) and expectedRevision == meta.claimRevision
      and contender != current.node and (not(meta.claimPending)
        or current.revision != meta.claimRevision or current.state == Leased)
    val updatedJob = current
      .with("state", Leased)
      .with("node", contender)
      .with("revision", effect.nextRevision)
      .with("generation", effect.nextGeneration)
      .with("fence", effect.nextFence)
      .with("token", effect.nextToken)
      .with("leaseUntil", effect.nextLeaseUntil)
      .with("dueRoute", false)
      .with("leaseRoute", true)
      .with("fairRoute", false)
      .with("wakeRoute", false)
      .with("attempts", effect.nextAttempts)
      .with("attemptId", effect.nextAttemptId)
    all {
      allowed or competing,
      jobs' = if (allowed) update(jobs, job, updatedJob) else jobs,
      meta' = if (allowed)
        result(meta.with("claimPending", false)
          .with("tokenProgression", update(meta.tokenProgression, job, effect.nextToken)),
          Committed, ClaimCommitted)
        else result(meta.with("claimPending", false), Conflict, ClaimConflict),
    }
  }


  action Claim = {
    nondet contender = NODES.oneOf()
    nondet expectedRevision = Set(meta.claimRevision, meta.claimRevision - 1).oneOf()
    ClaimInput(meta.claimJob, contender, expectedRevision)
  }

  action RenewInput(job: JobId, node: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, presentedOperation: OperationId): bool = {
    val current = jobs.get(job)
    val exact = not(blocked(job)) and not(current.cancelRequested) and current.state == Leased
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
        presentedOperation, meta.now)
    all {
      jobs' = if (exact) update(jobs, job,
        current.with("leaseUntil", max(current.leaseUntil, meta.now + 3))
          .with("revision", current.revision + 1)) else jobs,
      meta' = result(meta, if (exact) Committed else Conflict, if (exact) Renewed else RenewRejected),
    }
  }

  action Renew = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(jobs.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(jobs.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(jobs.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(jobs.get(job).leaseUntil).oneOf()
    nondet presentedOperation = OPERATIONS.oneOf()
    RenewInput(job, node, presentedRevision, presentedGeneration, presentedFence,
      presentedToken, presentedLeaseUntil, presentedOperation)
  }

  action CheckpointInput(job: JobId, node: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, presentedOperation: OperationId, bytes: int): bool = {
    val current = jobs.get(job)
    val exact = current.state == Leased and not(blocked(job)) and not(current.cancelRequested)
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
        presentedOperation, meta.now)
    val allowed = exact and bytes <= MAX_CHECKPOINT_BYTES
    all {
      jobs' = if (allowed) update(jobs, job, current.with("checkpointBytes", bytes).with("revision", current.revision + 1)) else jobs,
      meta' = result(meta, if (allowed) Committed else Conflict,
        if (allowed) CheckpointCommitted else if (bytes > MAX_CHECKPOINT_BYTES)
          CheckpointBoundRejected else CheckpointAuthorityRejected),
    }
  }

  action Checkpoint = {
    nondet job = leasedJobs.oneOf()
    nondet bytes = Set(0, MAX_CHECKPOINT_BYTES, MAX_CHECKPOINT_BYTES + 1).oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(jobs.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(jobs.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(jobs.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(jobs.get(job).leaseUntil).oneOf()
    nondet presentedOperation = OPERATIONS.oneOf()
    CheckpointInput(job, node, presentedRevision, presentedGeneration, presentedFence,
      presentedToken, presentedLeaseUntil, presentedOperation, bytes)
  }

  action CompleteInput(job: JobId, node: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId): bool = {
    val current = jobs.get(job)
    val allowed = not(blocked(job)) and not(current.cancelRequested) and current.state == Leased
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
        operation, meta.now)
    val terminal = terminalKernel(current.revision, false, completionReceiptCount,
      current.state == Leased)
    val updatedJob = completedLifecycleJob(current, operation)
    all {
      jobs' = if (allowed) update(jobs, job, updatedJob) else jobs,
      meta' = if (allowed) terminalResult(meta.with("completionPending", true)
        .with("completionJob", job).with("completionOperation", operation)
        .with("completionRevision", current.revision + 1)
        .with("completionGeneration", current.generation)
        .with("completionDetail", NoCompletionDetail)
        .with("completionAuthorityRecorded", true)
        .with("completionAuthorityNow", meta.now)
        .with("completionNode", current.node).with("completionFence", current.fence)
        .with("completionToken", current.token)
        .with("completionLeaseUntil", current.leaseUntil)
        .with("completionPresentedNode", node)
        .with("completionPresentedRevision", presentedRevision)
        .with("completionPresentedGeneration", presentedGeneration)
        .with("completionPresentedFence", presentedFence)
        .with("completionPresentedToken", presentedToken)
        .with("completionPresentedLeaseUntil", presentedLeaseUntil)
        .with("completionPresentedOperation", operation)
        .with("staleNode", current.node).with("staleRevision", current.revision)
        .with("staleGeneration", current.generation).with("staleFence", current.fence)
        .with("staleToken", current.token).with("staleLeaseUntil", current.leaseUntil)
        .with("staleOperation", current.operationId).with("presentedNode", node)
        .with("lastAttemptRevision", presentedRevision)
        .with("presentedGeneration", presentedGeneration)
        .with("presentedFence", presentedFence).with("presentedToken", presentedToken)
        .with("presentedLeaseUntil", presentedLeaseUntil)
        .with("lastAttemptOperation", operation)
        .with("committedTerminalJobs", meta.committedTerminalJobs.union(Set(job))),
        Committed, CompletionDeleted)
        else result(meta, Conflict, CompletionRejected),
    }
  }

  action Complete = {
    nondet job = leasedJobs.oneOf()
    val current = jobs.get(job)
    CompleteInput(job, current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operationId)
  }

  action CompleteRejected = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(jobs.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(jobs.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(jobs.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = jobs.get(job)
    val authority = exactAuthority(current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operationId, node,
      presentedRevision, presentedGeneration, presentedFence, presentedToken,
      presentedLeaseUntil, operation, meta.now)
    all {
      not(blocked(job)) and not(authority),
      jobs' = jobs,
      meta' = result(meta, Conflict, CompletionRejected),
    }
  }

  action ExposeCompletionInput(job: JobId, operation: OperationId,
      revision: int, generation: int): bool = {
    val current = jobs.get(job)
    val allowed = not(blocked(job)) and meta.completionPending
      and not(meta.unknownPending and job == meta.unknownJob)
      and current.state == Absent and not(current.payload) and not(current.dueRoute)
      and not(current.fairRoute) and not(current.leaseRoute) and not(current.wakeRoute)
      and job == meta.completionJob and operation == meta.completionOperation
      and revision == meta.completionRevision and generation == meta.completionGeneration
      and current.operationId == operation and current.revision == revision
      and current.generation == generation
    val detailAvailable = completionReceiptCount < MAX_COMPLETION_RECEIPTS
    all {
      jobs' = if (allowed and detailAvailable)
        update(jobs, job, current.with("completionReceipt", true)) else jobs,
      meta' = terminalResult(meta.with("completionPending", if (allowed) false else meta.completionPending)
        .with("completionDetail", if (allowed)
          completionDetailAt(completionReceiptCount) else NoCompletionDetail)
        .with("completionDetailJob", job)
        .with("completionOmissions", if (allowed and not(detailAvailable))
          meta.completionOmissions + 1 else meta.completionOmissions),
        if (allowed) Committed else Conflict, if (allowed) CompletionDeleted else CompletionRejected),
    }
  }

  action ExposeCompletion = ExposeCompletionInput(meta.completionJob,
    meta.completionOperation, meta.completionRevision, meta.completionGeneration)

  action HandleInput(job: JobId, node: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId,
      handler: HandlerResult): bool = {
    val effect = applyLifecycleHandler(jobs, meta, job, node, presentedRevision,
      presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
      operation, handler)
    all {
      jobs' = effect.jobs,
      meta' = effect.meta,
    }
  }

  action Handle = {
    nondet job = leasedJobs.oneOf()
    nondet handler = Set(Success, Transient, Throttled, Permanent, Ambiguous).oneOf()
    val current = jobs.get(job)
    HandleInput(job, current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, handler)
  }

  // Reachability probe for the named DLQ witness. This is the same public
  // handler reducer as Handle with the Permanent outcome selected explicitly;
  // it adds no transition semantics, only a stable way for the executable
  // witness gate to exercise the existing permanent-failure path.
  action DeadLetterWitnessStep = {
    nondet job = leasedJobs.oneOf()
    val current = jobs.get(job)
    HandleInput(job, current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, Permanent)
  }

  action AdvanceTimeInput(amount: int): bool = {
    all {
      jobs' = jobs,
      meta' = result(meta.with("now", meta.now + amount), Committed, TimeAdvanced),
    }
  }

  action AdvanceTime = {
    nondet amount = Set(0, 1, 3, 5, MAX_JOB_AGE_TICKS).oneOf()
    AdvanceTimeInput(amount)
  }

  // A scheduled item has an age bound independent of its retry count.  A
  // recovered driver must turn overdue work into a terminal result rather
  // than leave it permanently unclaimable behind a stale due route.
  action ExpireScheduledInput(job: JobId): bool = {
    val current = jobs.get(job)
    val allowed = not(blocked(job))
      and (current.state == Scheduled or current.state == RetryWaiting)
      and current.record == Valid and current.expiresAt <= meta.now
    val expired = deadLetteredLifecycleJob(current)
    all {
      jobs' = if (allowed) update(jobs, job, expired) else jobs,
      meta' = result(meta.with("tokenProgression", if (allowed)
        update(meta.tokenProgression, job, 0) else meta.tokenProgression)
        .with("quarantineAttempts", if (meta.unknownVersionJobs.contains(job))
        meta.quarantineAttempts + 1 else meta.quarantineAttempts)
        .with("committedTerminalJobs", if (allowed)
          meta.committedTerminalJobs.union(Set(job)) else meta.committedTerminalJobs),
        if (allowed) Committed else Conflict,
        if (allowed) ScheduledExpired else CompletionRejected),
    }
  }

  action ExpireScheduled = {
    nondet job = JOBS.filter(candidate =>
      (jobs.get(candidate).state == Scheduled or jobs.get(candidate).state == RetryWaiting)
        and jobs.get(candidate).expiresAt <= meta.now).oneOf()
    ExpireScheduledInput(job)
  }

  action ExpireLeaseInput(job: JobId): bool = {
    val current = jobs.get(job)
    val allowed = not(blocked(job))
      and current.state == Leased and current.leaseUntil <= meta.now
    val cancelled = allowed and current.cancelRequested
    val retry = allowed and not(cancelled) and current.expiresAt > meta.now
      and current.attempts < MAX_ATTEMPTS
    val updatedJob = if (cancelled)
      current.with("state", Cancelled).with("revision", current.revision + 1)
        .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false)
        .with("leaseRoute", false).with("leaseUntil", 0).with("cancelRequested", false)
        .with("token", 0)
    else if (retry)
      current.with("state", RetryWaiting).with("revision", current.revision + 1).with("dueAt", meta.now)
        .with("dueRoute", true).with("fairRoute", true).with("wakeRoute", true).with("leaseRoute", false)
      .with("leaseUntil", 0).with("cancelRequested", false)
        .with("token", 0)
    else deadLetteredLifecycleJob(current)
    all {
      jobs' = if (allowed) update(jobs, job, updatedJob) else jobs,
      meta' = result(meta.with("tokenProgression", if (allowed and not(retry))
        update(meta.tokenProgression, job, 0) else meta.tokenProgression)
        .with("committedTerminalJobs", if (allowed and not(retry))
        meta.committedTerminalJobs.union(Set(job)) else meta.committedTerminalJobs),
        if (allowed) Committed else Conflict, if (allowed and retry) LeaseExpired
        else if (cancelled) LeasedCancelled else if (allowed) PermanentDeadLetter else CompletionRejected),
    }
  }

  action ExpireLease = {
    nondet job = leasedJobs.oneOf()
    ExpireLeaseInput(job)
  }

  action CancelInput(job: JobId, node: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId): bool = {
    val current = jobs.get(job)
    val allowed = not(blocked(job)) and (current.state == Scheduled or current.state == RetryWaiting)
      and current.node == node and current.revision == presentedRevision
      and current.generation == presentedGeneration and current.fence == presentedFence
      and current.token == presentedToken and current.leaseUntil == presentedLeaseUntil
      and current.operationId == operation
    val updatedJob = current.with("state", Cancelled).with("revision", current.revision + 1)
      .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false)
      .with("cancelRequested", false)
    all {
      jobs' = if (allowed) update(jobs, job, updatedJob) else jobs,
      meta' = result(meta.with("quarantineAttempts", if (meta.unknownVersionJobs.contains(job))
        meta.quarantineAttempts + 1 else meta.quarantineAttempts)
        .with("committedTerminalJobs", if (allowed) meta.committedTerminalJobs.union(Set(job)) else meta.committedTerminalJobs),
        if (allowed) Committed else Conflict, if (allowed) CancelCommitted else CompletionRejected),
    }
  }

  action Cancel = {
    nondet job = activeJobs.filter(candidate => jobs.get(candidate).state != Completed).oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(jobs.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(jobs.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(jobs.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    CancelInput(job, node, presentedRevision, presentedGeneration, presentedFence,
      presentedToken, presentedLeaseUntil, operation)
  }

  action RequestCancelInput(job: JobId, node: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId): bool = {
    val current = jobs.get(job)
    val exact = not(blocked(job)) and current.node == node and current.revision == presentedRevision
      and current.generation == presentedGeneration and current.fence == presentedFence
      and current.token == presentedToken and current.leaseUntil == presentedLeaseUntil
      and current.operationId == operation and meta.now < current.leaseUntil
    all {
      // Cooperative cancellation is a marker write. It does not replace the
      // authoritative job record, so its revision remains unchanged until a
      // later handler transition commits the cancellation.
      jobs' = if (exact) update(jobs, job, current.with("cancelRequested", true)) else jobs,
      meta' = result(meta, if (exact) Committed else Conflict,
        if (exact) CancelRequested else CompletionRejected),
    }
  }

  action RequestCancel = {
    nondet job = leasedJobs.oneOf()
    val current = jobs.get(job)
    RequestCancelInput(job, current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operationId)
  }

  action CancelLeasedInput(job: JobId, node: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId): bool = {
    val current = jobs.get(job)
    val allowed = not(blocked(job)) and current.cancelRequested and current.state == Leased
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
        operation, meta.now)
    val updatedJob = current.with("state", Cancelled).with("revision", current.revision + 1)
      .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false).with("leaseRoute", false)
      .with("leaseUntil", 0).with("cancelRequested", false)
    all {
      jobs' = if (allowed) update(jobs, job, updatedJob) else jobs,
      meta' = result(meta.with("committedTerminalJobs", if (allowed) meta.committedTerminalJobs.union(Set(job)) else meta.committedTerminalJobs),
        if (allowed) Committed else Conflict, if (allowed) LeasedCancelled else CompletionRejected),
    }
  }

  action CancelLeased = {
    nondet job = leasedJobs.oneOf()
    val current = jobs.get(job)
    CancelLeasedInput(job, current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operationId)
  }

  action CancelLeasedRejected = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(jobs.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(jobs.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(jobs.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = jobs.get(job)
    val exact = current.cancelRequested and current.state == Leased
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
        operation, meta.now)
    all {
      not(exact),
      jobs' = jobs,
      meta' = result(meta, Conflict, LeasedCancelRejected),
    }
  }

  action RedriveInput(job: JobId, expectedRevision: int,
      expectedOperation: OperationId, reuseExecution: bool): bool = {
    val effect = applyLifecycleRedrive(jobs, meta, job, expectedRevision,
      expectedOperation, reuseExecution)
    all {
      jobs' = effect.jobs,
      meta' = effect.meta,
    }
  }

  action Redrive = {
    nondet job = JOBS.filter(candidate => jobs.get(candidate).state == DeadLettered).oneOf()
    nondet expectedRevision = Set(jobs.get(job).revision,
      jobs.get(job).revision - 1).oneOf()
    nondet expectedOperation = OPERATIONS.oneOf()
    nondet reuseExecution = bools.oneOf()
    RedriveInput(job, expectedRevision, expectedOperation, reuseExecution)
  }

  action UnknownCompletionInput(job: JobId, node: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, operation: OperationId, committed: bool): bool = {
    val current = jobs.get(job)
    val allowed = not(meta.unknownPending) and not(current.cancelRequested)
      and current.state == Leased
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, presentedRevision,
        presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
        operation, meta.now)
    val completed = current.with("operationId", operation).with("state", Absent)
      .with("revision", current.revision + 1).with("payload", false).with("dueRoute", false)
      .with("fairRoute", false).with("leaseRoute", false).with("wakeRoute", false)
      .with("leaseUntil", 0).with("expiresAt", 0).with("checkpointBytes", 0)
      .with("failureRecorded", false)
      // A committed terminal operation leaves a durable receipt even though
      // the record itself projects as absent.
      .with("completionReceipt", true).with("cancelRequested", false)
    val observedJob = if (allowed) update(jobs, job, if (committed) completed else current.with("operationId", operation)) else jobs
    all {
      jobs' = observedJob,
      meta' = if (allowed) result(meta.with("unknownPending", true).with("unknownJob", job)
        .with("unknownOperation", operation).with("unknownAfterCommit", committed)
        .with("unknownNode", node).with("unknownRevision", presentedRevision)
        .with("unknownGeneration", presentedGeneration).with("unknownFence", presentedFence)
        .with("unknownToken", presentedToken).with("unknownLeaseUntil", presentedLeaseUntil)
        .with("unknownReadback", if (committed) Committed else Conflict)
        .with("completionDetail", NoCompletionDetail)
        .with("completionDetailJob", job)
        .with("committedTerminalJobs", if (committed)
          meta.committedTerminalJobs.union(Set(job)) else meta.committedTerminalJobs), Unknown,
        if (committed) UnknownAfterCommit else UnknownBeforeCommit)
        else result(meta, Conflict, CompletionRejected),
    }
  }

  action UnknownCompletion = {
    nondet job = leasedJobs.oneOf()
    nondet committed = bools.oneOf()
    val current = jobs.get(job)
    UnknownCompletionInput(job, current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operationId, committed)
  }

  action ReconcileUnknownInput(job: JobId, operation: OperationId,
      observed: StoreResult): bool = {
    val current = jobs.get(job)
    val exactAuthorityReadback = current.operationId == meta.unknownOperation
      and current.node == meta.unknownNode and current.generation == meta.unknownGeneration
      and current.fence == meta.unknownFence and current.token == meta.unknownToken
      and (if (meta.unknownAfterCommit) current.state == Absent
        and current.revision == meta.unknownRevision + 1 and current.leaseUntil == 0
        else current.state == Leased and current.revision == meta.unknownRevision
          and current.leaseUntil == meta.unknownLeaseUntil)
    val authorityChanged = current.revision != (if (meta.unknownAfterCommit)
      meta.unknownRevision + 1 else meta.unknownRevision)
    val exact = not(meta.unknownVersionJobs.contains(job))
      and meta.unknownPending and job == meta.unknownJob
      and operation == meta.unknownOperation and observed == meta.unknownReadback
      and (if (observed == AuthorityChanged) authorityChanged else exactAuthorityReadback)
    val committedExact = exact and meta.unknownAfterCommit and observed == Committed
    val detailAvailable = completionReceiptCount < MAX_COMPLETION_RECEIPTS
    all {
      jobs' = if (committedExact and detailAvailable)
        update(jobs, job, current.with("completionReceipt", true)) else jobs,
      meta' = if (exact) terminalResult(meta.with("unknownPending", false)
        .with("completionPending", false)
        .with("completionJob", if (meta.unknownAfterCommit) job else meta.completionJob)
        .with("completionOperation", if (meta.unknownAfterCommit) meta.unknownOperation else meta.completionOperation)
        .with("completionRevision", if (meta.unknownAfterCommit) meta.unknownRevision + 1 else meta.completionRevision)
        .with("completionGeneration", if (meta.unknownAfterCommit) meta.unknownGeneration else meta.completionGeneration)
        .with("completionDetail", if (committedExact)
          completionDetailAt(completionReceiptCount) else NoCompletionDetail)
        .with("completionDetailJob", job)
        .with("completionOmissions", if (committedExact and not(detailAvailable))
          meta.completionOmissions + 1 else meta.completionOmissions), Committed,
        if (observed == AuthorityChanged) UnknownAuthorityChanged
        else if (meta.unknownAfterCommit) UnknownReconciled else UnknownConflictReconciled)
        else result(meta, Conflict, CompletionRejected),
    }
  }

  action ReconcileUnknown = {
    nondet observed = Set(Committed, Conflict, AuthorityChanged).oneOf()
    ReconcileUnknownInput(meta.unknownJob, meta.unknownOperation, observed)
  }

  action ChangeUnknownAuthority = {
    val job = meta.unknownJob
    val current = jobs.get(job)
    all {
      meta.unknownPending,
      jobs' = update(jobs, job, current.with("revision", current.revision + 2)),
      meta' = meta.with("unknownReadback", AuthorityChanged).with("lastResult", Unknown)
        .with("lastOutcome", UnknownAuthorityChanged),
    }
  }

  // This is a real stale conditional mutation.  It is enabled only when at
  // least one presented authority component is stale and leaves the job maps
  // byte-for-byte unchanged while recording the rejected result.
  action StaleMutation = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(jobs.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(jobs.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(jobs.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = jobs.get(job)
    val exact = exactAuthority(current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, node, presentedRevision,
      presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil, operation,
      meta.now)
    val stale = current.state == Leased and not(exact)
    val attempted = current.with("revision", current.revision + 1).with("operationId", operation)
    all {
      stale,
      jobs' = jobs,
      meta' = result(meta.with("lastAttemptRevision", attempted.revision)
        .with("lastAttemptApplied", false).with("lastAttemptOperation", operation)
        .with("lastAttemptJob", job).with("staleRevision", current.revision)
        .with("staleGeneration", current.generation).with("staleFence", current.fence)
        .with("staleToken", current.token).with("staleLeaseUntil", current.leaseUntil)
        .with("staleOperation", current.operationId), Conflict,
        StaleWriteRejected),
    }
  }

  action CorruptRecordInput(job: JobId, kind: RecordKind): bool = {
    val current = jobs.get(job)
    val unknown = kind == UnknownVersion
    val updatedJob = current.with("record", kind).with("dueRoute", false)
      .with("fairRoute", false).with("wakeRoute", false).with("leaseRoute", false)
      .with("revision", current.revision + 1)
    all {
      current.record == Valid and current.state != Leased and not(blocked(job)),
      kind == Corrupt or kind == UnknownVersion or kind == Missing,
      jobs' = if (unknown) jobs else update(jobs, job, updatedJob),
      meta' = result(meta
        .with("unknownVersionJobs", if (unknown)
          meta.unknownVersionJobs.union(Set(job)) else meta.unknownVersionJobs)
        .with("quarantineSnapshot", if (unknown)
          update(meta.quarantineSnapshot, job, current) else meta.quarantineSnapshot)
        .with("quarantineAttempts", if (unknown) 0 else meta.quarantineAttempts),
        if (unknown) Rejected else Committed,
        if (unknown) UnknownVersionQuarantined else CorruptQuarantined),
    }
  }

  action CorruptRecord = {
    nondet job = JOBS.filter(candidate => jobs.get(candidate).record == Valid
      and jobs.get(candidate).state != Leased and not(blocked(candidate))).oneOf()
    nondet kind = Set(Corrupt, UnknownVersion, Missing).oneOf()
    CorruptRecordInput(job, kind)
  }

  action RepairInput(job: JobId, expectedRevision: int,
      expectedOperation: OperationId): bool = {
    val current = jobs.get(job)
    val allowed = repairAllowed(current, meta.unknownPending, meta.unknownJob,
      meta.unknownVersionJobs.contains(job), job, expectedRevision, expectedOperation)
    val updatedJob = lifecycleRepairCandidate(current, allowed)
    all {
      jobs' = if (allowed) update(jobs, job, updatedJob) else jobs,
      meta' = result(meta.with("quarantineAttempts", if (meta.unknownVersionJobs.contains(job))
        meta.quarantineAttempts + 1 else meta.quarantineAttempts)
        .with("unrelatedProgress", if (allowed and meta.unknownPending
            and meta.unknownJob != job)
          min(meta.unrelatedProgress + 1, MAX_UNRELATED_PROGRESS)
          else meta.unrelatedProgress),
        if (allowed) Committed else Conflict, if (allowed) RepairCommitted else RepairConflict),
    }
  }

  pure def repairAllowed(current, pending, pendingJob, quarantined, job,
      expectedRevision, expectedOperation) =
    not(pending and pendingJob == job) and not(quarantined)
      and expectedRevision == current.revision
      and expectedOperation == current.operationId and current.record == Corrupt

  /// A repair reducer understands only the closed Corrupt representation.
  /// Passing false is the fail-closed UnknownVersion path and is identity.
  pure def lifecycleRepairCandidate(current, allowed) = if (allowed)
    current.with("record", Valid).with("revision", current.revision + 1)
      .with("dueRoute", current.state == Scheduled or current.state == RetryWaiting)
      .with("fairRoute", current.state == Scheduled or current.state == RetryWaiting)
      .with("wakeRoute", current.state == Scheduled or current.state == RetryWaiting)
      .with("leaseRoute", current.state == Leased)
  else current

  action Repair = {
    nondet job = JOBS.filter(candidate => jobs.get(candidate).record == Corrupt).oneOf()
    nondet expectedRevision = Set(jobs.get(job).revision, jobs.get(job).revision - 1).oneOf()
    nondet expectedOperation = OPERATIONS.oneOf()
    RepairInput(job, expectedRevision, expectedOperation)
  }

  action PauseQueue = all {
    jobs' = jobs,
    meta' = result(meta.with("paused", true), Committed, QueuePaused),
  }

  action ResumeQueue = all {
    jobs' = jobs,
    meta' = result(meta.with("paused", false), Committed, QueueResumed),
  }

  action PartialFailure = all {
    jobs' = jobs,
    meta' = result(meta, Conflict, PartialCommitRejected),
  }

  action DedupeReplay = {
    nondet sameJob = JOBS.oneOf()
    val activeMatch = meta.dedupeActive and sameJob == meta.dedupeJob
    val expiredMatch = meta.dedupeExpired and sameJob == meta.dedupeJob
    all {
      jobs' = jobs,
      meta' = result(meta, if (activeMatch) Committed else Rejected,
        if (activeMatch) DedupeReplayExisting else if (expiredMatch) DedupeRetentionExpired else DedupeNotFound),
    }
  }

  // A dedupe key is durable metadata independent of the later terminal
  // record.  Registering it lets bounded exploration exercise retention
  // expiry without smuggling a terminal-state mutation into replay.
  action RegisterDedupe = {
    nondet job = activeJobs.oneOf()
    val allowed = not(blocked(job))
    all {
      jobs' = jobs,
      meta' = if (allowed) result(meta.with("dedupeActive", true).with("dedupeJob", job)
        .with("dedupeExpired", false), Committed, DedupeRegistered)
        else meta,
    }
  }

  action ExpireDedupe = {
    val allowed = meta.dedupeActive and isTerminal(jobs.get(meta.dedupeJob).state)
    all {
      jobs' = jobs,
      meta' = result(meta.with("dedupeActive", if (allowed) false else meta.dedupeActive)
        .with("dedupeExpired", allowed), if (allowed) Committed else Conflict,
        if (allowed) DedupeRetentionExpired else DedupeNotFound),
    }
  }

  // This deterministic trace starts from the ordinary valid scheduled record,
  // recognizes an unknown version without touching it, then invokes three real
  // lifecycle entrypoints that would otherwise replace, cancel, or repair the
  // record. The snapshot invariant proves every attempt is identity.
  action UnknownVersionQuarantineChainStep =
    if (not(meta.unknownVersionJobs.contains(JobA)))
      CorruptRecordInput(JobA, UnknownVersion)
    else if (meta.quarantineAttempts == 0)
      // Force the real enqueue conflict path with a durable due-time
      // mismatch; quarantine still blocks replacement and preserves the
      // original snapshot.
      EnqueueInput(JobA, meta.now + 3, OperationB, false, 0)
    else if (meta.quarantineAttempts == 1) {
      val current = jobs.get(JobA)
      CancelInput(JobA, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId)
    } else RepairInput(JobA, jobs.get(JobA).revision,
      jobs.get(JobA).operationId)

  action UnknownVersionTerminalChainStep = {
    val current = jobs.get(JobB)
    if (current.state == Leased)
      HandleInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId,
        Permanent)
    else if (not(meta.unknownVersionJobs.contains(JobB)))
      CorruptRecordInput(JobB, UnknownVersion)
    else RedriveInput(JobB, current.revision, current.operationId, false)
  }

  action StableEnqueueChainStep =
    if (jobs.get(JobC).state == Absent)
      EnqueueInput(JobC, meta.now, OperationC, false, 3)
    else if (meta.lastEnqueueDisposition == Inserted)
      EnqueueInput(JobC, meta.now, OperationC, false, 3)
    else EnqueueInput(JobC, jobs.get(JobC).dueAt + 3, OperationC, false, 2)

  action TerminalReplayChainStep = {
    val current = jobs.get(JobB)
    if (current.state == Leased)
      HandleInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId,
        Permanent)
    else if (meta.lastOutcome == PermanentDeadLetter)
      EnqueueInput(JobB, current.dueAt, current.operationId, false, 0)
    else RedriveInput(JobB, current.revision, current.operationId, false)
  }

  // Redrive starts a fresh retry-age window. This trace exhausts the original
  // age, commits a DLQ record, redrives through caller-supplied authority, and
  // claims the same immutable logical job before the new deadline.
  action AgeExpiredRedriveClaimChainStep = {
    val current = jobs.get(JobA)
    if (current.generation == 0 and meta.now < current.expiresAt)
      AdvanceTimeInput(current.expiresAt - meta.now)
    else if (current.generation == 0
        and (current.state == Scheduled or current.state == RetryWaiting))
      ExpireScheduledInput(JobA)
    else if (current.state == DeadLettered)
      RedriveInput(JobA, current.revision, current.operationId, true)
    else if (not(meta.claimPending))
      SelectClaimInput(JobA, NodeA, current.revision)
    else ClaimInput(JobA, NodeA, current.revision)
  }

  // A retry schedules the same execution without allocating an attempt. The
  // next successful claim is the sole transition that advances both bounded
  // attempt counters, exactly once and under the freshly read revision.
  action OneAttemptPerClaimChainStep = {
    val current = jobs.get(JobB)
    if (meta.lastOutcome == Initialised)
      HandleInput(JobB, current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId,
        Transient)
    else if (current.dueAt > meta.now)
      AdvanceTimeInput(current.dueAt - meta.now)
    else if (not(meta.claimPending))
      SelectClaimInput(JobB, NodeA, current.revision)
    else ClaimInput(JobB, NodeA, current.revision)
  }

  action step = any {
    Enqueue, SelectClaim, Claim, Renew, Checkpoint, Complete, CompleteRejected,
    ExposeCompletion, Handle, AdvanceTime,
    ExpireScheduled, ExpireLease, Cancel, RequestCancel, CancelLeased, CancelLeasedRejected,
    Redrive, UnknownCompletion, ChangeUnknownAuthority,
    ReconcileUnknown, StaleMutation, CorruptRecord, Repair, PauseQueue, ResumeQueue,
    PartialFailure, RegisterDedupe, DedupeReplay, ExpireDedupe,
    UnknownVersionQuarantineChainStep, UnknownVersionTerminalChainStep,
    StableEnqueueChainStep,
    TerminalReplayChainStep, AgeExpiredRedriveClaimChainStep,
    OneAttemptPerClaimChainStep, DeadLetterWitnessStep,
  }

  // Named reachability predicates are used by the runner as executable
  // witnesses; each names a concrete outcome, not merely a changed flag.
  // ClaimConflict is the two-contender compare-and-swap outcome; the stale
  // authority witness exercises the same rejection boundary after a lease has
  // moved to another generation/fence/token.
  val two_node_race_witness = meta.lastOutcome == ClaimConflict or meta.lastOutcome == StaleWriteRejected
  val expired_reclaim_witness = meta.lastOutcome == LeaseExpired
  val expired_scheduled_witness = meta.lastOutcome == ScheduledExpired
  val durable_enqueue_witness = meta.lastOutcome == EnqueueCommitted or meta.lastOutcome == EnqueueDedupeCommitted
  val future_enqueue_witness = meta.lastOutcome == EnqueueFutureCommitted or meta.lastOutcome == EnqueueDedupeCommitted
  val dedupe_replay_witness = meta.lastOutcome == DedupeReplayExisting
  val dedupe_conflict_witness = meta.lastOutcome == DedupeIdConflict or meta.lastOutcome == EnqueueDedupeConflict
  val dedupe_expired_witness = meta.lastOutcome == DedupeRetentionExpired
  val retry_witness = meta.lastOutcome == RetryTransient or meta.lastOutcome == RetryThrottled
    or meta.lastOutcome == RetryAmbiguous
  val throttled_retry_witness = meta.lastOutcome == RetryThrottled
  val ambiguous_retry_witness = meta.lastOutcome == RetryAmbiguous
  val checkpoint_witness = meta.lastOutcome == CheckpointCommitted or meta.lastOutcome == CheckpointBoundRejected
  val checkpoint_bound_witness = meta.lastOutcome == CheckpointBoundRejected
  val checkpoint_authority_witness = meta.lastOutcome == CheckpointAuthorityRejected
  val dlq_witness = meta.lastOutcome == PermanentDeadLetter
  val permanent_dlq_witness = meta.lastOutcome == PermanentDeadLetter
  val unknown_commit_witness = meta.lastOutcome == UnknownBeforeCommit or meta.lastOutcome == UnknownAfterCommit
  val unknown_before_commit_witness = meta.lastOutcome == UnknownBeforeCommit
  val unknown_after_commit_witness = meta.lastOutcome == UnknownAfterCommit
  val repair_witness = meta.lastOutcome == RepairCommitted
  val repair_conflict_witness = meta.lastOutcome == RepairConflict
  val omitted_receipt_witness = meta.lastOutcome == CompletionDeleted
    and meta.completionDetail == CompletionDetailOmitted
  val full_receipt_capacity_witness = completionReceiptCount == MAX_COMPLETION_RECEIPTS
  val unknown_no_detail_witness = meta.unknownPending
    and (meta.completionDetailJob != meta.unknownJob
      or meta.completionDetail == NoCompletionDetail)
  val reconciled_receipt_witness = meta.lastOutcome == UnknownReconciled
    and (meta.completionDetail == CompletionDetailReturned
      or meta.completionDetail == CompletionDetailOmitted)
  val unclaimed_cancel_witness = meta.lastOutcome == CancelCommitted
  val cooperative_cancel_witness = meta.lastOutcome == CancelRequested or meta.lastOutcome == LeasedCancelled
  val unauthorized_cancel_witness = meta.lastOutcome == LeasedCancelRejected
  val redrive_witness = meta.lastOutcome == Redriven
    and jobs.get(JobB).state == Scheduled and jobs.get(JobB).checkpointBytes == 0
    and not(jobs.get(JobB).failureRecorded)
    and not(meta.committedTerminalJobs.contains(JobB)) and not(meta.completionPending)
    and not(meta.completionAuthorityRecorded) and meta.completionDetail == NoCompletionDetail
  val age_expired_redrive_claim_witness = meta.lastOutcome == ClaimCommitted
    and jobs.get(JobA).state == Leased and jobs.get(JobA).expiresAt > meta.now
    // The chain explicitly reuses the execution identity across redrive.
    and jobs.get(JobA).executionId == 1
    and jobs.get(JobA).generation == 2 and jobs.get(JobA).attempts == 1
  val stale_generation_witness = meta.lastOutcome == StaleWriteRejected
  val one_attempt_per_claim_witness = meta.lastOutcome == ClaimCommitted
    and meta.claimJob == JobB and jobs.get(JobB).executionId == 2
    and jobs.get(JobB).attempts == 2 and jobs.get(JobB).attemptId == 2
  val unknown_version_chain_witness = meta.unknownVersionJobs.contains(JobA)
    and meta.quarantineAttempts >= 3
  val unknown_version_terminal_chain_witness = meta.unknownVersionJobs.contains(JobB)
    and meta.lastOutcome == RedriveRejected and meta.lastResult == Rejected
    and jobs.get(JobB) == meta.quarantineSnapshot.get(JobB)
    and jobs.get(JobB).state == DeadLettered
    and jobs.get(JobA) == meta.quarantineSnapshot.get(JobA)
  val stable_enqueue_inserted_witness = meta.lastEnqueueDisposition == Inserted
    and jobs.get(JobC).state == Scheduled and jobs.get(JobC).revision == 0
  val stable_enqueue_replay_witness = meta.lastEnqueueDisposition == AlreadyPresent
    and jobs.get(JobC).state == Scheduled and jobs.get(JobC).revision == 0
  val stable_enqueue_conflict_witness = meta.lastEnqueueDisposition == JobIdConflict
    and jobs.get(JobC).state == Scheduled and jobs.get(JobC).revision == 0
  val terminal_enqueue_replay_witness = meta.lastEnqueueDisposition == AlreadyPresent
    and jobs.get(JobB).state == DeadLettered and jobs.get(JobB).failureRecorded

  pure def retryKeepsExecutionId(previous: int, candidate: int): bool = previous == candidate
  pure def retrySchedulesWithoutAttempt(beforeAttempts: int, beforeId: int,
      afterAttempts: int, afterId: int): bool =
    beforeAttempts == afterAttempts and beforeId == afterId
  pure def claimStartsOneAttempt(beforeAttempts: int, beforeId: int,
      afterAttempts: int, afterId: int): bool =
    afterAttempts == beforeAttempts + 1 and afterId == beforeId + 1
  pure def completionReady(payload: bool, due: bool, lease: bool, fair: bool, wake: bool): bool =
    not(payload) and not(due) and not(lease) and not(fair) and not(wake)

  run stable_execution_id_on_retry = all {
    assert(retryKeepsExecutionId(17, 17)),
    assert(not(retryKeepsExecutionId(17, 18))),
    assert(retrySchedulesWithoutAttempt(1, 1, 1, 1)),
    assert(not(retrySchedulesWithoutAttempt(1, 1, 2, 2))),
    assert(claimStartsOneAttempt(1, 1, 2, 2)),
  }

  run completion_requires_every_route_deleted = all {
    assert(completionReady(false, false, false, false, false)),
    assert(not(completionReady(false, false, false, true, false))),
  }

  run dlq_paths_share_durable_record = {
    val scheduled = deadLetteredLifecycleJob(initialJobs.get(JobA))
    val leased = deadLetteredLifecycleJob(initialJobs.get(JobB))
    all {
      assert(scheduled.state == DeadLettered and leased.state == DeadLettered),
      assert(scheduled.payload and leased.payload
        and scheduled.failureRecorded and leased.failureRecorded),
      assert(not(scheduled.dueRoute) and not(scheduled.fairRoute)
        and not(scheduled.leaseRoute) and not(scheduled.wakeRoute)),
      assert(not(leased.dueRoute) and not(leased.fairRoute)
        and not(leased.leaseRoute) and not(leased.wakeRoute)),
    }
  }

  run unknown_version_repair_is_identity = {
    val unknown = initialJobs.get(JobA).with("record", UnknownVersion)
      .with("dueRoute", false).with("fairRoute", false).with("wakeRoute", false)
    assert(lifecycleRepairCandidate(unknown, unknown.record == Corrupt) == unknown)
  }

  run repair_is_scoped_to_exact_job_and_authority = {
    val corrupt = initialJobs.get(JobC).with("record", Corrupt).with("revision", 1)
    all {
      assert(repairAllowed(corrupt, true, JobB, false, JobC,
        corrupt.revision, corrupt.operationId)),
      assert(not(repairAllowed(corrupt, true, JobC, false, JobC,
        corrupt.revision, corrupt.operationId))),
      assert(not(repairAllowed(corrupt, false, JobB, true, JobC,
        corrupt.revision, corrupt.operationId))),
      assert(not(repairAllowed(corrupt, false, JobB, false, JobC,
        corrupt.revision - 1, corrupt.operationId))),
    }
  }

  run receipt_capacity_is_not_commit_authority = all {
    assert(completionReady(false, false, false, false, false)),
    assert(completionDetailAt(MAX_COMPLETION_RECEIPTS) == CompletionDetailOmitted),
    assert(receiptCountAfterCompletion(MAX_COMPLETION_RECEIPTS)
      == MAX_COMPLETION_RECEIPTS),
    assert(initialJobs.get(JobB).state == Leased
      and not(initialJobs.get(JobB).completionReceipt)),
  }

  run portable_resource_bounds = all {
    assert(MAX_INLINE_PAYLOAD_BYTES == 972800),
    assert(MAX_CHECKPOINT_BYTES == 65536),
    assert(MAX_MANIFEST_BYTES < MAX_INLINE_PAYLOAD_BYTES),
    assert(MAX_CHUNK_BYTES > 0),
    assert(MAX_CHUNK_BYTES <= MAX_INLINE_PAYLOAD_BYTES),
  }
}
