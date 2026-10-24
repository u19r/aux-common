/// Synchronized product of scheduling, durable enqueue, fair claim, HTTP
/// handling, and lifecycle authority.
///
/// The product has explicit schedule occurrence identities and job identities.
/// Materialization and enqueue publish the primary record, due/fair routes,
/// and wake requirement together.  Fair selection records candidate/head
/// identity; two real nodes then race on the same revision, so the losing
/// claim is a conditional conflict caused by competing state.  A successful
/// claim carries node, generation, fence, token, lease expiry, and operation
/// identity into HTTP handling and completion.
///
/// HTTP status/result classes feed one retry owner per batch item. Retries
/// preserve the stable execution identity and allocate a new attempt identity;
/// permanent failures enter the DLQ. Unknown completion records the affected
/// job and stable operation ID and reconciles by readback without replaying the
/// handler.  Stale mutations are real rejected writes.  Completion removes
/// all live routes and marks the occurrence/job absent so a later recurring
/// occurrence can materialize JobC rather than being blocked by a terminal
/// record.  Corruption, cancellation, redrive, and revision-checked repair
/// remain in the same state machine.  This finite model abstracts storage
/// bytes, network timing, and external effect idempotency.
module bg_jobs_system {
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
    enqueueFingerprint: int,
    payloadBytes: int,
    manifestBytes: int,
    chunkBytes: int,
    digestBytes: int,
    checkpointBytes: int,
    failureRecorded: bool,
    dlqRoute: bool,
    routeCorrupt: bool,
    danglingRoute: bool,
    dueRoute: bool,
    fairRoute: bool,
    leaseRoute: bool,
    wakeRoute: bool,
    occurrence: Occurrence,
    operationId: OperationId,
    cancelRequested: bool,
    completionReceipt: bool,
    completionPending: bool,
    completionRevision: int,
    completionGeneration: int,
    completionOperation: OperationId,
    handlerStatus: HttpStatus,
    handlerTransport: TransportResult,
    handlerResult: HandlerResult,
    handlerRetryOwner: RetryOwner,
    handlerRetryAfter: int,
    handlerRevision: int,
    handlerNode: Node,
    handlerGeneration: int,
    handlerFence: int,
    handlerToken: int,
    handlerLeaseUntil: int,
    handlerOperation: OperationId,
  }

  type SystemState = {
    jobs: JobId -> Job,
    emitted: Occurrence -> bool,
    emissionCount: int,
    occurrenceIdentity: Occurrence -> int,
    previousIdentity: Occurrence -> int,
    occurrenceJob: Occurrence -> JobId,
    materialized: Occurrence -> bool,
    completed: Occurrence -> bool,
    durableRoute: Occurrence -> bool,
    scheduleRevision: int,
    watermark: int,
    nextDue: int,
    scheduleMisfire: Misfire,
    catchUpLimit: int,
    lastBacklog: int,
    skippedRemainder: int,
    lastEvaluationNow: int,
    now: int,
    scheduleEnabled: bool,
    paused: bool,
    overlap: bool,
    wakePending: bool,
    wakeToken: int,
    wakeAt: int,
    materializePending: bool,
    materializeOccurrence: Occurrence,
    materializeRevision: int,
    materializeReader: Node,
    selectedJob: JobId,
    selectedScope: Scope,
    selectedHead: int,
    claimPending: bool,
    claimJob: JobId,
    claimRevision: int,
    claimReader: Node,
    fairReady: JobId -> bool,
    fairPriority: JobId -> Priority,
    fairHead: JobId -> int,
    fairOrder: JobId -> int,
    fairBlock: JobId -> BlockReason,
    fairPayloadBytes: JobId -> int,
    fairPermits: JobId -> int,
    fairRate: JobId -> int,
    fairInFlight: JobId -> int,
    fairServed: JobId -> int,
    fairCost: JobId -> int,
    fairWeight: JobId -> int,
    fairOrdering: JobId -> OrderingGroup,
    orderHead: OrderingGroup -> int,
    orderInFlight: OrderingGroup -> bool,
    orderOwner: OrderingGroup -> JobId,
    fairCritical: int,
    fairDefault: int,
    fairBulk: int,
    lastAttemptRevision: int,
    lastAttemptApplied: bool,
    lastAttemptOperation: OperationId,
    staleJob: JobId,
    staleState: JobState,
    staleRecord: RecordKind,
    stalePayload: bool,
    staleDueAt: int,
    staleAttempts: int,
    staleAttemptId: int,
    staleExecutionId: int,
    staleDueRoute: bool,
    staleFairRoute: bool,
    staleLeaseRoute: bool,
    staleWakeRoute: bool,
    staleRevision: int,
    staleGeneration: int,
    staleFence: int,
    staleToken: int,
    staleLeaseUntil: int,
    staleNode: Node,
    staleOperation: OperationId,
    fairCycle: int,
    lastClaimNode: Node,
    lastHandlerStatus: HttpStatus,
    lastTransport: TransportResult,
    lastHandlerResult: HandlerResult,
    retryOwner: RetryOwner,
    handlerJob: JobId,
    handlerRevision: int,
    handlerNode: Node,
    handlerGeneration: int,
    handlerFence: int,
    handlerToken: int,
    handlerLeaseUntil: int,
    handlerOperation: OperationId,
    // Durable HTTP batch contract. Secrets are deliberately represented only
    // by their absence; idempotency, membership, per-item retry ownership and
    // partial classification survive independently of last-handler fields.
    httpBatchMembers: Set[JobId],
    httpBatchResults: JobId -> BatchResult,
    httpRetryOwners: JobId -> RetryOwner,
    httpSecretPersisted: JobId -> bool,
    httpIdempotency: JobId -> int,
    httpDuplicate: JobId -> bool,
    httpOmitted: JobId -> bool,
    httpAttemptExecuted: JobId -> bool,
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
    completionDetail: CompletionDetail,
    completionDetailJob: JobId,
    completionOmissions: int,
    committedTerminalJobs: Set[JobId],
    pulseActions: int,
    activePulses: int,
    progressCounter: int,
    driveProgressBefore: int,
    driveProgressAfter: int,
    lastDrive: CompositeDriveResult,
    lastDriveBranch: DriveKernelBranch,
    lastDriveWork: DriveWork,
    lastDriveStop: DriveStopReason,
    lastResult: StoreResult,
    lastOutcome: SystemOutcome,
  }

  type SystemOutcome = Initialised | EnqueueCommitted | EnqueueConflict | ScheduleEmitted
    | ScheduleSkipped | ScheduleNotDue | ScheduleEnqueue | FairSelected | FairRefilled | ClaimCommitted | ClaimConflict
    | HandlerSuccess | HandlerRetry | HandlerDeadLetter | HandlerRejected | CompletionCommitted
    | CompletionConflict | UnknownCommitObserved | UnknownReconciled
    | UnknownAuthorityChanged | StaleRejected
    | CancelCommitted | CancelRequested | LeasedCancelled | ScheduledExpired | LeaseExpired
    | CompletionExposed | RedriveCommitted | RepairCommitted | RepairConflict | WakeAccepted
    | WakeRejected | PulseExit | SchedulePolicyChanged | DriveReported | CorruptQuarantined

  type CompositeDriveResult = CompositeDriveRecurrence | CompositeDriveMaterialized
    | CompositeDriveClaimed | CompositeDriveTerminal | CompositeDriveConflict
    | CompositeDrivePaused | CompositeDriveBudgetExhausted | CompositeDriveFuture
    | CompositeDriveNoWork

  var system: SystemState

  pure def makeJob(state, node, revision, execution, attempt, occurrence) = {
    state: state,
    node: node,
    revision: revision,
    generation: if (state == Leased) 1 else 0,
    fence: if (state == Leased) 1 else 0,
    token: if (state == Leased) 3 else 0,
    leaseUntil: if (state == Leased) 3 else 0,
    dueAt: 0,
    expiresAt: MAX_JOB_AGE_TICKS,
    executionId: execution,
    attemptId: attempt,
    attempts: if (state == Leased) 1 else 0,
    record: Valid,
    payload: state != Absent,
    enqueueFingerprint: if (state == Absent) 0 else execution,
    payloadBytes: if (state == Absent) 0 else execution,
    manifestBytes: if (state == Absent) 0 else execution + 1,
    chunkBytes: if (state == Absent) 0 else execution + 2,
    digestBytes: if (state == Absent) 0 else execution + 3,
    checkpointBytes: 0,
    failureRecorded: state == DeadLettered,
    dlqRoute: state == DeadLettered,
    routeCorrupt: false,
    danglingRoute: false,
    dueRoute: state == Scheduled or state == RetryWaiting,
    fairRoute: state == Scheduled or state == RetryWaiting,
    leaseRoute: state == Leased,
    wakeRoute: state == Scheduled or state == RetryWaiting,
    occurrence: occurrence,
    operationId: OperationA,
    cancelRequested: false,
    completionReceipt: false,
    completionPending: false,
    completionRevision: 0,
    completionGeneration: 0,
    completionOperation: OperationA,
    handlerStatus: Status2xx,
    handlerTransport: TransportOk,
    handlerResult: Success,
    handlerRetryOwner: NoRetry,
    handlerRetryAfter: 0,
    handlerRevision: 0,
    handlerNode: node,
    handlerGeneration: 0,
    handlerFence: 0,
    handlerToken: 0,
    handlerLeaseUntil: 0,
    handlerOperation: OperationA,
  }

  pure def initialJobs = Map(
    JobA -> makeJob(Scheduled, NodeA, 1, 1, 0, Occ1),
    JobB -> makeJob(Absent, NodeB, 0, 2, 0, Occ2),
    JobC -> makeJob(Absent, NodeB, 0, 3, 0, Occ3),
  )

  pure def initialSystem = {
    jobs: initialJobs,
    emitted: Map(Occ1 -> true, Occ2 -> false, Occ3 -> false),
    emissionCount: 1,
    occurrenceIdentity: Map(Occ1 -> 1, Occ2 -> 0, Occ3 -> 0),
    previousIdentity: Map(Occ1 -> 0, Occ2 -> 0, Occ3 -> 0),
    occurrenceJob: Map(Occ1 -> JobA, Occ2 -> JobB, Occ3 -> JobC),
    materialized: Map(Occ1 -> true, Occ2 -> false, Occ3 -> false),
    completed: Map(Occ1 -> false, Occ2 -> false, Occ3 -> false),
    durableRoute: Map(Occ1 -> true, Occ2 -> false, Occ3 -> false),
    scheduleRevision: 1,
    watermark: 0,
    nextDue: OCCURRENCE_STEP,
    scheduleMisfire: FireOnce,
    catchUpLimit: MAX_OCCURRENCES,
    lastBacklog: 0,
    skippedRemainder: 0,
    lastEvaluationNow: 0,
    now: 0,
    scheduleEnabled: true,
    paused: false,
    overlap: false,
    wakePending: true,
    wakeToken: 1,
    wakeAt: 0,
    materializePending: false,
    materializeOccurrence: Occ1,
    materializeRevision: 0,
    materializeReader: NodeA,
    selectedJob: JobA,
    selectedScope: ScopeA,
    selectedHead: 1,
    claimPending: false,
    claimJob: JobA,
    claimRevision: 1,
    claimReader: NodeA,
    fairReady: Map(JobA -> true, JobB -> false, JobC -> false),
    fairPriority: Map(JobA -> Critical, JobB -> Default, JobC -> Bulk),
    fairHead: Map(JobA -> 1, JobB -> 1, JobC -> 0),
    fairOrder: Map(JobA -> 1, JobB -> 1, JobC -> 0),
    fairBlock: Map(JobA -> Unblocked, JobB -> Unblocked, JobC -> Unblocked),
    fairPayloadBytes: Map(JobA -> 2, JobB -> 1, JobC -> 1),
    fairPermits: Map(JobA -> MAX_CONCURRENCY_PER_SCOPE, JobB -> MAX_CONCURRENCY_PER_SCOPE, JobC -> MAX_CONCURRENCY_PER_SCOPE),
    fairRate: Map(JobA -> MAX_RATE_PER_SCOPE, JobB -> MAX_RATE_PER_SCOPE, JobC -> MAX_RATE_PER_SCOPE),
    fairInFlight: Map(JobA -> 0, JobB -> 0, JobC -> 0),
    fairServed: Map(JobA -> 0, JobB -> 0, JobC -> 0),
    fairCost: Map(JobA -> 2, JobB -> 1, JobC -> 1),
    fairWeight: Map(JobA -> primaryWeight(ScopeA), JobB -> primaryWeight(ScopeB), JobC -> 1),
    // JobB and JobC intentionally share one ordering authority. OrderA is
    // independent and can progress concurrently; OrderC remains in the
    // finite domain to make absent-group map behavior explicit.
    fairOrdering: Map(JobA -> OrderA, JobB -> OrderB, JobC -> OrderB),
    orderHead: Map(OrderA -> 1, OrderB -> 1, OrderC -> 1),
    orderInFlight: Map(OrderA -> false, OrderB -> false, OrderC -> false),
    orderOwner: Map(OrderA -> JobA, OrderB -> JobB, OrderC -> JobC),
    fairCritical: 0,
    fairDefault: 0,
    fairBulk: 0,
    lastAttemptRevision: 0,
    lastAttemptApplied: false,
    lastAttemptOperation: OperationA,
    staleJob: JobA,
    staleState: Scheduled,
    staleRecord: Valid,
    stalePayload: true,
    staleDueAt: 0,
    staleAttempts: 0,
    staleAttemptId: 0,
    staleExecutionId: 1,
    staleDueRoute: true,
    staleFairRoute: true,
    staleLeaseRoute: false,
    staleWakeRoute: true,
    staleRevision: 0,
    staleGeneration: 0,
    staleFence: 0,
    staleToken: 0,
    staleLeaseUntil: 0,
    staleNode: NodeA,
    staleOperation: OperationA,
    fairCycle: 0,
    lastClaimNode: NodeA,
    lastHandlerStatus: Status2xx,
    lastTransport: TransportOk,
    lastHandlerResult: Success,
    retryOwner: NoRetry,
    handlerJob: JobA,
    handlerRevision: 0,
    handlerNode: NodeA,
    handlerGeneration: 0,
    handlerFence: 0,
    handlerToken: 0,
    handlerLeaseUntil: 0,
    handlerOperation: OperationA,
    httpBatchMembers: Set(),
    httpBatchResults: Map(),
    httpRetryOwners: Map(JobA -> NoRetry, JobB -> NoRetry, JobC -> NoRetry),
    httpSecretPersisted: Map(JobA -> false, JobB -> false, JobC -> false),
    httpIdempotency: Map(JobA -> 0, JobB -> 0, JobC -> 0),
    httpDuplicate: Map(JobA -> false, JobB -> false, JobC -> false),
    httpOmitted: Map(JobA -> false, JobB -> false, JobC -> false),
    httpAttemptExecuted: Map(JobA -> false, JobB -> false, JobC -> false),
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
    completionDetail: NoCompletionDetail,
    completionDetailJob: JobA,
    completionOmissions: 0,
    committedTerminalJobs: Set(),
    pulseActions: 0,
    activePulses: 0,
    progressCounter: 0,
    driveProgressBefore: 0,
    driveProgressAfter: 0,
    lastDrive: CompositeDriveNoWork,
    lastDriveBranch: KernelNoWork,
    lastDriveWork: DriveNoImmediateWork,
    lastDriveStop: StopNoWork,
    lastResult: Committed,
    lastOutcome: Initialised,
  }

  def activeJobs = JOBS.filter(job => system.jobs.get(job).state != Absent)
  pure def compositeBlocked(current, job) =
    current.unknownPending and current.unknownJob == job
  pure def jobScope(job) = if (job == JobA) ScopeA else if (job == JobB) ScopeB else ScopeA1
  pure def primaryJob(job) = fairPrimaryJob(job)
  pure def acquireBudget(values, job, amount) = {
    val primary = primaryJob(job)
    val charged = update(values, job, values.get(job) - amount)
    if (primary == job) charged else update(charged, primary, charged.get(primary) - amount)
  }
  pure def releaseBudget(values, job, amount, maximum) = {
    val primary = primaryJob(job)
    val released = update(values, job, min(maximum, values.get(job) + amount))
    if (primary == job) released
    else update(released, primary, min(maximum, released.get(primary) + amount))
  }
  pure def acquireFlight(values, job) = {
    val primary = primaryJob(job)
    val charged = update(values, job, values.get(job) + 1)
    if (primary == job) charged else update(charged, primary, charged.get(primary) + 1)
  }
  pure def releaseFlight(values, job) = {
    val primary = primaryJob(job)
    val released = update(values, job, max(0, values.get(job) - 1))
    if (primary == job) released else update(released, primary, max(0, released.get(primary) - 1))
  }
  pure def chargeService(values, job, cost) = {
    val primary = primaryJob(job)
    val charged = update(values, job, values.get(job) + cost)
    if (primary == job) charged else update(charged, primary, charged.get(primary) + cost)
  }
  pure def acquireCompositeOrder(state, job) = {
    val group = state.fairOrdering.get(job)
    state.with("orderInFlight", update(state.orderInFlight, group, true))
      .with("orderOwner", update(state.orderOwner, group, job))
  }
  pure def releaseCompositeOrder(state, job, terminal) = {
    val group = state.fairOrdering.get(job)
    state.with("orderInFlight", update(state.orderInFlight, group, false))
      .with("orderHead", update(state.orderHead, group,
        if (terminal) state.orderHead.get(group) + 1 else state.orderHead.get(group)))
  }

  // Project the product into the shared fair-service prestate.  Claim and
  // Drive both consume the resulting effect; neither maintains a second
  // mutable budget/order reducer.
  pure def compositeFairPrestate(current, job) = {
    val primary = primaryJob(job)
    val group = current.fairOrdering.get(job)
    val queued = current.jobs.get(job)
    {
      jobState: queued.state,
      dueRoute: queued.dueRoute,
      fairRoute: queued.fairRoute,
      childPermits: current.fairPermits.get(job),
      primaryPermits: current.fairPermits.get(primary),
      childRate: current.fairRate.get(job),
      primaryRate: current.fairRate.get(primary),
      childInFlight: current.fairInFlight.get(job),
      primaryInFlight: current.fairInFlight.get(primary),
      childServed: 0,
      childServedCost: current.fairServed.get(job),
      primaryServedCost: current.fairServed.get(primary),
      orderHead: current.orderHead.get(group),
      orderInFlight: current.orderInFlight.get(group),
      orderOwner: current.orderOwner.get(group),
      critical: current.fairCritical,
      default: current.fairDefault,
      bulk: current.fairBulk,
      cycle: current.fairCycle,
      serviceUnits: current.fairCritical + current.fairDefault + current.fairBulk,
      jobServiceUnits: current.fairServed.get(job),
    }
  }

  pure def applyCompositeFairEffect(current, job, contender, effect) = {
    val primary = primaryJob(job)
    val group = current.fairOrdering.get(job)
    val queued = current.jobs.get(job)
    val childPermits = update(current.fairPermits, job, effect.state.childPermits)
    val permits = if (primary == job) childPermits
      else update(childPermits, primary, effect.state.primaryPermits)
    val childRate = update(current.fairRate, job, effect.state.childRate)
    val rate = if (primary == job) childRate
      else update(childRate, primary, effect.state.primaryRate)
    val childFlight = update(current.fairInFlight, job, effect.state.childInFlight)
    val flight = if (primary == job) childFlight
      else update(childFlight, primary, effect.state.primaryInFlight)
    val childServed = update(current.fairServed, job, effect.state.childServedCost)
    val served = if (primary == job) childServed
      else update(childServed, primary, effect.state.primaryServedCost)
    val authority = claimAuthorityKernel(queued.revision, queued.generation,
      queued.fence, queued.token, queued.attempts, queued.attemptId, current.now)
    val claimed = queued.with("state", effect.state.jobState).with("node", contender)
      .with("revision", authority.nextRevision).with("generation", authority.nextGeneration)
      .with("fence", authority.nextFence).with("token", authority.nextToken)
      .with("leaseUntil", authority.nextLeaseUntil).with("attempts", authority.nextAttempts)
      .with("attemptId", authority.nextAttemptId).with("dueRoute", effect.state.dueRoute)
      .with("fairRoute", effect.state.fairRoute).with("leaseRoute", true)
      .with("wakeRoute", false)
    val claimedJobs = update(current.jobs, job, claimed)
    current.with("jobs", claimedJobs)
      .with("fairReady", update(current.fairReady, job, effect.state.fairRoute))
      .with("fairPermits", permits).with("fairRate", rate).with("fairInFlight", flight)
      .with("fairServed", served)
      .with("orderHead", update(current.orderHead, group, effect.state.orderHead))
      .with("orderInFlight", update(current.orderInFlight, group, effect.state.orderInFlight))
      .with("orderOwner", update(current.orderOwner, group, effect.state.orderOwner))
      .with("fairCritical", effect.state.critical).with("fairDefault", effect.state.default)
      .with("fairBulk", effect.state.bulk).with("fairCycle", effect.state.cycle)
      .with("httpBatchMembers", current.httpBatchMembers.union(Set(job)))
      .with("httpBatchResults", current.httpBatchResults.put(job, ItemMissing))
      .with("httpRetryOwners", update(current.httpRetryOwners, job, NoRetry))
      .with("httpSecretPersisted", update(current.httpSecretPersisted, job, false))
      .with("httpIdempotency", update(current.httpIdempotency, job, claimed.executionId))
      .with("httpDuplicate", update(current.httpDuplicate, job, false))
      .with("httpOmitted", update(current.httpOmitted, job, false))
      .with("httpAttemptExecuted", update(current.httpAttemptExecuted, job, false))
      .with("wakePending", durableRoutes(claimedJobs))
  }

  pure def withoutHttpMember(members: Set[JobId], job: JobId): Set[JobId] =
    members.filter(member => member != job)
  pure def withoutHttpResult(results: JobId -> BatchResult,
      members: Set[JobId], job: JobId): JobId -> BatchResult = withoutHttpMember(members, job)
    .fold(Map(), (acc, member) => acc.put(member, results.get(member)))

  pure def clearCompositeHttpMember(current, job) = current
    .with("httpBatchMembers", withoutHttpMember(current.httpBatchMembers, job))
    .with("httpBatchResults", withoutHttpResult(current.httpBatchResults,
      current.httpBatchMembers, job))
    .with("httpRetryOwners", update(current.httpRetryOwners, job, NoRetry))
    .with("httpSecretPersisted", update(current.httpSecretPersisted, job, false))
    .with("httpIdempotency", update(current.httpIdempotency, job, 0))
    .with("httpDuplicate", update(current.httpDuplicate, job, false))
    .with("httpOmitted", update(current.httpOmitted, job, false))
    .with("httpAttemptExecuted", update(current.httpAttemptExecuted, job, false))

  pure def httpResolutionPending(current, job) = current.httpBatchMembers.contains(job)
    and current.httpAttemptExecuted.get(job)
    and current.httpBatchResults.get(job) == ItemRetry

  /// Durable per-member delivery classifications. These reducers deliberately
  /// leave membership, idempotency, retry policy and secret state untouched.
  pure def applyHttpDuplicate(current, job) = if (
      current.httpBatchMembers.contains(job)
        and (current.httpBatchResults.get(job) == ItemMissing
          or current.httpBatchResults.get(job) == ItemRetry))
    current.with("httpDuplicate", update(current.httpDuplicate, job, true))
      .with("httpOmitted", update(current.httpOmitted, job, false))
  else current.with("lastResult", Rejected).with("lastOutcome", HandlerRejected)

  pure def applyHttpOmission(current, job) = if ({
      val queued = current.jobs.get(job)
      current.httpBatchMembers.contains(job)
        and current.httpBatchResults.get(job) == ItemMissing
        and not(current.httpAttemptExecuted.get(job))
        and queued.state == Leased and queued.attempts < MAX_ATTEMPTS
        and not(compositeBlocked(current, job))
        and exactAuthority(queued.node, queued.revision, queued.generation, queued.fence,
          queued.token, queued.leaseUntil, queued.operationId, queued.node, queued.revision,
          queued.generation, queued.fence, queued.token, queued.leaseUntil,
          queued.operationId, current.now)
    }) {
    val queued = current.jobs.get(job)
    val omitted = queued.with("handlerStatus", Status408).with("handlerTransport", Timeout)
      .with("handlerResult", Transient).with("handlerRetryOwner", EngineOwnsRetry)
      .with("handlerRetryAfter", RETRY_AFTER_FALLBACK_TICKS)
      .with("handlerRevision", queued.revision).with("handlerNode", queued.node)
      .with("handlerGeneration", queued.generation).with("handlerFence", queued.fence)
      .with("handlerToken", queued.token).with("handlerLeaseUntil", queued.leaseUntil)
      .with("handlerOperation", queued.operationId)
    current.with("jobs", update(current.jobs, job, omitted))
      .with("httpBatchResults", current.httpBatchResults.put(job, ItemRetry))
      .with("httpRetryOwners", update(current.httpRetryOwners, job, EngineOwnsRetry))
      .with("httpOmitted", update(current.httpOmitted, job, true))
      .with("httpDuplicate", update(current.httpDuplicate, job, false))
      .with("httpAttemptExecuted", update(current.httpAttemptExecuted, job, true))
      .with("lastHandlerStatus", Status408).with("lastTransport", Timeout)
      .with("lastHandlerResult", Transient).with("retryOwner", EngineOwnsRetry)
      .with("handlerJob", job).with("handlerRevision", queued.revision)
      .with("handlerNode", queued.node).with("handlerGeneration", queued.generation)
      .with("handlerFence", queued.fence).with("handlerToken", queued.token)
      .with("handlerLeaseUntil", queued.leaseUntil).with("handlerOperation", queued.operationId)
      .with("lastOutcome", HandlerRetry)
  }
  else current.with("lastResult", Rejected).with("lastOutcome", HandlerRejected)
  pure def compositeFairEligibleJobs(currentSystem) = JOBS.filter(job => {
    val current = currentSystem.jobs.get(job)
    val primary = primaryJob(job)
    val group = currentSystem.fairOrdering.get(job)
    currentSystem.fairReady.get(job) and not(current.routeCorrupt)
      and not(compositeBlocked(currentSystem, job))
      and fairJobIsEligible(current.state, current.record, current.payload, current.dueRoute,
        current.fairRoute, current.dueAt, currentSystem.now, currentSystem.fairBlock.get(job),
        currentSystem.fairPermits.get(job), currentSystem.fairRate.get(job),
        currentSystem.fairInFlight.get(job), currentSystem.fairPayloadBytes.get(job),
        MAX_INLINE_PAYLOAD_BYTES, currentSystem.fairOrder.get(job),
        currentSystem.orderHead.get(group), current.attempts, currentSystem.paused)
      and orderCanAcquire(currentSystem.fairOrder.get(job), currentSystem.orderHead.get(group),
        currentSystem.orderInFlight.get(group))
      and currentSystem.fairPermits.get(primary) > 0
      and currentSystem.fairRate.get(primary) > 0
      and currentSystem.fairInFlight.get(primary) < MAX_CONCURRENCY_PER_SCOPE
  })
  def fairEligibleJobs = compositeFairEligibleJobs(system)
  def fairPriorityAvailable(priority) = fairEligibleJobs.exists(job =>
    system.fairPriority.get(job) == priority)
  pure def compositeFairForcesBulk(currentSystem, job) = {
    val eligible = compositeFairEligibleJobs(currentSystem)
    eligible.exists(candidate => currentSystem.fairPriority.get(candidate) == Bulk)
      and currentSystem.fairCycle + currentSystem.fairCost.get(job) >= FAIR_QUIET_ERROR
  }
  /// One admission authority supplies selection, Claim, and Drive. The caller
  /// contributes only its durable read/authority predicate; scope resolution,
  /// prospective fairness, lane capacity, and child-plus-primary accounting
  /// remain identical for every entry point.
  pure def compositeFairClaimEffect(currentSystem, job, candidateAllowed) = {
    val eligible = compositeFairEligibleJobs(currentSystem)
    val priority = currentSystem.fairPriority.get(job)
    val cost = currentSystem.fairCost.get(job)
    val primary = primaryJob(job)
    val otherPrimary = if (primary == JobA) JobB else JobA
    val normalized = normalizedAdmissionAllowed(currentSystem.fairServed.get(primary),
      currentSystem.fairWeight.get(primary), cost, currentSystem.fairServed.get(otherPrimary),
      currentSystem.fairWeight.get(otherPrimary), eligible.exists(candidate =>
        primaryJob(candidate) == otherPrimary))
    fairSelectedServiceKernel(candidateAllowed, job, jobScope(job), jobScope(primary),
      priority, cost, false, true, normalized,
      compositeFairForcesBulk(currentSystem, job), compositeFairPrestate(currentSystem, job))
  }
  pure def compositeFairServiceEligibleJobs(currentSystem) = {
    val eligible = compositeFairEligibleJobs(currentSystem)
    JOBS.filter(job => compositeFairClaimEffect(currentSystem, job,
      eligible.contains(job)).allowed)
  }
  def fairServiceEligibleJobs = compositeFairServiceEligibleJobs(system)
  def leasedJobs = JOBS.filter(job => system.jobs.get(job).state == Leased)
  pure def durableRoutes(jobs) = JOBS.exists(job => jobs.get(job).state != Absent
    and not(jobs.get(job).routeCorrupt) and (jobs.get(job).dueRoute or jobs.get(job).fairRoute
      or jobs.get(job).leaseRoute or jobs.get(job).wakeRoute))
  def durableWork = durableRoutes(system.jobs)
    or OCCURRENCES.exists(occ => system.emitted.get(occ) and not(system.completed.get(occ))
      and not(system.materialized.get(occ)))
  def emittedOccurrences = OCCURRENCES.filter(occ => system.emitted.get(occ))
  def availableOccurrences = OCCURRENCES.filter(occ => occurrenceAvailable(
    system.emitted.get(occ), system.completed.get(occ), system.occurrenceIdentity.get(occ), system.nextDue))
  def firstAvailableOccurrence = if (availableOccurrences.contains(Occ1)) Occ1
    else if (availableOccurrences.contains(Occ2)) Occ2 else Occ3
  def secondAvailableOccurrence(first) = if (first != Occ1 and availableOccurrences.contains(Occ1)) Occ1
    else if (first != Occ2 and availableOccurrences.contains(Occ2)) Occ2 else Occ3
  def occurrenceCanMaterialize(occ) = system.overlap
    or system.jobs.get(system.occurrenceJob.get(occ)).state != Leased
  def activeEmissionCount(emittedState) = OCCURRENCES.filter(occ => emittedState.get(occ)).size()
  def completionReceiptCount = JOBS.filter(job => system.jobs.get(job).completionReceipt).size()

  // Composite scheduling consumes the same canonical full-backlog cursor
  // functions as the readable family. Only occurrence-slot allocation is
  // product-specific; policy count, identity, skipped remainder, and future
  // cursor are shared vocabulary.
  pure def evaluateCompositeSchedule(current, mode, catchUpLimit) = {
    val emittedNow = OCCURRENCES.filter(occ => current.emitted.get(occ))
    val availableNow = OCCURRENCES.filter(occ => occurrenceAvailable(
      current.emitted.get(occ), current.completed.get(occ),
      current.occurrenceIdentity.get(occ), current.nextDue)
      and (current.overlap
        or current.jobs.get(current.occurrenceJob.get(occ)).state != Leased))
    val effect = recurrenceStateKernel(current.now, current.nextDue,
      current.scheduleEnabled, current.paused, false,
      emittedNow.size() == 0, mode, catchUpLimit, current.emitted,
      current.completed, current.occurrenceIdentity, current.previousIdentity,
      current.emissionCount, current.watermark, current.wakePending, availableNow)
    if (effect.applied) current.with("scheduleMisfire", mode)
      .with("catchUpLimit", catchUpLimit).with("lastBacklog", effect.backlog)
      .with("skippedRemainder", effect.skipped).with("lastEvaluationNow", current.now)
      .with("emitted", effect.emitted).with("completed", effect.completed)
      .with("emissionCount", effect.emissionCount).with("occurrenceIdentity", effect.identity)
      .with("previousIdentity", effect.previousIdentity).with("watermark", effect.watermark)
      .with("nextDue", effect.nextDue).with("scheduleRevision", current.scheduleRevision + 1)
      .with("wakePending", effect.wakePending or durableRoutes(current.jobs))
      .with("lastOutcome", if (mode == Skip) ScheduleSkipped else ScheduleEmitted)
    else current.with("scheduleMisfire", mode).with("catchUpLimit", catchUpLimit)
      .with("lastBacklog", 0).with("skippedRemainder", 0)
      .with("lastEvaluationNow", current.now).with("lastResult", Rejected)
      .with("lastOutcome", ScheduleNotDue)
  }

  /// Concrete composite materialization reducer used by Drive and parity
  /// checks. It updates both schedule occurrence state and the durable job.
  pure def applyCompositeMaterialization(current, occurrence, node) = {
    val job = current.occurrenceJob.get(occurrence)
    val queued = current.jobs.get(job)
    val effect = materializeKernel(true, current.scheduleRevision,
      current.scheduleRevision, current.scheduleRevision, node, node,
      if (node == NodeA) NodeB else NodeA, current.scheduleEnabled,
      current.paused, current.emitted.get(occurrence),
      current.materialized.get(occurrence), current.overlap,
      queued.state == Leased)
    val inserted = queued.with("state", Scheduled)
      .with("revision", queued.revision + 1).with("payload", true)
      .with("enqueueFingerprint", max(1, queued.executionId))
      .with("payloadBytes", max(1, queued.executionId))
      .with("manifestBytes", max(1, queued.executionId + 1))
      .with("chunkBytes", max(1, queued.executionId + 2))
      .with("digestBytes", max(1, queued.executionId + 3))
      .with("checkpointBytes", 0).with("failureRecorded", false).with("dlqRoute", false)
      .with("record", Valid).with("routeCorrupt", false).with("dueRoute", true)
      .with("fairRoute", true).with("leaseRoute", false).with("wakeRoute", true)
      .with("occurrence", occurrence).with("operationId", OperationA)
      .with("dueAt", current.now).with("expiresAt", current.now + MAX_JOB_AGE_TICKS)
      .with("leaseUntil", 0).with("attempts", 0).with("attemptId", 0)
      .with("completionReceipt", false).with("completionPending", false)
    current.with("jobs", update(current.jobs, job, inserted))
      .with("fairReady", update(current.fairReady, job, true))
      .with("materialized", update(current.materialized, occurrence, true))
      .with("durableRoute", update(current.durableRoute, occurrence, true))
      .with("scheduleRevision", effect.nextRevision).with("wakePending", true)
      .with("wakeToken", current.wakeToken + effect.nextWakeToken)
      .with("materializePending", false).with("lastResult", Committed)
      .with("completionDetail", NoCompletionDetail).with("completionDetailJob", job)
      .with("lastOutcome", EnqueueCommitted)
  }

  pure def terminalJob(current, terminalState, retainPayload, receiptPending) = {
    val terminal = terminalKernel(current.revision, retainPayload, 0,
      current.state == Leased)
    current.with("state", terminalState).with("revision", terminal.nextRevision)
      .with("payload", terminal.keepPayload)
      .with("failureRecorded", terminalState == DeadLettered)
      .with("dlqRoute", terminalState == DeadLettered)
      .with("dueRoute", terminal.dueRoute)
      .with("fairRoute", terminal.fairRoute).with("leaseRoute", terminal.leaseRoute)
      .with("wakeRoute", terminal.wakeRoute).with("leaseUntil", 0)
      // Dead-lettered records no longer carry a lease authority token. A
      // successful terminal receipt still retains its attempt token.
      .with("token", if (terminalState == DeadLettered) 0 else current.token)
      .with("cancelRequested", false).with("completionReceipt", false)
      .with("completionPending", receiptPending).with("completionRevision", current.revision + 1)
      .with("completionGeneration", current.generation).with("completionOperation", current.operationId)
  }

  pure def terminalSystemFrom(currentSystem, job, terminalState, retainPayload,
      receiptPending, outcome) = {
    val current = currentSystem.jobs.get(job)
    val occurrence = current.occurrence
    val terminal = terminalJob(current, terminalState, retainPayload, receiptPending)
    val terminalEffect = terminalKernel(current.revision, retainPayload, 0,
      current.state == Leased)
    val jobs = update(currentSystem.jobs, job, terminal)
    val emitted = update(currentSystem.emitted, occurrence, terminalEffect.emitted)
    val heldLease = current.state == Leased
    val httpReleased = clearCompositeHttpMember(currentSystem, job)
    val released = if (terminalEffect.releaseFairAuthority)
      releaseCompositeOrder(httpReleased, job, true) else httpReleased
    released.with("jobs", jobs).with("fairReady", update(currentSystem.fairReady, job, false))
      .with("fairPermits", if (heldLease) releaseBudget(currentSystem.fairPermits, job, 1,
        MAX_CONCURRENCY_PER_SCOPE) else currentSystem.fairPermits)
      .with("fairRate", if (heldLease)
        releaseBudget(currentSystem.fairRate, job, 1, MAX_RATE_PER_SCOPE) else currentSystem.fairRate)
      .with("fairInFlight", if (heldLease)
        releaseFlight(currentSystem.fairInFlight, job) else currentSystem.fairInFlight)
      .with("wakePending", durableRoutes(jobs))
      .with("selectedHead", if (currentSystem.selectedJob == job) 0 else currentSystem.selectedHead)
      .with("claimPending", if (currentSystem.claimJob == job) false else currentSystem.claimPending)
      .with("materialized", update(currentSystem.materialized, occurrence,
        terminalEffect.materialized))
      .with("durableRoute", update(currentSystem.durableRoute, occurrence, false))
      .with("emitted", emitted).with("emissionCount", activeEmissionCount(emitted))
      .with("completed", update(currentSystem.completed, occurrence, terminalEffect.completed))
      .with("watermark", max(currentSystem.watermark,
        currentSystem.occurrenceIdentity.get(occurrence)))
      .with("scheduleRevision", currentSystem.scheduleRevision + 1)
      .with("completionDetail", NoCompletionDetail).with("completionDetailJob", job)
      .with("committedTerminalJobs", currentSystem.committedTerminalJobs.union(Set(job)))
      .with("lastResult", Committed).with("lastOutcome", outcome)
  }

  def terminalSystem(job, terminalState, retainPayload, receiptPending, outcome) =
    terminalSystemFrom(system, job, terminalState, retainPayload, receiptPending, outcome)

  pure def authoritativeProjection(state) = {
    jobs: state.jobs,
    emitted: state.emitted,
    occurrenceIdentity: state.occurrenceIdentity,
    previousIdentity: state.previousIdentity,
    materialized: state.materialized,
    completed: state.completed,
    durableRoute: state.durableRoute,
    scheduleRevision: state.scheduleRevision,
    watermark: state.watermark,
    nextDue: state.nextDue,
    wakePending: state.wakePending,
    wakeToken: state.wakeToken,
    wakeAt: state.wakeAt,
    fairReady: state.fairReady,
    fairPriority: state.fairPriority,
    fairHead: state.fairHead,
    fairOrder: state.fairOrder,
    fairBlock: state.fairBlock,
    fairPermits: state.fairPermits,
    fairRate: state.fairRate,
    fairInFlight: state.fairInFlight,
    fairServed: state.fairServed,
    fairCost: state.fairCost,
    fairWeight: state.fairWeight,
    fairOrdering: state.fairOrdering,
    orderHead: state.orderHead,
    orderInFlight: state.orderInFlight,
    orderOwner: state.orderOwner,
    fairCritical: state.fairCritical,
    fairDefault: state.fairDefault,
    fairBulk: state.fairBulk,
    fairCycle: state.fairCycle,
    selectedJob: state.selectedJob,
    selectedHead: state.selectedHead,
    claimPending: state.claimPending,
    materializePending: state.materializePending,
    materializeOccurrence: state.materializeOccurrence,
    materializeRevision: state.materializeRevision,
    unknownPending: state.unknownPending,
    completionDetail: state.completionDetail,
    completionOmissions: state.completionOmissions,
    committedTerminalJobs: state.committedTerminalJobs,
    httpBatchMembers: state.httpBatchMembers,
    httpBatchResults: state.httpBatchResults,
    httpRetryOwners: state.httpRetryOwners,
    httpIdempotency: state.httpIdempotency,
    httpDuplicate: state.httpDuplicate,
    httpOmitted: state.httpOmitted,
    httpAttemptExecuted: state.httpAttemptExecuted,
    progressCounter: state.progressCounter,
    driveProgressBefore: state.driveProgressBefore,
    driveProgressAfter: state.driveProgressAfter,
    lastDriveBranch: state.lastDriveBranch,
    lastDriveWork: state.lastDriveWork,
    lastDriveStop: state.lastDriveStop,
  }

  val inv_routes = JOBS.forall(job =>
    (system.jobs.get(job).state == Absent implies not(system.jobs.get(job).payload)
      and not(system.jobs.get(job).dueRoute) and not(system.jobs.get(job).fairRoute)
      and not(system.jobs.get(job).leaseRoute) and not(system.jobs.get(job).wakeRoute))
    and (system.jobs.get(job).state == Leased implies system.jobs.get(job).payload
      and system.jobs.get(job).leaseRoute and not(system.jobs.get(job).dueRoute)
      and not(system.jobs.get(job).fairRoute) and not(system.jobs.get(job).wakeRoute))
    and (system.jobs.get(job).state == Scheduled and not(system.jobs.get(job).routeCorrupt)
      implies system.jobs.get(job).payload and system.jobs.get(job).dueRoute
        and system.jobs.get(job).fairRoute and system.jobs.get(job).wakeRoute)
    and (system.jobs.get(job).state == DeadLettered implies
      system.jobs.get(job).payload and system.jobs.get(job).failureRecorded
        and system.jobs.get(job).dlqRoute)
  )
  val inv_evidence = JOBS.forall(job => {
    val current = system.jobs.get(job)
    current.enqueueFingerprint >= 0
      and current.payloadBytes >= 0 and current.payloadBytes <= MAX_INLINE_PAYLOAD_BYTES
      and current.manifestBytes >= 0 and current.manifestBytes <= MAX_MANIFEST_BYTES
      and current.chunkBytes >= 0 and current.chunkBytes <= MAX_CHUNK_BYTES
      and current.digestBytes >= 0 and current.digestBytes <= MAX_DIGEST_BYTES
      and current.checkpointBytes >= 0 and current.checkpointBytes <= MAX_CHECKPOINT_BYTES
      and (current.dlqRoute implies current.state == DeadLettered)
  })
  val inv_corrupt_quarantine = JOBS.forall(job =>
    not(system.jobs.get(job).routeCorrupt)
      or (not(system.fairReady.get(job)) and system.jobs.get(job).danglingRoute)
  )
  val inv_authority = JOBS.forall(job =>
    system.jobs.get(job).revision >= 0 and system.jobs.get(job).generation >= 0
      and system.jobs.get(job).fence >= 0 and system.jobs.get(job).token >= 0
      and system.jobs.get(job).leaseUntil >= 0
      // Lease tokens are opaque identities. They are required while leased,
      // but do not have an arithmetic relationship with generation. Redrive
      // may advance generation before the next claim advances fence.
      and (system.jobs.get(job).state != Leased or (
        system.jobs.get(job).generation > 0 and system.jobs.get(job).fence > 0
          and system.jobs.get(job).token > 0))
      and (system.jobs.get(job).state != Leased or (
        system.jobs.get(job).record == Valid
          and (system.jobs.get(job).node == NodeA or system.jobs.get(job).node == NodeB)
      ))
  )
  val inv_occurrence_completion = OCCURRENCES.forall(occ =>
    system.completed.get(occ) implies not(system.materialized.get(occ))
      and not(system.durableRoute.get(occ))
      and (system.jobs.get(system.occurrenceJob.get(occ)).state == Absent
        or system.jobs.get(system.occurrenceJob.get(occ)).state == DeadLettered)
  )
  val inv_occurrence_route = OCCURRENCES.forall(occ =>
    system.materialized.get(occ) implies system.durableRoute.get(occ))
  val inv_occurrence_identity = OCCURRENCES.forall(occ =>
    not(system.emitted.get(occ)) or (
      system.occurrenceIdentity.get(occ) > 0 and JOBS.contains(system.occurrenceJob.get(occ))
    )
  )
  val inv_occurrence_distinct = OCCURRENCES.forall(first => OCCURRENCES.forall(second =>
    first == second or not(system.emitted.get(first)) or not(system.emitted.get(second))
      or system.occurrenceIdentity.get(first) != system.occurrenceIdentity.get(second)))
  val inv_occurrence_sets = system.emissionCount >= 0
    and system.emissionCount <= MAX_OCCURRENCES
    and emittedOccurrences.size() == system.emissionCount
    and system.lastBacklog >= 0 and system.skippedRemainder >= 0
    and (system.lastOutcome == ScheduleSkipped implies system.emissionCount == 0
      and system.skippedRemainder == system.lastBacklog
      and system.nextDue > system.lastEvaluationNow)
    and (system.lastOutcome == ScheduleEmitted and system.scheduleMisfire == FireOnce implies
      system.emissionCount == 1 and system.skippedRemainder == system.lastBacklog - 1
      and system.nextDue > system.lastEvaluationNow)
    and (system.lastOutcome == ScheduleEmitted and system.scheduleMisfire == CatchUp implies
      system.emissionCount == min(system.lastBacklog, system.catchUpLimit)
      and system.skippedRemainder == system.lastBacklog - system.emissionCount
      and system.nextDue > system.lastEvaluationNow)
    and (system.lastOutcome == ScheduleNotDue implies system.lastBacklog == 0
      and system.skippedRemainder == 0)
  val inv_unknown_scoped = not(system.unknownPending) or (
    system.jobs.get(system.unknownJob).operationId == system.unknownOperation
      and system.jobs.get(system.unknownJob).node == system.unknownNode
      and system.jobs.get(system.unknownJob).generation == system.unknownGeneration
      and system.jobs.get(system.unknownJob).fence == system.unknownFence
      and system.jobs.get(system.unknownJob).token == system.unknownToken
      and (system.unknownReadback == AuthorityChanged implies
        system.jobs.get(system.unknownJob).revision != system.unknownRevision
          and system.jobs.get(system.unknownJob).revision != system.unknownRevision + 1)
      and (system.unknownReadback == Committed implies system.jobs.get(system.unknownJob).state == Absent
        and system.jobs.get(system.unknownJob).revision == system.unknownRevision + 1
        and system.jobs.get(system.unknownJob).leaseUntil == 0)
      and (system.unknownReadback == Conflict implies
        system.jobs.get(system.unknownJob).state == Leased
        and system.jobs.get(system.unknownJob).revision == system.unknownRevision
        and system.jobs.get(system.unknownJob).leaseUntil == system.unknownLeaseUntil
        and system.fairInFlight.get(system.unknownJob) == 1)
  )
  val inv_execution = JOBS.forall(job => system.jobs.get(job).executionId > 0
    and system.jobs.get(job).attempts >= 0 and system.jobs.get(job).attempts <= MAX_ATTEMPTS
    and system.jobs.get(job).attemptId >= system.jobs.get(job).attempts)
  val inv_fair_identity = JOBS.contains(system.selectedJob) and system.selectedHead >= 0
    and (system.selectedHead == 0 or system.jobs.get(system.selectedJob).state != Absent)
  val inv_fair_budget = JOBS.forall(job => system.fairPermits.get(job) >= 0
    and system.fairPermits.get(job) <= MAX_CONCURRENCY_PER_SCOPE
    and system.fairRate.get(job) >= 0 and system.fairRate.get(job) <= MAX_RATE_PER_SCOPE
    and system.fairInFlight.get(job) >= 0 and system.fairInFlight.get(job) <= MAX_CONCURRENCY_PER_SCOPE
    and system.fairServed.get(job) >= 0 and system.fairCost.get(job) > 0
    and system.fairPayloadBytes.get(job) > 0 and system.fairPayloadBytes.get(job) <= MAX_INLINE_PAYLOAD_BYTES)
    and system.fairCritical >= 0 and system.fairDefault >= 0 and system.fairBulk >= 0
    and system.fairCritical <= 8 and system.fairDefault <= 4 and system.fairBulk <= 1
    and system.fairCritical + system.fairDefault + system.fairBulk <= 13
    and (system.fairCritical + system.fairDefault + system.fairBulk == 13 implies
      system.fairCritical == 8 and system.fairDefault == 4 and system.fairBulk == 1)
    and system.fairServed.get(JobC) <= system.fairServed.get(JobA)
    and normalizedServiceError(system.fairServed.get(JobA), system.fairWeight.get(JobA),
      system.fairServed.get(JobB), system.fairWeight.get(JobB)) <= FAIR_NORMALIZED_ERROR
  val inv_order_group_authority = ORDERING_GROUPS.forall(group => {
    val leased = JOBS.filter(job => system.jobs.get(job).state == Leased
      and system.fairOrdering.get(job) == group)
    system.orderHead.get(group) >= 0 and leased.size() <= 1
      and (system.orderInFlight.get(group) == (leased.size() == 1))
      and (system.orderInFlight.get(group) implies leased.contains(system.orderOwner.get(group)))
  })
  val inv_fair_progress = system.fairCycle < FAIR_QUIET_ERROR or not(fairPriorityAvailable(Bulk))
    or system.lastOutcome == FairSelected or system.lastOutcome == ClaimCommitted
  val inv_claim_read = JOBS.contains(system.claimJob) and system.claimRevision >= 0
    and (not(system.claimPending) or system.selectedJob == system.claimJob)
  val inv_receipt_budget = completionReceiptCount >= 0
    and completionReceiptCount <= MAX_COMPLETION_RECEIPTS
    and JOBS.forall(job => system.jobs.get(job).completionReceipt implies (
      system.jobs.get(job).state == Absent
        and system.jobs.get(job).completionRevision == system.jobs.get(job).revision
        and system.jobs.get(job).completionGeneration == system.jobs.get(job).generation
        and system.jobs.get(job).completionOperation == system.jobs.get(job).operationId))
    and system.completionOmissions >= 0
    and (system.completionDetail != NoCompletionDetail implies
      system.committedTerminalJobs.contains(system.completionDetailJob))
    and (system.completionDetail == CompletionDetailReturned implies
      system.jobs.get(system.completionDetailJob).completionReceipt)
    and (system.completionDetail == CompletionDetailOmitted implies
      completionReceiptCount == MAX_COMPLETION_RECEIPTS)
    and (system.unknownPending and system.completionDetailJob == system.unknownJob implies
      system.completionDetail == NoCompletionDetail)
  val inv_stale_rejection = system.lastOutcome != StaleRejected or (
    not(system.lastAttemptApplied) and system.lastAttemptRevision == system.jobs.get(system.staleJob).revision
      and system.jobs.get(system.staleJob).generation == system.staleGeneration
      and system.jobs.get(system.staleJob).fence == system.staleFence
      and system.jobs.get(system.staleJob).token == system.staleToken
      and system.jobs.get(system.staleJob).leaseUntil == system.staleLeaseUntil
      and system.jobs.get(system.staleJob).node == system.staleNode
      and system.jobs.get(system.staleJob).operationId == system.staleOperation
      and system.jobs.get(system.staleJob).state == system.staleState
      and system.jobs.get(system.staleJob).record == system.staleRecord
      and system.jobs.get(system.staleJob).payload == system.stalePayload
      and system.jobs.get(system.staleJob).dueAt == system.staleDueAt
      and system.jobs.get(system.staleJob).attempts == system.staleAttempts
      and system.jobs.get(system.staleJob).attemptId == system.staleAttemptId
      and system.jobs.get(system.staleJob).executionId == system.staleExecutionId
      and system.jobs.get(system.staleJob).dueRoute == system.staleDueRoute
      and system.jobs.get(system.staleJob).fairRoute == system.staleFairRoute
      and system.jobs.get(system.staleJob).leaseRoute == system.staleLeaseRoute
      and system.jobs.get(system.staleJob).wakeRoute == system.staleWakeRoute
  )
  val inv_http = (system.retryOwner == EngineOwnsRetry)
    == (system.lastTransport != TransportOk or statusIsRetryable(system.lastHandlerStatus))
    and JOBS.forall(job => not(system.httpSecretPersisted.get(job)))
    and system.httpBatchResults.keys() == system.httpBatchMembers
    and system.httpBatchMembers.forall(job =>
      system.httpIdempotency.get(job) == system.jobs.get(job).executionId
        and (system.httpBatchResults.get(job) == ItemRetry
          implies system.httpRetryOwners.get(job) == EngineOwnsRetry)
        and ((system.httpBatchResults.get(job) == ItemSuccess
            or system.httpBatchResults.get(job) == ItemDeadLetter)
          implies system.httpRetryOwners.get(job) == NoRetry)
        and (system.httpDuplicate.get(job) implies
          (system.httpBatchResults.get(job) == ItemMissing
            or system.httpBatchResults.get(job) == ItemRetry))
        and (system.httpOmitted.get(job) implies
          system.httpBatchResults.get(job) == ItemRetry
            and system.httpRetryOwners.get(job) == EngineOwnsRetry
            and system.httpAttemptExecuted.get(job)
            and system.jobs.get(job).attempts < MAX_ATTEMPTS
            and (compositeEngineRetryAvailable(system, job)
              or system.jobs.get(job).state == RetryWaiting
              or (system.jobs.get(job).state == Leased
                and system.now >= system.jobs.get(job).leaseUntil)))
        and (system.httpAttemptExecuted.get(job) implies
          system.httpBatchResults.get(job) != ItemMissing))
  val inv_handler_scope = not(system.lastOutcome == HandlerSuccess
      or system.lastOutcome == HandlerRetry or system.lastOutcome == HandlerDeadLetter)
    or (JOBS.contains(system.handlerJob)
      and system.jobs.get(system.handlerJob).handlerStatus == system.lastHandlerStatus
      and system.jobs.get(system.handlerJob).handlerTransport == system.lastTransport
      and system.jobs.get(system.handlerJob).handlerResult == system.lastHandlerResult
      and system.jobs.get(system.handlerJob).handlerRetryOwner == system.retryOwner)
  val inv_wake = system.wakeToken >= 0 and system.wakeAt >= 0
    and (not(system.wakePending) or system.wakeAt >= 0)
  val inv_pulse = system.pulseActions >= 0 and system.pulseActions <= MAX_PULSE_ACTIONS
    and system.activePulses >= 0 and system.activePulses <= MAX_ACTIVE_PULSES
  val inv_drive_progress = system.progressCounter >= 0
    and system.driveProgressAfter >= system.driveProgressBefore
    and (system.lastDrive == CompositeDriveRecurrence
      or system.lastDrive == CompositeDriveMaterialized
      or system.lastDrive == CompositeDriveClaimed
      or system.lastDrive == CompositeDriveTerminal implies
      system.driveProgressAfter > system.driveProgressBefore)
  val inv_schedule_cursor = system.scheduleRevision >= 0 and system.watermark >= 0
    and system.nextDue >= system.watermark
  val inv = and {
    inv_routes,
    inv_evidence,
    inv_corrupt_quarantine,
    inv_authority,
    inv_occurrence_completion,
    inv_occurrence_route,
    inv_occurrence_identity,
    inv_occurrence_distinct,
    inv_occurrence_sets,
    inv_unknown_scoped,
    inv_execution,
    inv_fair_identity,
    inv_fair_budget,
    inv_order_group_authority,
    inv_fair_progress,
    inv_claim_read,
    inv_receipt_budget,
    inv_stale_rejection,
    inv_http,
    inv_handler_scope,
    inv_wake,
    inv_pulse,
    inv_drive_progress,
    inv_schedule_cursor,
  }
  val inv_except_authority = and {
    inv_routes, inv_evidence, inv_corrupt_quarantine, inv_occurrence_completion, inv_occurrence_route,
    inv_occurrence_identity, inv_occurrence_distinct, inv_occurrence_sets,
    inv_unknown_scoped, inv_execution, inv_fair_identity, inv_fair_budget,
    inv_order_group_authority, inv_fair_progress, inv_claim_read,
    inv_receipt_budget, inv_stale_rejection, inv_http, inv_handler_scope,
    inv_wake, inv_pulse, inv_drive_progress, inv_schedule_cursor,
  }

  action init = system' = initialSystem

  // A near-boundary product state with two earlier exact completion details
  // retained. Live JobA still follows the ordinary claim/complete/reconcile
  // actions, so this initializer changes response capacity but no live-job
  // authority or dispatch rule.
  action fullCapacityCompositeInit = {
    val retained = update(update(initialSystem.jobs, JobB,
      initialSystem.jobs.get(JobB).with("completionReceipt", true)), JobC,
      initialSystem.jobs.get(JobC).with("completionReceipt", true))
    all { system' = initialSystem.with("jobs", retained)
      .with("committedTerminalJobs", Set(JobB, JobC)) }
  }

  action Advance = {
    nondet amount = Set(0, 1, OCCURRENCE_STEP, OCCURRENCE_STEP * 2).oneOf()
    all { system' = system.with("now", system.now + amount) }
  }

  action ScheduleOccurrence = {
    nondet mode = Set(Skip, FireOnce, CatchUp).oneOf()
    nondet catchUpLimit = Set(1, 2, MAX_OCCURRENCES).oneOf()
    all { system' = evaluateCompositeSchedule(system, mode, catchUpLimit) }
  }

  // Two schedulers first record the same occurrence revision.  The selected
  // reader may commit once; a peer retaining that read can only conflict.
  action SelectMaterialization = {
    nondet occurrence = OCCURRENCES.filter(candidate => system.emitted.get(candidate)
      and not(system.materialized.get(candidate)) and not(system.completed.get(candidate))
      and (system.jobs.get(system.occurrenceJob.get(candidate)).state == Absent
        or system.jobs.get(system.occurrenceJob.get(candidate)).state == DeadLettered)).oneOf()
    nondet reader = NODES.oneOf()
    all {
      not(compositeBlocked(system, system.occurrenceJob.get(occurrence))),
      system' = system.with("materializePending", true)
        .with("materializeOccurrence", occurrence)
        .with("materializeRevision", system.scheduleRevision)
        .with("materializeReader", reader),
    }
  }

  action Enqueue = {
    nondet contender = NODES.oneOf()
    nondet expectedRevision = Set(system.materializeRevision, system.materializeRevision - 1).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val occurrence = system.materializeOccurrence
    val job = system.occurrenceJob.get(occurrence)
    val current = system.jobs.get(job)
    val inserted = current.with("state", Scheduled).with("revision", current.revision + 1)
      .with("payload", true).with("enqueueFingerprint", max(1, current.executionId))
      .with("payloadBytes", max(1, current.executionId))
      .with("manifestBytes", max(1, current.executionId + 1))
      .with("chunkBytes", max(1, current.executionId + 2))
      .with("digestBytes", max(1, current.executionId + 3))
      .with("failureRecorded", false).with("dlqRoute", false)
      .with("checkpointBytes", 0)
      .with("record", Valid).with("routeCorrupt", false)
      .with("dueRoute", true).with("fairRoute", true).with("leaseRoute", false).with("wakeRoute", true)
      .with("occurrence", occurrence).with("operationId", operation).with("dueAt", system.now)
      .with("expiresAt", system.now + MAX_JOB_AGE_TICKS)
      .with("generation", current.generation).with("fence", current.fence)
      .with("token", current.token)
      .with("leaseUntil", 0).with("attempts", 0).with("attemptId", 0)
      .with("executionId", current.executionId)
      .with("completionReceipt", false).with("completionPending", false)
    val sameRead = expectedRevision == system.materializeRevision
    val materializeEffect = materializeKernel(system.materializePending,
      expectedRevision, system.materializeRevision, system.scheduleRevision,
      contender, system.materializeReader,
      if (system.materializeReader == NodeA) NodeB else NodeA,
      system.scheduleEnabled, system.paused,
      system.emitted.get(occurrence), system.materialized.get(occurrence),
      system.overlap, current.state == Leased)
    val allowed = materializeEffect.allowed
      and current.state == Absent
      and not(compositeBlocked(system, job)) and not(system.completed.get(occurrence))
    val peerConflict = not(system.materializePending) and sameRead
      and contender != system.materializeReader and system.scheduleRevision != system.materializeRevision
      and system.materialized.get(occurrence)
    all {
      system' = if (allowed) system.with("jobs", update(system.jobs, job, inserted))
        .with("httpBatchMembers", withoutHttpMember(system.httpBatchMembers, job))
        .with("httpBatchResults", withoutHttpResult(system.httpBatchResults,
          system.httpBatchMembers, job))
        .with("httpRetryOwners", update(system.httpRetryOwners, job, NoRetry))
        .with("httpIdempotency", update(system.httpIdempotency, job, 0))
        .with("httpDuplicate", update(system.httpDuplicate, job, false))
        .with("httpOmitted", update(system.httpOmitted, job, false))
        .with("fairReady", update(system.fairReady, job, true))
        .with("materialized", update(system.materialized, occurrence, true))
        .with("durableRoute", update(system.durableRoute, occurrence, true))
        .with("scheduleRevision", system.scheduleRevision + 1).with("wakePending", true)
        .with("materializePending", false)
        .with("completionDetail", NoCompletionDetail).with("completionDetailJob", job)
        .with("lastResult", Committed).with("lastOutcome", EnqueueCommitted)
        else if (compositeBlocked(system, job)) system
          else if (peerConflict or system.materializePending)
            system.with("materializePending", false).with("lastResult", Conflict)
              .with("lastOutcome", EnqueueConflict)
          else system,
    }
  }

  pure def applyCompositeFairSelect(currentSystem, job, reader) = {
    val current = currentSystem.jobs.get(job)
    currentSystem.with("selectedJob", job).with("selectedScope", jobScope(job))
      .with("selectedHead", currentSystem.orderHead.get(currentSystem.fairOrdering.get(job)))
      .with("claimPending", true)
      .with("claimJob", job).with("claimRevision", current.revision).with("claimReader", reader)
      .with("lastOutcome", FairSelected)
  }

  action FairSelect = {
    nondet priority = PRIORITIES.oneOf()
    nondet job = fairServiceEligibleJobs.filter(candidate => system.fairPriority.get(candidate) == priority).oneOf()
    nondet reader = NODES.oneOf()
    val serviceEffect = compositeFairClaimEffect(system, job,
      fairServiceEligibleJobs.contains(job))
    all {
      not(compositeBlocked(system, job)) and serviceEffect.allowed
        and system.fairReady.get(job)
        and not(system.jobs.get(job).routeCorrupt),
      system' = applyCompositeFairSelect(system, job, reader),
    }
  }

  pure def compositeClaimDecision(currentSystem, contender, expectedRevision) = {
    val job = currentSystem.claimJob
    val current = currentSystem.jobs.get(job)
    val sameRead = currentSystem.claimPending and currentSystem.selectedJob == job
      and expectedRevision == currentSystem.claimRevision
    val allowed = not(compositeBlocked(currentSystem, job)) and sameRead
      and contender == currentSystem.claimReader
      and compositeFairEligibleJobs(currentSystem).contains(job)
      and claimRouteIsEligible(current.state, current.record,
        current.payload, current.dueRoute, current.fairRoute, current.dueAt, currentSystem.now,
        current.attempts, false) and not(current.routeCorrupt)
      and expectedRevision == current.revision
    val competing = not(compositeBlocked(currentSystem, job))
      and expectedRevision == currentSystem.claimRevision
      and contender != current.node and (not(currentSystem.claimPending)
        or current.revision != currentSystem.claimRevision or current.state != Scheduled)
    val effect = compositeFairClaimEffect(currentSystem, job, allowed)
    { job: job, allowed: effect.allowed, competing: competing, effect: effect }
  }

  pure def applyCompositeClaimTransition(currentSystem, contender, expectedRevision) = {
    val decision = compositeClaimDecision(currentSystem, contender, expectedRevision)
    if (decision.allowed)
      applyCompositeFairEffect(currentSystem, decision.job, contender, decision.effect)
        .with("claimPending", false).with("lastClaimNode", contender)
        .with("lastResult", Committed).with("lastOutcome", ClaimCommitted)
    else currentSystem.with("claimPending", false).with("lastResult", Conflict)
      .with("lastOutcome", ClaimConflict)
  }

  // Both contenders read the same selected revision.  The first matching node
  // commits; a different node can only fail after the committed revision and
  // lease state provide competing durable evidence.
  action Claim = {
    nondet contender = NODES.oneOf()
    nondet expectedRevision = Set(system.claimRevision, system.claimRevision - 1).oneOf()
    val decision = compositeClaimDecision(system, contender, expectedRevision)
    all {
      decision.allowed or decision.competing,
      system' = applyCompositeClaimTransition(system, contender, expectedRevision),
    }
  }

  // Refill only restores unused permits/rate.  In-flight work is authoritative
  // and therefore cannot be erased by a quiet-period refill.
  action FairRefill = {
    nondet job = JOBS.oneOf()
    val current = system.jobs.get(job)
    val group = system.fairOrdering.get(job)
    val primary = primaryJob(job)
    val eligible = not(current.routeCorrupt) and fairJobIsEligible(current.state, current.record,
      current.payload, current.dueRoute, current.fairRoute, current.dueAt, system.now,
      system.fairBlock.get(job), max(0, MAX_CONCURRENCY_PER_SCOPE - system.fairInFlight.get(job)),
      MAX_RATE_PER_SCOPE, system.fairInFlight.get(job), system.fairPayloadBytes.get(job),
      MAX_INLINE_PAYLOAD_BYTES, system.fairOrder.get(job), system.orderHead.get(group), current.attempts,
      system.paused) and orderCanAcquire(system.fairOrder.get(job), system.orderHead.get(group),
        system.orderInFlight.get(group)) and system.fairPermits.get(primary) > 0
      and system.fairRate.get(primary) > 0
    all {
      not(compositeBlocked(system, job)),
      system' = system.with("fairReady", update(system.fairReady, job, eligible))
        .with("fairPermits", update(system.fairPermits, job,
          max(0, MAX_CONCURRENCY_PER_SCOPE - system.fairInFlight.get(job))))
        .with("fairRate", update(system.fairRate, job, MAX_RATE_PER_SCOPE))
        .with("lastOutcome", FairRefilled),
    }
  }

  action HandleHttp = {
    nondet job = leasedJobs.oneOf()
    nondet status = Set(Status2xx, Status408, Status425, Status429, Status4xx, Status5xx).oneOf()
    nondet transport = Set(TransportOk, Timeout, ConnectFailure, InvalidResponse).oneOf()
    nondet retryAfter = Set(-1, 0, 1, MAX_RETRY_AFTER_TICKS, MAX_RETRY_AFTER_TICKS + 1).oneOf()
    val current = system.jobs.get(job)
    val allowed = not(compositeBlocked(system, job))
      and system.httpBatchMembers.contains(job)
      and not(system.httpSecretPersisted.get(job))
      and system.httpIdempotency.get(job) == current.executionId
      and not(system.httpAttemptExecuted.get(job))
      and system.httpBatchResults.get(job) == ItemMissing
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, current.node,
        current.revision, current.generation, current.fence, current.token,
        current.leaseUntil, current.operationId, system.now)
    all {
      not(compositeBlocked(system, job)),
      system' = if (allowed)
        applyCompositeHttpResult(system, job, status, transport, retryAfter)
        else system.with("lastResult", Conflict).with("lastOutcome", HandlerRejected),
    }
  }

  /// Canonical durable HTTP delivery reducer. Status/transport policy comes
  /// only from the shared HTTP helpers; this reducer records the resulting
  /// per-item classification and immutable authority snapshot together.
  pure def applyCompositeHttpResult(currentSystem, job, status, transport,
      retryAfter) = {
    val current = currentSystem.jobs.get(job)
    val handler = httpHandlerResult(status, transport)
    val owner = httpRetryOwner(status, transport)
    val itemResult = if (handler == Success) ItemSuccess
      else if (handler == Transient) ItemRetry else ItemDeadLetter
    val handled = current.with("handlerStatus", status).with("handlerTransport", transport)
      .with("handlerResult", handler).with("handlerRetryOwner", owner)
      .with("handlerRetryAfter", clampRetryAfter(retryAfter)).with("handlerRevision", current.revision)
      .with("handlerNode", current.node).with("handlerGeneration", current.generation)
      .with("handlerFence", current.fence).with("handlerToken", current.token)
      .with("handlerLeaseUntil", current.leaseUntil).with("handlerOperation", current.operationId)
    currentSystem.with("jobs", update(currentSystem.jobs, job, handled))
      .with("httpBatchResults", currentSystem.httpBatchResults.put(job, itemResult))
      .with("httpRetryOwners", update(currentSystem.httpRetryOwners, job, owner))
      .with("httpDuplicate", update(currentSystem.httpDuplicate, job, false))
      .with("httpOmitted", update(currentSystem.httpOmitted, job, false))
      .with("httpAttemptExecuted", update(currentSystem.httpAttemptExecuted, job, true))
      .with("lastHandlerStatus", status).with("lastHandlerResult", handler)
      .with("lastTransport", transport).with("retryOwner", owner)
      .with("handlerJob", job).with("handlerRevision", current.revision)
      .with("handlerNode", current.node).with("handlerGeneration", current.generation)
      .with("handlerFence", current.fence).with("handlerToken", current.token)
      .with("handlerLeaseUntil", current.leaseUntil).with("handlerOperation", current.operationId)
      .with("lastOutcome", if (handler == Success) HandlerSuccess
        else if (handler == Transient) HandlerRetry else HandlerDeadLetter)
  }

  /// Duplicate delivery and omission are per-member classifications. They do
  /// not change membership, retry ownership, idempotency or secret absence.
  action HttpDuplicateDelivery = {
    nondet job = system.httpBatchMembers.oneOf()
    all {
      system' = applyHttpDuplicate(system, job),
    }
  }

  action HttpOmitItem = {
    nondet job = system.httpBatchMembers.oneOf()
    all {
      system' = applyHttpOmission(system, job),
    }
  }

  // Rejected handlers still present job identity and the complete lease
  // authority tuple.  Keeping rejection separate makes both an authorized
  // classification and a wrong-job/stale attempt independently reachable.
  action HandleHttpRejected = {
    nondet job = leasedJobs.oneOf()
    nondet presentedJob = JOBS.oneOf()
    nondet node = NODES.oneOf()
    nondet revision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet generation = authorityChoices(system.jobs.get(job).generation).oneOf()
    nondet fence = authorityChoices(system.jobs.get(job).fence).oneOf()
    nondet token = authorityChoices(system.jobs.get(job).token).oneOf()
    nondet leaseUntil = authorityChoices(system.jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = system.jobs.get(job)
    val authority = presentedJob == job
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, revision, generation,
        fence, token, leaseUntil, operation, system.now)
    all {
      not(compositeBlocked(system, job)) and not(authority),
      system' = system.with("lastResult", Conflict).with("lastOutcome", HandlerRejected),
    }
  }

  pure def compositeHandlerAvailable(currentSystem, job) = {
    val current = currentSystem.jobs.get(job)
    not(compositeBlocked(currentSystem, job)) and currentSystem.handlerJob == job
      and current.state == Leased and current.handlerRevision == current.revision
      and current.handlerStatus == currentSystem.lastHandlerStatus
      and current.handlerTransport == currentSystem.lastTransport
      and current.handlerResult == currentSystem.lastHandlerResult
      and current.handlerRetryOwner == currentSystem.retryOwner
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, currentSystem.handlerNode,
        currentSystem.handlerRevision, currentSystem.handlerGeneration,
        currentSystem.handlerFence, currentSystem.handlerToken,
        currentSystem.handlerLeaseUntil, currentSystem.handlerOperation, currentSystem.now)
  }

  pure def compositeEngineRetryAvailable(currentSystem, job) = {
    val current = currentSystem.jobs.get(job)
    compositeHandlerAvailable(currentSystem, job) and current.handlerResult == Transient
      and current.handlerRetryOwner == EngineOwnsRetry and current.attempts < MAX_ATTEMPTS
  }

  pure def applyCompositeHandler(currentSystem, job) = {
    val current = currentSystem.jobs.get(job)
    val available = compositeHandlerAvailable(currentSystem, job)
    val success = available and current.handlerResult == Success
      and current.handlerStatus == Status2xx
    val retry = compositeEngineRetryAvailable(currentSystem, job)
    val dead = available and (current.handlerResult == Permanent
      or (current.handlerResult == Transient and current.handlerRetryOwner == EngineOwnsRetry and not(retry)))
    val retried = current.with("state", RetryWaiting).with("revision", current.revision + 1)
      .with("dueAt", currentSystem.now + 1).with("dueRoute", true).with("fairRoute", true)
      .with("wakeRoute", true).with("leaseRoute", false).with("leaseUntil", 0)
      .with("cancelRequested", false)
    val releasedReady = update(currentSystem.fairReady, job, if (retry) true else false)
    val releasedPermits = releaseBudget(currentSystem.fairPermits, job, 1,
      MAX_CONCURRENCY_PER_SCOPE)
    val releasedRate = releaseBudget(currentSystem.fairRate, job, 1, MAX_RATE_PER_SCOPE)
    val releasedFlight = releaseFlight(currentSystem.fairInFlight, job)
    if (success) terminalSystemFrom(currentSystem, job, Absent, false, true,
      CompletionCommitted)
    else if (dead) terminalSystemFrom(currentSystem, job, DeadLettered, true, false,
      HandlerDeadLetter)
    else if (retry) releaseCompositeOrder(clearCompositeHttpMember(currentSystem, job), job, false)
      .with("jobs", update(currentSystem.jobs, job, retried))
      .with("fairReady", releasedReady).with("fairPermits", releasedPermits)
      .with("fairRate", releasedRate).with("fairInFlight", releasedFlight)
      .with("wakePending", true)
      .with("fairOrder", update(currentSystem.fairOrder, job,
        currentSystem.fairHead.get(job)))
      .with("lastResult", Committed).with("lastOutcome", HandlerRetry)
    else if (not(available)) currentSystem
    else currentSystem.with("lastResult", Conflict)
  }

  action ApplyHandler = {
    nondet job = leasedJobs.oneOf()
    all {
      system' = applyCompositeHandler(system, job),
    }
  }

  action Complete = {
    nondet job = leasedJobs.oneOf()
    val node = system.jobs.get(job).node
    val presentedRevision = system.jobs.get(job).revision
    val generation = system.jobs.get(job).generation
    val fence = system.jobs.get(job).fence
    val token = system.jobs.get(job).token
    val presentedLeaseUntil = system.jobs.get(job).leaseUntil
    val operation = system.jobs.get(job).operationId
    val current = system.jobs.get(job)
    val exact = exactAuthority(current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, node, presentedRevision, generation,
      fence, token, presentedLeaseUntil, operation, system.now)
    val allowed = not(compositeBlocked(system, job)) and exact and current.state == Leased
      and not(httpResolutionPending(system, job))
    all {
      system' = if (allowed) terminalSystem(job, Absent, false, true, CompletionCommitted)
        else if (compositeBlocked(system, job)) system
          else system.with("lastResult", Conflict).with("lastOutcome", CompletionConflict),
    }
  }

  action CompleteRejected = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet generation = authorityChoices(system.jobs.get(job).generation).oneOf()
    nondet fence = authorityChoices(system.jobs.get(job).fence).oneOf()
    nondet token = authorityChoices(system.jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(system.jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = system.jobs.get(job)
    val exact = exactAuthority(current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, node, presentedRevision, generation,
      fence, token, presentedLeaseUntil, operation, system.now)
    all {
      not(exact) and not(compositeBlocked(system, job)),
      system' = system.with("lastResult", Conflict).with("lastOutcome", CompletionConflict),
    }
  }

  pure def exposeCompletionFrom(currentSystem, job, node, revision, generation,
      fence, token, presentedLeaseUntil, operation) = {
    val current = currentSystem.jobs.get(job)
    val exact = not(compositeBlocked(currentSystem, job)) and exactIdentity(current.node,
      current.revision, current.generation, current.fence, current.token,
      current.leaseUntil, current.operationId, node, revision, generation, fence,
      token, presentedLeaseUntil, operation)
      and current.completionPending and current.completionRevision == current.revision
      and current.completionGeneration == current.generation
      and current.completionOperation == current.operationId
      and not(current.payload) and not(current.dueRoute) and not(current.fairRoute)
      and not(current.leaseRoute) and not(current.wakeRoute)
    val receiptCount = JOBS.filter(candidate =>
      currentSystem.jobs.get(candidate).completionReceipt).size()
    val detailAvailable = receiptCount < MAX_COMPLETION_RECEIPTS
    if (exact) currentSystem.with("jobs", update(currentSystem.jobs, job,
        current.with("completionReceipt", detailAvailable).with("completionPending", false)))
      .with("completionDetail", completionDetailAt(receiptCount))
      .with("completionDetailJob", job)
      .with("completionOmissions", if (detailAvailable) currentSystem.completionOmissions
        else currentSystem.completionOmissions + 1)
      .with("lastResult", Committed).with("lastOutcome", CompletionExposed)
    else currentSystem
  }

  action ExposeCompletion = {
    nondet job = JOBS.filter(candidate => system.jobs.get(candidate).state == Absent
      and system.jobs.get(candidate).completionPending
      and not(system.jobs.get(candidate).completionReceipt)).oneOf()
    nondet node = NODES.oneOf()
    nondet revision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet generation = authorityChoices(system.jobs.get(job).generation).oneOf()
    nondet fence = authorityChoices(system.jobs.get(job).fence).oneOf()
    nondet token = authorityChoices(system.jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(system.jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = system.jobs.get(job)
    all {
      system' = exposeCompletionFrom(system, job, node, revision, generation,
        fence, token, presentedLeaseUntil, operation),
    }
  }

  action UnknownCommit = {
    nondet job = leasedJobs.oneOf()
    val node = system.jobs.get(job).node
    val presentedRevision = system.jobs.get(job).revision
    val generation = system.jobs.get(job).generation
    val fence = system.jobs.get(job).fence
    val token = system.jobs.get(job).token
    val presentedLeaseUntil = system.jobs.get(job).leaseUntil
    val operation = system.jobs.get(job).operationId
    nondet committed = bools.oneOf()
    val current = system.jobs.get(job)
    val exact = not(system.unknownPending) and current.state == Leased
      and not(httpResolutionPending(system, job))
      and exactAuthority(current.node, current.revision, current.generation, current.fence,
        current.token, current.leaseUntil, current.operationId, node, presentedRevision,
        generation, fence, token, presentedLeaseUntil, operation, system.now)
    val resolved = if (committed)
      terminalSystem(job, Absent, false, true, CompletionCommitted) else system
    all {
      system' = if (exact) resolved
        .with("unknownPending", true).with("unknownJob", job).with("unknownOperation", operation)
        .with("unknownNode", node).with("unknownRevision", presentedRevision)
        .with("unknownGeneration", generation).with("unknownFence", fence)
        .with("unknownToken", token).with("unknownLeaseUntil", presentedLeaseUntil)
        .with("unknownReadback", if (committed) Committed else Conflict)
        .with("completionDetail", NoCompletionDetail).with("completionDetailJob", job)
        .with("lastResult", Unknown)
        .with("lastOutcome", UnknownCommitObserved) else system,
    }
  }

  action UnknownRejected = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet generation = authorityChoices(system.jobs.get(job).generation).oneOf()
    nondet fence = authorityChoices(system.jobs.get(job).fence).oneOf()
    nondet token = authorityChoices(system.jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(system.jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = system.jobs.get(job)
    val exact = exactAuthority(current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, node, presentedRevision, generation,
      fence, token, presentedLeaseUntil, operation, system.now)
    all {
      not(exact) and not(system.unknownPending),
      system' = system.with("lastResult", Conflict).with("lastOutcome", CompletionConflict),
    }
  }

  action ReconcileUnknown = {
    nondet observed = Set(Committed, Conflict, AuthorityChanged).oneOf()
    val job = system.unknownJob
    val current = system.jobs.get(job)
    val authorityReadback = current.operationId == system.unknownOperation
      and current.node == system.unknownNode
      and current.generation == system.unknownGeneration and current.fence == system.unknownFence
      and current.token == system.unknownToken
      and (observed == Committed implies current.state == Absent
        and current.revision == system.unknownRevision + 1 and current.leaseUntil == 0)
      and (observed == Conflict implies current.state == Leased
        and current.revision == system.unknownRevision
        and current.leaseUntil == system.unknownLeaseUntil
        and system.fairInFlight.get(job) == 1)
    val authorityChanged = current.revision != system.unknownRevision
      and current.revision != system.unknownRevision + 1
    val exact = system.unknownPending and observed == system.unknownReadback
      and (if (observed == AuthorityChanged) authorityChanged else authorityReadback)
    val committedExact = exact and observed == Committed
    val detailAvailable = completionReceiptCount < MAX_COMPLETION_RECEIPTS
    all {
      system' = if (exact) system.with("jobs", if (committedExact)
        update(system.jobs, job, current.with("completionReceipt", detailAvailable)
          .with("completionPending", false)) else system.jobs)
        .with("unknownPending", false)
        .with("completionDetail", if (committedExact)
          completionDetailAt(completionReceiptCount) else NoCompletionDetail)
        .with("completionDetailJob", job)
        .with("completionOmissions", if (committedExact and not(detailAvailable))
          system.completionOmissions + 1 else system.completionOmissions)
        .with("lastResult", observed)
        .with("lastOutcome", UnknownReconciled) else system,
    }
  }

  action ChangeUnknownAuthority = {
    val job = system.unknownJob
    val current = system.jobs.get(job)
    all {
      system.unknownPending,
      system' = system.with("jobs", update(system.jobs, job,
        current.with("revision", current.revision + 2)))
        .with("unknownReadback", AuthorityChanged).with("lastResult", Unknown)
        .with("lastOutcome", UnknownAuthorityChanged),
    }
  }

  action StaleMutationInput(job: JobId, node: Node, presentedRevision: int,
      generation: int, fence: int, token: int, presentedLeaseUntil: int,
      operation: OperationId): bool = {
    val current = system.jobs.get(job)
    val exact = exactAuthority(current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, node, presentedRevision, generation,
      fence, token, presentedLeaseUntil, operation, system.now)
    val stale = not(compositeBlocked(system, job)) and current.state == Leased and not(exact)
    val rejected = system.with("staleJob", job).with("staleRevision", current.revision)
        .with("staleState", current.state).with("staleRecord", current.record)
        .with("stalePayload", current.payload).with("staleDueAt", current.dueAt)
        .with("staleAttempts", current.attempts).with("staleAttemptId", current.attemptId)
        .with("staleExecutionId", current.executionId).with("staleDueRoute", current.dueRoute)
        .with("staleFairRoute", current.fairRoute).with("staleLeaseRoute", current.leaseRoute)
        .with("staleWakeRoute", current.wakeRoute)
        .with("staleGeneration", current.generation).with("staleFence", current.fence)
        .with("staleToken", current.token).with("staleLeaseUntil", current.leaseUntil)
        .with("staleNode", current.node).with("staleOperation", current.operationId)
        .with("lastAttemptRevision", current.revision).with("lastAttemptApplied", false)
        .with("lastAttemptOperation", operation)
        .with("lastResult", Conflict)
        .with("lastOutcome", StaleRejected)
    all {
      stale,
      authoritativeProjection(rejected) == authoritativeProjection(system),
      system' = rejected,
    }
  }

  action StaleMutation = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet generation = authorityChoices(system.jobs.get(job).generation).oneOf()
    nondet fence = authorityChoices(system.jobs.get(job).fence).oneOf()
    nondet token = authorityChoices(system.jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(system.jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    StaleMutationInput(job, node, presentedRevision, generation, fence, token,
      presentedLeaseUntil, operation)
  }

  action StaleAuthorityWitnessStep = {
    val current = system.jobs.get(JobA)
    if (current.state == Leased) {
      StaleMutationInput(JobA, current.node, current.revision - 1,
        current.generation, current.fence, current.token, current.leaseUntil,
        current.operationId)
    } else {
      val effect = fairSelectedServiceKernel(true, JobA, ScopeA, ScopeA,
        Critical, system.fairCost.get(JobA), false, true, true, false,
        compositeFairPrestate(system, JobA))
      all {
        effect.allowed,
        system' = applyCompositeFairEffect(system, JobA, NodeA, effect),
      }
    }
  }

  action Cancel = {
    nondet job = JOBS.filter(candidate =>
      (system.jobs.get(candidate).state == Scheduled or system.jobs.get(candidate).state == RetryWaiting)
        and not(compositeBlocked(system, candidate))).oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet generation = authorityChoices(system.jobs.get(job).generation).oneOf()
    nondet fence = authorityChoices(system.jobs.get(job).fence).oneOf()
    nondet token = authorityChoices(system.jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(system.jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = system.jobs.get(job)
    val exact = not(compositeBlocked(system, job)) and exactIdentity(current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, node, presentedRevision, generation,
      fence, token, presentedLeaseUntil, operation)
    all {
      system' = if (exact) terminalSystem(job, Absent, false, false, CancelCommitted)
        else if (compositeBlocked(system, job)) system
          else system.with("lastResult", Conflict).with("lastOutcome", CompletionConflict),
    }
  }

  action RequestCancel = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet generation = authorityChoices(system.jobs.get(job).generation).oneOf()
    nondet fence = authorityChoices(system.jobs.get(job).fence).oneOf()
    nondet token = authorityChoices(system.jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(system.jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = system.jobs.get(job)
    val exact = not(compositeBlocked(system, job)) and exactAuthority(current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operationId, node, presentedRevision, generation,
      fence, token, presentedLeaseUntil, operation, system.now)
    all {
      system' = if (exact) system.with("jobs", update(system.jobs, job,
        current.with("cancelRequested", true).with("revision", current.revision + 1)))
        .with("lastResult", Committed).with("lastOutcome", CancelRequested)
        else if (compositeBlocked(system, job)) system
          else system.with("lastResult", Conflict).with("lastOutcome", CompletionConflict),
    }
  }

  action CancelLeased = {
    nondet job = leasedJobs.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet generation = authorityChoices(system.jobs.get(job).generation).oneOf()
    nondet fence = authorityChoices(system.jobs.get(job).fence).oneOf()
    nondet token = authorityChoices(system.jobs.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(system.jobs.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = system.jobs.get(job)
    val exact = not(compositeBlocked(system, job)) and current.cancelRequested and exactAuthority(current.node, current.revision,
      current.generation, current.fence, current.token, current.leaseUntil, current.operationId,
      node, presentedRevision, generation, fence, token, presentedLeaseUntil, operation, system.now)
    all {
      system' = if (exact) terminalSystem(job, Absent, false, false, LeasedCancelled)
        else if (compositeBlocked(system, job)) system
          else system.with("lastResult", Conflict).with("lastOutcome", CompletionConflict),
    }
  }

  pure def applyCompositeScheduledExpiry(currentSystem, job) =
    terminalSystemFrom(currentSystem, job, DeadLettered, true, false, ScheduledExpired)

  action ExpireScheduled = {
    nondet job = JOBS.filter(candidate =>
      (system.jobs.get(candidate).state == Scheduled or system.jobs.get(candidate).state == RetryWaiting)
        and system.jobs.get(candidate).expiresAt <= system.now
        and not(compositeBlocked(system, candidate))).oneOf()
    val current = system.jobs.get(job)
    all {
      system' = applyCompositeScheduledExpiry(system, job),
    }
  }

  action ExpireLease = {
    nondet job = leasedJobs.oneOf()
    val current = system.jobs.get(job)
    val allowed = not(compositeBlocked(system, job)) and current.leaseUntil <= system.now
    val cancelled = allowed and current.cancelRequested
    val retry = allowed and not(cancelled) and current.expiresAt > system.now
      and current.attempts < MAX_ATTEMPTS
    val updated = if (retry)
      current.with("state", RetryWaiting).with("revision", current.revision + 1)
        .with("dueAt", system.now).with("dueRoute", true).with("fairRoute", true)
        .with("leaseRoute", false).with("wakeRoute", true).with("leaseUntil", 0)
      else terminalJob(current, DeadLettered, true, false)
    all {
      system' = if (cancelled) terminalSystem(job, Absent, false, false, LeasedCancelled)
        else if (allowed and retry) releaseCompositeOrder(system, job, false)
        .with("jobs", update(system.jobs, job, updated))
        .with("fairReady", update(system.fairReady, job, retry))
        .with("fairPermits", releaseBudget(system.fairPermits, job, 1,
          MAX_CONCURRENCY_PER_SCOPE))
        .with("fairRate", releaseBudget(system.fairRate, job, 1, MAX_RATE_PER_SCOPE))
        .with("fairInFlight", releaseFlight(system.fairInFlight, job))
        .with("wakePending", durableRoutes(update(system.jobs, job, updated)))
        .with("lastResult", Committed).with("lastOutcome", LeaseExpired)
        else if (allowed) terminalSystem(job, DeadLettered, true, false, LeaseExpired)
        else if (compositeBlocked(system, job)) system
          else system.with("lastResult", Conflict).with("lastOutcome", CompletionConflict),
    }
  }

  pure def applyCompositeRedrive(currentSystem, job, expectedRevision,
      expectedOperation) = {
    val current = currentSystem.jobs.get(job)
    val nextOperation = nextOperationId(current.operationId)
    val group = currentSystem.fairOrdering.get(job)
    val kernel = redriveKernel(current.state, current.record,
      compositeBlocked(currentSystem, job), current.revision, current.operationId,
      expectedRevision, expectedOperation, current.generation, current.fence, current.token,
      current.executionId, false, currentSystem.now)
    val allowed = kernel.allowed
      and current.failureRecorded and current.dlqRoute
      and currentSystem.fairInFlight.get(job) == 0
      and not(currentSystem.orderInFlight.get(group))
    val redriven = current.with("state", Scheduled).with("revision", kernel.nextRevision)
      .with("payload", true).with("checkpointBytes", 0).with("failureRecorded", false)
      .with("dlqRoute", false).with("dueRoute", true).with("fairRoute", true)
      .with("wakeRoute", true).with("leaseRoute", false).with("leaseUntil", 0)
      .with("attempts", kernel.nextAttempts).with("attemptId", kernel.nextAttemptId)
      .with("dueAt", currentSystem.now).with("expiresAt", kernel.nextExpiresAt)
      .with("routeCorrupt", false).with("danglingRoute", false)
      .with("generation", kernel.nextGeneration).with("fence", current.fence)
      .with("token", 0).with("executionId", kernel.nextExecutionId)
      .with("operationId", nextOperation).with("cancelRequested", false)
      .with("completionPending", false).with("completionReceipt", false)
      .with("completionRevision", 0).with("completionGeneration", 0)
      .with("completionOperation", nextOperation)
      .with("handlerStatus", Status2xx).with("handlerTransport", TransportOk)
      .with("handlerResult", Success).with("handlerRetryOwner", NoRetry)
      .with("handlerRetryAfter", 0).with("handlerRevision", 0).with("handlerNode", current.node)
      .with("handlerGeneration", 0).with("handlerFence", 0).with("handlerToken", 0)
      .with("handlerLeaseUntil", 0).with("handlerOperation", nextOperation)
    val occurrence = current.occurrence
    val cleaned = clearCompositeHttpMember(currentSystem, job)
    val clearedHandler = if (currentSystem.handlerJob == job) cleaned
      .with("lastHandlerStatus", Status2xx).with("lastTransport", TransportOk)
      .with("lastHandlerResult", Success).with("retryOwner", NoRetry)
      .with("handlerRevision", 0).with("handlerNode", current.node)
      .with("handlerGeneration", 0).with("handlerFence", 0).with("handlerToken", 0)
      .with("handlerLeaseUntil", 0).with("handlerOperation", nextOperation)
      else cleaned
    if (allowed) clearedHandler.with("jobs", update(currentSystem.jobs, job, redriven))
      .with("fairReady", update(currentSystem.fairReady, job, true))
      .with("fairHead", update(currentSystem.fairHead, job,
        currentSystem.orderHead.get(group)))
      .with("fairOrder", update(currentSystem.fairOrder, job,
        currentSystem.orderHead.get(group)))
      .with("orderOwner", update(currentSystem.orderOwner, group, job))
      .with("claimPending", if (currentSystem.claimJob == job) false
        else currentSystem.claimPending)
      .with("selectedHead", if (currentSystem.selectedJob == job) 0
        else currentSystem.selectedHead)
      .with("committedTerminalJobs", currentSystem.committedTerminalJobs
        .filter(candidate => candidate != job))
      .with("wakePending", true).with("emitted", update(currentSystem.emitted, occurrence, true))
      .with("materialized", update(currentSystem.materialized, occurrence, true))
      .with("durableRoute", update(currentSystem.durableRoute, occurrence, true))
      .with("completed", update(currentSystem.completed, occurrence, false))
      .with("emissionCount", activeEmissionCount(update(currentSystem.emitted, occurrence, true)))
      .with("completionDetail", NoCompletionDetail).with("completionDetailJob", job)
      .with("lastResult", Committed).with("lastOutcome", RedriveCommitted)
    else currentSystem.with("lastResult", Conflict).with("lastOutcome", CompletionConflict)
  }

  action Redrive = {
    nondet job = JOBS.filter(candidate => system.jobs.get(candidate).state == DeadLettered
      and not(compositeBlocked(system, candidate))).oneOf()
    nondet expectedRevision = authorityChoices(system.jobs.get(job).revision).oneOf()
    nondet expectedOperation = OPERATIONS.oneOf()
    all { system' = applyCompositeRedrive(system, job, expectedRevision,
      expectedOperation) }
  }

  action DropRoute = {
    nondet job = JOBS.filter(candidate => system.jobs.get(candidate).state == Scheduled
      and not(compositeBlocked(system, candidate))).oneOf()
    val current = system.jobs.get(job)
    val dropped = current.with("routeCorrupt", true).with("danglingRoute", true)
      .with("revision", current.revision + 1).with("dueRoute", false)
      .with("fairRoute", true).with("wakeRoute", false)
    all {
      system' = system.with("jobs", update(system.jobs, job, dropped))
        .with("fairReady", update(system.fairReady, job, false))
        .with("wakePending", durableRoutes(update(system.jobs, job, dropped))).with("lastResult", Committed)
        .with("lastOutcome", CorruptQuarantined),
    }
  }

  action Repair = {
    nondet job = JOBS.filter(candidate => system.jobs.get(candidate).routeCorrupt
      and not(compositeBlocked(system, candidate))).oneOf()
    nondet expectedRevision = Set(system.jobs.get(job).revision, system.jobs.get(job).revision - 1).oneOf()
    nondet expectedOperation = OPERATIONS.oneOf()
    val current = system.jobs.get(job)
    val allowed = expectedRevision == current.revision and expectedOperation == current.operationId
      and not(compositeBlocked(system, job))
    val repaired = current.with("routeCorrupt", false).with("danglingRoute", false)
      .with("revision", current.revision + 1)
      .with("dueRoute", current.state == Scheduled or current.state == RetryWaiting)
      .with("fairRoute", current.state == Scheduled or current.state == RetryWaiting)
      .with("wakeRoute", current.state == Scheduled or current.state == RetryWaiting)
    all {
      system' = if (allowed) system.with("jobs", update(system.jobs, job, repaired))
        .with("fairReady", update(system.fairReady, job,
          repaired.state == Scheduled or repaired.state == RetryWaiting))
        .with("lastResult", Committed).with("lastOutcome", RepairCommitted)
        else system.with("lastResult", Conflict).with("lastOutcome", RepairConflict),
    }
  }

  action SetWake = {
    nondet revision = Set(system.scheduleRevision, system.scheduleRevision - 1).oneOf()
    nondet token = Set(system.wakeToken, system.wakeToken - 1).oneOf()
    val requirement = durableWork
      or (system.scheduleEnabled and not(system.paused) and system.nextDue >= system.now)
    val allowed = revision == system.scheduleRevision and token == system.wakeToken and requirement
    all {
      system' = if (allowed) system.with("wakePending", true)
        .with("wakeToken", system.wakeToken + 1)
        .with("wakeAt", if (durableWork) system.now else system.nextDue)
        .with("lastResult", Committed)
        .with("lastOutcome", WakeAccepted)
        else system.with("lastResult", Rejected).with("lastOutcome", WakeRejected),
    }
  }

  // Prompt delivery is only a hint.  Exact delivery consumes the current
  // token; loss, duplication, and stale delivery leave durable work intact.
  action DeliverWake = {
    nondet token = Set(system.wakeToken, system.wakeToken - 1).oneOf()
    nondet delivered = bools.oneOf()
    val exact = delivered and system.wakePending and token == system.wakeToken
    all {
      system' = if (exact) system.with("wakePending", false)
        .with("lastResult", Committed).with("lastOutcome", WakeAccepted)
        else system.with("lastResult", Conflict).with("lastOutcome", WakeRejected),
    }
  }

  action SetSchedulePolicy = {
    nondet scheduleEnabled = bools.oneOf()
    nondet paused = bools.oneOf()
    nondet overlap = bools.oneOf()
    all {
      system' = system.with("scheduleEnabled", scheduleEnabled).with("paused", paused).with("overlap", overlap)
        .with("lastOutcome", SchedulePolicyChanged),
    }
  }

  action ResetFairWindow = all {
    system.fairCritical == 8 and system.fairDefault == 4 and system.fairBulk == 1,
    system' = system.with("fairCritical", 0).with("fairDefault", 0)
      .with("fairBulk", 0).with("lastOutcome", FairRefilled),
  }

  pure def compositeDriveResult(branch: DriveKernelBranch): CompositeDriveResult =
    if (branch == KernelRecurrence) CompositeDriveRecurrence
    else if (branch == KernelMaterialize) CompositeDriveMaterialized
    else if (branch == KernelClaim) CompositeDriveClaimed
    else if (branch == KernelTerminal) CompositeDriveTerminal
    else if (branch == KernelConflict) CompositeDriveConflict
    else if (branch == KernelPaused) CompositeDrivePaused
    else if (branch == KernelBudget) CompositeDriveBudgetExhausted
    else if (branch == KernelFuture) CompositeDriveFuture else CompositeDriveNoWork

  /// Complete composite Drive selector from one immutable prestate.  The
  /// action and cross-family parity model consume the same typed decision.
  pure def compositeDriveDecision(current: SystemState): DriveKernelEffect = {
    val evaluated = evaluateCompositeSchedule(current, current.scheduleMisfire,
      current.catchUpLimit)
    val dueCursorWork = evaluated.scheduleRevision > current.scheduleRevision
    val unmaterialized = OCCURRENCES.filter(occ => current.emitted.get(occ)
      and not(current.materialized.get(occ)) and not(current.completed.get(occ))
      and not(compositeBlocked(current, current.occurrenceJob.get(occ))))
    val occurrence = if (unmaterialized.contains(Occ1)) Occ1
      else if (unmaterialized.contains(Occ2)) Occ2 else Occ3
    val job = current.occurrenceJob.get(occurrence)
    val queued = current.jobs.get(job)
    val materialize = materializeKernel(unmaterialized.size() > 0,
      current.scheduleRevision, current.scheduleRevision, current.scheduleRevision,
      NodeA, NodeA, NodeB, current.scheduleEnabled, current.paused,
      current.emitted.get(occurrence), current.materialized.get(occurrence),
      current.overlap, queued.state == Leased)
    val materializeWork = materialize.allowed and queued.state == Absent
    val materializeConflict = unmaterialized.size() > 0 and not(materializeWork)
    val claimWork = compositeFairServiceEligibleJobs(current).size() > 0
    val terminalWork = JOBS.exists(candidate => current.jobs.get(candidate).state == Leased
      and current.now < current.jobs.get(candidate).leaseUntil
      and not(compositeBlocked(current, candidate))
      and not(httpResolutionPending(current, candidate)))
    val futureWork = not(dueCursorWork) and not(materializeWork)
      and not(claimWork) and not(terminalWork) and current.nextDue > current.now
    driveEffectKernel(current.activePulses, current.paused, current.pulseActions,
      current.progressCounter, dueCursorWork, materializeWork, claimWork,
      terminalWork, materializeConflict, futureWork)
  }

  /// Complete composite Drive reducer. The real action and cross-family parity
  /// proof consume this one path for every progress and stop branch.
  pure def applyCompositeDriveTransition(current: SystemState): SystemState = {
    val evaluated = evaluateCompositeSchedule(current, current.scheduleMisfire, current.catchUpLimit)
    val unmaterialized = OCCURRENCES.filter(occ => current.emitted.get(occ)
      and not(current.materialized.get(occ)) and not(current.completed.get(occ))
      and not(compositeBlocked(current, current.occurrenceJob.get(occ))))
    val occurrence = if (unmaterialized.contains(Occ1)) Occ1
      else if (unmaterialized.contains(Occ2)) Occ2 else Occ3
    val materializedState = applyCompositeMaterialization(current, occurrence, NodeA)
    val serviceEligible = compositeFairServiceEligibleJobs(current)
    val claimJob = if (serviceEligible.contains(JobA)) JobA
      else if (serviceEligible.contains(JobB)) JobB else JobC
    val claimWork = serviceEligible.size() > 0
    val claimEffect = compositeFairClaimEffect(current, claimJob, claimWork)
    val claimedState = applyCompositeFairEffect(current, claimJob, NodeA, claimEffect)
      .with("claimPending", false).with("selectedJob", claimJob)
      .with("selectedScope", jobScope(claimJob))
      .with("selectedHead", current.fairOrder.get(claimJob))
      .with("lastClaimNode", NodeA).with("lastResult", Committed)
      .with("lastOutcome", ClaimCommitted)
    val executableJobs = JOBS.filter(job => current.jobs.get(job).state == Leased
      and current.now < current.jobs.get(job).leaseUntil
      and not(compositeBlocked(current, job))
      and not(httpResolutionPending(current, job)))
    val executeJob = if (executableJobs.contains(JobA)) JobA
      else if (executableJobs.contains(JobB)) JobB else JobC
    val executedState = terminalSystemFrom(current, executeJob, Absent, false, true,
      CompletionCommitted)
    val driveEffect = compositeDriveDecision(current)
    val branch = driveEffect.branch
    val progressed = if (branch == KernelRecurrence) evaluated
      else if (branch == KernelMaterialize) materializedState
      else if (branch == KernelClaim) claimedState else executedState
    val accepted = progressed.with("pulseActions", driveEffect.nextActions)
      .with("progressCounter", driveEffect.progressAfter)
      .with("driveProgressBefore", driveEffect.progressBefore)
      .with("driveProgressAfter", driveEffect.progressAfter)
      .with("lastDrive", compositeDriveResult(branch))
      .with("lastDriveBranch", branch).with("lastDriveWork", driveEffect.work)
      .with("lastDriveStop", driveEffect.stop)
    val result = compositeDriveResult(branch)
    if (driveEffect.accepted) accepted
    else current.with("activePulses", driveEffect.nextActive)
        .with("driveProgressBefore", driveEffect.progressBefore)
        .with("driveProgressAfter", driveEffect.progressAfter)
        .with("lastDrive", result).with("lastDriveBranch", branch)
        .with("lastDriveWork", driveEffect.work).with("lastDriveStop", driveEffect.stop)
        .with("lastResult", if (driveEffect.class == ConflictClass) Conflict else Rejected)
        .with("lastOutcome", DriveReported)
  }

  // Drive performs one immediately useful authoritative transition. A pulse
  // may call it again only while that transition reports immediate progress;
  // future, blocked, paused, exhausted, and empty states close the pulse.
  // The finite command order mirrors the implementation dispatcher:
  // cursor -> materialize -> fair claim -> execute/terminal commit.
  action Drive = {
    all {
      system' = applyCompositeDriveTransition(system),
    }
  }

  action Pulse = {
    val allowed = system.pulseActions < MAX_PULSE_ACTIONS and system.activePulses < MAX_ACTIVE_PULSES
    all {
      system' = system.with("pulseActions", system.pulseActions)
        .with("activePulses", if (allowed) system.activePulses + 1 else 0)
        .with("lastOutcome", if (allowed) Initialised else PulseExit),
    }
  }

  action step = any {
    Advance, ScheduleOccurrence, SelectMaterialization, Enqueue, FairSelect, Claim, FairRefill,
    HandleHttp, HandleHttpRejected, HttpDuplicateDelivery, HttpOmitItem, ApplyHandler,
    Complete, CompleteRejected, ExposeCompletion, UnknownCommit, UnknownRejected,
    ChangeUnknownAuthority, ReconcileUnknown, StaleMutation, Cancel,
    RequestCancel, CancelLeased, ExpireScheduled, ExpireLease, Redrive, DropRoute, Repair,
    SetWake, DeliverWake, SetSchedulePolicy, Drive, Pulse,
    ResetFairWindow,
  }

  val enqueue_witness = system.lastOutcome == EnqueueCommitted
  val two_node_witness = system.lastOutcome == ClaimCommitted or system.lastOutcome == ClaimConflict
  val failure_witness = system.lastOutcome == HandlerRetry or system.lastOutcome == HandlerDeadLetter
  val unknown_witness = system.lastOutcome == UnknownCommitObserved
  val stale_authority_witness = system.lastOutcome == StaleRejected
  val repair_witness = system.lastOutcome == RepairCommitted
  val schedule_witness = system.lastOutcome == ScheduleEmitted or system.lastOutcome == ScheduleSkipped
  val schedule_enqueue_witness = system.lastOutcome == ScheduleEnqueue or system.lastOutcome == EnqueueCommitted
  val completion_witness = system.lastOutcome == CompletionCommitted
  val policy_witness = system.lastOutcome == SchedulePolicyChanged
  val drive_witness = system.lastDrive == CompositeDriveRecurrence
    or system.lastDrive == CompositeDriveMaterialized
    or system.lastDrive == CompositeDriveClaimed
    or system.lastDrive == CompositeDriveTerminal
  val wrong_handler_witness = system.lastOutcome == HandlerRejected
  val materialization_race_witness = system.lastOutcome == EnqueueConflict
  val unknown_conflict_accounting_witness = system.unknownPending
    and system.unknownReadback == Conflict
    and system.fairInFlight.get(system.unknownJob) == 1
  val wake_probe_witness = system.lastOutcome == WakeAccepted or system.lastOutcome == WakeRejected
  val recurring_completion_witness = system.watermark >= OCCURRENCE_STEP
    and OCCURRENCES.exists(occ => system.completed.get(occ))
    and system.emissionCount > 0
  val drive_progress_witness = (system.lastDrive == CompositeDriveRecurrence
      or system.lastDrive == CompositeDriveMaterialized
      or system.lastDrive == CompositeDriveClaimed
      or system.lastDrive == CompositeDriveTerminal)
    and system.driveProgressAfter > system.driveProgressBefore
  val drive_terminal_path_witness = system.lastOutcome == CompletionCommitted
    and system.progressCounter >= 2
  val composite_order_witness = ORDERING_GROUPS.exists(group =>
    system.orderInFlight.get(group) and JOBS.filter(job => system.jobs.get(job).state == Leased
      and system.fairOrdering.get(job) == group).size() == 1)
  val composite_independent_order_witness = system.orderInFlight.get(OrderA)
    and system.orderInFlight.get(OrderB)
  val composite_full_receipt_omission_witness = system.lastOutcome == CompletionExposed
    and system.completionDetail == CompletionDetailOmitted
  val composite_unknown_no_detail_witness = system.unknownPending
    and system.completionDetailJob == system.unknownJob
    and system.completionDetail == NoCompletionDetail
  val composite_unknown_at_full_capacity_no_detail_witness =
    composite_unknown_no_detail_witness
      and completionReceiptCount == MAX_COMPLETION_RECEIPTS
  val composite_reconciled_full_receipt_omission_witness =
    system.lastOutcome == UnknownReconciled
      and system.completionDetail == CompletionDetailOmitted
      and completionReceiptCount == MAX_COMPLETION_RECEIPTS

  val composite_http_membership_witness = system.httpBatchMembers.size() > 0
    and system.httpBatchResults.keys() == system.httpBatchMembers
    and system.httpBatchMembers.forall(job => not(system.httpSecretPersisted.get(job))
      and system.httpIdempotency.get(job) == system.jobs.get(job).executionId)
  val composite_http_duplicate_witness = system.httpBatchMembers.exists(job =>
    system.httpDuplicate.get(job)
      and (system.httpBatchResults.get(job) == ItemMissing
        or system.httpBatchResults.get(job) == ItemRetry))
  val composite_http_omission_witness = system.httpBatchMembers.exists(job =>
    system.httpOmitted.get(job) and system.httpBatchResults.get(job) == ItemRetry
      and system.httpRetryOwners.get(job) == EngineOwnsRetry)

  run composite_long_downtime_cursor_contracts = {
    val idle = initialSystem.with("jobs", JOBS.mapBy(job => initialSystem.jobs.get(job)
        .with("state", Absent).with("payload", false).with("dueRoute", false)
        .with("fairRoute", false).with("leaseRoute", false).with("wakeRoute", false)))
      .with("emitted", Map(Occ1 -> false, Occ2 -> false, Occ3 -> false))
      .with("emissionCount", 0).with("materialized", Map(Occ1 -> false, Occ2 -> false, Occ3 -> false))
      .with("durableRoute", Map(Occ1 -> false, Occ2 -> false, Occ3 -> false))
      .with("completed", Map(Occ1 -> true, Occ2 -> true, Occ3 -> true))
      .with("now", OCCURRENCE_STEP * 4).with("nextDue", OCCURRENCE_STEP)
    val skipped = evaluateCompositeSchedule(idle, Skip, 2)
    val fired = evaluateCompositeSchedule(idle, FireOnce, 2)
    val caught = evaluateCompositeSchedule(idle, CatchUp, 2)
    val skippedAgain = evaluateCompositeSchedule(skipped, Skip, 2)
    val firedAgain = evaluateCompositeSchedule(fired, FireOnce, 2)
    val caughtAgain = evaluateCompositeSchedule(caught, CatchUp, 2)
    all {
      assert(skipped.nextDue > skipped.now and skipped.emissionCount == 0
        and skipped.skippedRemainder == 4),
      assert(fired.nextDue > fired.now and fired.emissionCount == 1
        and fired.skippedRemainder == 3),
      assert(caught.nextDue > caught.now and caught.emissionCount == 2
        and caught.skippedRemainder == 2),
      assert(skippedAgain == skipped.with("lastBacklog", 0).with("skippedRemainder", 0)
        .with("lastEvaluationNow", skipped.now).with("lastResult", Rejected)
        .with("lastOutcome", ScheduleNotDue)),
      assert(firedAgain == fired.with("lastBacklog", 0).with("skippedRemainder", 0)
        .with("lastEvaluationNow", fired.now).with("lastResult", Rejected)
        .with("lastOutcome", ScheduleNotDue)),
      assert(caughtAgain == caught.with("lastBacklog", 0).with("skippedRemainder", 0)
        .with("lastEvaluationNow", caught.now).with("lastResult", Rejected)
        .with("lastOutcome", ScheduleNotDue)),
    }
  }

  run initial_absent_cannot_expose_completion = all {
    assert(initialSystem.jobs.get(JobB).state == Absent),
    assert(not(initialSystem.jobs.get(JobB).completionPending)),
    assert(not(initialSystem.jobs.get(JobB).completionReceipt)),
  }

  run composite_http_delivery_contracts = {
    val effectA = fairSelectedServiceKernel(true, JobA, ScopeA, ScopeA,
      Critical, initialSystem.fairCost.get(JobA), false, true, true, false,
      compositeFairPrestate(initialSystem, JobA))
    val claimedA = applyCompositeFairEffect(initialSystem, JobA, NodeA, effectA)
    val jobB = claimedA.jobs.get(JobB).with("state", Scheduled).with("payload", true)
      .with("dueRoute", true).with("fairRoute", true).with("leaseRoute", false)
      .with("wakeRoute", true)
    val readyB = claimedA.with("jobs", update(claimedA.jobs, JobB, jobB))
      .with("fairReady", update(claimedA.fairReady, JobB, true))
    val effectB = fairSelectedServiceKernel(true, JobB, ScopeB, ScopeB,
      Default, readyB.fairCost.get(JobB), false, true, true, false,
      compositeFairPrestate(readyB, JobB))
    val claimed = applyCompositeFairEffect(readyB, JobB, NodeB, effectB)
    val retried = applyCompositeHttpResult(claimed, JobA, Status429,
      TransportOk, MAX_RETRY_AFTER_TICKS)
    val delivered = applyHttpDuplicate(retried, JobA)
    val partial = applyHttpOmission(delivered, JobB)
    val driven = applyCompositeDriveTransition(partial.with("activePulses", 1))
    all {
      assert(effectA.allowed and effectB.allowed),
      assert(partial.httpBatchMembers == Set(JobA, JobB)
        and partial.httpBatchResults.keys() == partial.httpBatchMembers),
      assert(partial.httpBatchMembers.forall(job =>
        not(partial.httpSecretPersisted.get(job))
          and partial.httpIdempotency.get(job) == partial.jobs.get(job).executionId)),
      assert(partial.httpDuplicate.get(JobA)
        and partial.httpBatchResults.get(JobA) == ItemRetry
        and partial.httpRetryOwners.get(JobA) == EngineOwnsRetry),
      assert(partial.httpOmitted.get(JobB)
        and partial.httpBatchResults.get(JobB) == ItemRetry
        and partial.httpRetryOwners.get(JobB) == EngineOwnsRetry
        and partial.httpAttemptExecuted.get(JobB)
        and httpResolutionPending(partial, JobB)
        and compositeEngineRetryAvailable(partial, JobB)),
      assert(httpRetryOwner(Status429, TransportOk) == EngineOwnsRetry),
      assert(httpRetryOwner(Status4xx, TransportOk) == NoRetry),
      assert(driven.jobs.get(JobA).state == Leased
        and driven.jobs.get(JobB).state == Leased
        and driven.lastDriveBranch != KernelTerminal),
    }
  }

  run unknown_identity_blocks_only_its_job = {
    val leasedB = initialSystem.jobs.get(JobB).with("state", Leased)
      .with("payload", true).with("revision", 1).with("generation", 1)
      .with("fence", 2).with("token", 3).with("leaseUntil", 3)
      .with("attempts", 1).with("attemptId", 1).with("leaseRoute", true)
    val uncertain = initialSystem.with("jobs", update(initialSystem.jobs, JobB, leasedB))
      .with("unknownPending", true).with("unknownJob", JobB)
      .with("unknownOperation", leasedB.operationId).with("unknownNode", leasedB.node)
      .with("unknownRevision", leasedB.revision).with("unknownGeneration", leasedB.generation)
      .with("unknownFence", leasedB.fence).with("unknownToken", leasedB.token)
      .with("unknownLeaseUntil", leasedB.leaseUntil).with("unknownReadback", Conflict)
    val eligible = compositeFairEligibleJobs(uncertain)
    val effectA = compositeFairClaimEffect(uncertain, JobA, eligible.contains(JobA))
    val effectB = compositeFairClaimEffect(uncertain, JobB, eligible.contains(JobB))
    val progressed = applyCompositeFairEffect(uncertain, JobA, NodeA, effectA)
    val deadA = terminalSystemFrom(progressed, JobA, DeadLettered, true, false,
      HandlerDeadLetter)
    val redrivenA = applyCompositeRedrive(deadA, JobA,
      deadA.jobs.get(JobA).revision, deadA.jobs.get(JobA).operationId)
    all {
      assert(compositeBlocked(uncertain, JobB) and not(compositeBlocked(uncertain, JobA))),
      assert(effectA.allowed and not(effectB.allowed)),
      assert(progressed.jobs.get(JobA).state == Leased
        and progressed.jobs.get(JobB) == leasedB),
      assert(redrivenA.lastOutcome == RedriveCommitted
        and redrivenA.jobs.get(JobA).state == Scheduled
        and redrivenA.unknownPending and redrivenA.unknownJob == JobB),
    }
  }

  run composite_permanent_failure_redrive_clears_execution_state = {
    val seeded = initialSystem.with("jobs", update(initialSystem.jobs, JobA,
      initialSystem.jobs.get(JobA).with("enqueueFingerprint", 11)
        .with("payloadBytes", 12).with("manifestBytes", 13)
        .with("chunkBytes", 14).with("digestBytes", 15).with("checkpointBytes", 16)))
    val selected = applyCompositeFairSelect(seeded, JobA, NodeA)
    val claimDecision = compositeClaimDecision(selected, NodeA, selected.claimRevision)
    val claimed = applyCompositeClaimTransition(selected, NodeA, selected.claimRevision)
    val handled = applyCompositeHttpResult(claimed, JobA, Status4xx, TransportOk, 0)
    val dead = applyCompositeHandler(handled, JobA)
    val current = dead.jobs.get(JobA)
    val redriven = applyCompositeRedrive(dead, JobA, current.revision,
      current.operationId)
    val nextJob = redriven.jobs.get(JobA)
    all {
      assert(selected.lastOutcome == FairSelected and selected.claimPending),
      assert(claimDecision.allowed and claimed.lastOutcome == ClaimCommitted
        and claimed.jobs.get(JobA).state == Leased),
      assert(handled.httpBatchResults.get(JobA) == ItemDeadLetter),
      assert(dead.jobs.get(JobA).state == DeadLettered
        and dead.committedTerminalJobs.contains(JobA)),
      assert(redriven.lastOutcome == RedriveCommitted and nextJob.state == Scheduled),
      assert(nextJob.checkpointBytes == 0 and not(nextJob.failureRecorded)
        and not(nextJob.dlqRoute) and not(nextJob.leaseRoute)
        and nextJob.dueRoute and nextJob.fairRoute and nextJob.wakeRoute),
      assert(nextJob.attempts == 0 and nextJob.attemptId == 0 and nextJob.leaseUntil == 0
        and not(nextJob.cancelRequested) and not(nextJob.completionPending)
        and not(nextJob.completionReceipt)),
      assert(not(redriven.committedTerminalJobs.contains(JobA))
        and not(redriven.httpBatchMembers.contains(JobA))
        and not(redriven.httpBatchResults.keys().contains(JobA))
        and redriven.fairInFlight.get(JobA) == 0
        and not(redriven.orderInFlight.get(OrderA))),
      assert(redriven.lastHandlerStatus == Status2xx
        and redriven.lastTransport == TransportOk
        and redriven.lastHandlerResult == Success and redriven.retryOwner == NoRetry
        and redriven.handlerRevision == 0 and redriven.handlerGeneration == 0
        and redriven.handlerFence == 0 and redriven.handlerToken == 0
        and redriven.handlerLeaseUntil == 0),
      assert(nextJob.enqueueFingerprint == 11 and nextJob.payloadBytes == 12
        and nextJob.manifestBytes == 13 and nextJob.chunkBytes == 14
        and nextJob.digestBytes == 15),
    }
  }

  run age_expiry_redrive_grants_fresh_claimable_window = {
    val evidence = initialSystem.jobs.get(JobA).with("enqueueFingerprint", 11)
      .with("payloadBytes", 12).with("manifestBytes", 13)
      .with("chunkBytes", 14).with("digestBytes", 15).with("checkpointBytes", 16)
    val expired = initialSystem.with("jobs", update(initialSystem.jobs, JobA, evidence))
      .with("now", evidence.expiresAt)
    val dead = applyCompositeScheduledExpiry(expired, JobA)
    val current = dead.jobs.get(JobA)
    val redriven = applyCompositeRedrive(dead, JobA, current.revision,
      current.operationId)
    val eligible = compositeFairEligibleJobs(redriven)
    val selected = applyCompositeFairSelect(redriven, JobA, NodeA)
    val claimed = applyCompositeClaimTransition(selected, NodeA, selected.claimRevision)
    val redrivenJob = redriven.jobs.get(JobA)
    all {
      assert(dead.jobs.get(JobA).state == DeadLettered
        and dead.committedTerminalJobs.contains(JobA)),
      assert(redrivenJob.state == Scheduled
        and redrivenJob.expiresAt == redriven.now + MAX_JOB_AGE_TICKS
        and redrivenJob.expiresAt > redriven.now and eligible.contains(JobA)),
      assert(claimed.jobs.get(JobA).state == Leased),
      assert(redrivenJob.enqueueFingerprint == 11 and redrivenJob.payloadBytes == 12
        and redrivenJob.manifestBytes == 13 and redrivenJob.chunkBytes == 14
        and redrivenJob.digestBytes == 15 and redrivenJob.checkpointBytes == 0),
    }
  }

}
