/// Shared finite vocabulary for the background-job protocol models.
///
/// The domains are deliberately small so bounded exploration can inspect
/// competing nodes, retries, corruption, and scheduled occurrences.  Byte
/// limits retain their production meaning: payloads use a 950 KiB ceiling,
/// checkpoints use a separate 64 KiB ceiling, and transaction/receipt/pulse
/// limits are independent operational budgets.  The models abstract away byte
/// encoding, cryptography, clocks with sub-millisecond precision, and storage
/// implementation details while preserving every durable choice visible to a
/// caller.
module bg_jobs_types {
  type Node = NodeA | NodeB
  type JobId = JobA | JobB | JobC
  type Occurrence = Occ1 | Occ2 | Occ3
  type Priority = Critical | Default | Bulk
  type JobState = Absent | Scheduled | Leased | RetryWaiting | DeadLettered | Cancelled | Completed
  type StoreResult = Committed | Conflict | AuthorityChanged | Unknown | Rejected
  type ActionDecision = Accepted | ConflictDecision | RejectedDecision | UnknownDecision
    | ReconciledDecision
  type ResultClass = AppliedClass | RejectedClass | ConflictClass | UnknownClass
  // A fingerprint is a collision-free name for the complete immutable enqueue
  // byte sequence in this finite model. Production stores compare the encoded
  // immutable fields and payload digest; the abstraction deliberately excludes
  // mutable lease, retry, failure, and terminal state.
  type EnqueueDisposition = Inserted | AlreadyPresent | JobIdConflict | NotEnqueue
  type RecordKind = Valid | Missing | Corrupt | UnknownVersion
  type HandlerResult = Success | Transient | Throttled | Permanent | Ambiguous
  type Wake = Now | At | None
  type Misfire = Skip | FireOnce | CatchUp
  type HttpStatus = Status2xx | Status408 | Status425 | Status429 | Status4xx | Status5xx
  type TransportResult = TransportOk | Timeout | ConnectFailure | InvalidResponse
  type AuthResult = Authorised | Denied | MissingSecret | SignFailure
  type BatchResult = ItemSuccess | ItemRetry | ItemDeadLetter | ItemMissing | ItemDuplicate
  type CompletionDetail = CompletionDetailReturned | CompletionDetailOmitted | NoCompletionDetail
  type DriveWork = DriveRecurrenceWork | DriveMaterializeWork | DriveClaimWork
    | DriveTerminalWork | DriveConflictWork | DriveNoImmediateWork
  // The engine is the only durable attempt retry owner.  The transport has a
  // zero-retry policy and reports failures back to the engine classifier.
  type RetryOwner = EngineOwnsRetry | NoRetry
  type Scope = ScopeA | ScopeB | ScopeA1 | ScopeA2 | ScopeB1
  type OrderingGroup = OrderA | OrderB | OrderC
  type BlockReason = Unblocked | LeasedHead | CorruptHead | OversizedHead | PoisonHead
    | RateLimitedHead | CapacityBlockedHead
  type VolumeMode = ScopedVolume | LowVolume
  type CronForm = PortableFiveField | SecondsField | YearField | AliasForm | TimezoneForm | ProviderExtension
  type OperationId = OperationA | OperationB | OperationC | OperationD
  type HandlerKind = HandlerA | HandlerB
  type BatchKey = BatchA | BatchB
  type AuthConfigId = AuthConfigA | AuthConfigB
  type EffectModeModel = ReadOnlyEffect | IdempotentEffect | AtLeastOnceEffect | FencedEffect
  type RetryPolicyModel = InteractiveRetry | NetworkRetry | MaintenanceRetry
  type TimeoutPolicyModel = ShortTimeout | LongTimeout

  pure val NODES: Set[Node] = Set(NodeA, NodeB)
  pure val JOBS: Set[JobId] = Set(JobA, JobB, JobC)
  pure val OCCURRENCES: Set[Occurrence] = Set(Occ1, Occ2, Occ3)
  pure val PRIORITIES: Set[Priority] = Set(Critical, Default, Bulk)
  pure val SCOPES: Set[Scope] = Set(ScopeA, ScopeB, ScopeA1, ScopeA2, ScopeB1)
  pure val ORDERING_GROUPS: Set[OrderingGroup] = Set(OrderA, OrderB, OrderC)
  pure val OPERATIONS: Set[OperationId] = Set(OperationA, OperationB, OperationC, OperationD)

  // These limits intentionally do not share one generic finite constant.
  pure val MAX_ATTEMPTS = 3
  pure val MAX_JOB_AGE_TICKS = 12
  pure val MAX_OCCURRENCES = 3
  pure val MAX_UNRELATED_PROGRESS = 4
  // Two retained details are enough to exercise both the exact-capacity and
  // omitted-detail branches while the three-job universe still has a third
  // terminal operation. Production bounds are caller supplied and larger;
  // the durable completion rule is independent of this finite detail bound.
  pure val MAX_COMPLETION_RECEIPTS = 2
  pure val MAX_INLINE_PAYLOAD_BYTES = 972800
  pure val MAX_CHECKPOINT_BYTES = 65536
  pure val MAX_MANIFEST_BYTES = 4096
  pure val MAX_CHUNK_BYTES = 65536
  pure val MAX_DIGEST_BYTES = 64
  pure val MAX_TRANSACTION_CHECKS = 8
  pure val MAX_TRANSACTION_MUTATIONS = 8
  pure val MAX_TRANSACTION_BYTES = 32768
  pure val MAX_REPAIR_STEPS = 8
  pure val MAX_RETRY_AFTER_TICKS = 4
  pure val RETRY_AFTER_FALLBACK_TICKS = 1
  pure val MAX_BATCH_ITEMS = 3
  pure val MAX_BATCH_PAYLOAD_BYTES = MAX_INLINE_PAYLOAD_BYTES
  pure val MAX_BATCH_DELAY_TICKS = 4
  // The fair dispatcher exposes only a small ready-candidate window.  This is
  // distinct from the batch, occurrence, and transaction limits.
  pure val MAX_CANDIDATE_ITEMS = 3
  pure val MAX_PULSE_ACTIONS = 16
  pure val MAX_ACTIVE_PULSES = 3
  pure val MAX_CONCURRENCY_PER_SCOPE = 2
  pure val MAX_RATE_PER_SCOPE = 3
  pure val MAX_LOW_VOLUME_SERVICE = 1
  pure val MAX_REGISTERED_COST = 2
  pure val FAIR_CANDIDATE_WINDOW = MAX_CANDIDATE_ITEMS
  pure val FAIR_LOCAL_CLAIMS = 2
  pure val FAIR_QUIET_ERROR = MAX_REGISTERED_COST * (FAIR_CANDIDATE_WINDOW + FAIR_LOCAL_CLAIMS)
  // Primary weights are explicit even though the portable default gives
  // equal primary shares. Multiplication by this finite scale lets Quint
  // compare service/weight using integers: normalized(S,w)=S*scale/w. The
  // scale is divisible by every modeled weight, so no rounding can hide a
  // service difference. This is the finite form of E=C*(W+N).
  pure val FAIR_NORMALIZATION_SCALE = 2
  pure val FAIR_NORMALIZED_ERROR = FAIR_QUIET_ERROR * FAIR_NORMALIZATION_SCALE
  pure val OCCURRENCE_STEP = 5

  pure def bools: Set[bool] = Set(true, false)

  // Deterministic finite abstraction of production fresh operation generation.
  pure def nextOperationId(operation: OperationId): OperationId =
    if (operation == OperationA) OperationB
    else if (operation == OperationB) OperationC
    else if (operation == OperationC) OperationD
    else OperationA

  pure def update(m: a -> b, key: a, value: b): a -> b =
    m.keys().union(Set(key)).mapBy(k => if (k == key) value else m.get(k))

  pure def max(left: int, right: int): int = if (left > right) left else right
  pure def min(left: int, right: int): int = if (left < right) left else right
  pure def abs(value: int): int = if (value < 0) -value else value

  // A caller can present either the current authority or a stale zero.  The
  // distinction is intentional: generation, fence, and token are checked
  // independently even though each lives in a small numeric abstraction.
  pure def authorityChoices(current: int): Set[int] = Set(current, 0)

  pure def isTerminal(state: JobState): bool =
    state == DeadLettered or state == Cancelled or state == Completed

  pure def isDue(state: JobState, now: int, due: int): bool =
    (state == Scheduled or state == RetryWaiting) and due <= now

  pure def isRetryable(result: HandlerResult): bool =
    result == Transient or result == Throttled or result == Ambiguous

  pure def scopePrimary(scope: Scope): Scope =
    if (scope == ScopeA1 or scope == ScopeA2) ScopeA
    else if (scope == ScopeB1) ScopeB
    else scope

  pure def scopeSecondary(scope: Scope): bool =
    scope == ScopeA1 or scope == ScopeA2 or scope == ScopeB1

  // The finite job universe assigns one durable budget record to each exact
  // scope and one to its aggregate primary. JobC is the secondary ScopeA1
  // candidate; JobA is its primary authority. Keeping this resolution here
  // prevents schedule and composite Drive from disagreeing about which
  // permits, rate, capacity, and normalized service must be charged.
  pure def fairPrimaryJob(job: JobId): JobId = if (job == JobC) JobA else job

  pure def stableEnqueueDisposition(present: bool, storedFingerprint: int,
      presentedFingerprint: int): EnqueueDisposition =
    if (not(present)) Inserted
    else if (storedFingerprint == presentedFingerprint) AlreadyPresent
    else JobIdConflict

  pure def registeredCost(scope: Scope): int =
    if (scope == ScopeA or scope == ScopeB) 2 else 1

  pure def priorityWeight(priority: Priority): int =
    if (priority == Critical) 8 else if (priority == Default) 4 else 1

  pure def statusIsRetryable(status: HttpStatus): bool =
    status == Status408 or status == Status425 or status == Status429 or status == Status5xx

  pure def statusIsSuccess(status: HttpStatus): bool = status == Status2xx

  pure def wakeRank(wake: Wake): int = if (wake == Now) 0 else if (wake == At) 1 else 2

  // Canonical guards shared by the family models and the composite.  They
  // describe the authority and route vocabulary once; individual records add
  // their own corruption, schedule, and budget predicates around these pure
  // relations.
  pure def exactAuthority(currentNode: Node, currentRevision: int, currentGeneration: int,
      currentFence: int, currentToken: int, currentLeaseUntil: int, currentOperation: OperationId,
      presentedNode: Node, presentedRevision: int, presentedGeneration: int, presentedFence: int,
      presentedToken: int, presentedLeaseUntil: int, presentedOperation: OperationId, now: int): bool =
    currentNode == presentedNode and currentRevision == presentedRevision
      and currentGeneration == presentedGeneration and currentFence == presentedFence
      and currentToken == presentedToken and currentLeaseUntil == presentedLeaseUntil
      and currentOperation == presentedOperation and now < currentLeaseUntil

  pure def exactIdentity(currentNode: Node, currentRevision: int, currentGeneration: int,
      currentFence: int, currentToken: int, currentLeaseUntil: int, currentOperation: OperationId,
      presentedNode: Node, presentedRevision: int, presentedGeneration: int, presentedFence: int,
      presentedToken: int, presentedLeaseUntil: int, presentedOperation: OperationId): bool =
    currentNode == presentedNode and currentRevision == presentedRevision
      and currentGeneration == presentedGeneration and currentFence == presentedFence
      and currentToken == presentedToken and currentLeaseUntil == presentedLeaseUntil
      and currentOperation == presentedOperation

  pure def claimRouteIsEligible(state: JobState, record: RecordKind, payload: bool,
      dueRoute: bool, fairRoute: bool, dueAt: int, now: int, attempts: int,
      paused: bool): bool =
    not(paused) and record == Valid and payload and (state == Scheduled or state == RetryWaiting)
      and dueRoute and fairRoute and dueAt <= now and attempts < MAX_ATTEMPTS

  // This is the shared dispatch predicate used by the readable fairness
  // model and the synchronized system product.  A service decision must name
  // one durable routed job and satisfy every applicable eligibility budget;
  // counters alone can never create service credit.
  pure def fairJobIsEligible(state: JobState, record: RecordKind, payload: bool,
      dueRoute: bool, fairRoute: bool, dueAt: int, now: int, block: BlockReason,
      permits: int, rate: int, inFlight: int, payloadBytes: int,
      remainingPayloadBytes: int, order: int, orderHead: int, attempts: int,
      paused: bool): bool =
    claimRouteIsEligible(state, record, payload, dueRoute, fairRoute, dueAt, now, attempts, paused)
      and block == Unblocked and permits > 0 and rate > 0
      and inFlight < MAX_CONCURRENCY_PER_SCOPE and payloadBytes <= remainingPayloadBytes
      and order == orderHead

  pure def httpHandlerResult(status: HttpStatus, transport: TransportResult): HandlerResult =
    if (transport != TransportOk) Transient
    else if (statusIsSuccess(status)) Success
    else if (statusIsRetryable(status)) Transient else Permanent

  pure def httpRetryOwner(status: HttpStatus, transport: TransportResult): RetryOwner =
    if (transport != TransportOk or statusIsRetryable(status)) EngineOwnsRetry else NoRetry

  // A valid lower bound above policy is clamped.  A malformed negative value
  // cannot enter durable state and uses the documented bounded fallback.
  pure def clampRetryAfter(value: int): int =
    if (value < 0) RETRY_AFTER_FALLBACK_TICKS else min(value, MAX_RETRY_AFTER_TICKS)

  pure def occurrenceAvailable(emitted: bool, completed: bool, identity: int, due: int): bool =
    not(emitted) and (not(completed) or identity < due)

  // Misfire evaluation is one authoritative decision over the entire overdue
  // backlog. Every policy moves the cursor past now. Skip emits none,
  // FireOnce emits the most recent missed intended time, and CatchUp emits the
  // oldest bounded prefix. The remainder is explicit rather than left behind
  // as another overdue cursor evaluation.
  pure def occurrenceBacklog(now: int, nextDue: int): int =
    if (now < nextDue) 0 else ((now - nextDue) / OCCURRENCE_STEP) + 1

  pure def misfireEmissionCount(mode: Misfire, backlog: int, catchUpLimit: int): int =
    if (backlog == 0 or mode == Skip) 0
    else if (mode == FireOnce) 1 else min(backlog, catchUpLimit)

  pure def misfireSkippedCount(mode: Misfire, backlog: int, catchUpLimit: int): int =
    backlog - misfireEmissionCount(mode, backlog, catchUpLimit)

  pure def misfireNextDue(nextDue: int, backlog: int): int =
    nextDue + backlog * OCCURRENCE_STEP

  pure def misfireIdentity(mode: Misfire, nextDue: int, backlog: int, index: int): int =
    if (mode == FireOnce) nextDue + (backlog - 1) * OCCURRENCE_STEP
    else nextDue + index * OCCURRENCE_STEP

  // Terminal durability is independent of bounded response-detail storage.
  // Once this cap is full, the exact terminal commit still succeeds and its
  // response explicitly reports omission instead of fabricating failure.
  pure def completionDetailAt(receiptCount: int): CompletionDetail =
    if (receiptCount < MAX_COMPLETION_RECEIPTS)
      CompletionDetailReturned else CompletionDetailOmitted

  pure def receiptCountAfterCompletion(receiptCount: int): int =
    min(MAX_COMPLETION_RECEIPTS, receiptCount + 1)

  pure def primaryWeight(primary: Scope): int =
    if (primary == ScopeA or primary == ScopeB) 1 else 1

  pure def normalizedService(service: int, weight: int): int =
    (service * FAIR_NORMALIZATION_SCALE) / weight

  pure def normalizedServiceError(leftService: int, leftWeight: int,
      rightService: int, rightWeight: int): int =
    abs(normalizedService(leftService, leftWeight) - normalizedService(rightService, rightWeight))

  pure def normalizedServiceWindowAllowed(leftService: int, leftWeight: int,
      leftAdded: int, rightService: int, rightWeight: int, rightAdded: int): bool =
    normalizedServiceError(leftService + leftAdded, leftWeight,
      rightService + rightAdded, rightWeight) <= FAIR_NORMALIZED_ERROR

  pure def normalizedAdmissionAllowed(service: int, weight: int, added: int,
      otherService: int, otherWeight: int, otherEligible: bool): bool =
    not(otherEligible) or normalizedServiceWindowAllowed(service, weight, added,
      otherService, otherWeight, 0)

  pure def orderCanAcquire(order: int, headValue: int, inFlight: bool): bool =
    not(inFlight) and order == headValue

  pure def driveHasImmediate(dueCursorWork: bool, materializeWork: bool,
      claimWork: bool, executeWork: bool, repairWork: bool): bool =
    dueCursorWork or materializeWork or claimWork or executeWork or repairWork

  type RecurrenceKernelEffect = { due: bool, first: int, backlog: int,
    emitCount: int, skipped: int, nextDue: int }

  pure def recurrenceKernel(now: int, nextDue: int, enabledState: bool,
      pausedState: bool, blocked: bool, noActiveEmissions: bool, mode: Misfire,
      catchUpLimit: int): RecurrenceKernelEffect = {
    due: now >= nextDue and enabledState and not(pausedState) and not(blocked)
      and noActiveEmissions,
    first: nextDue,
    backlog: occurrenceBacklog(now, nextDue),
    emitCount: misfireEmissionCount(mode, occurrenceBacklog(now, nextDue), catchUpLimit),
    skipped: misfireSkippedCount(mode, occurrenceBacklog(now, nextDue), catchUpLimit),
    nextDue: misfireNextDue(nextDue, occurrenceBacklog(now, nextDue)),
  }

  // Complete recurrence/cursor effect shared by the family and product.  A
  // caller supplies the occurrence slots that its overlap policy makes
  // available; slot choice, history, skipped backlog, cursor and wake result
  // are then owned here.
  type RecurrenceStateEffect = { applied: bool, emitted: Occurrence -> bool,
    completed: Occurrence -> bool, identity: Occurrence -> int,
    previousIdentity: Occurrence -> int, emissionCount: int, backlog: int,
    skipped: int, nextDue: int, watermark: int, wakePending: bool }

  pure def recurrenceStateKernel(now: int, nextDue: int, enabledState: bool,
      pausedState: bool, blocked: bool, noActiveEmissions: bool, mode: Misfire,
      catchUpLimit: int, currentEmitted: Occurrence -> bool,
      currentCompleted: Occurrence -> bool, currentIdentity: Occurrence -> int,
      currentPrevious: Occurrence -> int, currentEmissionCount: int,
      currentWatermark: int, currentWakePending: bool,
      available: Set[Occurrence]): RecurrenceStateEffect = {
    val cursor = recurrenceKernel(now, nextDue, enabledState, pausedState,
      blocked, noActiveEmissions, mode, catchUpLimit)
    val firstOccurrence = if (available.contains(Occ1)) Occ1
      else if (available.contains(Occ2)) Occ2 else Occ3
    val secondOccurrence = if (firstOccurrence != Occ1 and available.contains(Occ1)) Occ1
      else if (firstOccurrence != Occ2 and available.contains(Occ2)) Occ2 else Occ3
    val thirdOccurrence = if (firstOccurrence != Occ1 and secondOccurrence != Occ1
        and available.contains(Occ1)) Occ1
      else if (firstOccurrence != Occ2 and secondOccurrence != Occ2
        and available.contains(Occ2)) Occ2 else Occ3
    val enough = available.contains(firstOccurrence)
      and (cursor.emitCount == 1 or (available.contains(secondOccurrence)
        and secondOccurrence != firstOccurrence))
      and (cursor.emitCount < MAX_OCCURRENCES or (available.contains(thirdOccurrence)
        and thirdOccurrence != firstOccurrence and thirdOccurrence != secondOccurrence))
    val applied = cursor.due and (mode == Skip or enough)
    val firstCompleted = update(currentCompleted, firstOccurrence, false)
    val secondCompleted = update(firstCompleted, secondOccurrence, false)
    val allCompleted = update(secondCompleted, thirdOccurrence, false)
    val firstEmitted = update(currentEmitted, firstOccurrence, true)
    val secondEmitted = update(firstEmitted, secondOccurrence, true)
    val allEmitted = update(secondEmitted, thirdOccurrence, true)
    val firstIdentity = update(currentIdentity, firstOccurrence,
      misfireIdentity(mode, cursor.first, cursor.backlog, 0))
    val secondIdentity = update(firstIdentity, secondOccurrence,
      misfireIdentity(mode, cursor.first, cursor.backlog, 1))
    val allIdentity = update(secondIdentity, thirdOccurrence,
      misfireIdentity(mode, cursor.first, cursor.backlog, 2))
    val firstPrevious = update(currentPrevious, firstOccurrence,
      currentIdentity.get(firstOccurrence))
    val secondPrevious = update(firstPrevious, secondOccurrence,
      currentIdentity.get(secondOccurrence))
    val allPrevious = update(secondPrevious, thirdOccurrence,
      currentIdentity.get(thirdOccurrence))
    val emitted = if (not(applied) or mode == Skip) currentEmitted
      else if (cursor.emitCount == 1) firstEmitted
      else if (cursor.emitCount == 2) secondEmitted else allEmitted
    val completed = if (not(applied) or mode == Skip) currentCompleted
      else if (cursor.emitCount == 1) firstCompleted
      else if (cursor.emitCount == 2) secondCompleted else allCompleted
    val identity = if (not(applied) or mode == Skip) currentIdentity
      else if (cursor.emitCount == 1) firstIdentity
      else if (cursor.emitCount == 2) secondIdentity else allIdentity
    val previous = if (not(applied) or mode == Skip) currentPrevious
      else if (cursor.emitCount == 1) firstPrevious
      else if (cursor.emitCount == 2) secondPrevious else allPrevious
    {
      applied: applied,
      emitted: emitted,
      completed: completed,
      identity: identity,
      previousIdentity: previous,
      emissionCount: if (applied) cursor.emitCount else currentEmissionCount,
      backlog: if (applied) cursor.backlog else 0,
      skipped: if (applied) cursor.skipped else 0,
      nextDue: if (applied) cursor.nextDue else nextDue,
      watermark: if (not(applied)) currentWatermark
        else if (mode == Skip) cursor.first
        else misfireIdentity(mode, cursor.first, cursor.backlog, cursor.emitCount - 1),
      wakePending: if (applied) mode != Skip else currentWakePending,
    }
  }

  type MaterializeKernelEffect = { allowed: bool, conflict: bool,
    nextRevision: int, nextWakeToken: int }

  pure def materializeKernel(pending: bool, expectedRevision: int,
      selectedRevision: int, currentRevision: int, contender: Node,
      reader: Node, otherReader: Node, enabledState: bool, pausedState: bool,
      emitted: bool, materialized: bool, overlap: bool,
      targetLeased: bool): MaterializeKernelEffect = {
    val sameRead = pending and expectedRevision == selectedRevision
    val selectedReader = contender == reader or contender == otherReader
    val allowed = sameRead and selectedReader and not(pausedState) and enabledState
      and emitted and not(materialized) and expectedRevision == currentRevision
      and (overlap or not(targetLeased))
    {
      allowed: allowed,
      conflict: sameRead and materialized and contender != reader,
      nextRevision: if (allowed) currentRevision + 1 else currentRevision,
      nextWakeToken: if (allowed) 1 else 0,
    }
  }

  // One selected service operation is charged in registered cost units.  The
  // same effect record is consumed by the standalone dispatcher and the
  // composite system, including the transient acquire/release of permits,
  // rate, in-flight and ordering authority.
  type FairServiceState = { jobState: JobState, dueRoute: bool, fairRoute: bool,
    childPermits: int, primaryPermits: int, childRate: int, primaryRate: int,
    childInFlight: int, primaryInFlight: int, childServed: int,
    childServedCost: int, primaryServedCost: int, orderHead: int,
    orderInFlight: bool, orderOwner: JobId, critical: int, default: int,
    bulk: int, cycle: int, serviceUnits: int, jobServiceUnits: int }

  type FairSelectedServiceEffect = { allowed: bool, job: JobId, scope: Scope,
    primary: Scope, priority: Priority, registeredCost: int,
    priorityDelta: int, state: FairServiceState }

  pure def fairSelectedServiceKernel(eligible: bool, job: JobId, scope: Scope,
      primary: Scope, priority: Priority, registeredCost: int, refillRate: bool,
      retainLease: bool, normalized: bool, bulkForced: bool,
      current: FairServiceState): FairSelectedServiceEffect = {
    val lane = if (priority == Critical) current.critical + registeredCost <= 8
      else if (priority == Default) current.default + registeredCost <= 4
      else current.bulk + registeredCost <= 1
    val allowed = eligible and registeredCost > 0 and lane and normalized
      and (not(bulkForced) or priority == Bulk) and not(current.orderInFlight)
      and current.childPermits > 0 and current.primaryPermits > 0
      and current.childRate > 0 and current.primaryRate > 0
      and current.childInFlight < MAX_CONCURRENCY_PER_SCOPE
      and current.primaryInFlight < MAX_CONCURRENCY_PER_SCOPE
    val sameScope = scope == primary
    val nextRate = if (refillRate) current.childRate else current.childRate - 1
    val nextPrimaryRate = if (sameScope) nextRate
      else if (refillRate) current.primaryRate else current.primaryRate - 1
    val nextState = if (allowed) {
      jobState: if (retainLease) Leased else RetryWaiting,
      dueRoute: not(retainLease),
      fairRoute: not(retainLease),
      childPermits: current.childPermits - (if (retainLease) 1 else 0),
      primaryPermits: current.primaryPermits - (if (retainLease) 1 else 0),
      childRate: nextRate,
      primaryRate: nextPrimaryRate,
      childInFlight: current.childInFlight + (if (retainLease) 1 else 0),
      primaryInFlight: current.primaryInFlight + (if (retainLease) 1 else 0),
      childServed: current.childServed + 1,
      childServedCost: current.childServedCost + registeredCost,
      primaryServedCost: if (sameScope) current.childServedCost + registeredCost
        else current.primaryServedCost + registeredCost,
      orderHead: current.orderHead,
      orderInFlight: retainLease,
      orderOwner: job,
      critical: current.critical + (if (priority == Critical) registeredCost else 0),
      default: current.default + (if (priority == Default) registeredCost else 0),
      bulk: current.bulk + (if (priority == Bulk) registeredCost else 0),
      cycle: if (priority == Bulk) 0 else current.cycle + registeredCost,
      serviceUnits: current.serviceUnits + registeredCost,
      jobServiceUnits: current.jobServiceUnits + registeredCost,
    } else current
    { allowed: allowed, job: job, scope: scope, primary: primary,
      priority: priority, registeredCost: registeredCost,
      priorityDelta: if (allowed) registeredCost else 0, state: nextState }
  }

  type TerminalKernelEffect = { nextRevision: int, keepPayload: bool,
    dueRoute: bool, fairRoute: bool, leaseRoute: bool, wakeRoute: bool,
    materialized: bool, emitted: bool, completed: bool,
    releaseFairAuthority: bool, nextReceiptCount: int,
    receiptDetail: CompletionDetail }

  pure def terminalKernel(revision: int, keepPayload: bool,
      receiptCount: int, heldLease: bool): TerminalKernelEffect = {
    nextRevision: revision + 1,
    keepPayload: keepPayload,
    dueRoute: false,
    fairRoute: false,
    leaseRoute: false,
    wakeRoute: false,
    materialized: false,
    emitted: false,
    completed: true,
    releaseFairAuthority: heldLease,
    nextReceiptCount: receiptCountAfterCompletion(receiptCount),
    receiptDetail: completionDetailAt(receiptCount),
  }

  // Claim is the only transition that advances delivery authority. The
  // caller supplies the last opaque token progression it observed; this is
  // deliberately separate from a route token, which is cleared when work
  // returns to a scheduled state.
  type ClaimAuthorityKernelEffect = { nextRevision: int, nextGeneration: int,
    nextFence: int, nextToken: int, nextLeaseUntil: int,
    nextAttempts: int, nextAttemptId: int }

  pure def claimAuthorityKernel(revision: int, generation: int, fence: int,
      tokenProgression: int, attempts: int, attemptId: int,
      now: int): ClaimAuthorityKernelEffect = {
    nextRevision: revision + 1,
    nextGeneration: generation + 1,
    nextFence: fence + 1,
    nextToken: tokenProgression + 3,
    nextLeaseUntil: now + 3,
    nextAttempts: attempts + 1,
    nextAttemptId: attemptId + 1,
  }

  run claim_authority_kernel_preserves_delivery_progression = {
    val effect = claimAuthorityKernel(4, 2, 7, 9, 1, 3, 10)
    all {
      assert(effect.nextRevision == 5),
      assert(effect.nextGeneration == 3),
      assert(effect.nextFence == 8),
      assert(effect.nextToken == 12),
      assert(effect.nextLeaseUntil == 13),
      assert(effect.nextAttempts == 2 and effect.nextAttemptId == 4),
    }
  }

  type RedriveKernelEffect = { allowed: bool, nextRevision: int,
    nextGeneration: int, nextFence: int, nextToken: int,
    nextExecutionId: int, nextAttemptId: int, nextAttempts: int,
    nextExpiresAt: int, authorityConflict: bool,
    dueRoute: bool, fairRoute: bool, leaseRoute: bool, wakeRoute: bool }

  pure def redriveKernel(state: JobState, kind: RecordKind, blocked: bool,
      revision: int, operation: OperationId, expectedRevision: int,
      expectedOperation: OperationId, generation: int, fence: int, token: int,
      executionId: int, reuseExecution: bool, now: int): RedriveKernelEffect = {
    val eligible = not(blocked) and state == DeadLettered and kind == Valid
    val authorityConflict = revision != expectedRevision or operation != expectedOperation
    val allowed = eligible and not(authorityConflict)
    { allowed: allowed,
      nextRevision: if (allowed) revision + 1 else revision,
      nextGeneration: if (allowed) generation + 1 else generation,
      // Redrive creates a new generation while retaining the operation
      // marker's fence high-water.  Scheduled records carry no lease token;
      // the next claim allocates a fresh opaque token and advances the fence.
      nextFence: if (allowed) fence else fence,
      nextToken: if (allowed) 0 else token,
      nextExecutionId: if (allowed and not(reuseExecution)) executionId + 1 else executionId,
      nextAttemptId: 0, nextAttempts: 0,
      // Redrive is an explicit new delivery generation. It preserves the
      // immutable enqueue fingerprint and payload evidence, but starts a fresh
      // bounded retry-age window so an age-exhausted DLQ item can run again.
      nextExpiresAt: if (allowed) now + MAX_JOB_AGE_TICKS else now,
      authorityConflict: authorityConflict,
      dueRoute: allowed, fairRoute: allowed, leaseRoute: false, wakeRoute: allowed }
  }

  // Drive selects exactly one authoritative effect.  The branch, typed work,
  // result class and progress projection are produced together, so a caller
  // cannot apply one branch while reporting another one.
  type DriveKernelBranch = KernelRecurrence | KernelMaterialize | KernelClaim
    | KernelTerminal | KernelConflict | KernelPaused | KernelBudget
    | KernelFuture | KernelNoWork
  type DriveStopReason = ContinuePulse | StopConflict | StopPaused | StopBudget
    | StopFuture | StopNoWork

  type DriveKernelEffect = { branch: DriveKernelBranch, work: DriveWork,
    class: ResultClass, stop: DriveStopReason, accepted: bool,
    nextActive: int, nextActions: int,
    progressBefore: int, progressAfter: int }

  pure def driveEffectKernel(active: int, pausedState: bool, actions: int,
      progress: int, recurrenceWork: bool, materializeWork: bool,
      claimWork: bool, terminalWork: bool, conflictWork: bool,
      futureWork: bool): DriveKernelEffect = {
    val budget = active > 0 and not(pausedState) and actions < MAX_PULSE_ACTIONS
    val branch = if (budget and conflictWork) KernelConflict
      else if (budget and recurrenceWork) KernelRecurrence
      else if (budget and materializeWork) KernelMaterialize
      else if (budget and claimWork) KernelClaim
      else if (budget and terminalWork) KernelTerminal
      else if (pausedState) KernelPaused
      else if (actions >= MAX_PULSE_ACTIONS) KernelBudget
      else if (futureWork) KernelFuture else KernelNoWork
    val accepted = branch == KernelRecurrence or branch == KernelMaterialize
      or branch == KernelClaim or branch == KernelTerminal
    val work = if (branch == KernelRecurrence) DriveRecurrenceWork
      else if (branch == KernelMaterialize) DriveMaterializeWork
      else if (branch == KernelClaim) DriveClaimWork
      else if (branch == KernelTerminal) DriveTerminalWork
      else if (branch == KernelConflict) DriveConflictWork
      else DriveNoImmediateWork
    {
      branch: branch,
      work: work,
      class: if (accepted) AppliedClass
        else if (branch == KernelConflict) ConflictClass else RejectedClass,
      stop: if (accepted) ContinuePulse else if (branch == KernelConflict) StopConflict
        else if (branch == KernelPaused) StopPaused else if (branch == KernelBudget) StopBudget
        else if (branch == KernelFuture) StopFuture else StopNoWork,
      accepted: accepted,
      nextActive: if (accepted) active else 0,
      nextActions: if (accepted) actions + 1 else actions,
      progressBefore: progress,
      progressAfter: if (accepted) progress + 1 else progress,
    }
  }
}
