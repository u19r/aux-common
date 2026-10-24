/// Hierarchical fair dispatch over opaque primary and secondary scopes.
///
/// A candidate carries its scope, priority lane, head/order identity, and
/// registered cost.  Selection consumes an explicit permit, rate token, and
/// capacity slot; LowVolume has its own cap.  Secondary scopes subdivide their
/// parent share and never multiply it.  A blocked head can be bypassed by a
/// different eligible scope, avoiding head-of-line starvation.
///
/// Weighted service is real service: the 8:4:1 Critical:Default:Bulk cycle is
/// represented by counters and a cycle phase, and a ready Bulk candidate is
/// forced before another cost unit would reach the phase bound. Quiet-scope
/// dwell is bounded by E=C*(W+N)=2*(3+2)=10. Partial batches retain per-item membership/results;
/// scratch is cleared and shrunk after the batch.  The model abstracts queue
/// bytes and worker internals but preserves selection-visible state and result
/// decisions.
module job_fair_dispatch {
  import bg_jobs_types.* from "./bg-jobs-types"

  // Retry timing is finite in the model: zero is immediately due, one is a
  // durable future due value, and two is a clock observation after that due
  // value. The connector maps these values to the authoritative durable
  // timestamp rather than maintaining a parallel retry reducer.
  pure val FAIR_RETRY_NOT_DUE_TICK = 1
  pure val FAIR_RETRY_DUE_TICK = 2

  type FairJob = {
    state: JobState,
    record: RecordKind,
    payload: bool,
    dueRoute: bool,
    fairRoute: bool,
    dueAt: int,
    scope: Scope,
    priority: Priority,
    ordering: OrderingGroup,
    order: int,
    orderHead: int,
    cost: int,
    block: BlockReason,
    payloadBytes: int,
    handlerKind: HandlerKind,
    schemaVersion: int,
    batchKey: BatchKey,
    authConfig: AuthConfigId,
    effectMode: EffectModeModel,
    retryPolicy: RetryPolicyModel,
    timeoutPolicy: TimeoutPolicyModel,
    serviceTransitions: int,
    enqueuedAt: int,
    batchDeadline: int,
  }

  type ScopeState = {
    primary: Scope,
    secondary: bool,
    share: int,
    mode: VolumeMode,
    ready: bool,
    priority: Priority,
    candidates: Set[JobId],
    head: int,
    order: int,
    cost: int,
    block: BlockReason,
    inFlight: int,
    permits: int,
    rate: int,
    quietDwell: int,
    served: int,
    servedCost: int,
    errors: int,
    acquisitions: int,
    releases: int,
  }

  // Ordering authority is owned once per group. Candidate records carry only
  // their immutable position; selection atomically acquires this shared head,
  // and every retry, unresolved, or terminal path releases it. A per-job
  // in-flight flag would let two jobs in OrderB lease concurrently.
  type OrderState = {
    head: int,
    inFlight: bool,
    owner: JobId,
    acquisitions: int,
    releases: int,
  }

  type Meta = {
    cycle: int,
    criticalServed: int,
    defaultServed: int,
    bulkServed: int,
    criticalWindow: int,
    defaultWindow: int,
    bulkWindow: int,
    holEscapes: int,
    batchActive: bool,
    batchScope: Scope,
    batchAuthConfig: AuthConfigId,
    batchMembers: Set[JobId],
    batchResults: JobId -> BatchResult,
    scratchSize: int,
    scratchCapacity: int,
    batchPayloadBytes: int,
    batchFormedAt: int,
    batchDeadline: int,
    selectedScope: Scope,
    selectedJob: JobId,
    selectedCost: int,
    serviceTransitions: int,
    lastOutcome: FairOutcome,
  }

  type FairOutcome = Initialised | HeadReady | SelectionServed | SelectionRejected | BulkForced
    | QuietTick | HeadBlocked | HolEscaped | RateBlocked | CapacityBlocked | PermitBlocked
    | LowVolumeRejected | BatchPartial | ScratchCleared | ScratchShrunk | ServiceErrorRecorded
    | ClaimReleased | ScopeRefilled

  type BatchCandidateInput = { job: JobId, scope: Scope, primary: Scope, priority: Priority,
    ordering: OrderingGroup, order: int, payloadBytes: int,
    handlerKind: HandlerKind, schemaVersion: int, batchKey: BatchKey,
    authConfig: AuthConfigId, effectMode: EffectModeModel,
    retryPolicy: RetryPolicyModel, timeoutPolicy: TimeoutPolicyModel,
    enqueuedAt: int, batchDeadline: int, mode: VolumeMode }

  var scopes: Scope -> ScopeState
  var jobs: JobId -> FairJob
  var orders: OrderingGroup -> OrderState
  var meta: Meta

  pure def makeFairJob(state, scope, priority, ordering, order, cost, block, payloadBytes) = {
    state: state,
    record: Valid,
    payload: state != Absent,
    dueRoute: state == Scheduled or state == RetryWaiting,
    fairRoute: state == Scheduled or state == RetryWaiting,
    dueAt: 0,
    scope: scope,
    priority: priority,
    ordering: ordering,
    order: order,
    orderHead: order,
    cost: cost,
    block: block,
    payloadBytes: payloadBytes,
    handlerKind: HandlerA,
    schemaVersion: 1,
    batchKey: BatchA,
    authConfig: AuthConfigA,
    effectMode: IdempotentEffect,
    retryPolicy: NetworkRetry,
    timeoutPolicy: ShortTimeout,
    serviceTransitions: 0,
    enqueuedAt: 0,
    batchDeadline: MAX_BATCH_DELAY_TICKS,
  }

  pure def initialJobs = Map(
    JobA -> makeFairJob(Scheduled, ScopeA, Critical, OrderA, 1, 2, Unblocked, 1),
    JobB -> makeFairJob(Scheduled, ScopeB, Default, OrderB, 1, 2, Unblocked, 1),
    // JobB and JobC deliberately share OrderB. This retains the reported
    // two-candidate race in the finite universe instead of proving ordering
    // by assigning every job a distinct group.
    JobC -> makeFairJob(Absent, ScopeA1, Bulk, OrderB, 1, 1, Unblocked, 1),
  )

  pure def makeScope(primary, secondary, share, mode, ready, priority, candidate, headValue, order) = {
    primary: primary,
    secondary: secondary,
    share: share,
    mode: mode,
    ready: ready,
    priority: priority,
    candidates: if (ready) Set(candidate) else Set(),
    head: headValue,
    order: order,
    cost: if (secondary) 1 else registeredCost(primary),
    block: Unblocked,
    inFlight: 0,
    permits: MAX_CONCURRENCY_PER_SCOPE,
    rate: MAX_RATE_PER_SCOPE,
    quietDwell: 0,
    served: 0,
    servedCost: 0,
    errors: 0,
    acquisitions: 0,
    releases: 0,
  }

  pure def initialScopes = Map(
    ScopeA -> makeScope(ScopeA, false, primaryWeight(ScopeA), ScopedVolume, true, Critical, JobA, 1, 1),
    ScopeB -> makeScope(ScopeB, false, primaryWeight(ScopeB), ScopedVolume, true, Default, JobB, 1, 1),
    ScopeA1 -> makeScope(ScopeA, true, 1, LowVolume, false, Bulk, JobC, 0, 0),
    ScopeA2 -> makeScope(ScopeA, true, 1, ScopedVolume, false, Default, JobC, 0, 0),
    ScopeB1 -> makeScope(ScopeB, true, 1, LowVolume, false, Bulk, JobC, 0, 0),
  )

  pure def initialOrders = Map(
    OrderA -> { head: 1, inFlight: false, owner: JobA, acquisitions: 0, releases: 0 },
    OrderB -> { head: 1, inFlight: false, owner: JobB, acquisitions: 0, releases: 0 },
    OrderC -> { head: 1, inFlight: false, owner: JobC, acquisitions: 0, releases: 0 },
  )

  pure def initialMeta = {
    cycle: 0,
    criticalServed: 0,
    defaultServed: 0,
    bulkServed: 0,
    criticalWindow: 0,
    defaultWindow: 0,
    bulkWindow: 0,
    holEscapes: 0,
    batchActive: false,
    batchScope: ScopeA,
    batchAuthConfig: AuthConfigA,
    batchMembers: Set(),
    batchResults: Map(),
    scratchSize: 0,
    scratchCapacity: MAX_BATCH_ITEMS,
    batchPayloadBytes: 0,
    batchFormedAt: 0,
    batchDeadline: 0,
    selectedScope: ScopeA,
    selectedJob: JobA,
    selectedCost: 0,
    serviceTransitions: 0,
    lastOutcome: Initialised,
  }

  pure def readyMap(current) = current.keys().mapBy(scope => current.get(scope).ready)
  pure def updateDwell(current, ready) = current.keys().mapBy(scope =>
    current.get(scope).with("quietDwell", if (ready.get(scope) and current.get(scope).quietDwell < FAIR_QUIET_ERROR)
      current.get(scope).quietDwell + 1 else current.get(scope).quietDwell))
  pure def serviceableBulkReadyIn(currentJobs, currentScopes, currentOrders) =
    eligibleJobsIn(currentJobs, currentScopes, currentOrders)
    .exists(job => currentJobs.get(job).priority == Bulk)
  def serviceableBulkReady = eligibleJobs.exists(job => jobs.get(job).priority == Bulk)
  def bulkDeadline = meta.cycle >= FAIR_QUIET_ERROR and serviceableBulkReady
  pure def eligibleJobsInAt(currentJobs, currentScopes, currentOrders, now) = JOBS.filter(job => {
    val queued = currentJobs.get(job)
    val scope = currentScopes.get(queued.scope)
    val primary = currentScopes.get(scopePrimary(queued.scope))
    val orderState = currentOrders.get(queued.ordering)
    fairJobIsEligible(queued.state, queued.record, queued.payload, queued.dueRoute,
      queued.fairRoute, queued.dueAt, now, queued.block, scope.permits, scope.rate,
      scope.inFlight, queued.payloadBytes, MAX_INLINE_PAYLOAD_BYTES, queued.order,
      orderState.head, 0, false)
      and scope.ready and scope.candidates.contains(job) and scope.priority == queued.priority
      and orderCanAcquire(queued.order, orderState.head, orderState.inFlight)
      and primary.permits > 0 and primary.rate > 0
      and primary.inFlight < MAX_CONCURRENCY_PER_SCOPE
      and (scope.mode != LowVolume or scope.served < MAX_LOW_VOLUME_SERVICE)
  })
  def eligibleJobsIn(currentJobs, currentScopes, currentOrders) =
    eligibleJobsInAt(currentJobs, currentScopes, currentOrders, 0)
  def eligibleJobs = eligibleJobsIn(jobs, scopes, orders)
  def normalizedJobAdmissionAt(currentScopes, currentJobs, currentOrders, job, addedCost, now) = {
    val primary = scopePrimary(currentJobs.get(job).scope)
    val otherPrimary = if (primary == ScopeA) ScopeB else ScopeA
    val otherEligible = eligibleJobsInAt(currentJobs, currentScopes, currentOrders, now).exists(candidate =>
      scopePrimary(currentJobs.get(candidate).scope) == otherPrimary)
    normalizedAdmissionAllowed(currentScopes.get(primary).servedCost,
      currentScopes.get(primary).share, addedCost,
      currentScopes.get(otherPrimary).servedCost,
      currentScopes.get(otherPrimary).share, otherEligible)
  }
  def normalizedJobAdmission(currentScopes, currentJobs, currentOrders, job, addedCost) =
    normalizedJobAdmissionAt(currentScopes, currentJobs, currentOrders, job, addedCost, 0)
  def readyCandidateCount(currentJobs) = JOBS.filter(job => currentJobs.get(job).state == Scheduled
    or currentJobs.get(job).state == RetryWaiting).size()
  pure def lowVolumeEligible(current, primary, currentOrders, queued, job) = current.mode == LowVolume
    and fairJobIsEligible(queued.state, queued.record, queued.payload, queued.dueRoute,
      queued.fairRoute, queued.dueAt, 0, queued.block, current.permits, current.rate,
      current.inFlight, queued.payloadBytes, MAX_INLINE_PAYLOAD_BYTES, queued.order,
      currentOrders.get(queued.ordering).head, 0, false)
    and orderCanAcquire(queued.order, currentOrders.get(queued.ordering).head,
      currentOrders.get(queued.ordering).inFlight)
    and primary.permits > 0 and primary.rate > 0
    and primary.inFlight < MAX_CONCURRENCY_PER_SCOPE
    and current.ready and current.candidates.contains(job)
    and (current.mode != LowVolume or current.served < MAX_LOW_VOLUME_SERVICE)

  pure def batchCompatible(first, second, firstScope, secondScope) =
    first.handlerKind == second.handlerKind
      and first.schemaVersion == second.schemaVersion
      and first.batchKey == second.batchKey
      and first.authConfig == second.authConfig
      and first.priority == second.priority
      and first.effectMode == second.effectMode
      and first.retryPolicy == second.retryPolicy
      and first.timeoutPolicy == second.timeoutPolicy
      and ((firstScope.mode == LowVolume and secondScope.mode == LowVolume
          and firstScope.primary == secondScope.primary)
        or (firstScope.mode == ScopedVolume and secondScope.mode == ScopedVolume
          and first.scope == second.scope
          and firstScope.primary == secondScope.primary
          and firstScope.secondary == secondScope.secondary))

  pure def batchResourceAllowed(first, second, formedAt) = {
    val aggregateBytes = first.payloadBytes + second.payloadBytes
    val formationStartedAt = min(first.enqueuedAt, second.enqueuedAt)
    val latestEnqueue = max(first.enqueuedAt, second.enqueuedAt)
    val deadline = min(first.batchDeadline, second.batchDeadline)
    aggregateBytes <= MAX_BATCH_PAYLOAD_BYTES and formedAt <= deadline
      and formedAt >= latestEnqueue
      and formedAt - formationStartedAt <= MAX_BATCH_DELAY_TICKS
  }

  /// Complete batch admission decision over one immutable prestate. Exact
  /// compatibility is necessary but not sufficient: each affected primary
  /// also retains its own capacity and normalized fairness authority.
  def batchStartAllowed(first: JobId, second: JobId): bool = {
    val members = Set(first, second)
    val firstJob = jobs.get(first)
    val secondJob = jobs.get(second)
    val firstPrimary = scopePrimary(firstJob.scope)
    val secondPrimary = scopePrimary(secondJob.scope)
    val firstAggregate = scopes.get(firstPrimary)
    val secondAggregate = scopes.get(secondPrimary)
    val samePrimary = firstPrimary == secondPrimary
    val criticalCost = (if (firstJob.priority == Critical) firstJob.cost else 0)
      + (if (secondJob.priority == Critical) secondJob.cost else 0)
    val defaultCost = (if (firstJob.priority == Default) firstJob.cost else 0)
      + (if (secondJob.priority == Default) secondJob.cost else 0)
    val bulkCost = (if (firstJob.priority == Bulk) firstJob.cost else 0)
      + (if (secondJob.priority == Bulk) secondJob.cost else 0)
    val laneBudget = meta.criticalWindow + criticalCost <= 8
      and meta.defaultWindow + defaultCost <= 4 and meta.bulkWindow + bulkCost <= 1
    val batchCapacityAllowed = if (samePrimary)
      firstAggregate.permits >= members.size() and firstAggregate.rate >= members.size()
        and firstAggregate.inFlight + members.size() <= MAX_CONCURRENCY_PER_SCOPE
      else firstAggregate.permits > 0 and firstAggregate.rate > 0
        and firstAggregate.inFlight < MAX_CONCURRENCY_PER_SCOPE
        and secondAggregate.permits > 0 and secondAggregate.rate > 0
        and secondAggregate.inFlight < MAX_CONCURRENCY_PER_SCOPE
    val exactScopeCapacity = if (firstJob.scope == secondJob.scope)
      scopes.get(firstJob.scope).permits >= members.size()
        and scopes.get(firstJob.scope).rate >= members.size()
        and scopes.get(firstJob.scope).inFlight + members.size()
          <= MAX_CONCURRENCY_PER_SCOPE
    else true
    val fairAdmission = if (samePrimary)
      normalizedJobAdmission(scopes, jobs, orders, first, firstJob.cost + secondJob.cost)
      else normalizedJobAdmission(scopes, jobs, orders, first, firstJob.cost)
        and normalizedJobAdmission(scopes, jobs, orders, second, secondJob.cost)
    first != second and eligibleJobs.contains(first) and eligibleJobs.contains(second)
      and batchCompatible(firstJob, secondJob,
      scopes.get(firstJob.scope), scopes.get(secondJob.scope))
      and laneBudget and firstJob.ordering != secondJob.ordering
      and members.size() <= MAX_BATCH_ITEMS
      and batchResourceAllowed(firstJob, secondJob, meta.cycle)
      and batchCapacityAllowed and exactScopeCapacity and fairAdmission
  }

  pure def leaseJob(queued) = queued.with("state", Leased)
    .with("dueRoute", false).with("fairRoute", false)

  pure def acquireOrder(currentOrders, queued, job) =
    update(currentOrders, queued.ordering,
      currentOrders.get(queued.ordering).with("inFlight", true).with("owner", job)
        .with("acquisitions", currentOrders.get(queued.ordering).acquisitions + 1))

  pure def releaseOrder(currentOrders, queued, terminal) = {
    val current = currentOrders.get(queued.ordering)
    update(currentOrders, queued.ordering, current.with("inFlight", false)
      .with("releases", current.releases + 1)
      .with("head", if (terminal) current.head + 1 else current.head))
  }

  pure def acquireScope(currentScopes, scope, cost, job) = {
    val child = currentScopes.get(scope)
    val remaining = child.candidates.filter(candidate => candidate != job)
    val childChanged = update(currentScopes, scope, child.with("ready", remaining.size() > 0)
      .with("candidates", remaining)
      .with("inFlight", child.inFlight + 1).with("permits", child.permits - 1)
      .with("rate", child.rate - 1).with("quietDwell", 0)
      .with("served", child.served + 1).with("servedCost", child.servedCost + cost)
      .with("acquisitions", child.acquisitions + 1))
    val primary = scopePrimary(scope)
    val primaryState = childChanged.get(primary)
    if (scope == primary) childChanged
    else update(childChanged, primary, primaryState.with("inFlight", primaryState.inFlight + 1)
      .with("permits", primaryState.permits - 1).with("rate", primaryState.rate - 1)
      .with("servedCost", primaryState.servedCost + cost)
      .with("acquisitions", primaryState.acquisitions + 1))
  }

  pure def releaseScope(currentScopes, scope, makeReady, job) = {
    val child = currentScopes.get(scope)
    val childChanged = update(currentScopes, scope, child.with("ready", makeReady)
      .with("candidates", if (makeReady) child.candidates.union(Set(job))
        else child.candidates)
      .with("inFlight", max(0, child.inFlight - 1))
      .with("releases", child.releases + 1)
      .with("permits", min(MAX_CONCURRENCY_PER_SCOPE, child.permits + 1)))
    val primary = scopePrimary(scope)
    val primaryState = childChanged.get(primary)
    if (scope == primary) childChanged
    else update(childChanged, primary, primaryState
      .with("inFlight", max(0, primaryState.inFlight - 1))
      .with("releases", primaryState.releases + 1)
      .with("permits", min(MAX_CONCURRENCY_PER_SCOPE, primaryState.permits + 1)))
  }

  pure def restoreServiceRate(currentScopes, scope) = {
    val child = currentScopes.get(scope)
    val childChanged = update(currentScopes, scope,
      child.with("rate", min(MAX_RATE_PER_SCOPE, child.rate + 1)))
    val primary = scopePrimary(scope)
    if (scope == primary) childChanged
    else update(childChanged, primary, childChanged.get(primary)
      .with("rate", min(MAX_RATE_PER_SCOPE, childChanged.get(primary).rate + 1)))
  }

  pure def releaseScopeAndRate(currentScopes, scope, makeReady, job) =
    restoreServiceRate(releaseScope(currentScopes, scope, makeReady, job), scope)

  val inv_candidate_identity = SCOPES.forall(scope =>
    scopes.get(scope).head >= 0 and scopes.get(scope).order >= scopes.get(scope).head
      and (scopes.get(scope).ready == (scopes.get(scope).candidates.size() > 0))
      and scopes.get(scope).candidates.forall(job => JOBS.contains(job)
        and jobs.get(job).scope == scope and jobs.get(job).state != Absent
        and jobs.get(job).dueRoute and jobs.get(job).fairRoute)
  )
  val inv_candidate_budget = readyCandidateCount(jobs) <= MAX_CANDIDATE_ITEMS
  val inv_hierarchical_share = SCOPES.forall(scope =>
    scopes.get(scope).share > 0 and (not(scopes.get(scope).secondary)
      or scopes.get(scope).share <= scopes.get(scopes.get(scope).primary).share))
  val inv_secondary_aggregate =
    scopes.get(ScopeA1).servedCost + scopes.get(ScopeA2).servedCost <= scopes.get(ScopeA).servedCost
      and scopes.get(ScopeB1).servedCost <= scopes.get(ScopeB).servedCost
  val inv_cost_accounting = SCOPES.forall(scope => scopes.get(scope).cost > 0
    and (scopes.get(scope).secondary
      implies scopes.get(scope).servedCost == scopes.get(scope).served * scopes.get(scope).cost)
    and (not(scopes.get(scope).secondary)
      implies scopes.get(scope).servedCost >= scopes.get(scope).served * scopes.get(scope).cost))
  val inv_priority_window = meta.criticalWindow >= 0 and meta.criticalWindow <= 8
    and meta.defaultWindow >= 0 and meta.defaultWindow <= 4
    and meta.bulkWindow >= 0 and meta.bulkWindow <= 1
    and meta.criticalWindow + meta.defaultWindow + meta.bulkWindow <= 13
    and (meta.criticalWindow + meta.defaultWindow + meta.bulkWindow == 13 implies
      meta.criticalWindow == 8 and meta.defaultWindow == 4 and meta.bulkWindow == 1)
  val inv_weighted_progress = meta.criticalServed <= 8 * (meta.bulkServed + 1)
    and meta.defaultServed <= 4 * (meta.bulkServed + 1)
    and (not(bulkDeadline) or not(
      (meta.lastOutcome == SelectionServed or meta.lastOutcome == HolEscaped
        or (meta.lastOutcome == BatchPartial and meta.batchActive))
      and jobs.get(meta.selectedJob).priority != Bulk))
  // Normalized error is a contract among simultaneously serviceable primary
  // scopes. A blocked primary must not freeze an independent group; when both
  // compete, normalizedJobAdmission guards every service-producing action.
  val inv_normalized_service_error = not(
      eligibleJobs.exists(job => scopePrimary(jobs.get(job).scope) == ScopeA)
        and eligibleJobs.exists(job => scopePrimary(jobs.get(job).scope) == ScopeB))
    or normalizedServiceError(scopes.get(ScopeA).servedCost, scopes.get(ScopeA).share,
      scopes.get(ScopeB).servedCost, scopes.get(ScopeB).share) <= FAIR_NORMALIZED_ERROR
  val inv_quiet_service_error = SCOPES.forall(scope => scopes.get(scope).quietDwell <= FAIR_QUIET_ERROR)
  val inv_error_budget = SCOPES.forall(scope => scopes.get(scope).errors >= 0
    and scopes.get(scope).errors <= FAIR_NORMALIZED_ERROR)
  val inv_dispatch_budget = SCOPES.forall(scope =>
    scopes.get(scope).inFlight >= 0 and scopes.get(scope).inFlight <= MAX_CONCURRENCY_PER_SCOPE
      and scopes.get(scope).permits >= 0 and scopes.get(scope).permits <= MAX_CONCURRENCY_PER_SCOPE
      and scopes.get(scope).rate >= 0 and scopes.get(scope).rate <= MAX_RATE_PER_SCOPE
      and scopes.get(scope).permits + scopes.get(scope).inFlight <= MAX_CONCURRENCY_PER_SCOPE
      and (scopes.get(scope).mode != LowVolume or scopes.get(scope).served <= MAX_LOW_VOLUME_SERVICE)
  )
  val inv_order_group_authority = ORDERING_GROUPS.forall(group => {
    val leased = JOBS.filter(job => jobs.get(job).state == Leased
      and jobs.get(job).ordering == group)
    orders.get(group).head >= 0 and leased.size() <= 1
      and (orders.get(group).inFlight == (leased.size() == 1))
      and (orders.get(group).inFlight implies leased.contains(orders.get(group).owner))
  })
  val inv_batch_results = not(meta.batchActive) or meta.batchMembers.forall(job =>
    meta.batchResults.keys().contains(job))
  val inv_batch_safety = not(meta.batchActive) or (
    meta.batchMembers.size() > 0 and meta.batchMembers.size() <= MAX_BATCH_ITEMS
      and meta.batchMembers.contains(meta.selectedJob)
      and meta.batchPayloadBytes == meta.batchMembers.fold(0,
        (total, job) => total + jobs.get(job).payloadBytes)
      and meta.batchPayloadBytes <= MAX_BATCH_PAYLOAD_BYTES
      and meta.batchFormedAt <= meta.batchDeadline
      and meta.batchMembers.forall(job => meta.batchDeadline <= jobs.get(job).batchDeadline)
      and meta.batchMembers.exists(job => meta.batchDeadline == jobs.get(job).batchDeadline)
      and meta.batchFormedAt >= meta.batchMembers.fold(0,
        (latest, job) => max(latest, jobs.get(job).enqueuedAt))
      and meta.batchFormedAt >= meta.batchMembers.fold(meta.batchFormedAt,
        (earliest, job) => min(earliest, jobs.get(job).enqueuedAt))
      and meta.batchFormedAt - meta.batchMembers.fold(meta.batchFormedAt,
        (earliest, job) => min(earliest, jobs.get(job).enqueuedAt)) <= MAX_BATCH_DELAY_TICKS
      and meta.batchMembers.forall(job =>
        jobs.get(job).authConfig == meta.batchAuthConfig
          and scopePrimary(jobs.get(job).scope) == meta.batchScope
          and batchCompatible(jobs.get(job), jobs.get(meta.selectedJob),
            scopes.get(jobs.get(job).scope), scopes.get(jobs.get(meta.selectedJob).scope))))
  val inv_scratch = meta.scratchSize >= 0 and meta.scratchSize <= meta.scratchCapacity
    and meta.scratchCapacity <= MAX_BATCH_ITEMS
  val inv_service_has_selected_job = not(meta.lastOutcome == SelectionServed
      or meta.lastOutcome == BulkForced or meta.lastOutcome == HolEscaped)
    or (JOBS.contains(meta.selectedJob) and jobs.get(meta.selectedJob).cost > 0
      and ((jobs.get(meta.selectedJob).state == Leased
          and not(scopes.get(meta.selectedScope).candidates.contains(meta.selectedJob)))
        or (jobs.get(meta.selectedJob).state == RetryWaiting
          and scopes.get(meta.selectedScope).candidates.contains(meta.selectedJob))))
  val inv_service_transition_delta = meta.serviceTransitions
      == meta.criticalWindow + meta.defaultWindow + meta.bulkWindow
    and JOBS.fold(0, (count, job) => count + jobs.get(job).serviceTransitions)
      == meta.serviceTransitions
    and ORDERING_GROUPS.forall(group => orders.get(group).acquisitions
      == orders.get(group).releases + (if (orders.get(group).inFlight) 1 else 0))
    and SCOPES.forall(scope => scopes.get(scope).acquisitions
      == scopes.get(scope).releases + scopes.get(scope).inFlight)
  val inv = and {
    inv_candidate_identity,
    inv_candidate_budget,
    inv_hierarchical_share,
    inv_secondary_aggregate,
    inv_cost_accounting,
    inv_weighted_progress,
    inv_priority_window,
    inv_normalized_service_error,
    inv_quiet_service_error,
    inv_error_budget,
    inv_dispatch_budget,
    inv_order_group_authority,
    inv_batch_results,
    inv_batch_safety,
    inv_scratch,
    inv_service_has_selected_job,
    inv_service_transition_delta,
  }
  val inv_except_weighted_progress = and {
    inv_candidate_identity, inv_candidate_budget, inv_hierarchical_share,
    inv_secondary_aggregate, inv_cost_accounting, inv_priority_window,
    inv_normalized_service_error, inv_quiet_service_error, inv_error_budget,
    inv_dispatch_budget, inv_order_group_authority, inv_batch_results, inv_batch_safety,
    inv_scratch, inv_service_has_selected_job, inv_service_transition_delta,
  }

  action init = all {
    scopes' = initialScopes,
    jobs' = initialJobs,
    orders' = initialOrders,
    meta' = initialMeta,
  }

  /// Alternate finite prestate for a real two-item primary scoped batch. Both
  /// jobs occupy one exact fairness key and retain distinct ordering groups.
  action compatibleBatchInit = {
    all {
      scopes' = primaryBatchScopes, jobs' = primaryBatchJobs,
      orders' = initialOrders, meta' = initialMeta,
    }
  }

  pure def primaryBatchJobs = update(update(initialJobs, JobA,
    initialJobs.get(JobA).with("scope", ScopeA).with("priority", Default)), JobB,
    initialJobs.get(JobB).with("scope", ScopeA).with("priority", Default))
  pure def primaryBatchScopes = update(update(initialScopes, ScopeA,
    initialScopes.get(ScopeA).with("ready", true).with("priority", Default)
      .with("candidates", Set(JobA, JobB))), ScopeB,
    initialScopes.get(ScopeB).with("ready", false).with("candidates", Set()))

  action batchKindMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("record", Corrupt)),
    orders' = initialOrders, meta' = initialMeta }
  pure def batchScopeMismatchScopes = update(update(initialScopes, ScopeA,
    initialScopes.get(ScopeA).with("ready", true).with("priority", Default)
      .with("candidates", Set(JobA))), ScopeB,
    initialScopes.get(ScopeB).with("ready", true).with("priority", Default)
      .with("candidates", Set(JobB)))
  action batchScopeMismatchInit = all { scopes' = batchScopeMismatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("scope", ScopeB)),
    orders' = initialOrders, meta' = initialMeta }
  action batchHandlerMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("handlerKind", HandlerB)),
    orders' = initialOrders, meta' = initialMeta }
  action batchSchemaMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("schemaVersion", 2)),
    orders' = initialOrders, meta' = initialMeta }
  action batchKeyMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("batchKey", BatchB)),
    orders' = initialOrders, meta' = initialMeta }
  action batchAuthMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("authConfig", AuthConfigB)),
    orders' = initialOrders, meta' = initialMeta }
  action batchPriorityMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("priority", Bulk)),
    orders' = initialOrders, meta' = initialMeta }
  action batchEffectMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("effectMode", FencedEffect)),
    orders' = initialOrders, meta' = initialMeta }
  action batchRetryMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("retryPolicy", MaintenanceRetry)),
    orders' = initialOrders, meta' = initialMeta }
  action batchTimeoutMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("timeoutPolicy", LongTimeout)),
    orders' = initialOrders, meta' = initialMeta }
  action batchDeadlineMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB).with("batchDeadline", -1)),
    orders' = initialOrders, meta' = initialMeta }
  action batchBytesMismatchInit = all { scopes' = primaryBatchScopes,
    jobs' = update(primaryBatchJobs, JobB, primaryBatchJobs.get(JobB)
      .with("payloadBytes", MAX_BATCH_PAYLOAD_BYTES)),
    orders' = initialOrders, meta' = initialMeta }

  /// Alternate finite prestate for a secondary scoped batch. The exact child
  /// and its aggregate primary both own two permits, rate units, and capacity.
  action compatibleSecondaryBatchInit = {
    val batchJobs = update(update(initialJobs, JobA,
      initialJobs.get(JobA).with("scope", ScopeA1).with("priority", Default)), JobB,
      initialJobs.get(JobB).with("scope", ScopeA1).with("priority", Default))
    val quietPrimaries = update(update(initialScopes, ScopeA,
      initialScopes.get(ScopeA).with("ready", false).with("candidates", Set())), ScopeB,
      initialScopes.get(ScopeB).with("ready", false).with("candidates", Set()))
    val batchScopes = update(quietPrimaries, ScopeA1,
      initialScopes.get(ScopeA1).with("mode", ScopedVolume)
        .with("ready", true).with("priority", Default)
        .with("candidates", Set(JobA, JobB)).with("head", 1)
        .with("order", 1).with("cost", 2))
    all {
      scopes' = batchScopes, jobs' = batchJobs,
      orders' = initialOrders, meta' = initialMeta,
    }
  }

  pure def scopeQuiescentIn(currentScopes, scope) = currentScopes.get(scope).inFlight == 0

  pure def scopeConfigurationMatches(currentScopes, input) = {
    val target = currentScopes.get(input.scope)
    target.primary == input.primary
      and target.secondary == (input.scope != input.primary)
      and target.mode == input.mode
      and target.priority == input.priority
      and target.cost == registeredCost(input.scope)
      and target.block == Unblocked
  }

  pure def batchCandidateAllowedIn(currentScopes, currentJobs, currentOrders,
      currentMeta, input) = {
    val current = currentJobs.get(input.job)
    val currentPrimary = scopePrimary(current.scope)
    val targetPrimary = scopePrimary(input.scope)
    not(currentMeta.batchActive)
    and input.primary == scopePrimary(input.scope)
    and scopeConfigurationMatches(currentScopes, input)
    and (current.state == Scheduled or current.state == RetryWaiting)
    and current.record == Valid and current.payload
    and current.dueRoute and current.fairRoute and current.block == Unblocked
    and scopeQuiescentIn(currentScopes, current.scope)
    and scopeQuiescentIn(currentScopes, currentPrimary)
    and scopeQuiescentIn(currentScopes, input.scope)
    and scopeQuiescentIn(currentScopes, targetPrimary)
    and not(currentOrders.get(current.ordering).inFlight)
    and not(currentOrders.get(input.ordering).inFlight)
    and input.order == currentOrders.get(input.ordering).head
    and input.order > 0 and input.payloadBytes >= 0
    and input.payloadBytes <= MAX_BATCH_PAYLOAD_BYTES
    and input.enqueuedAt >= 0 and input.batchDeadline >= input.enqueuedAt
    and currentMeta.cycle <= input.batchDeadline
  }

  def batchCandidateAllowed(input) =
    batchCandidateAllowedIn(scopes, jobs, orders, meta, input)

  pure def withoutBatchCandidate(currentScopes, job) = SCOPES.fold(currentScopes,
    (acc, scope) => {
      val current = acc.get(scope)
      val candidates = current.candidates.filter(candidate => candidate != job)
      update(acc, scope, current.with("candidates", candidates)
        .with("ready", candidates.size() > 0))
    })

  pure def applyBatchCandidate(currentScopes, currentJobs, input) = {
    val cleared = withoutBatchCandidate(currentScopes, input.job)
    val target = cleared.get(input.scope)
    val targetCandidates = target.candidates.union(Set(input.job))
    // Candidate configuration owns membership only. Scope configuration,
    // service counters, budgets, and ordering heads remain authoritative.
    val configuredTarget = target.with("ready", true)
      .with("candidates", targetCandidates)
    val configuredScopes = update(cleared, input.scope, configuredTarget)
    val configuredJob = currentJobs.get(input.job).with("scope", input.scope)
      .with("priority", input.priority).with("ordering", input.ordering)
      .with("order", input.order).with("orderHead", input.order)
      .with("cost", registeredCost(input.scope))
      .with("payloadBytes", input.payloadBytes).with("handlerKind", input.handlerKind)
      .with("schemaVersion", input.schemaVersion).with("batchKey", input.batchKey)
      .with("authConfig", input.authConfig).with("effectMode", input.effectMode)
      .with("retryPolicy", input.retryPolicy).with("timeoutPolicy", input.timeoutPolicy)
      .with("enqueuedAt", input.enqueuedAt).with("batchDeadline", input.batchDeadline)
    { scopes: configuredScopes, jobs: update(currentJobs, input.job, configuredJob) }
  }

  action ConfigureBatchCandidateInput(input) = {
    val allowed = batchCandidateAllowed(input)
    val effect = applyBatchCandidate(scopes, jobs, input)
    all {
      scopes' = if (allowed) effect.scopes else scopes,
      jobs' = if (allowed) effect.jobs else jobs,
      orders' = orders,
      meta' = meta.with("lastOutcome", if (allowed) HeadReady else SelectionRejected),
    }
  }

  /// Exact prestate decision shared by SeedReady and its command adapter.
  def seedReadyAllowed(job: JobId, priority: Priority): bool = {
    val queued = jobs.get(job)
    val scope = queued.scope
    val current = scopes.get(scope)
    val nextOrder = current.order + 1
    val readyJob = queued.with("state", Scheduled).with("payload", true)
      .with("dueRoute", true).with("fairRoute", true).with("priority", priority)
      .with("order", nextOrder).with("orderHead", nextOrder).with("block", Unblocked)
    val readyScope = current.with("ready", true).with("priority", priority)
      .with("candidates", current.candidates.union(Set(job)))
      .with("head", nextOrder).with("order", nextOrder)
      .with("block", Unblocked).with("quietDwell", 0)
    val candidateScopes = update(scopes, scope, readyScope)
    val candidateJobs = update(jobs, job, readyJob)
    val bothPrimariesReady = eligibleJobsIn(candidateJobs, candidateScopes, orders)
      .exists(candidate => scopePrimary(candidateJobs.get(candidate).scope) == ScopeA)
      and eligibleJobsIn(candidateJobs, candidateScopes, orders)
        .exists(candidate => scopePrimary(candidateJobs.get(candidate).scope) == ScopeB)
    val admissionFair = not(bothPrimariesReady)
      or normalizedServiceError(candidateScopes.get(ScopeA).servedCost,
        candidateScopes.get(ScopeA).share, candidateScopes.get(ScopeB).servedCost,
        candidateScopes.get(ScopeB).share) <= FAIR_NORMALIZED_ERROR
    not(bulkDeadline) and not(current.ready) and queued.state == Absent
      and readyCandidateCount(jobs) < MAX_CANDIDATE_ITEMS and admissionFair
  }

  action SeedReadyInput(job: JobId, priority: Priority): bool = {
    val queued = jobs.get(job)
    val scope = queued.scope
    val current = scopes.get(scope)
    val nextOrder = current.order + 1
    val readyJob = queued.with("state", Scheduled).with("payload", true)
      .with("dueRoute", true).with("fairRoute", true).with("priority", priority)
      .with("order", nextOrder).with("orderHead", nextOrder).with("block", Unblocked)
    val readyScope = current.with("ready", true).with("priority", priority)
      .with("candidates", current.candidates.union(Set(job)))
      .with("head", nextOrder).with("order", nextOrder)
      .with("block", Unblocked).with("quietDwell", 0)
    val candidateScopes = update(scopes, scope, readyScope)
    val candidateJobs = update(jobs, job, readyJob)
    val allowed = seedReadyAllowed(job, priority)
    all {
      not(bulkDeadline),
      scopes' = if (allowed) candidateScopes else scopes,
      jobs' = if (allowed) candidateJobs else jobs,
      orders' = orders,
      meta' = meta.with("lastOutcome", if (allowed) HeadReady else SelectionRejected),
    }
  }

  action SeedReady = {
    nondet job = JOBS.oneOf()
    nondet priority = PRIORITIES.oneOf()
    SeedReadyInput(job, priority)
  }

  /// Shared command decision used by the authoritative transition and MBT.
  /// It captures the prestate decision; callers never classify a selection
  /// from the mutable selected job after dispatch.
  def selectionAllowedAt(job: JobId, now: int): bool = {
    val queued = jobs.get(job)
    val current = scopes.get(queued.scope)
    val available = eligibleJobsInAt(jobs, scopes, orders, now).contains(job)
      and (current.mode != LowVolume or current.served < MAX_LOW_VOLUME_SERVICE)
    val weighted = if (current.priority == Critical)
      meta.criticalServed + queued.cost <= 8 * (meta.bulkServed + 1)
      else if (current.priority == Default)
        meta.defaultServed + queued.cost <= 4 * (meta.bulkServed + 1) else true
    val deadline = not(serviceableBulkReady
      and meta.cycle + queued.cost >= FAIR_QUIET_ERROR) or current.priority == Bulk
    val laneBudget = if (current.priority == Critical)
      meta.criticalWindow + queued.cost <= 8
      else if (current.priority == Default) meta.defaultWindow + queued.cost <= 4
      else meta.bulkWindow + queued.cost <= 1
    available and weighted and deadline and laneBudget
      and normalizedJobAdmissionAt(scopes, jobs, orders, job, queued.cost, now)
      and (not(bulkDeadline) or current.priority == Bulk)
  }

  def selectionAllowed(job: JobId): bool = selectionAllowedAt(job, 0)

  action SelectInputAt(job: JobId, now: int): bool = {
    val queued = jobs.get(job)
    val scope = queued.scope
    val current = scopes.get(scope)
    val bulkReady = serviceableBulkReady
    val forcedBulk = bulkDeadline
    val available = eligibleJobsInAt(jobs, scopes, orders, now).contains(job)
      and (current.mode != LowVolume or current.served < MAX_LOW_VOLUME_SERVICE)
    val weighted = if (current.priority == Critical)
      meta.criticalServed + queued.cost <= 8 * (meta.bulkServed + 1)
      else if (current.priority == Default)
        meta.defaultServed + queued.cost <= 4 * (meta.bulkServed + 1)
      else true
    val deadline = not(bulkReady and meta.cycle + queued.cost >= FAIR_QUIET_ERROR)
      or current.priority == Bulk
    val primaryFair = normalizedJobAdmissionAt(scopes, jobs, orders, job, queued.cost, now)
    val laneBudget = if (current.priority == Critical) meta.criticalWindow + queued.cost <= 8
      else if (current.priority == Default) meta.defaultWindow + queued.cost <= 4
      else meta.bulkWindow + queued.cost <= 1
    val allowed = selectionAllowedAt(job, now)
    val eligible = available and current.priority == Bulk
    val anotherEligibleBulk = SCOPES.exists(candidate => candidate != scope
      and scopes.get(candidate).ready and scopes.get(candidate).block == Unblocked
      and scopes.get(candidate).priority == Bulk and scopes.get(candidate).permits > 0
      and scopes.get(candidate).rate > 0
      and scopes.get(candidate).inFlight < MAX_CONCURRENCY_PER_SCOPE
      and (scopes.get(candidate).mode != LowVolume
        or scopes.get(candidate).served < MAX_LOW_VOLUME_SERVICE))
    val actionAllowed = not(bulkDeadline)
      or (eligible and not(anotherEligibleBulk))
    val nextScopes = acquireScope(scopes, scope, queued.cost, job)
    val leasedJob = leaseJob(queued)
      .with("serviceTransitions", queued.serviceTransitions + queued.cost)
    val nextMeta = if (allowed and current.priority == Critical)
      meta.with("criticalServed", meta.criticalServed + queued.cost)
        .with("criticalWindow", meta.criticalWindow + queued.cost).with("cycle", meta.cycle + queued.cost)
    else if (allowed and current.priority == Default)
      meta.with("defaultServed", meta.defaultServed + queued.cost)
        .with("defaultWindow", meta.defaultWindow + queued.cost).with("cycle", meta.cycle + queued.cost)
    else if (allowed)
      meta.with("bulkServed", meta.bulkServed + queued.cost)
        .with("bulkWindow", meta.bulkWindow + queued.cost).with("cycle", 0)
    else meta
    all {
      actionAllowed,
      scopes' = if (allowed) nextScopes else scopes,
      jobs' = if (allowed) update(jobs, job, leasedJob) else jobs,
      orders' = if (allowed) acquireOrder(orders, queued, job) else orders,
      meta' = nextMeta.with("selectedScope", scope).with("selectedJob", job)
        .with("selectedCost", if (allowed) queued.cost else 0)
        .with("serviceTransitions", if (allowed)
          meta.serviceTransitions + queued.cost else meta.serviceTransitions)
        .with("lastOutcome", if (allowed and forcedBulk) BulkForced
        else if (allowed) SelectionServed else SelectionRejected),
    }
  }

  action SelectInput(job: JobId): bool = SelectInputAt(job, 0)

  action Select = {
    nondet job = JOBS.oneOf()
    SelectInput(job)
  }

  pure def releaseCandidate(currentScopes, currentJobs, currentOrders,
      job, itemResult) = {
    val queued = currentJobs.get(job)
    val retry = itemResult == ItemRetry or itemResult == ItemMissing
    val terminal = not(retry)
    val releasedJob = if (retry) queued.with("state", RetryWaiting)
      .with("dueAt", FAIR_RETRY_NOT_DUE_TICK)
      .with("dueRoute", true).with("fairRoute", true)
      else queued.with("state", if (itemResult == ItemDeadLetter) DeadLettered else Absent)
        .with("payload", itemResult == ItemDeadLetter)
        .with("dueRoute", false).with("fairRoute", false)
    val nextScopes = releaseScopeAndRate(currentScopes, queued.scope, retry, job)
    val nextJobs = update(currentJobs, job, releasedJob)
    val nextOrders = releaseOrder(currentOrders, queued, terminal)
    { scopes: nextScopes, jobs: nextJobs, orders: nextOrders }
  }

  pure def releaseAllowedIn(currentScopes, currentJobs, currentOrders,
      job, itemResult) = {
    val candidate = releaseCandidate(currentScopes, currentJobs, currentOrders,
      job, itemResult)
    val bothPrimariesReady = eligibleJobsIn(candidate.jobs, candidate.scopes, candidate.orders)
      .exists(jobCandidate => scopePrimary(candidate.jobs.get(jobCandidate).scope) == ScopeA)
      and eligibleJobsIn(candidate.jobs, candidate.scopes, candidate.orders)
        .exists(jobCandidate => scopePrimary(candidate.jobs.get(jobCandidate).scope) == ScopeB)
    not(bothPrimariesReady) or normalizedServiceError(
      candidate.scopes.get(ScopeA).servedCost, candidate.scopes.get(ScopeA).share,
      candidate.scopes.get(ScopeB).servedCost, candidate.scopes.get(ScopeB).share)
        <= FAIR_NORMALIZED_ERROR
  }

  pure def familyReleaseTransition(currentScopes, currentJobs, currentOrders,
      currentMeta, job, itemResult) = {
    val candidate = releaseCandidate(currentScopes, currentJobs, currentOrders,
      job, itemResult)
    val releaseFair = releaseAllowedIn(currentScopes, currentJobs, currentOrders,
      job, itemResult)
    { scopes: if (releaseFair) candidate.scopes else currentScopes,
      jobs: if (releaseFair) candidate.jobs else currentJobs,
      orders: if (releaseFair) candidate.orders else currentOrders,
      meta: if (not(releaseFair)) currentMeta.with("lastOutcome", SelectionRejected)
        else currentMeta.with("lastOutcome", ClaimReleased),
      allowed: releaseFair }
  }

  action ReleaseInput(job: JobId, itemResult: BatchResult): bool = {
    val effect = familyReleaseTransition(scopes, jobs, orders, meta, job, itemResult)
    all {
      jobs.get(job).state == Leased,
      Set(ItemSuccess, ItemRetry, ItemDeadLetter, ItemMissing).contains(itemResult),
      not(meta.batchActive and meta.batchMembers.contains(job)),
      scopes' = effect.scopes,
      jobs' = effect.jobs,
      orders' = effect.orders,
      meta' = effect.meta,
    }
  }

  /// Release is revision-free but still has a fairness rejection boundary.
  /// The adapter snapshots this decision before ReleaseInput mutates service.
  def releaseAllowed(job: JobId, itemResult: BatchResult): bool = {
    releaseAllowedIn(scopes, jobs, orders, job, itemResult)
  }

  action Release = {
    nondet job = JOBS.filter(candidate => jobs.get(candidate).state == Leased).oneOf()
    nondet itemResult = Set(ItemSuccess, ItemRetry, ItemDeadLetter, ItemMissing).oneOf()
    ReleaseInput(job, itemResult)
  }

  action TickInput(expectedCycle: int): bool = {
    val ready = readyMap(scopes)
    val allowed = expectedCycle == meta.cycle and not(bulkDeadline)
      and SCOPES.forall(scope => not(ready.get(scope))
      or scopes.get(scope).quietDwell < FAIR_QUIET_ERROR)
    all {
      not(bulkDeadline),
      scopes' = if (allowed) updateDwell(scopes, ready) else scopes,
      jobs' = jobs,
      orders' = orders,
      meta' = meta.with("lastOutcome", if (allowed) QuietTick else SelectionRejected),
    }
  }


  action Tick = TickInput(meta.cycle)

  action BlockHeadInput(job: JobId, reason: BlockReason): bool = {
    val scope = jobs.get(job).scope
    val current = scopes.get(scope)
    val eligible = current.ready and current.block == Unblocked and current.priority == Bulk
      and current.permits > 0 and current.rate > 0
      and current.inFlight < MAX_CONCURRENCY_PER_SCOPE
      and (current.mode != LowVolume or current.served < MAX_LOW_VOLUME_SERVICE)
    val anotherEligibleBulk = SCOPES.exists(candidate => candidate != scope
      and scopes.get(candidate).ready and scopes.get(candidate).block == Unblocked
      and scopes.get(candidate).priority == Bulk and scopes.get(candidate).permits > 0
      and scopes.get(candidate).rate > 0
      and scopes.get(candidate).inFlight < MAX_CONCURRENCY_PER_SCOPE
      and (scopes.get(candidate).mode != LowVolume
        or scopes.get(candidate).served < MAX_LOW_VOLUME_SERVICE))
    val actionAllowed = not(bulkDeadline)
      or (eligible and not(anotherEligibleBulk))
    all {
      jobs.get(job).state == Scheduled or jobs.get(job).state == RetryWaiting,
      Set(LeasedHead, CorruptHead, OversizedHead, PoisonHead, RateLimitedHead,
        CapacityBlockedHead).contains(reason),
      actionAllowed,
      scopes' = update(scopes, scope, current.with("block", reason)),
      jobs' = update(jobs, job, jobs.get(job).with("block", reason)),
      orders' = orders,
      meta' = meta.with("lastOutcome", if (reason == RateLimitedHead) RateBlocked
        else if (reason == CapacityBlockedHead) CapacityBlocked else HeadBlocked),
    }
  }

  action BlockHead = {
    nondet job = JOBS.filter(candidate => jobs.get(candidate).state == Scheduled
      or jobs.get(candidate).state == RetryWaiting).oneOf()
    nondet reason = Set(LeasedHead, CorruptHead, OversizedHead, PoisonHead, RateLimitedHead,
      CapacityBlockedHead).oneOf()
    BlockHeadInput(job, reason)
  }

  // A HOL escape services an unrelated ready scope while the selected head is
  // blocked.  It is real work and consumes the same budgets as Select.
  action HolEscapeInput(blockedJob: JobId, job: JobId): bool = {
    val scope = jobs.get(job).scope
    val current = scopes.get(scope)
    val allowed = holEscapeAllowed(blockedJob, job)
    val nextScopes = acquireScope(scopes, scope, jobs.get(job).cost, job)
    val nextMeta = if (jobs.get(job).priority == Critical)
      meta.with("criticalServed", meta.criticalServed + jobs.get(job).cost)
        .with("criticalWindow", meta.criticalWindow + jobs.get(job).cost)
    else if (jobs.get(job).priority == Default)
      meta.with("defaultServed", meta.defaultServed + jobs.get(job).cost)
        .with("defaultWindow", meta.defaultWindow + jobs.get(job).cost)
    else meta.with("bulkServed", meta.bulkServed + jobs.get(job).cost)
      .with("bulkWindow", meta.bulkWindow + jobs.get(job).cost)
    all {
      jobs.get(blockedJob).block != Unblocked and jobs.get(blockedJob).state == Scheduled,
      eligibleJobs.contains(job),
      jobs.get(job).ordering != jobs.get(blockedJob).ordering,
      not(bulkDeadline),
      scopes' = if (allowed) nextScopes else scopes,
      jobs' = if (allowed) update(jobs, job, leaseJob(jobs.get(job))
        .with("serviceTransitions", jobs.get(job).serviceTransitions + jobs.get(job).cost)) else jobs,
      orders' = if (allowed) acquireOrder(orders, jobs.get(job), job) else orders,
      meta' = (if (allowed) nextMeta else meta)
        .with("holEscapes", if (allowed) meta.holEscapes + 1 else meta.holEscapes)
        .with("selectedScope", scope).with("selectedJob", job)
        .with("selectedCost", if (allowed) jobs.get(job).cost else 0)
        .with("serviceTransitions", if (allowed)
          meta.serviceTransitions + jobs.get(job).cost else meta.serviceTransitions)
        .with("lastOutcome", if (allowed) HolEscaped else SelectionRejected),
    }
  }

  /// Exact prestate classification for one head-of-line escape command.
  def holEscapeAllowed(blockedJob: JobId, job: JobId): bool = {
    val queued = jobs.get(job)
    val current = scopes.get(queued.scope)
    val weighted = if (queued.priority == Critical)
      meta.criticalServed + queued.cost <= 8 * (meta.bulkServed + 1)
      else if (queued.priority == Default)
        meta.defaultServed + queued.cost <= 4 * (meta.bulkServed + 1) else true
    val laneBudget = if (queued.priority == Critical)
      meta.criticalWindow + queued.cost <= 8
      else if (queued.priority == Default) meta.defaultWindow + queued.cost <= 4
      else meta.bulkWindow + queued.cost <= 1
    jobs.get(blockedJob).block != Unblocked and jobs.get(blockedJob).state == Scheduled
      and eligibleJobs.contains(job) and queued.ordering != jobs.get(blockedJob).ordering
      and not(bulkDeadline) and weighted and laneBudget
      and normalizedJobAdmission(scopes, jobs, orders, job, queued.cost)
      and (current.mode != LowVolume or current.served < MAX_LOW_VOLUME_SERVICE)
  }

  action HolEscape = {
    nondet blockedJob = JOBS.filter(candidate => jobs.get(candidate).block != Unblocked
      and jobs.get(candidate).state == Scheduled).oneOf()
    nondet job = eligibleJobs.filter(candidate => jobs.get(candidate).ordering
      != jobs.get(blockedJob).ordering).oneOf()
    HolEscapeInput(blockedJob, job)
  }

  action RefillInput(scope: Scope): bool = {
    val current = scopes.get(scope)
    val nextScopes = update(scopes, scope, current
      .with("rate", MAX_RATE_PER_SCOPE)
      .with("permits", max(0, MAX_CONCURRENCY_PER_SCOPE - current.inFlight)))
    val refillFair = refillAllowed(scope)
    all {
      scopes' = if (refillFair) nextScopes else scopes,
      jobs' = jobs,
      orders' = orders,
      meta' = if (not(refillFair)) meta.with("lastOutcome", SelectionRejected)
        else meta.with("lastOutcome", ScopeRefilled),
    }
  }

  /// Refill can be rejected when it would exceed normalized cross-tenant
  /// service error. Its result must therefore be correlated to this prestate.
  def refillAllowed(scope: Scope): bool = {
    val current = scopes.get(scope)
    val nextScopes = update(scopes, scope, current
      .with("rate", MAX_RATE_PER_SCOPE)
      .with("permits", max(0, MAX_CONCURRENCY_PER_SCOPE - current.inFlight)))
    val bothPrimariesReady = eligibleJobsIn(jobs, nextScopes, orders)
      .exists(candidate => scopePrimary(jobs.get(candidate).scope) == ScopeA)
      and eligibleJobsIn(jobs, nextScopes, orders)
        .exists(candidate => scopePrimary(jobs.get(candidate).scope) == ScopeB)
    not(bothPrimariesReady) or normalizedServiceError(nextScopes.get(ScopeA).servedCost,
      nextScopes.get(ScopeA).share, nextScopes.get(ScopeB).servedCost,
      nextScopes.get(ScopeB).share) <= FAIR_NORMALIZED_ERROR
  }


  action Refill = {
    nondet scope = SCOPES.oneOf()
    RefillInput(scope)
  }

  action LowVolumeAttemptInput(job: JobId): bool = {
    val queued = jobs.get(job)
    val scope = queued.scope
    val current = scopes.get(scope)
    // Low-volume credit is earned only by a concrete ready candidate.  An
    // idle scope, even when its permit and rate buckets are refilled, cannot
    // advance service or consume capacity.
    val allowed = lowVolumeAttemptAllowed(job)
    val nextScopes = acquireScope(scopes, scope, queued.cost, job)
    val nextMeta = if (queued.priority == Critical)
      meta.with("criticalServed", meta.criticalServed + queued.cost)
        .with("criticalWindow", meta.criticalWindow + queued.cost).with("cycle", meta.cycle + queued.cost)
    else if (queued.priority == Default)
      meta.with("defaultServed", meta.defaultServed + queued.cost)
        .with("defaultWindow", meta.defaultWindow + queued.cost).with("cycle", meta.cycle + queued.cost)
    else meta.with("bulkServed", meta.bulkServed + queued.cost)
      .with("bulkWindow", meta.bulkWindow + queued.cost).with("cycle", 0)
    all {
      scopes.get(jobs.get(job).scope).mode == LowVolume,
      not(bulkDeadline),
      scopes' = if (allowed) nextScopes else scopes,
      jobs' = if (allowed) update(jobs, job, leaseJob(queued)
        .with("serviceTransitions", queued.serviceTransitions + queued.cost)) else jobs,
      orders' = if (allowed) acquireOrder(orders, queued, job) else orders,
      meta' = if (allowed) nextMeta.with("selectedScope", scope).with("selectedJob", job)
        .with("selectedCost", queued.cost)
        .with("serviceTransitions", meta.serviceTransitions + queued.cost)
        .with("lastOutcome", SelectionServed) else meta.with("lastOutcome", LowVolumeRejected),
    }
  }

  /// Exact low-volume credit decision shared with the command adapter.
  def lowVolumeAttemptAllowed(job: JobId): bool = {
    val queued = jobs.get(job)
    val current = scopes.get(queued.scope)
    val weighted = if (queued.priority == Critical)
      meta.criticalServed + queued.cost <= 8 * (meta.bulkServed + 1)
      else if (queued.priority == Default)
        meta.defaultServed + queued.cost <= 4 * (meta.bulkServed + 1) else true
    val laneBudget = if (queued.priority == Critical) meta.criticalWindow + queued.cost <= 8
      else if (queued.priority == Default) meta.defaultWindow + queued.cost <= 4
      else meta.bulkWindow + queued.cost <= 1
    current.mode == LowVolume and not(bulkDeadline) and weighted and laneBudget
      and normalizedJobAdmission(scopes, jobs, orders, job, queued.cost)
      and lowVolumeEligible(current, scopes.get(current.primary), orders, queued, job)
  }


  action LowVolumeAttempt = {
    nondet job = JOBS.filter(candidate => scopes.get(jobs.get(candidate).scope).mode == LowVolume).oneOf()
    LowVolumeAttemptInput(job)
  }

  action StartBatchInput(first: JobId, second: JobId, capacity: int): bool = {
    val members = Set(first, second)
    val firstJob = jobs.get(first)
    val secondJob = jobs.get(second)
    val firstPrimary = scopePrimary(firstJob.scope)
    val claimedJobs = update(update(jobs, first, leaseJob(firstJob)
      .with("serviceTransitions", firstJob.serviceTransitions + firstJob.cost)), second,
      leaseJob(secondJob).with("serviceTransitions", secondJob.serviceTransitions + secondJob.cost))
    val claimedScopes = acquireScope(acquireScope(scopes, firstJob.scope,
      firstJob.cost, first), secondJob.scope, secondJob.cost, second)
    val claimedOrders = acquireOrder(acquireOrder(orders, firstJob, first), secondJob, second)
    val criticalCost = (if (firstJob.priority == Critical) firstJob.cost else 0)
      + (if (secondJob.priority == Critical) secondJob.cost else 0)
    val defaultCost = (if (firstJob.priority == Default) firstJob.cost else 0)
      + (if (secondJob.priority == Default) secondJob.cost else 0)
    val bulkCost = (if (firstJob.priority == Bulk) firstJob.cost else 0)
      + (if (secondJob.priority == Bulk) secondJob.cost else 0)
    val allowed = batchStartAllowed(first, second)
    val formedAt = meta.cycle
    val deadline = min(firstJob.batchDeadline, secondJob.batchDeadline)
    all {
      capacity == meta.scratchCapacity,
      not(bulkDeadline),
      not(meta.batchActive),
      scopes' = if (allowed) claimedScopes else scopes,
      jobs' = if (allowed) claimedJobs else jobs,
      orders' = if (allowed) claimedOrders else orders,
      meta' = if (allowed) meta.with("batchActive", true).with("batchScope", jobs.get(first).scope).with("batchMembers", members)
        .with("batchResults", Map(first -> ItemMissing, second -> ItemMissing))
        .with("criticalServed", meta.criticalServed + criticalCost)
        .with("defaultServed", meta.defaultServed + defaultCost)
        .with("bulkServed", meta.bulkServed + bulkCost)
        .with("criticalWindow", meta.criticalWindow + criticalCost)
        .with("defaultWindow", meta.defaultWindow + defaultCost)
        .with("bulkWindow", meta.bulkWindow + bulkCost)
        .with("selectedJob", second).with("selectedScope", secondJob.scope)
        .with("selectedCost", secondJob.cost)
        .with("serviceTransitions", meta.serviceTransitions + criticalCost + defaultCost + bulkCost)
        .with("scratchCapacity", MAX_BATCH_ITEMS).with("scratchSize", 2)
        .with("batchPayloadBytes", firstJob.payloadBytes + secondJob.payloadBytes)
        .with("batchScope", firstPrimary).with("batchAuthConfig", firstJob.authConfig)
        .with("batchFormedAt", formedAt).with("batchDeadline", deadline)
        .with("lastOutcome", BatchPartial)
        else meta.with("lastOutcome", SelectionRejected),
    }
  }


  action StartBatch = {
    nondet first = JOBS.oneOf()
    nondet second = JOBS.oneOf()
    StartBatchInput(first, second, meta.scratchCapacity)
  }

  action SubmitPartialBatchInput(batchItem: JobId, itemResult: BatchResult): bool = {
    val currentResult = meta.batchResults.get(batchItem)
    // ItemMissing is the sole not-yet-classified marker. A missing response or
    // duplicate delivery becomes one durable retry result and releases its
    // claim exactly once; ItemRetry is therefore final for this batch.
    val unresolved = currentResult == ItemMissing
    val durableResult = if (itemResult == ItemDuplicate or itemResult == ItemMissing)
      ItemRetry else itemResult
    val allowed = not(bulkDeadline) and meta.batchActive and meta.batchMembers.contains(batchItem)
      and unresolved
    val queued = jobs.get(batchItem)
    val retry = durableResult == ItemRetry or durableResult == ItemMissing
    val terminal = not(retry)
    val transitioned = if (retry) queued.with("state", RetryWaiting)
      .with("dueAt", FAIR_RETRY_NOT_DUE_TICK)
      .with("dueRoute", true).with("fairRoute", true)
      else queued.with("state", if (durableResult == ItemDeadLetter) DeadLettered else Absent)
        .with("payload", durableResult == ItemDeadLetter)
        .with("dueRoute", false).with("fairRoute", false)
    all {
      Set(ItemSuccess, ItemRetry, ItemDeadLetter, ItemMissing, ItemDuplicate).contains(itemResult),
      not(bulkDeadline),
      scopes' = if (allowed)
        releaseScopeAndRate(scopes, queued.scope, retry, batchItem) else scopes,
      jobs' = if (allowed) update(jobs, batchItem, transitioned) else jobs,
      orders' = if (allowed) releaseOrder(orders, queued, terminal) else orders,
      meta' = if (allowed) meta.with("batchResults", update(meta.batchResults, batchItem, durableResult))
        .with("lastOutcome", BatchPartial) else meta.with("lastOutcome", SelectionRejected),
    }
  }


  action SubmitPartialBatch = {
    nondet batchItem = meta.batchMembers.oneOf()
    nondet itemResult = Set(ItemSuccess, ItemRetry, ItemDeadLetter, ItemMissing, ItemDuplicate).oneOf()
    SubmitPartialBatchInput(batchItem, itemResult)
  }

  def scratchClearAllowed(expectedCapacity: int): bool =
    expectedCapacity == meta.scratchCapacity and not(bulkDeadline)
      and meta.batchActive and meta.batchMembers.forall(job =>
        meta.batchResults.get(job) != ItemMissing)

  action ClearScratchInput(expectedCapacity: int): bool = all {
    scratchClearAllowed(expectedCapacity),
    scopes' = scopes,
    jobs' = jobs,
    orders' = orders,
    meta' = meta.with("scratchSize", 0).with("batchActive", false)
      .with("batchMembers", Set()).with("batchResults", Map())
      .with("batchAuthConfig", AuthConfigA)
      .with("batchPayloadBytes", 0).with("batchFormedAt", 0).with("batchDeadline", 0)
      .with("lastOutcome", ScratchCleared),
  }


  action ClearScratch = ClearScratchInput(meta.scratchCapacity)

  action ShrinkScratchInput(expectedCapacity: int): bool = {
    val allowed = expectedCapacity == meta.scratchCapacity and not(bulkDeadline)
      and meta.scratchSize == 0 and meta.scratchCapacity > 0
    all {
      not(bulkDeadline),
      scopes' = scopes,
      jobs' = jobs,
      orders' = orders,
      meta' = meta.with("scratchCapacity", if (allowed) 0 else meta.scratchCapacity)
        .with("lastOutcome", if (allowed) ScratchShrunk else SelectionRejected),
    }
  }


  action ShrinkScratch = ShrinkScratchInput(meta.scratchCapacity)

  action RecordServiceError = {
    nondet job = eligibleJobs.oneOf()
    val scope = jobs.get(job).scope
    val current = scopes.get(scope)
    val otherPrimary = if (scopePrimary(scope) == ScopeA) ScopeB else ScopeA
    val error = normalizedServiceError(scopes.get(scopePrimary(scope)).servedCost,
      scopes.get(scopePrimary(scope)).share, scopes.get(otherPrimary).servedCost,
      scopes.get(otherPrimary).share)
    val allowed = eligibleJobs.contains(job) and error <= FAIR_NORMALIZED_ERROR
    all {
      not(bulkDeadline),
      scopes' = if (allowed) update(scopes, scope,
        current.with("errors", error)) else scopes,
      jobs' = jobs,
      orders' = orders,
      meta' = meta.with("lastOutcome", if (allowed) ServiceErrorRecorded else SelectionRejected),
    }
  }

  // A completed 8:4:1 service window is a bounded proof epoch. Resetting only
  // after the exact ratio makes the finite window repeatable without allowing
  // a partial window to erase missing Bulk service.
  action ResetPriorityWindowInput(critical: int, default: int, bulk: int): bool = all {
    critical == meta.criticalWindow and default == meta.defaultWindow
      and bulk == meta.bulkWindow,
    meta.criticalWindow == 8 and meta.defaultWindow == 4 and meta.bulkWindow == 1,
    scopes' = scopes,
    jobs' = JOBS.fold(jobs, (currentJobs, job) => update(currentJobs, job,
      currentJobs.get(job).with("serviceTransitions", 0))),
    orders' = orders,
    meta' = meta.with("criticalWindow", 0).with("defaultWindow", 0)
      .with("bulkWindow", 0).with("serviceTransitions", 0)
      .with("selectedCost", 0).with("lastOutcome", HeadReady),
  }


  action ResetPriorityWindow = ResetPriorityWindowInput(meta.criticalWindow,
    meta.defaultWindow, meta.bulkWindow)

  /// Complete cost-weighted service reducer. `forceBulk` is the sole priority
  /// safety input; every accounting field is derived from the registered cost.
  pure def familyServiceTransitionAt(currentScopes, currentJobs, currentOrders,
      currentMeta, job, refillRate, forceBulk, now) = {
    val queued = currentJobs.get(job)
    val scope = queued.scope
    val primary = scopePrimary(scope)
    val currentScope = currentScopes.get(scope)
    val primaryScope = currentScopes.get(primary)
    val orderState = currentOrders.get(queued.ordering)
    val weighted = if (queued.priority == Critical)
      currentMeta.criticalServed + queued.cost <= 8 * (currentMeta.bulkServed + 1)
      else if (queued.priority == Default)
        currentMeta.defaultServed + queued.cost <= 4 * (currentMeta.bulkServed + 1) else true
    val before = { jobState: queued.state, dueRoute: queued.dueRoute,
      fairRoute: queued.fairRoute, childPermits: currentScope.permits,
      primaryPermits: primaryScope.permits, childRate: currentScope.rate,
      primaryRate: primaryScope.rate, childInFlight: currentScope.inFlight,
      primaryInFlight: primaryScope.inFlight, childServed: currentScope.served,
      childServedCost: currentScope.servedCost,
      primaryServedCost: primaryScope.servedCost, orderHead: orderState.head,
      orderInFlight: orderState.inFlight, orderOwner: orderState.owner,
      critical: currentMeta.criticalWindow, default: currentMeta.defaultWindow,
      bulk: currentMeta.bulkWindow, cycle: currentMeta.cycle,
      serviceUnits: currentMeta.serviceTransitions,
      jobServiceUnits: queued.serviceTransitions }
    val effect = fairSelectedServiceKernel(
      eligibleJobsInAt(currentJobs, currentScopes, currentOrders, now).contains(job) and weighted,
      job, scope, primary, queued.priority, queued.cost, refillRate,
      false, normalizedJobAdmissionAt(currentScopes, currentJobs, currentOrders,
        job, queued.cost, now), forceBulk, before)
    val childNext = currentScope.with("permits", effect.state.childPermits)
      .with("rate", effect.state.childRate).with("inFlight", effect.state.childInFlight)
      .with("served", effect.state.childServed).with("servedCost", effect.state.childServedCost)
      .with("acquisitions", currentScope.acquisitions + 1)
      .with("releases", currentScope.releases + 1)
    val childChanged = update(currentScopes, scope, childNext)
    val primaryNext = if (scope == primary) childNext else primaryScope
      .with("permits", effect.state.primaryPermits).with("rate", effect.state.primaryRate)
      .with("inFlight", effect.state.primaryInFlight)
      .with("servedCost", effect.state.primaryServedCost)
      .with("acquisitions", primaryScope.acquisitions + 1)
      .with("releases", primaryScope.releases + 1)
    val finalScopes = if (scope == primary) childChanged
      else update(childChanged, primary, primaryNext)
    val finalOrders = update(currentOrders, queued.ordering, orderState
      .with("head", effect.state.orderHead).with("inFlight", effect.state.orderInFlight)
      .with("owner", effect.state.orderOwner)
      .with("acquisitions", orderState.acquisitions + 1)
      .with("releases", orderState.releases + 1))
    val servicedJob = queued.with("state", effect.state.jobState)
      .with("dueRoute", effect.state.dueRoute).with("fairRoute", effect.state.fairRoute)
      .with("dueAt", if (effect.allowed and effect.state.jobState == RetryWaiting)
        FAIR_RETRY_NOT_DUE_TICK else queued.dueAt)
      .with("serviceTransitions", effect.state.jobServiceUnits)
    val finalJobs = update(currentJobs, job, servicedJob)
    val nextMeta = currentMeta.with("criticalServed", currentMeta.criticalServed
        + (if (queued.priority == Critical) effect.priorityDelta else 0))
      .with("defaultServed", currentMeta.defaultServed
        + (if (queued.priority == Default) effect.priorityDelta else 0))
      .with("bulkServed", currentMeta.bulkServed
        + (if (queued.priority == Bulk) effect.priorityDelta else 0))
      .with("criticalWindow", effect.state.critical)
      .with("defaultWindow", effect.state.default).with("bulkWindow", effect.state.bulk)
      .with("cycle", effect.state.cycle)
    { allowed: effect.allowed, effect: effect, scopes: finalScopes,
      jobs: finalJobs, orders: finalOrders,
      meta: nextMeta.with("selectedJob", job).with("selectedScope", scope)
        .with("selectedCost", queued.cost)
        .with("serviceTransitions", effect.state.serviceUnits)
        .with("lastOutcome", if (effect.allowed and forceBulk) BulkForced
          else if (effect.allowed) SelectionServed else SelectionRejected) }
  }

  pure def familyServiceTransition(currentScopes, currentJobs, currentOrders,
      currentMeta, job, refillRate, forceBulk) = familyServiceTransitionAt(
        currentScopes, currentJobs, currentOrders, currentMeta, job, refillRate, forceBulk, 0)

  // A service unit is the smallest authoritative fairness transition. It
  // applies the complete reducer above and atomically replaces all authorities.
  action ServiceUnitInputAt(job: JobId, refillRate: bool, now: int): bool = {
    // A non-Bulk cost unit may not be the transition that reaches the quiet
    // bound while Bulk is already serviceable. The command decides this from
    // its immutable prestate; the reducer only enforces the typed decision.
    val forceBulk = serviceForcesBulkAt(job, now)
    val transition = familyServiceTransitionAt(scopes, jobs, orders, meta,
      job, refillRate, forceBulk, now)
    all {
      transition.allowed,
      scopes' = transition.scopes, jobs' = transition.jobs,
      orders' = transition.orders, meta' = transition.meta,
    }
  }

  action ServiceUnitInput(job: JobId, refillRate: bool): bool =
    ServiceUnitInputAt(job, refillRate, 0)

  action ServiceUnit = {
    nondet job = eligibleJobs.oneOf()
    nondet refillRate = bools.oneOf()
    ServiceUnitInput(job, refillRate)
  }

  def serviceForcesBulkAt(job: JobId, now: int): bool =
    eligibleJobsInAt(jobs, scopes, orders, now)
      .exists(candidate => jobs.get(candidate).priority == Bulk)
    and meta.cycle + jobs.get(job).cost >= FAIR_QUIET_ERROR
  def serviceForcesBulk(job: JobId): bool = serviceForcesBulkAt(job, 0)

  // The bounded witness is deterministic but does not synthesize service.
  // Its first transition makes the real Bulk job ready; each following
  // transition delegates to exactly one canonical service unit.
  action PriorityWindowWitnessStep = if (jobs.get(JobC).state == Absent)
    SeedReadyInput(JobC, Bulk)
  else {
    val unit = meta.serviceTransitions
    val job = if (unit == 0 or unit == 2 or unit == 4 or unit == 6) JobA
      else if (unit == 8) JobC else JobB
    all {
      if (unit < 13)
        ServiceUnitInputAt(job, true,
          if (jobs.get(job).state == RetryWaiting) FAIR_RETRY_DUE_TICK else 0)
      else ResetPriorityWindowInput(meta.criticalWindow, meta.defaultWindow, meta.bulkWindow),
    }
  }

  action IndependentGroupProgressWitnessStep = if (not(orders.get(OrderA).inFlight))
    SelectInputAt(JobA, 0)
  else if (not(orders.get(OrderB).inFlight)) SelectInputAt(JobB, 0)
  else TickInput(meta.cycle)

  action CompatibleBatchWitnessStep = StartBatchInput(JobA, JobB,
    meta.scratchCapacity)

  action ResolvedBatchClearWitnessStep = if (not(meta.batchActive))
    StartBatchInput(JobA, JobB, meta.scratchCapacity)
  else if (meta.batchResults.get(JobA) == ItemMissing)
    SubmitPartialBatchInput(JobA, ItemSuccess)
  else if (meta.batchResults.get(JobB) == ItemMissing)
    SubmitPartialBatchInput(JobB, ItemSuccess)
  else ClearScratchInput(meta.scratchCapacity)

  action step = any {
    SeedReady, Select, Release, Tick, BlockHead, HolEscape, Refill, LowVolumeAttempt,
    StartBatch, SubmitPartialBatch, ClearScratch, ShrinkScratch, RecordServiceError,
    ResetPriorityWindow, ServiceUnit, PriorityWindowWitnessStep,
  }

  val noisy_quiet_witness = meta.lastOutcome == QuietTick or meta.lastOutcome == SelectionServed
  val secondary_witness = SCOPES.exists(scope => scopes.get(scope).secondary)
  val weighted_priority_witness = meta.criticalServed >= 1 or meta.defaultServed >= 1 or meta.bulkServed >= 1
  val bulk_progress_witness = meta.bulkServed > 0
  val low_volume_rejection_witness = meta.lastOutcome == LowVolumeRejected
  val low_volume_registered_witness = SCOPES.exists(scope => scopes.get(scope).mode == LowVolume)
  val blocked_reason_witness = meta.lastOutcome == HeadBlocked
  val leased_head_witness = SCOPES.exists(scope => scopes.get(scope).block == LeasedHead)
  val corrupt_head_witness = SCOPES.exists(scope => scopes.get(scope).block == CorruptHead)
  val oversized_head_witness = SCOPES.exists(scope => scopes.get(scope).block == OversizedHead)
  val poison_head_witness = SCOPES.exists(scope => scopes.get(scope).block == PoisonHead)
  val rate_limited_head_witness = meta.lastOutcome == RateBlocked
  val capacity_blocked_head_witness = meta.lastOutcome == CapacityBlocked
  val blocked_head_witness = SCOPES.exists(scope => scopes.get(scope).block != Unblocked)
  val partial_batch_witness = meta.lastOutcome == BatchPartial
  val budget_witness = SCOPES.exists(scope => scopes.get(scope).permits < MAX_CONCURRENCY_PER_SCOPE
    or scopes.get(scope).rate < MAX_RATE_PER_SCOPE)
  val scratch_reuse_witness = meta.scratchSize > 0
  val scratch_shrink_witness = meta.lastOutcome == ScratchShrunk
  val hol_escape_witness = meta.lastOutcome == HolEscaped
  val no_two_group_leases_witness = ORDERING_GROUPS.exists(group =>
    orders.get(group).inFlight and JOBS.filter(job => jobs.get(job).state == Leased
      and jobs.get(job).ordering == group).size() == 1)
  val independent_group_progress_witness = orders.get(OrderA).inFlight
    and orders.get(OrderB).inFlight and orders.get(OrderA).owner != orders.get(OrderB).owner
  val exact_candidate_bound_witness = readyCandidateCount(jobs) == MAX_CANDIDATE_ITEMS
  val exact_priority_window_witness = meta.criticalWindow == 8
    and meta.defaultWindow == 4 and meta.bulkWindow == 1
  val real_batch_transition_witness = meta.batchActive
    and meta.batchMembers.forall(job => jobs.get(job).state == Leased)
  val primary_scoped_batch_witness = real_batch_transition_witness
    and meta.batchMembers.forall(job => jobs.get(job).scope == ScopeA)
  val secondary_scoped_batch_witness = real_batch_transition_witness
    and meta.batchMembers.forall(job => jobs.get(job).scope == ScopeA1)
    and scopes.get(ScopeA1).inFlight == 2 and scopes.get(ScopeA).inFlight == 2
  val batch_rejection_witness = meta.lastOutcome == SelectionRejected
    and not(meta.batchActive) and meta.batchMembers.size() == 0
  val resolved_batch_clear_witness = meta.lastOutcome == ScratchCleared
    and not(meta.batchActive) and meta.batchMembers.size() == 0
    and meta.batchResults.keys().size() == 0

  run quiet_service_error_formula = all {
    assert(FAIR_QUIET_ERROR == MAX_REGISTERED_COST
      * (FAIR_CANDIDATE_WINDOW + FAIR_LOCAL_CLAIMS)),
    assert(normalizedService(4, 1) == 8),
  }

  run low_volume_requires_ready_candidate = all {
    assert(not(lowVolumeEligible(initialScopes.get(ScopeA1), initialScopes.get(ScopeA),
      initialOrders, initialJobs.get(JobC), JobC))),
    assert(lowVolumeEligible(initialScopes.get(ScopeA1).with("ready", true)
      .with("candidates", Set(JobC)), initialScopes.get(ScopeA),
      initialOrders,
      initialJobs.get(JobC).with("state", Scheduled).with("payload", true)
        .with("dueRoute", true).with("fairRoute", true), JobC)),
  }


  run service_and_ordering_contracts = {
    val absentA = update(initialJobs, JobA,
      initialJobs.get(JobA).with("state", Absent).with("payload", false)
        .with("dueRoute", false).with("fairRoute", false))
    all {
      assert(not(eligibleJobsIn(absentA, initialScopes, initialOrders).contains(JobA))),
    }
  }

  run exact_batch_compatibility_contract = {
    val first = initialJobs.get(JobA)
    val same = first.with("ordering", OrderB)
    all {
      assert(batchCompatible(first, same, initialScopes.get(ScopeA),
        initialScopes.get(ScopeA))),
      assert(not(batchCompatible(first, same.with("handlerKind", HandlerB),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA)))),
      assert(not(batchCompatible(first, same.with("schemaVersion", 2),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA)))),
      assert(not(batchCompatible(first, same.with("batchKey", BatchB),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA)))),
      assert(not(batchCompatible(first, same.with("authConfig", AuthConfigB),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA)))),
      assert(not(batchCompatible(first, same.with("priority", Bulk),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA)))),
      assert(not(batchCompatible(first, same.with("effectMode", FencedEffect),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA)))),
      assert(not(batchCompatible(first, same.with("retryPolicy", MaintenanceRetry),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA)))),
      assert(not(batchCompatible(first, same.with("timeoutPolicy", LongTimeout),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA)))),
      assert(not(batchCompatible(first, same.with("scope", ScopeA1),
        initialScopes.get(ScopeA), initialScopes.get(ScopeA1)))),
      assert(not(batchCompatible(first.with("scope", ScopeA1),
        same.with("scope", ScopeB1), initialScopes.get(ScopeA1),
        initialScopes.get(ScopeB1)))),
      assert(batchCompatible(first.with("scope", ScopeA1),
        same.with("scope", ScopeA2), initialScopes.get(ScopeA1),
        initialScopes.get(ScopeA2).with("mode", LowVolume))),
    }
  }

  run batch_payload_and_formation_bounds_are_enforced = {
    val first = initialJobs.get(JobA).with("payloadBytes", MAX_BATCH_PAYLOAD_BYTES)
      .with("enqueuedAt", 1).with("batchDeadline", 4)
    val second = initialJobs.get(JobB).with("payloadBytes", 0)
      .with("enqueuedAt", 2).with("batchDeadline", 4)
    all {
      assert(batchResourceAllowed(first, second, 2)),
      assert(not(batchResourceAllowed(first,
        second.with("payloadBytes", 1), 2))),
      assert(not(batchResourceAllowed(first,
        second.with("enqueuedAt", 5), 2))),
      assert(not(batchResourceAllowed(first.with("enqueuedAt", 0)
        .with("batchDeadline", MAX_BATCH_DELAY_TICKS + 1),
        second.with("enqueuedAt", 0).with("batchDeadline", MAX_BATCH_DELAY_TICKS + 1),
        MAX_BATCH_DELAY_TICKS + 1))),
    }
  }

  run live_scope_authority_rejects_candidate_reconfiguration = {
    val queuedA = initialJobs.get(JobA)
    val leasedScopes = acquireScope(initialScopes, queuedA.scope, queuedA.cost, JobA)
    val leasedJobs = update(initialJobs, JobA, leaseJob(queuedA))
    val leasedOrders = acquireOrder(initialOrders, queuedA, JobA)
    val claimed = { allowed: true, scopes: leasedScopes, jobs: leasedJobs,
      orders: leasedOrders, meta: initialMeta }
    val input = { job: JobB, scope: ScopeA, primary: ScopeA, priority: Default,
      ordering: OrderB, order: claimed.orders.get(OrderB).head, payloadBytes: 1,
      handlerKind: HandlerA, schemaVersion: 1, batchKey: BatchA,
      authConfig: AuthConfigA, effectMode: IdempotentEffect,
      retryPolicy: NetworkRetry, timeoutPolicy: ShortTimeout,
      enqueuedAt: 0, batchDeadline: MAX_BATCH_DELAY_TICKS, mode: ScopedVolume }
    val secondary = input.with("scope", ScopeA1)
    val primaryAllowed = batchCandidateAllowedIn(claimed.scopes, claimed.jobs,
      claimed.orders, claimed.meta, input)
    val secondaryAllowed = batchCandidateAllowedIn(claimed.scopes, claimed.jobs,
      claimed.orders, claimed.meta, secondary)
    val primaryAfter = if (primaryAllowed)
      applyBatchCandidate(claimed.scopes, claimed.jobs, input).scopes else claimed.scopes
    val secondaryAfter = if (secondaryAllowed)
      applyBatchCandidate(claimed.scopes, claimed.jobs, secondary).scopes else claimed.scopes
    all {
      assert(claimed.allowed),
      assert(not(primaryAllowed) and not(secondaryAllowed)),
      assert(primaryAfter == claimed.scopes and secondaryAfter == claimed.scopes),
      assert(claimed.scopes.get(ScopeA).inFlight == 1
        and claimed.scopes.get(ScopeA).permits == MAX_CONCURRENCY_PER_SCOPE - 1
        and claimed.scopes.get(ScopeA).rate == MAX_RATE_PER_SCOPE - 1
        and claimed.scopes.get(ScopeA).servedCost == registeredCost(ScopeA)),
      assert(claimed.orders.get(OrderA).inFlight
        and claimed.orders.get(OrderA).owner == JobA),
    }
  }

  run quiescent_candidate_configuration_preserves_scope_authority = {
    val input = { job: JobB, scope: ScopeA, primary: ScopeA, priority: Critical,
      ordering: OrderB, order: initialOrders.get(OrderB).head, payloadBytes: 1,
      handlerKind: HandlerA, schemaVersion: 1, batchKey: BatchA,
      authConfig: AuthConfigA, effectMode: IdempotentEffect,
      retryPolicy: NetworkRetry, timeoutPolicy: ShortTimeout,
      enqueuedAt: 0, batchDeadline: MAX_BATCH_DELAY_TICKS, mode: ScopedVolume }
    val allowed = batchCandidateAllowedIn(initialScopes, initialJobs,
      initialOrders, initialMeta, input)
    val effect = applyBatchCandidate(initialScopes, initialJobs, input)
    val before = initialScopes.get(ScopeA)
    val after = effect.scopes.get(ScopeA)
    all {
      assert(allowed),
      assert(after.candidates == before.candidates.union(Set(JobB)) and after.ready),
      assert(after.primary == before.primary and after.secondary == before.secondary
        and after.share == before.share and after.mode == before.mode
        and after.priority == before.priority and after.head == before.head
        and after.order == before.order and after.cost == before.cost
        and after.block == before.block and after.inFlight == before.inFlight
        and after.permits == before.permits and after.rate == before.rate
        and after.quietDwell == before.quietDwell and after.served == before.served
        and after.servedCost == before.servedCost and after.errors == before.errors
        and after.acquisitions == before.acquisitions and after.releases == before.releases),
      assert(effect.jobs.get(JobB).scope == ScopeA
        and effect.jobs.get(JobB).priority == Critical
        and batchCompatible(effect.jobs.get(JobA), effect.jobs.get(JobB),
          effect.scopes.get(ScopeA), effect.scopes.get(ScopeA))),
    }
  }

  run secondary_candidate_configuration_preserves_lifecycle_authority = {
    val input = { job: JobB, scope: ScopeA2, primary: ScopeA, priority: Default,
      ordering: OrderB, order: initialOrders.get(OrderB).head, payloadBytes: 1,
      handlerKind: HandlerA, schemaVersion: 1, batchKey: BatchA,
      authConfig: AuthConfigA, effectMode: IdempotentEffect,
      retryPolicy: NetworkRetry, timeoutPolicy: ShortTimeout,
      enqueuedAt: 0, batchDeadline: MAX_BATCH_DELAY_TICKS, mode: ScopedVolume }
    val before = initialJobs.get(JobB)
    val allowed = batchCandidateAllowedIn(initialScopes, initialJobs,
      initialOrders, initialMeta, input)
    val after = applyBatchCandidate(initialScopes, initialJobs, input).jobs.get(JobB)
    all {
      assert(allowed and after.scope == ScopeA2),
      assert(after.state == before.state and after.record == before.record
        and after.payload == before.payload and after.dueRoute == before.dueRoute
        and after.fairRoute == before.fairRoute and after.dueAt == before.dueAt
        and after.block == before.block
        and after.serviceTransitions == before.serviceTransitions),
    }
  }

  run terminal_invalid_and_expired_candidates_are_rejected_without_resurrection = {
    val input = { job: JobB, scope: ScopeA, primary: ScopeA, priority: Critical,
      ordering: OrderB, order: initialOrders.get(OrderB).head, payloadBytes: 1,
      handlerKind: HandlerA, schemaVersion: 1, batchKey: BatchA,
      authConfig: AuthConfigA, effectMode: IdempotentEffect,
      retryPolicy: NetworkRetry, timeoutPolicy: ShortTimeout,
      enqueuedAt: 0, batchDeadline: MAX_BATCH_DELAY_TICKS, mode: ScopedVolume }
    val base = initialJobs.get(JobB)
    val states = Set(DeadLettered, Completed, Cancelled, Absent, Leased)
    val invalidStatesReject = states.forall(state => {
      val candidate = base.with("state", state)
      val candidateJobs = update(initialJobs, JobB, candidate)
      val allowed = batchCandidateAllowedIn(initialScopes, candidateJobs,
        initialOrders, initialMeta, input)
      val reduced = applyBatchCandidate(initialScopes, candidateJobs, input).jobs.get(JobB)
      not(allowed) and reduced.state == state and reduced.record == candidate.record
        and reduced.payload == candidate.payload and reduced.dueRoute == candidate.dueRoute
        and reduced.fairRoute == candidate.fairRoute and reduced.dueAt == candidate.dueAt
        and reduced.block == candidate.block
    })
    val corruptJobs = update(initialJobs, JobB, base.with("record", Corrupt))
    val quarantinedJobs = update(initialJobs, JobB, base.with("record", UnknownVersion))
    val expiredMeta = initialMeta.with("cycle", MAX_BATCH_DELAY_TICKS + 1)
    all {
      assert(invalidStatesReject),
      assert(not(batchCandidateAllowedIn(initialScopes, corruptJobs,
        initialOrders, initialMeta, input))),
      assert(not(batchCandidateAllowedIn(initialScopes, quarantinedJobs,
        initialOrders, initialMeta, input))),
      assert(not(batchCandidateAllowedIn(initialScopes, initialJobs,
        initialOrders, expiredMeta, input))),
    }
  }

}
