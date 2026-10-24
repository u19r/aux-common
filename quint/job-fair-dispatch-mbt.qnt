/// Typed MBT boundary for authoritative hierarchical fair dispatch.
/// Commands include the real candidate, registered cost, ordering-group
/// authority, primary/secondary budgets, batch membership, and item result.
/// The adapter freezes each prestate decision with its command, dispatches the
/// imported action atomically, and projects the resulting family state verbatim.
module job_fair_dispatch_mbt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_fair_dispatch.* from "./job-fair-dispatch"

  type CandidateInput = { job: JobId, scope: Scope, primary: Scope,
    priority: Priority, cost: int, ordering: OrderingGroup, order: int,
    orderHead: int, orderInFlight: bool, permits: int, rate: int, inFlight: int,
    primaryPermits: int, primaryRate: int, primaryInFlight: int,
    payloadBytes: int, handlerKind: HandlerKind, schemaVersion: int,
    batchKey: BatchKey, authConfig: AuthConfigId, effectMode: EffectModeModel,
    retryPolicy: RetryPolicyModel, timeoutPolicy: TimeoutPolicyModel,
    enqueuedAt: int, batchDeadline: int, mode: VolumeMode }
  type Command = FairSeed({ job: JobId, priority: Priority })
    | FairBatchCandidate(CandidateInput)
    | FairSelect({ candidate: CandidateInput, now: int })
    | FairRelease({ candidate: CandidateInput, result: BatchResult })
    | FairTick({ cycle: int }) | FairBlock({ job: JobId, reason: BlockReason })
    | FairHolEscape({ blocked: JobId, candidate: CandidateInput })
    | FairRefill({ scope: Scope, primary: Scope })
    | FairLowVolume(CandidateInput)
    | FairBatchStart({ first: CandidateInput, second: CandidateInput, capacity: int })
    | FairBatchItem({ job: JobId, result: BatchResult })
    | FairScratch({ clear: bool, capacity: int })
    | FairService({ candidate: CandidateInput, refillRate: bool })
    | FairResetWindow({ critical: int, default: int, bulk: int })

  /// One command-correlated result with all adapter-visible outputs frozen at
  /// dispatch. Release, refill and batch results never consult later globals.
  type LastTransition = { command: Command, class: ResultClass, outcome: FairOutcome,
    job: JobId, scope: Scope, priority: Priority, registeredCost: int,
    reason: BlockReason, handlerKind: HandlerKind, schemaVersion: int,
    batchKey: BatchKey, authConfig: AuthConfigId, effectMode: EffectModeModel,
    retryPolicy: RetryPolicyModel, timeoutPolicy: TimeoutPolicyModel,
    payloadBytes: int, enqueuedAt: int, batchDeadline: int,
    permits: int, rate: int, inFlight: int, primaryPermits: int,
    primaryRate: int, primaryInFlight: int, scratchCapacity: int,
    batchActive: bool, members: Set[JobId], results: JobId -> BatchResult }
  type CommandResult = FairApplied({ transition: LastTransition,
      batchResults: JobId -> BatchResult })
    | FairRejected(LastTransition)
    | FairBlockedResult({ transition: LastTransition, reason: BlockReason })
    | FairBatchResult({ transition: LastTransition, members: Set[JobId],
      results: JobId -> BatchResult })

  var lastCommand: Command
  var lastCommandResult: CommandResult
  var lastTransition: LastTransition

  type StateProjection = { scopes: Scope -> ScopeState, jobs: JobId -> FairJob,
    orders: OrderingGroup -> OrderState, meta: Meta, command: Command,
    transition: LastTransition, result: CommandResult }
  def mbtProjection(currentScopes: Scope -> ScopeState,
      currentJobs: JobId -> FairJob, currentOrders: OrderingGroup -> OrderState,
      currentMeta: Meta): StateProjection = {
    scopes: currentScopes, jobs: currentJobs, orders: currentOrders, meta: currentMeta,
    command: lastCommand, transition: lastTransition, result: lastCommandResult,
  }

  def commandJob(command) = match command {
    | FairSeed(input) => input.job | FairSelect(input) => input.candidate.job
    | FairBatchCandidate(input) => input.job
    | FairRelease(input) => input.candidate.job | FairTick(_) => JobA
    | FairBlock(input) => input.job | FairHolEscape(input) => input.candidate.job
    | FairRefill(_) => JobA
    | FairLowVolume(input) => input.job | FairBatchStart(input) => input.second.job
    | FairBatchItem(input) => input.job | FairScratch(_) => JobA
    | FairService(input) => input.candidate.job | FairResetWindow(_) => JobA
  }
  def transitionFor(command) = {
    val job = commandJob(command)
    val queued = jobs.get(job)
    val seedAllowed = match command {
      | FairSeed(input) => seedReadyAllowed(input.job, input.priority)
      | _ => true
    }
    val candidateAllowed = match command {
      | FairBatchCandidate(input) => batchCandidateAllowed(input)
      | _ => true
    }
    val selected = match command {
      | FairSelect(input) => selectionAllowedAt(job, input.now) | _ => true
    }
    val tickAllowed = match command {
      | FairTick(input) => input.cycle == meta.cycle and not(bulkDeadline)
          and SCOPES.forall(scope => not(readyMap(scopes).get(scope))
            or scopes.get(scope).quietDwell < FAIR_QUIET_ERROR)
      | _ => true
    }
    val releaseAllowedForCommand = match command {
      | FairRelease(input) => releaseAllowed(input.candidate.job, input.result)
      | _ => true
    }
    val holAllowed = match command {
      | FairHolEscape(input) => holEscapeAllowed(input.blocked, input.candidate.job)
      | _ => true
    }
    val refillAllowedForCommand = match command {
      | FairRefill(input) => refillAllowed(input.scope)
      | _ => true
    }
    val lowAllowed = match command {
      | FairLowVolume(input) => lowVolumeAttemptAllowed(input.job)
      | _ => true
    }
    val batchAllowed = match command {
      | FairBatchStart(input) => batchStartAllowed(input.first.job, input.second.job)
      | _ => true
    }
    val itemAllowed = match command {
      | FairBatchItem(input) => meta.batchActive and meta.batchMembers.contains(input.job)
          and meta.batchResults.get(input.job) == ItemMissing and not(bulkDeadline)
      | _ => true
    }
    val scratchAllowed = match command {
      | FairScratch(input) => if (input.clear) scratchClearAllowed(input.capacity)
        else not(meta.batchActive) and input.capacity == meta.scratchCapacity
          and meta.scratchCapacity > 0
      | _ => true
    }
    val allowed = seedAllowed and candidateAllowed and selected and releaseAllowedForCommand and tickAllowed
      and holAllowed and refillAllowedForCommand and lowAllowed and batchAllowed
      and itemAllowed and scratchAllowed
    val outcome = match command {
      | FairSeed(_) => if (allowed) HeadReady else SelectionRejected
      | FairBatchCandidate(_) => if (allowed) HeadReady else SelectionRejected
      | FairSelect(_) => if (allowed and bulkDeadline) BulkForced
          else if (allowed) SelectionServed else SelectionRejected
      | FairRelease(_) => if (allowed) ClaimReleased else SelectionRejected
      | FairTick(_) => if (allowed) QuietTick else SelectionRejected
      | FairBlock(input) => if (input.reason == RateLimitedHead) RateBlocked
          else if (input.reason == CapacityBlockedHead) CapacityBlocked else HeadBlocked
      | FairHolEscape(_) => if (allowed) HolEscaped else SelectionRejected
      | FairRefill(_) => if (allowed) ScopeRefilled else SelectionRejected
      | FairLowVolume(_) => if (allowed) SelectionServed else LowVolumeRejected
      | FairBatchStart(_) => if (allowed) BatchPartial else SelectionRejected
      | FairBatchItem(_) => if (allowed) BatchPartial else SelectionRejected
      | FairScratch(input) => if (allowed)
          (if (input.clear) ScratchCleared else ScratchShrunk) else SelectionRejected
      | FairService(_) => if (serviceForcesBulk(job)) BulkForced else SelectionServed
      | FairResetWindow(_) => HeadReady
    }
    val members = match command {
      | FairBatchStart(input) => if (allowed) Set(input.first.job, input.second.job) else Set()
      | FairBatchItem(_) => meta.batchMembers | _ => Set()
    }
    val itemResult = match command {
      | FairBatchItem(input) => if (input.result == ItemDuplicate or input.result == ItemMissing)
          ItemRetry else input.result | _ => ItemMissing
    }
    val results = match command {
      | FairBatchStart(input) => if (allowed)
          Map(input.first.job -> ItemMissing, input.second.job -> ItemMissing)
          else Map()
      | FairBatchItem(input) => if (allowed)
          update(meta.batchResults, input.job, itemResult) else Map()
      | _ => Map()
    }
    val reason = match command { | FairBlock(input) => input.reason | _ => queued.block }
    val output = match command {
      | FairBatchCandidate(input) => {
          val scope = scopes.get(input.scope)
          val primary = scopes.get(scopePrimary(input.scope))
          val order = orders.get(input.ordering)
          input.with("cost", registeredCost(input.scope))
            .with("orderHead", order.head).with("orderInFlight", order.inFlight)
            .with("permits", scope.permits).with("rate", scope.rate)
            .with("inFlight", scope.inFlight).with("primaryPermits", primary.permits)
            .with("primaryRate", primary.rate).with("primaryInFlight", primary.inFlight)
        }
      | _ => candidateFor(job)
    }
    { command: command, class: if (allowed) AppliedClass else RejectedClass, outcome: outcome,
      job: job, scope: output.scope, priority: output.priority,
      registeredCost: output.cost, reason: reason, handlerKind: output.handlerKind,
      schemaVersion: output.schemaVersion, batchKey: output.batchKey,
      authConfig: output.authConfig, effectMode: output.effectMode,
      retryPolicy: output.retryPolicy, timeoutPolicy: output.timeoutPolicy,
      payloadBytes: output.payloadBytes, enqueuedAt: output.enqueuedAt,
      batchDeadline: output.batchDeadline, permits: output.permits,
      rate: output.rate, inFlight: output.inFlight,
      primaryPermits: output.primaryPermits, primaryRate: output.primaryRate,
      primaryInFlight: output.primaryInFlight, scratchCapacity: meta.scratchCapacity,
      batchActive: match command { | FairBatchStart(_) => allowed
        | FairScratch(input) => if (input.clear and allowed) false else meta.batchActive
        | _ => meta.batchActive }, members: members, results: results }
  }
  pure def resultFor(transition) = if (transition.outcome == SelectionRejected
      or transition.outcome == LowVolumeRejected)
    FairRejected(transition)
  else if (transition.outcome == HeadBlocked or transition.outcome == RateBlocked
      or transition.outcome == CapacityBlocked)
    FairBlockedResult({ transition: transition,
      reason: transition.reason })
  else if (transition.outcome == BatchPartial)
    FairBatchResult({ transition: transition, members: transition.members,
      results: transition.results })
  else FairApplied({ transition: transition, batchResults: transition.results })

  pure def fairClassFor(outcome) = if (outcome == SelectionRejected
      or outcome == LowVolumeRejected) RejectedClass else AppliedClass

  def transitionOutputMatches = match lastCommand {
    | FairBatchStart(_) => if (lastTransition.class == AppliedClass)
        lastTransition.members == meta.batchMembers
          and lastTransition.results == meta.batchResults
      else lastTransition.results.keys().size() == 0
    | FairBatchItem(input) => lastTransition.members == meta.batchMembers
        and (if (lastTransition.class == AppliedClass)
          lastTransition.results.keys().contains(input.job)
            and lastTransition.results == meta.batchResults
        else lastTransition.results.keys().size() == 0)
    | FairScratch(input) => not(input.clear) or (
        lastTransition.members.size() == 0 and lastTransition.results.keys().size() == 0
          and not(meta.batchActive) and meta.batchMembers.size() == 0
          and meta.batchResults.keys().size() == 0)
    | _ => lastTransition.results.keys().size() == 0
  }

  pure val initialCommand = FairTick({ cycle: 0 })
  pure val initialTransition = { command: initialCommand, class: AppliedClass,
    outcome: Initialised, job: JobA, scope: ScopeA, priority: Critical,
    registeredCost: 2, reason: Unblocked, handlerKind: HandlerA,
    schemaVersion: 1, batchKey: BatchA, authConfig: AuthConfigA,
    effectMode: IdempotentEffect, retryPolicy: NetworkRetry,
    timeoutPolicy: ShortTimeout, payloadBytes: 1, enqueuedAt: 0,
    batchDeadline: MAX_BATCH_DELAY_TICKS, permits: MAX_CONCURRENCY_PER_SCOPE,
    rate: MAX_RATE_PER_SCOPE, inFlight: 0,
    primaryPermits: MAX_CONCURRENCY_PER_SCOPE, primaryRate: MAX_RATE_PER_SCOPE,
    primaryInFlight: 0, scratchCapacity: MAX_BATCH_ITEMS,
    batchActive: false, members: Set(), results: Map() }

  action mbtInit = all {
    init,
    lastCommand' = initialCommand,
    lastTransition' = initialTransition,
    lastCommandResult' = FairApplied({ transition: initialTransition, batchResults: Map() }),
  }
  action secondaryBatchMbtInit = all {
    compatibleSecondaryBatchInit,
    lastCommand' = initialCommand,
    lastTransition' = initialTransition,
    lastCommandResult' = FairApplied({ transition: initialTransition, batchResults: Map() }),
  }
  def candidateMatches(input: CandidateInput): bool = input == candidateFor(input.job)
  action dispatch(command: Command): bool = match command {
    | FairSeed(input) => all { JOBS.contains(input.job), SeedReadyInput(input.job, input.priority),
        lastCommand' = command }
    | FairBatchCandidate(input) => all { JOBS.contains(input.job),
        ConfigureBatchCandidateInput(input), lastCommand' = command }
    | FairSelect(input) => all { JOBS.contains(input.candidate.job),
        candidateMatches(input.candidate), SelectInputAt(input.candidate.job, input.now),
        lastCommand' = command }
    | FairRelease(input) => all { JOBS.contains(input.candidate.job),
        candidateMatches(input.candidate),
        ReleaseInput(input.candidate.job, input.result), lastCommand' = command }
    | FairTick(input) => all { input.cycle >= 0, TickInput(input.cycle), lastCommand' = command }
    | FairBlock(input) => all { JOBS.contains(input.job),
        BlockHeadInput(input.job, input.reason), lastCommand' = command }
    | FairHolEscape(input) => all { JOBS.contains(input.blocked),
        candidateMatches(input.candidate),
        HolEscapeInput(input.blocked, input.candidate.job), lastCommand' = command }
    | FairRefill(input) => all { SCOPES.contains(input.scope),
        input.primary == scopePrimary(input.scope), RefillInput(input.scope), lastCommand' = command }
    | FairLowVolume(input) => all { JOBS.contains(input.job), candidateMatches(input),
        LowVolumeAttemptInput(input.job), lastCommand' = command }
    | FairBatchStart(input) => all { candidateMatches(input.first),
        candidateMatches(input.second), input.capacity <= MAX_BATCH_ITEMS,
        StartBatchInput(input.first.job, input.second.job, input.capacity), lastCommand' = command }
    | FairBatchItem(input) => all { JOBS.contains(input.job),
        SubmitPartialBatchInput(input.job, input.result), lastCommand' = command }
    | FairScratch(input) => all { input.capacity >= 0,
        if (input.clear) ClearScratchInput(input.capacity) else ShrinkScratchInput(input.capacity),
        lastCommand' = command }
    | FairService(input) => all { JOBS.contains(input.candidate.job),
        candidateMatches(input.candidate),
        ServiceUnitInput(input.candidate.job, input.refillRate), lastCommand' = command }
    | FairResetWindow(input) => all { input.critical >= 0,
        ResetPriorityWindowInput(input.critical, input.default, input.bulk),
        lastCommand' = command }
  }

  action mbtStep(command: Command): bool = {
    val transition = transitionFor(command)
    all { dispatch(command), lastCommandResult' = resultFor(transition),
      lastTransition' = transition }
  }
  action mbtObserve = all {
    scopes' = scopes, jobs' = jobs, orders' = orders, meta' = meta,
    lastCommand' = lastCommand, lastTransition' = lastTransition,
    lastCommandResult' = resultFor(lastTransition),
  }

  def candidateFor(job) = {
    val queued = jobs.get(job)
    val scope = scopes.get(queued.scope)
    val primary = scopes.get(scope.primary)
    val orderState = orders.get(queued.ordering)
    { job: job, scope: queued.scope, primary: scope.primary, priority: queued.priority,
      cost: queued.cost, ordering: queued.ordering, order: queued.order,
      orderHead: orderState.head, orderInFlight: orderState.inFlight,
      permits: scope.permits, rate: scope.rate, inFlight: scope.inFlight,
      primaryPermits: primary.permits, primaryRate: primary.rate,
      primaryInFlight: primary.inFlight, payloadBytes: queued.payloadBytes,
      handlerKind: queued.handlerKind, schemaVersion: queued.schemaVersion,
      batchKey: queued.batchKey, authConfig: queued.authConfig,
      effectMode: queued.effectMode, retryPolicy: queued.retryPolicy,
      timeoutPolicy: queued.timeoutPolicy, enqueuedAt: queued.enqueuedAt,
      batchDeadline: queued.batchDeadline, mode: scope.mode }
  }

  action mbtDispatchNondet = any {
    mbtStep(FairSeed({ job: JobC, priority: Bulk })),
    mbtStep(FairBatchCandidate(candidateFor(JobA))),
    mbtStep(FairSelect({ candidate: candidateFor(meta.selectedJob), now: 0 })),
    mbtStep(FairRelease({ candidate: candidateFor(meta.selectedJob), result: ItemRetry })),
    mbtStep(FairTick({ cycle: meta.cycle })),
    mbtStep(FairBlock({ job: JobA, reason: RateLimitedHead })),
    mbtStep(FairHolEscape({ blocked: JobA, candidate: candidateFor(JobB) })),
    mbtStep(FairRefill({ scope: meta.selectedScope,
      primary: scopes.get(meta.selectedScope).primary })),
    mbtStep(FairLowVolume(candidateFor(JobC))),
    mbtStep(FairBatchStart({ first: candidateFor(JobB), second: candidateFor(JobC),
      capacity: meta.scratchCapacity })),
    mbtStep(FairBatchItem({ job: meta.selectedJob, result: ItemSuccess })),
    mbtStep(FairScratch({ clear: true, capacity: meta.scratchCapacity })),
    mbtStep(FairService({ candidate: candidateFor(meta.selectedJob), refillRate: true })),
    mbtStep(FairResetWindow({ critical: meta.criticalWindow,
      default: meta.defaultWindow, bulk: meta.bulkWindow })),
  }
  action mbtNondetStep = any { mbtDispatchNondet, mbtObserve }

  action fixedBulkSeed = mbtStep(FairSeed({ job: JobC, priority: Bulk }))
  action fixedBulkSeedTrace = fixedBulkSeed
  pure val fixedBulkOrder = initialScopes.get(ScopeA1).order + 1
  pure val fixedBulkJob = initialJobs.get(JobC).with("state", Scheduled)
    .with("payload", true).with("dueRoute", true).with("fairRoute", true)
    .with("priority", Bulk).with("order", fixedBulkOrder)
    .with("orderHead", fixedBulkOrder).with("block", Unblocked)
  pure val fixedBulkScope = initialScopes.get(ScopeA1).with("ready", true)
    .with("priority", Bulk).with("candidates", Set(JobC)).with("head", fixedBulkOrder)
    .with("order", fixedBulkOrder).with("block", Unblocked).with("quietDwell", 0)
  val fixed_bulk_seed_witness = jobs == update(initialJobs, JobC, fixedBulkJob)
    and scopes == update(initialScopes, ScopeA1, fixedBulkScope)
    and orders == initialOrders and meta == initialMeta.with("lastOutcome", HeadReady)
    and lastTransition.command == FairSeed({ job: JobC, priority: Bulk })
    and lastTransition.class == AppliedClass and lastTransition.outcome == HeadReady
    and lastTransition.job == JobC and lastTransition.scope == ScopeA1
    and lastTransition.priority == Bulk and lastTransition.registeredCost == 1
    and lastCommandResult == resultFor(lastTransition)

  def primaryBatchCandidate(job, ordering) = candidateFor(job)
    .with("scope", ScopeA).with("primary", ScopeA).with("priority", Critical)
    .with("cost", 2).with("ordering", ordering).with("order", 1)
    .with("orderHead", 1).with("orderInFlight", false)
    .with("permits", MAX_CONCURRENCY_PER_SCOPE).with("rate", MAX_RATE_PER_SCOPE)
    .with("inFlight", 0).with("primaryPermits", MAX_CONCURRENCY_PER_SCOPE)
    .with("primaryRate", MAX_RATE_PER_SCOPE).with("primaryInFlight", 0)
    .with("payloadBytes", 1).with("handlerKind", HandlerA).with("schemaVersion", 1)
    .with("batchKey", BatchA).with("authConfig", AuthConfigA)
    .with("effectMode", IdempotentEffect).with("retryPolicy", NetworkRetry)
    .with("timeoutPolicy", ShortTimeout).with("enqueuedAt", 0)
    .with("batchDeadline", MAX_BATCH_DELAY_TICKS).with("mode", ScopedVolume)

  def secondaryBatchCandidate(job, ordering) = primaryBatchCandidate(job, ordering)
    .with("scope", ScopeA2).with("primary", ScopeA).with("priority", Default)
    .with("cost", 1)

  def configuredFor(job, scope, priority, auth) = jobs.get(job).scope == scope
    and jobs.get(job).priority == priority and jobs.get(job).authConfig == auth

  action fixedPrimaryBatchTrace =
    if (not(configuredFor(JobA, ScopeA, Critical, AuthConfigA)))
      mbtStep(FairBatchCandidate(primaryBatchCandidate(JobA, OrderA)))
    else if (not(configuredFor(JobB, ScopeA, Critical, AuthConfigA)))
      mbtStep(FairBatchCandidate(primaryBatchCandidate(JobB, OrderB)))
    else if (not(meta.batchActive))
      mbtStep(FairBatchStart({ first: candidateFor(JobA), second: candidateFor(JobB),
        capacity: meta.scratchCapacity }))
    else if (meta.batchResults.get(JobA) == ItemMissing)
      mbtStep(FairBatchItem({ job: JobA, result: ItemSuccess }))
    else if (meta.batchResults.get(JobB) == ItemMissing)
      mbtStep(FairBatchItem({ job: JobB, result: ItemDeadLetter }))
    else mbtStep(FairScratch({ clear: true, capacity: meta.scratchCapacity }))

  val fixed_primary_batch_started_witness = meta.batchActive
    and meta.batchMembers == Set(JobA, JobB)
    and meta.batchResults == Map(JobA -> ItemMissing, JobB -> ItemMissing)
    and meta.batchPayloadBytes == 2 and meta.batchAuthConfig == AuthConfigA
    and meta.batchDeadline == MAX_BATCH_DELAY_TICKS
    and lastTransition.batchActive and lastTransition.scratchCapacity == MAX_BATCH_ITEMS
  val fixed_primary_batch_partial_witness = meta.batchActive
    and meta.batchResults.get(JobA) == ItemSuccess
    and meta.batchResults.get(JobB) == ItemMissing
    and lastTransition.members == Set(JobA, JobB)
    and lastTransition.results == meta.batchResults
  val fixed_primary_batch_resolved_witness = meta.batchActive
    and meta.batchResults == Map(JobA -> ItemSuccess, JobB -> ItemDeadLetter)
    and jobs.get(JobA).state == Absent and jobs.get(JobB).state == DeadLettered
    and not(orders.get(OrderA).inFlight) and not(orders.get(OrderB).inFlight)
  val fixed_primary_batch_cleared_witness = not(meta.batchActive)
    and meta.batchMembers.size() == 0 and meta.batchResults.keys().size() == 0
    and meta.scratchSize == 0 and meta.lastOutcome == ScratchCleared

  action fixedSecondaryBatchTrace =
    if (not(configuredFor(JobA, ScopeA2, Default, AuthConfigA)))
      mbtStep(FairBatchCandidate(secondaryBatchCandidate(JobA, OrderA)))
    else if (not(configuredFor(JobB, ScopeA2, Default, AuthConfigA)))
      mbtStep(FairBatchCandidate(secondaryBatchCandidate(JobB, OrderB)))
    else mbtStep(FairBatchStart({ first: candidateFor(JobA), second: candidateFor(JobB),
      capacity: meta.scratchCapacity }))
  val fixed_secondary_batch_started_witness = meta.batchActive
    and jobs.get(JobA).scope == ScopeA2 and jobs.get(JobB).scope == ScopeA2
    and scopes.get(ScopeA2).inFlight == 2 and scopes.get(ScopeA).inFlight == 2
    and scopes.get(ScopeA2).permits == 0 and scopes.get(ScopeA).permits == 0

  action fixedBatchRejectionTrace =
    if (not(configuredFor(JobA, ScopeA, Critical, AuthConfigA)))
      mbtStep(FairBatchCandidate(primaryBatchCandidate(JobA, OrderA)))
    else if (not(configuredFor(JobB, ScopeA, Critical, AuthConfigB)))
      mbtStep(FairBatchCandidate(primaryBatchCandidate(JobB, OrderB)
        .with("authConfig", AuthConfigB)))
    else mbtStep(FairBatchStart({ first: candidateFor(JobA), second: candidateFor(JobB),
      capacity: meta.scratchCapacity }))
  val fixed_batch_rejection_witness = not(meta.batchActive)
    and lastTransition.class == RejectedClass
    and lastTransition.outcome == SelectionRejected
    and lastCommandResult == FairRejected(lastTransition)

  action fixedLiveAuthorityCandidateTrace =
    if (jobs.get(JobA).state != Leased)
      mbtStep(FairSelect({ candidate: candidateFor(JobA), now: 0 }))
    else mbtStep(FairBatchCandidate(primaryBatchCandidate(JobB, OrderB)))
  val fixed_live_authority_candidate_rejected_witness = jobs.get(JobA).state == Leased
    and scopes.get(ScopeA).inFlight == 1
    and scopes.get(ScopeA).permits == MAX_CONCURRENCY_PER_SCOPE - 1
    and scopes.get(ScopeA).rate == MAX_RATE_PER_SCOPE - 1
    and orders.get(OrderA).inFlight and orders.get(OrderA).owner == JobA
    and jobs.get(JobB) == initialJobs.get(JobB)
    and lastTransition.class == RejectedClass
    and lastTransition.outcome == SelectionRejected
    and lastCommandResult == FairRejected(lastTransition)

  // This fixed replay exercises both sides of the finite retry clock. The
  // generated dispatcher keeps its fourteen action variants unchanged; this
  // witness supplies the explicit post-due observation that bounded
  // nondeterministic generation may not reach.
  action fixedRetryDueTrace =
    if (jobs.get(JobA).state == Scheduled)
      mbtStep(FairSelect({ candidate: candidateFor(JobA), now: 0 }))
    else if (jobs.get(JobA).state == Leased)
      mbtStep(FairRelease({ candidate: candidateFor(JobA), result: ItemRetry }))
    else mbtStep(FairSelect({ candidate: candidateFor(JobA), now: FAIR_RETRY_DUE_TICK }))
  val fixed_retry_not_due_witness = jobs.get(JobA).state == RetryWaiting
    and jobs.get(JobA).dueAt == FAIR_RETRY_NOT_DUE_TICK
    and not(selectionAllowedAt(JobA, 0))
    and lastTransition.outcome == ClaimReleased
  val fixed_retry_due_witness = jobs.get(JobA).state == Leased
    and lastTransition.command == FairSelect({ candidate: candidateFor(JobA), now: FAIR_RETRY_DUE_TICK })
    and lastTransition.outcome == SelectionServed

  run retry_timing_contract = {
    val waitingJobs = update(initialJobs, JobA,
      initialJobs.get(JobA).with("state", RetryWaiting)
        .with("dueAt", FAIR_RETRY_NOT_DUE_TICK)
        .with("dueRoute", true).with("fairRoute", true))
    all {
      assert(not(eligibleJobsInAt(waitingJobs, initialScopes, initialOrders, 0).contains(JobA))),
      assert(eligibleJobsInAt(waitingJobs, initialScopes, initialOrders,
        FAIR_RETRY_DUE_TICK).contains(JobA)),
    }
  }

  val mbtInv = inv and lastTransition.command == lastCommand
    and lastTransition.job == commandJob(lastCommand)
    and lastCommandResult == resultFor(lastTransition)
    and lastTransition.outcome == meta.lastOutcome
    and lastTransition.class == fairClassFor(lastTransition.outcome)
    and transitionOutputMatches
}
