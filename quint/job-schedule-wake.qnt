/// Trigger-neutral schedule and wake protocol.
///
/// A schedule occurrence has deterministic identity derived from its due
/// watermark.  Skip emits no occurrence, FireOnce emits exactly one, and
/// CatchUp emits each bounded missed occurrence with a distinct identity.
/// Materialization is a conditional two-node transaction over schedule
/// revision, occurrence identity, job state, and durable routes.  A failed
/// contender is a revision conflict, not a no-op boolean.
///
/// Wakes are advisory.  SetWake can observe durable pending work but cannot
/// fabricate a job; lost, duplicate, and stale wakes leave accepted durable
/// work intact.  Pause and overlap are explicit schedule policy.  The
/// watermark only advances through occurrence evaluation/completion, and a
/// drive returns a real result while consuming a bounded active-pulse budget.
module job_schedule_wake {
  import bg_jobs_types.* from "./bg-jobs-types"

  type ScheduleState = {
    enabled: bool,
    paused: bool,
    overlap: bool,
    misfire: Misfire,
    now: int,
    nextDue: int,
    watermark: int,
    revision: int,
    lastMaterializeNode: Node,
    emitted: Occurrence -> bool,
    emissionCount: int,
    lastBacklog: int,
    skippedRemainder: int,
    lastEvaluationNow: int,
    occurrenceIdentity: Occurrence -> int,
    previousIdentity: Occurrence -> int,
    occurrenceJob: Occurrence -> JobId,
    materialized: Occurrence -> bool,
    completed: Occurrence -> bool,
    jobState: JobId -> JobState,
    jobRevision: JobId -> int,
    jobGeneration: JobId -> int,
    jobFence: JobId -> int,
    jobToken: JobId -> int,
    jobLeaseUntil: JobId -> int,
    jobNode: JobId -> Node,
    jobDueRoute: JobId -> bool,
    jobFairRoute: JobId -> bool,
    jobLeaseRoute: JobId -> bool,
    jobWakeRoute: JobId -> bool,
    jobAttempts: JobId -> int,
    jobAttemptId: JobId -> int,
    jobExecutionId: JobId -> int,
    durableRoute: Occurrence -> bool,
    materializePending: bool,
    materializeOccurrence: Occurrence,
    materializeRevision: int,
    materializeReader: Node,
    materializeOtherReader: Node,
    materializeWinner: Node,
    materializeCommitted: bool,
    wakePending: bool,
    wakeRevision: int,
    wakeToken: int,
    wakeAt: int,
    catchUpLimit: int,
    activePulses: int,
    pulseActions: int,
    pulseExited: bool,
    cronAccepted: bool,
    fairReady: JobId -> bool,
    fairScope: JobId -> Scope,
    fairPriority: JobId -> Priority,
    fairCost: JobId -> int,
    fairWeight: JobId -> int,
    fairPermits: JobId -> int,
    fairRate: JobId -> int,
    fairInFlight: JobId -> int,
    fairServed: JobId -> int,
    fairOrdering: JobId -> OrderingGroup,
    fairOrder: JobId -> int,
    orderHead: OrderingGroup -> int,
    orderInFlight: OrderingGroup -> bool,
    orderOwner: OrderingGroup -> JobId,
    fairCritical: int,
    fairDefault: int,
    fairBulk: int,
    fairCycle: int,
    lastClaimNode: Node,
    lastDrive: DriveResult,
    lastDriveBranch: DriveKernelBranch,
    lastDriveWork: DriveWork,
    lastDriveStop: DriveStopReason,
    progressCounter: int,
    driveProgressBefore: int,
    driveProgressAfter: int,
    lastOutcome: ScheduleOutcome,
  }

  type DriveResult = DriveRecurrence | DriveMaterialized | DriveClaimed
    | DriveTerminal | DriveConflict | DrivePaused | DriveBudgetExhausted
    | DriveFuture | DriveNoWork
  type ScheduleOutcome = Initialised | Skipped | FireOnceEmitted | CatchUpEmitted
    | MaterializeSelected | Materialized | MaterializeConflict | ScheduleCompleted | CompletionConflict | WakeSet
    | WakeLost | WakeDuplicate | WakeStale | PauseChanged | ScheduleEnabledChanged
    | PulseStarted | PulseExited | DriveClaimCommitted
    | CronRejected | CronAccepted | TimeAdvanced | NotDue

  var state: ScheduleState

  pure def falseOccurrences = Map(Occ1 -> false, Occ2 -> false, Occ3 -> false)
  pure def zeroOccurrences = Map(Occ1 -> 0, Occ2 -> 0, Occ3 -> 0)
  pure def zeroJobValues = Map(JobA -> 0, JobB -> 0, JobC -> 0)
  pure def initialIdentity = Map(Occ1 -> 1, Occ2 -> 2, Occ3 -> 3)
  pure def initialJobs = Map(Occ1 -> JobA, Occ2 -> JobB, Occ3 -> JobC)
  pure def initialJobState = Map(JobA -> Absent, JobB -> Absent, JobC -> Absent)
  pure def initialJobRevision = Map(JobA -> 0, JobB -> 0, JobC -> 0)

  pure def initialState = {
    enabled: true,
    paused: false,
    overlap: false,
    misfire: FireOnce,
    now: 0,
    nextDue: OCCURRENCE_STEP,
    watermark: 0,
    revision: 0,
    lastMaterializeNode: NodeA,
    emitted: falseOccurrences,
    emissionCount: 0,
    lastBacklog: 0,
    skippedRemainder: 0,
    lastEvaluationNow: 0,
    occurrenceIdentity: zeroOccurrences,
    previousIdentity: zeroOccurrences,
    occurrenceJob: initialJobs,
    materialized: falseOccurrences,
    completed: falseOccurrences,
    jobState: initialJobState,
    jobRevision: initialJobRevision,
    jobGeneration: zeroJobValues,
    jobFence: zeroJobValues,
    jobToken: zeroJobValues,
    jobLeaseUntil: zeroJobValues,
    jobNode: Map(JobA -> NodeA, JobB -> NodeA, JobC -> NodeA),
    jobDueRoute: Map(JobA -> false, JobB -> false, JobC -> false),
    jobFairRoute: Map(JobA -> false, JobB -> false, JobC -> false),
    jobLeaseRoute: Map(JobA -> false, JobB -> false, JobC -> false),
    jobWakeRoute: Map(JobA -> false, JobB -> false, JobC -> false),
    jobAttempts: zeroJobValues,
    jobAttemptId: zeroJobValues,
    jobExecutionId: Map(JobA -> 1, JobB -> 2, JobC -> 3),
    durableRoute: falseOccurrences,
    materializePending: false,
    materializeOccurrence: Occ1,
    materializeRevision: 0,
    materializeReader: NodeA,
    materializeOtherReader: NodeB,
    materializeWinner: NodeA,
    materializeCommitted: false,
    wakePending: false,
    wakeRevision: 0,
    wakeToken: 0,
    wakeAt: OCCURRENCE_STEP,
    catchUpLimit: MAX_OCCURRENCES,
    activePulses: 0,
    pulseActions: 0,
    pulseExited: false,
    cronAccepted: true,
    fairReady: Map(JobA -> false, JobB -> false, JobC -> false),
    fairScope: Map(JobA -> ScopeA, JobB -> ScopeB, JobC -> ScopeA1),
    fairPriority: Map(JobA -> Critical, JobB -> Default, JobC -> Bulk),
    fairCost: Map(JobA -> 2, JobB -> 1, JobC -> 1),
    fairWeight: Map(JobA -> 1, JobB -> 1, JobC -> 1),
    fairPermits: Map(JobA -> MAX_CONCURRENCY_PER_SCOPE,
      JobB -> MAX_CONCURRENCY_PER_SCOPE, JobC -> MAX_CONCURRENCY_PER_SCOPE),
    fairRate: Map(JobA -> MAX_RATE_PER_SCOPE, JobB -> MAX_RATE_PER_SCOPE,
      JobC -> MAX_RATE_PER_SCOPE),
    fairInFlight: zeroJobValues,
    fairServed: zeroJobValues,
    fairOrdering: Map(JobA -> OrderA, JobB -> OrderB, JobC -> OrderB),
    fairOrder: Map(JobA -> 1, JobB -> 1, JobC -> 1),
    orderHead: Map(OrderA -> 1, OrderB -> 1, OrderC -> 1),
    orderInFlight: Map(OrderA -> false, OrderB -> false, OrderC -> false),
    orderOwner: Map(OrderA -> JobA, OrderB -> JobB, OrderC -> JobC),
    fairCritical: 0,
    fairDefault: 0,
    fairBulk: 0,
    fairCycle: 0,
    lastClaimNode: NodeA,
    lastDrive: DriveNoWork,
    lastDriveBranch: KernelNoWork,
    lastDriveWork: DriveNoImmediateWork,
    lastDriveStop: StopNoWork,
    progressCounter: 0,
    driveProgressBefore: 0,
    driveProgressAfter: 0,
    lastOutcome: Initialised,
  }

  def pendingOccurrences = OCCURRENCES.filter(occ => state.materialized.get(occ)
    and state.durableRoute.get(occ) and not(state.completed.get(occ)))
  def unmaterializedOccurrences = OCCURRENCES.filter(occ => state.emitted.get(occ)
    and not(state.materialized.get(occ)) and not(state.completed.get(occ)))
  def emittedOccurrences = OCCURRENCES.filter(occ => state.emitted.get(occ))
  def firstPendingOccurrence = if (pendingOccurrences.contains(Occ1)) Occ1
    else if (pendingOccurrences.contains(Occ2)) Occ2 else Occ3
  def firstUnmaterializedOccurrence = if (unmaterializedOccurrences.contains(Occ1)) Occ1
    else if (unmaterializedOccurrences.contains(Occ2)) Occ2 else Occ3
  def availableOccurrences = OCCURRENCES.filter(occ => occurrenceAvailable(
    state.emitted.get(occ), state.completed.get(occ), state.occurrenceIdentity.get(occ), state.nextDue))
  def firstAvailableOccurrence = if (availableOccurrences.contains(Occ1)) Occ1
    else if (availableOccurrences.contains(Occ2)) Occ2 else Occ3
  def secondAvailableOccurrence(first) = if (first != Occ1 and availableOccurrences.contains(Occ1)) Occ1
    else if (first != Occ2 and availableOccurrences.contains(Occ2)) Occ2 else Occ3
  def thirdAvailableOccurrence(first, second) = if (first != Occ1 and second != Occ1
      and availableOccurrences.contains(Occ1)) Occ1
    else if (first != Occ2 and second != Occ2 and availableOccurrences.contains(Occ2)) Occ2 else Occ3
  def activeEmissionCount(emittedState) = OCCURRENCES.filter(occ => emittedState.get(occ)).size()
  def durableWork = pendingOccurrences.size() > 0
    or emittedOccurrences.exists(occ => not(state.materialized.get(occ)) and not(state.completed.get(occ)))
  def wakeRequirement = durableWork or (state.enabled and not(state.paused) and state.nextDue >= state.now)

  val inv_occurrence_identity = OCCURRENCES.forall(occ =>
    not(state.emitted.get(occ)) or (
      state.occurrenceIdentity.get(occ) > 0 and JOBS.contains(state.occurrenceJob.get(occ))
        and (state.previousIdentity.get(occ) == 0
          or state.occurrenceIdentity.get(occ) > state.previousIdentity.get(occ))
    )
  )
  val inv_occurrence_distinct = OCCURRENCES.forall(first => OCCURRENCES.forall(second =>
    first == second or not(state.emitted.get(first)) or not(state.emitted.get(second))
      or state.occurrenceIdentity.get(first) != state.occurrenceIdentity.get(second)))
  val inv_occurrence_sets = state.emissionCount >= 0
    and state.emissionCount <= MAX_OCCURRENCES
    and emittedOccurrences.size() == state.emissionCount
    and state.catchUpLimit > 0 and state.catchUpLimit <= MAX_OCCURRENCES
    and state.lastBacklog >= 0 and state.skippedRemainder >= 0
    and (state.lastOutcome == Skipped implies state.emissionCount == 0
      and state.skippedRemainder == state.lastBacklog and state.nextDue > state.lastEvaluationNow)
    and (state.lastOutcome == FireOnceEmitted implies state.emissionCount == 1
      and state.skippedRemainder == state.lastBacklog - 1
      and state.nextDue > state.lastEvaluationNow)
    and (state.lastOutcome == CatchUpEmitted implies
      state.emissionCount == min(state.lastBacklog, state.catchUpLimit)
      and state.skippedRemainder == state.lastBacklog - state.emissionCount
      and state.nextDue > state.lastEvaluationNow)
  val inv_materialization = OCCURRENCES.forall(occ =>
    state.materialized.get(occ) implies state.emitted.get(occ) and state.durableRoute.get(occ)
      and state.jobState.get(state.occurrenceJob.get(occ)) != Absent
  )
  val inv_completion_clears_job = OCCURRENCES.forall(occ =>
    state.completed.get(occ) implies not(state.materialized.get(occ))
      and not(state.durableRoute.get(occ)) and state.jobState.get(state.occurrenceJob.get(occ)) == Absent
  )
  val inv_watermark = state.watermark >= 0 and state.nextDue >= state.watermark
    and state.revision >= 0 and state.now >= 0
  val inv_wake = state.wakeAt >= 0 and state.wakeToken >= 0
  val inv_revision = state.wakeRevision <= state.revision + 1
  val inv_materialize_read = state.materializeRevision >= 0 and state.materializeRevision <= state.revision
    and (not(state.materializePending) or state.emitted.get(state.materializeOccurrence))
  val inv_pulse = state.pulseActions >= 0 and state.pulseActions <= MAX_PULSE_ACTIONS
    and state.activePulses >= 0 and state.activePulses <= MAX_ACTIVE_PULSES
    and (state.pulseExited implies state.activePulses == 0)
  val inv_drive_progress = state.progressCounter >= 0
    and state.driveProgressAfter >= state.driveProgressBefore
    and (state.lastDrive == DriveRecurrence or state.lastDrive == DriveMaterialized
      or state.lastDrive == DriveClaimed or state.lastDrive == DriveTerminal
      implies state.driveProgressAfter > state.driveProgressBefore)
  val inv_claim_routes = JOBS.forall(job =>
    (state.jobState.get(job) == Leased) == state.jobLeaseRoute.get(job)
      and (state.jobState.get(job) == Leased implies
        state.jobRevision.get(job) > 0 and state.jobGeneration.get(job) > 0
          and state.jobFence.get(job) > 0 and state.jobToken.get(job) > 0
          and state.jobLeaseUntil.get(job) > 0
          and not(state.jobDueRoute.get(job)) and not(state.jobFairRoute.get(job))
          and not(state.jobWakeRoute.get(job))
          and state.orderInFlight.get(state.fairOrdering.get(job))
          and state.orderOwner.get(state.fairOrdering.get(job)) == job))
  val inv_claim_ordering = ORDERING_GROUPS.forall(group =>
      JOBS.filter(job => state.jobState.get(job) == Leased
        and state.fairOrdering.get(job) == group).size() <= 1)
  val inv_claim_capacity = JOBS.forall(job => state.fairPermits.get(job) >= 0
      and state.fairRate.get(job) >= 0 and state.fairInFlight.get(job) >= 0
      and state.fairInFlight.get(job) <= MAX_CONCURRENCY_PER_SCOPE)
    and state.fairInFlight.get(JobC) <= state.fairInFlight.get(JobA)
    and state.fairServed.get(JobC) <= state.fairServed.get(JobA)
  val inv_fresh_claim = state.lastOutcome != DriveClaimCommitted or JOBS.exists(job =>
    state.jobState.get(job) == Leased and state.now < state.jobLeaseUntil.get(job))
  val inv_claim_authority = inv_claim_routes and inv_claim_ordering
    and inv_claim_capacity and inv_fresh_claim
  val inv = and {
    inv_occurrence_identity,
    inv_occurrence_distinct,
    inv_occurrence_sets,
    inv_materialization,
    inv_completion_clears_job,
    inv_watermark,
    inv_wake,
    inv_revision,
    inv_materialize_read,
    inv_pulse,
    inv_drive_progress,
    inv_claim_authority,
  }
  val inv_except_occurrence_identity = and {
    inv_occurrence_distinct, inv_occurrence_sets, inv_materialization,
    inv_completion_clears_job, inv_watermark, inv_wake, inv_revision,
    inv_materialize_read, inv_pulse, inv_drive_progress, inv_claim_authority,
  }

  // The family action and Drive share this one cursor transition. It consumes
  // the complete overdue backlog in one bounded decision, emits only the
  // configured policy prefix, records the skipped remainder, and leaves the
  // authoritative cursor at the first future intended time.
  pure def evaluateMisfireState(current, mode, catchUpLimit) = {
    val emittedNow = OCCURRENCES.filter(occ => current.emitted.get(occ))
    val availableNow = OCCURRENCES.filter(occ => occurrenceAvailable(
      current.emitted.get(occ), current.completed.get(occ),
      current.occurrenceIdentity.get(occ), current.nextDue))
    val effect = recurrenceStateKernel(current.now, current.nextDue,
      current.enabled, current.paused, false, emittedNow.size() == 0, mode,
      catchUpLimit, current.emitted, current.completed,
      current.occurrenceIdentity, current.previousIdentity, current.emissionCount,
      current.watermark, current.wakePending, availableNow)
    if (effect.applied) current.with("misfire", mode).with("catchUpLimit", catchUpLimit)
      .with("emitted", effect.emitted).with("completed", effect.completed)
      .with("occurrenceIdentity", effect.identity)
      .with("previousIdentity", effect.previousIdentity)
      .with("emissionCount", effect.emissionCount).with("lastBacklog", effect.backlog)
      .with("skippedRemainder", effect.skipped).with("lastEvaluationNow", current.now)
      .with("watermark", effect.watermark).with("nextDue", effect.nextDue)
      .with("revision", current.revision + 1).with("wakePending", effect.wakePending)
      .with("lastOutcome", if (mode == Skip) Skipped
        else if (mode == FireOnce) FireOnceEmitted else CatchUpEmitted)
    else current.with("misfire", mode).with("catchUpLimit", catchUpLimit)
      .with("lastBacklog", 0).with("skippedRemainder", 0)
      .with("lastEvaluationNow", current.now).with("lastOutcome", NotDue)
  }

  action init = state' = initialState

  /// A secondary scope is independently bounded and also consumes the permit,
  /// rate, capacity, and normalized service authority of its aggregate primary.
  pure def secondaryClaimState = initialState.with("activePulses", 1)
    .with("wakePending", true)
    .with("jobState", update(initialState.jobState, JobC, Scheduled))
    .with("jobDueRoute", update(initialState.jobDueRoute, JobC, true))
    .with("jobFairRoute", update(initialState.jobFairRoute, JobC, true))
    .with("jobWakeRoute", update(initialState.jobWakeRoute, JobC, true))
    .with("fairReady", update(initialState.fairReady, JobC, true))

  action secondaryClaimInit = state' = secondaryClaimState
  action primaryExhaustedClaimInit = state' = secondaryClaimState
    .with("fairPermits", update(secondaryClaimState.fairPermits, JobA, 0))
  action SecondaryClaimWitnessStep = DriveInput(NodeA, state.activePulses, state.pulseActions)

  action AdvanceInput(amount: int): bool = {
    all {
      state' = state.with("now", state.now + amount).with("lastOutcome", TimeAdvanced),
    }
  }


  action Advance = {
    nondet amount = Set(0, 1, OCCURRENCE_STEP, OCCURRENCE_STEP * 2, OCCURRENCE_STEP * 4).oneOf()
    AdvanceInput(amount)
  }

  action EvaluateMisfireInput(mode: Misfire, catchUpLimit: int,
      expectedNow: int, expectedNextDue: int): bool = {
    all {
      expectedNow == state.now and expectedNextDue == state.nextDue,
      state' = evaluateMisfireState(state, mode, catchUpLimit),
    }
  }


  action EvaluateMisfire = {
    nondet mode = Set(Skip, FireOnce, CatchUp).oneOf()
    nondet catchUpLimit = Set(1, 2, MAX_OCCURRENCES).oneOf()
    EvaluateMisfireInput(mode, catchUpLimit, state.now, state.nextDue)
  }

  action SelectMaterializeInput(occurrence: Occurrence, reader: Node,
      expectedRevision: int): bool = {
    all {
      emittedOccurrences.contains(occurrence) and not(state.materialized.get(occurrence)),
      expectedRevision == state.revision,
      state' = state.with("materializePending", true).with("materializeOccurrence", occurrence)
        .with("materializeRevision", state.revision).with("materializeReader", reader)
        .with("materializeOtherReader", if (reader == NodeA) NodeB else NodeA)
        .with("materializeCommitted", false)
        .with("lastOutcome", MaterializeSelected),
    }
  }


  action SelectMaterialize = {
    nondet occurrence = emittedOccurrences.filter(occ => not(state.materialized.get(occ))).oneOf()
    nondet reader = NODES.oneOf()
    SelectMaterializeInput(occurrence, reader, state.revision)
  }

  /// Complete family materialization reducer.  The action and cross-product
  /// parity checks both execute this reducer from their mapped prestates.
  pure def applyMaterialization(current, occurrence, contender, expectedRevision) = {
    val job = current.occurrenceJob.get(occurrence)
    val effect = materializeKernel(current.materializePending, expectedRevision,
      current.materializeRevision, current.revision, contender,
      current.materializeReader, current.materializeOtherReader,
      current.enabled, current.paused, current.emitted.get(occurrence),
      current.materialized.get(occurrence), current.overlap,
      current.jobState.get(job) == Leased)
    if (effect.allowed) current
      .with("materialized", update(current.materialized, occurrence, true))
      .with("durableRoute", update(current.durableRoute, occurrence, true))
      .with("jobState", update(current.jobState, job, Scheduled))
      .with("jobRevision", update(current.jobRevision, job,
        current.jobRevision.get(job) + 1)).with("revision", current.revision + 1)
      .with("jobDueRoute", update(current.jobDueRoute, job, true))
      .with("jobFairRoute", update(current.jobFairRoute, job, true))
      .with("jobLeaseRoute", update(current.jobLeaseRoute, job, false))
      .with("jobWakeRoute", update(current.jobWakeRoute, job, true))
      .with("fairReady", update(current.fairReady, job, true))
      .with("lastMaterializeNode", contender).with("materializeWinner", contender)
      .with("materializeCommitted", true).with("wakePending", true)
      .with("wakeRevision", current.revision + 1)
      .with("wakeToken", current.wakeToken + 1).with("materializePending", false)
      .with("lastOutcome", Materialized)
    else current.with("materializePending", false).with("lastOutcome", MaterializeConflict)
  }

  action MaterializeInput(occurrence: Occurrence, contender: Node,
      expectedRevision: int): bool = {
    val job = state.occurrenceJob.get(occurrence)
    val effect = materializeKernel(state.materializePending, expectedRevision,
      state.materializeRevision, state.revision, contender, state.materializeReader,
      state.materializeOtherReader, state.enabled, state.paused,
      state.emitted.get(occurrence), state.materialized.get(occurrence), state.overlap,
      state.jobState.get(job) == Leased)
    val allowed = effect.allowed
    val competing = effect.conflict
    all {
      allowed or competing,
      state' = applyMaterialization(state, occurrence, contender, expectedRevision),
    }
  }


  action Materialize = {
    nondet contender = NODES.oneOf()
    nondet expectedRevision = Set(state.materializeRevision, state.materializeRevision - 1).oneOf()
    MaterializeInput(state.materializeOccurrence, contender, expectedRevision)
  }

  pure def applyScheduleCompletion(current, occurrence, expectedJobRevision) = {
    val job = current.occurrenceJob.get(occurrence)
    val allowed = current.materialized.get(occurrence)
      and current.durableRoute.get(occurrence)
      and expectedJobRevision == current.jobRevision.get(job)
    val terminalEffect = terminalKernel(current.jobRevision.get(job), false, 0, false)
    val heldLease = current.jobState.get(job) == Leased
    val primaryJob = fairPrimaryJob(job)
    val group = current.fairOrdering.get(job)
    val emitted = update(current.emitted, occurrence, terminalEffect.emitted)
    val pending = OCCURRENCES.filter(other => current.materialized.get(other)
      and current.durableRoute.get(other) and not(current.completed.get(other)))
    val otherWork = pending.size() > 1 or OCCURRENCES.exists(other => other != occurrence
      and current.emitted.get(other) and not(current.materialized.get(other))
      and not(current.completed.get(other)))
    val childPermits = update(current.fairPermits, job, if (heldLease)
      min(MAX_CONCURRENCY_PER_SCOPE, current.fairPermits.get(job) + 1)
      else current.fairPermits.get(job))
    val releasedPermits = if (heldLease and primaryJob != job)
      update(childPermits, primaryJob, min(MAX_CONCURRENCY_PER_SCOPE,
        childPermits.get(primaryJob) + 1)) else childPermits
    val childRate = update(current.fairRate, job, if (heldLease)
      min(MAX_RATE_PER_SCOPE, current.fairRate.get(job) + 1)
      else current.fairRate.get(job))
    val releasedRate = if (heldLease and primaryJob != job)
      update(childRate, primaryJob, min(MAX_RATE_PER_SCOPE,
        childRate.get(primaryJob) + 1)) else childRate
    val childFlight = update(current.fairInFlight, job, if (heldLease)
      max(0, current.fairInFlight.get(job) - 1) else current.fairInFlight.get(job))
    val releasedFlight = if (heldLease and primaryJob != job)
      update(childFlight, primaryJob, max(0, childFlight.get(primaryJob) - 1))
      else childFlight
    if (allowed) current
      .with("jobState", update(current.jobState, job, Absent))
      .with("jobRevision", update(current.jobRevision, job, terminalEffect.nextRevision))
      .with("jobDueRoute", update(current.jobDueRoute, job, false))
      .with("jobFairRoute", update(current.jobFairRoute, job, false))
      .with("jobLeaseRoute", update(current.jobLeaseRoute, job, false))
      .with("jobWakeRoute", update(current.jobWakeRoute, job, false))
      .with("jobLeaseUntil", update(current.jobLeaseUntil, job, 0))
      .with("fairReady", update(current.fairReady, job, false))
      .with("fairPermits", releasedPermits)
      .with("fairRate", releasedRate)
      .with("fairInFlight", releasedFlight)
      .with("orderInFlight", update(current.orderInFlight, group,
        if (heldLease) false else current.orderInFlight.get(group)))
      .with("orderHead", update(current.orderHead, group, if (heldLease)
        current.orderHead.get(group) + 1 else current.orderHead.get(group)))
      .with("materialized", update(current.materialized, occurrence,
        terminalEffect.materialized))
      .with("completed", update(current.completed, occurrence, terminalEffect.completed))
      .with("emitted", emitted).with("materializePending", false)
      .with("emissionCount", activeEmissionCount(emitted))
      .with("durableRoute", update(current.durableRoute, occurrence,
        terminalEffect.dueRoute))
      .with("watermark", max(current.watermark, current.occurrenceIdentity.get(occurrence)))
      .with("revision", current.revision + 1).with("wakePending", otherWork)
      .with("lastOutcome", ScheduleCompleted)
    else current.with("lastOutcome", CompletionConflict)
  }

  action CompleteInput(occurrence: Occurrence, expectedJob: JobId,
      expectedJobRevision: int): bool = {
    val job = state.occurrenceJob.get(occurrence)
    val allowed = state.materialized.get(occurrence) and state.durableRoute.get(occurrence)
      and expectedJobRevision == state.jobRevision.get(job)
    val terminalEffect = terminalKernel(state.jobRevision.get(job), false, 0, false)
    val jobs = update(state.jobState, job, Absent)
    val revisions = update(state.jobRevision, job, terminalEffect.nextRevision)
    val materialized = update(state.materialized, occurrence, terminalEffect.materialized)
    val completed = update(state.completed, occurrence, terminalEffect.completed)
    val routes = update(state.durableRoute, occurrence, terminalEffect.dueRoute)
    val emitted = update(state.emitted, occurrence, terminalEffect.emitted)
    val otherWork = pendingOccurrences.size() > 1
      or emittedOccurrences.exists(other => other != occurrence
        and not(state.materialized.get(other)) and not(state.completed.get(other)))
    all {
      expectedJob == job,
      state' = applyScheduleCompletion(state, occurrence, expectedJobRevision),
    }
  }


  action Complete = {
    nondet occurrence = pendingOccurrences.oneOf()
    nondet expectedJobRevision = Set(state.jobRevision.get(state.occurrenceJob.get(occurrence)),
      state.jobRevision.get(state.occurrenceJob.get(occurrence)) - 1).oneOf()
    CompleteInput(occurrence, state.occurrenceJob.get(occurrence), expectedJobRevision)
  }

  action SetWakeInput(presentedRevision: int, presentedToken: int): bool = {
    val exact = presentedRevision == state.revision and presentedToken == state.wakeToken
    val allowed = exact and wakeRequirement
    val requestedAt = if (durableWork) state.now else state.nextDue
    all {
      state' = if (allowed) state.with("wakePending", true).with("wakeAt", requestedAt)
        .with("wakeRevision", state.revision).with("wakeToken", state.wakeToken + 1)
        .with("lastOutcome", WakeSet)
        else state.with("lastOutcome", WakeStale),
    }
  }


  action SetWake = {
    nondet presentedRevision = Set(state.revision, state.revision - 1).oneOf()
    nondet presentedToken = Set(state.wakeToken, 0).oneOf()
    SetWakeInput(presentedRevision, presentedToken)
  }

  action LoseWake = all {
    state' = state.with("wakePending", false).with("lastOutcome", WakeLost),
  }

  action DuplicateWake = {
    val allowed = state.wakePending and durableWork
    all {
      state' = state.with("wakePending", allowed).with("lastOutcome", if (allowed) WakeDuplicate else WakeStale),
    }
  }

  action StaleWake = all {
    state' = state.with("wakePending", state.wakePending).with("lastOutcome", WakeStale)
  }

  action SetPauseInput(paused: bool): bool = {
    all {
      state' = state.with("paused", paused).with("lastOutcome", PauseChanged),
    }
  }

  action SetPause = { nondet paused = bools.oneOf(); SetPauseInput(paused) }

  action SetEnabledInput(enabledState: bool): bool = {
    all {
      state' = state.with("enabled", enabledState).with("lastOutcome", ScheduleEnabledChanged),
    }
  }

  action SetEnabled = { nondet enabledState = bools.oneOf(); SetEnabledInput(enabledState) }

  action SetOverlapInput(overlap: bool): bool = {
    all {
      state' = state.with("overlap", overlap).with("lastOutcome", PauseChanged),
    }
  }

  action SetOverlap = { nondet overlap = bools.oneOf(); SetOverlapInput(overlap) }

  action SetPolicyInput(enabledState: bool, paused: bool, overlap: bool): bool =
    state' = state.with("enabled", enabledState).with("paused", paused)
      .with("overlap", overlap).with("lastOutcome", PauseChanged)

  action StartPulseInput(expectedActive: int, expectedActions: int): bool = {
    val allowed = state.activePulses < MAX_ACTIVE_PULSES
    all {
      expectedActive == state.activePulses and expectedActions == state.pulseActions,
      state' = state.with("activePulses", if (allowed) state.activePulses + 1 else 0)
        .with("pulseActions", if (allowed) 0 else state.pulseActions)
        .with("pulseExited", not(allowed))
        .with("lastOutcome", if (allowed) PulseStarted else PulseExited),
    }
  }

  action StartPulse = StartPulseInput(state.activePulses, state.pulseActions)

  /// The complete Drive decision for the current command.  Both the family
  /// transition and its MBT result consume this value, so Future, NoWork and
  /// Conflict cannot be reconstructed from a later schedule state.
  pure def driveDecision(current, node) = {
    val dueEvaluation = evaluateMisfireState(current, current.misfire, current.catchUpLimit)
    val dueProgress = dueEvaluation.revision > current.revision
    val pending = OCCURRENCES.filter(occ => current.materialized.get(occ)
      and current.durableRoute.get(occ) and not(current.completed.get(occ)))
    val unmaterialized = OCCURRENCES.filter(occ => current.emitted.get(occ)
      and not(current.materialized.get(occ)) and not(current.completed.get(occ)))
    val hasPending = pending.size() > 0
    val hasUnmaterialized = unmaterialized.size() > 0
    val occurrence = if (unmaterialized.contains(Occ1)) Occ1
      else if (unmaterialized.contains(Occ2)) Occ2 else Occ3
    val job = current.occurrenceJob.get(occurrence)
    val materializeEffect = materializeKernel(hasUnmaterialized, current.revision,
      current.revision, current.revision, node, node,
      if (node == NodeA) NodeB else NodeA, current.enabled, current.paused,
      current.emitted.get(occurrence), current.materialized.get(occurrence),
      current.overlap, current.jobState.get(job) == Leased)
    val conflictWork = hasUnmaterialized and not(materializeEffect.allowed)
    val futureWork = not(dueProgress) and not(hasPending) and not(hasUnmaterialized)
      and current.nextDue > current.now
    val claimWork = scheduleClaimEligible(current).size() > 0
    driveEffectKernel(current.activePulses, current.paused, current.pulseActions,
      current.progressCounter, dueProgress, materializeEffect.allowed,
      claimWork,
      hasPending, conflictWork, futureWork)
  }

  pure def scheduleClaimCandidate(current, job) = {
    val group = current.fairOrdering.get(job)
    current.jobState.get(job) == Scheduled and current.jobDueRoute.get(job)
      and current.jobFairRoute.get(job) and current.fairReady.get(job)
      and current.jobAttempts.get(job) < MAX_ATTEMPTS
      and not(current.orderInFlight.get(group))
      and current.fairOrder.get(job) == current.orderHead.get(group)
  }

  pure def scheduleClaimNormalized(current, job) = {
    val primaryJob = fairPrimaryJob(job)
    val otherPrimary = if (primaryJob == JobA) JobB else JobA
    val otherReady = JOBS.exists(candidate => fairPrimaryJob(candidate) == otherPrimary
      and scheduleClaimCandidate(current, candidate))
    normalizedAdmissionAllowed(current.fairServed.get(primaryJob),
      current.fairWeight.get(primaryJob), current.fairCost.get(job),
      current.fairServed.get(otherPrimary), current.fairWeight.get(otherPrimary),
      otherReady)
  }

  pure def scheduleClaimPrestate(current, job) = {
    val primaryJob = fairPrimaryJob(job)
    { jobState: current.jobState.get(job), dueRoute: current.jobDueRoute.get(job),
      fairRoute: current.jobFairRoute.get(job), childPermits: current.fairPermits.get(job),
      primaryPermits: current.fairPermits.get(primaryJob), childRate: current.fairRate.get(job),
      primaryRate: current.fairRate.get(primaryJob), childInFlight: current.fairInFlight.get(job),
      primaryInFlight: current.fairInFlight.get(primaryJob), childServed: 0,
      childServedCost: current.fairServed.get(job),
      primaryServedCost: current.fairServed.get(primaryJob),
      orderHead: current.orderHead.get(current.fairOrdering.get(job)),
      orderInFlight: current.orderInFlight.get(current.fairOrdering.get(job)),
      orderOwner: current.orderOwner.get(current.fairOrdering.get(job)),
      critical: current.fairCritical, default: current.fairDefault, bulk: current.fairBulk,
      cycle: current.fairCycle,
      serviceUnits: current.fairCritical + current.fairDefault + current.fairBulk,
      jobServiceUnits: current.fairServed.get(job) }
  }

  pure def scheduleClaimEffect(current, job) = {
    val scope = current.fairScope.get(job)
    val primaryJob = fairPrimaryJob(job)
    fairSelectedServiceKernel(scheduleClaimCandidate(current, job),
      job, scope, current.fairScope.get(primaryJob), current.fairPriority.get(job),
      current.fairCost.get(job), false, true, scheduleClaimNormalized(current, job),
      false, scheduleClaimPrestate(current, job))
  }

  pure def scheduleClaimEligible(current) =
    JOBS.filter(job => scheduleClaimEffect(current, job).allowed)

  pure def applyScheduleClaim(current, job, node) = {
    val primaryJob = fairPrimaryJob(job)
    val effect = scheduleClaimEffect(current, job)
    val authority = claimAuthorityKernel(current.jobRevision.get(job),
      current.jobGeneration.get(job), current.jobFence.get(job),
      current.jobToken.get(job), current.jobAttempts.get(job),
      current.jobAttemptId.get(job), current.now)
    val group = current.fairOrdering.get(job)
    if (effect.allowed) current
      .with("jobState", update(current.jobState, job, Leased))
      .with("jobRevision", update(current.jobRevision, job, authority.nextRevision))
      .with("jobGeneration", update(current.jobGeneration, job, authority.nextGeneration))
      .with("jobFence", update(current.jobFence, job, authority.nextFence))
      .with("jobToken", update(current.jobToken, job, authority.nextToken))
      .with("jobLeaseUntil", update(current.jobLeaseUntil, job, authority.nextLeaseUntil))
      .with("jobNode", update(current.jobNode, job, node))
      .with("jobAttempts", update(current.jobAttempts, job,
        authority.nextAttempts))
      .with("jobAttemptId", update(current.jobAttemptId, job,
        authority.nextAttemptId))
      .with("jobDueRoute", update(current.jobDueRoute, job, effect.state.dueRoute))
      .with("jobFairRoute", update(current.jobFairRoute, job, effect.state.fairRoute))
      .with("jobLeaseRoute", update(current.jobLeaseRoute, job, true))
      .with("jobWakeRoute", update(current.jobWakeRoute, job, false))
      .with("fairReady", update(current.fairReady, job, false))
      .with("fairPermits", update(update(current.fairPermits, job,
        effect.state.childPermits), primaryJob, effect.state.primaryPermits))
      .with("fairRate", update(update(current.fairRate, job,
        effect.state.childRate), primaryJob, effect.state.primaryRate))
      .with("fairInFlight", update(update(current.fairInFlight, job,
        effect.state.childInFlight), primaryJob, effect.state.primaryInFlight))
      .with("fairServed", update(update(current.fairServed, job,
        effect.state.childServedCost), primaryJob, effect.state.primaryServedCost))
      .with("orderHead", update(current.orderHead, group, effect.state.orderHead))
      .with("orderInFlight", update(current.orderInFlight, group, true))
      .with("orderOwner", update(current.orderOwner, group, job))
      .with("fairCritical", effect.state.critical).with("fairDefault", effect.state.default)
      .with("fairBulk", effect.state.bulk).with("fairCycle", effect.state.cycle)
      .with("lastClaimNode", node)
      .with("lastOutcome", DriveClaimCommitted)
    else current
  }

  def currentDriveEffect(node: Node): DriveKernelEffect = driveDecision(state, node)

  /// Complete schedule Drive reducer. The real action and the cross-family
  /// parity proof both apply this reducer, including every non-progress branch.
  pure def applyDriveTransition(current, node) = {
    val dueEvaluation = evaluateMisfireState(current, current.misfire, current.catchUpLimit)
    val pending = OCCURRENCES.filter(occ => current.materialized.get(occ)
      and current.durableRoute.get(occ) and not(current.completed.get(occ)))
    val unmaterialized = OCCURRENCES.filter(occ => current.emitted.get(occ)
      and not(current.materialized.get(occ)) and not(current.completed.get(occ)))
    val hasPending = pending.size() > 0
    val hasUnmaterialized = unmaterialized.size() > 0
    val occurrence = if (unmaterialized.contains(Occ1)) Occ1
      else if (unmaterialized.contains(Occ2)) Occ2 else Occ3
    val canMaterialize = hasUnmaterialized
    val job = current.occurrenceJob.get(occurrence)
    val materialized = update(current.materialized, occurrence, true)
    val routes = update(current.durableRoute, occurrence, true)
    val jobs = update(current.jobState, job, Scheduled)
    val revisions = update(current.jobRevision, job, current.jobRevision.get(job) + 1)
    val materializeEffect = materializeKernel(canMaterialize, current.revision,
      current.revision, current.revision, node, node,
      if (node == NodeA) NodeB else NodeA, current.enabled, current.paused,
      current.emitted.get(occurrence), current.materialized.get(occurrence),
      current.overlap, current.jobState.get(job) == Leased)
    val driveSelected = current.with("materializePending", canMaterialize)
      .with("materializeOccurrence", occurrence).with("materializeRevision", current.revision)
      .with("materializeReader", node)
      .with("materializeOtherReader", if (node == NodeA) NodeB else NodeA)
    val materializedState = applyMaterialization(driveSelected, occurrence, node,
      current.revision)
    val pendingOccurrence = if (pending.contains(Occ1)) Occ1
      else if (pending.contains(Occ2)) Occ2 else Occ3
    val pendingJob = current.occurrenceJob.get(pendingOccurrence)
    val completedJobs = update(current.jobState, pendingJob, Absent)
    val terminalEffect = terminalKernel(current.jobRevision.get(pendingJob), false, 0, false)
    val completedRevisions = update(current.jobRevision, pendingJob, terminalEffect.nextRevision)
    val completedMaterialized = update(current.materialized, pendingOccurrence,
      terminalEffect.materialized)
    val completedOccurrences = update(current.completed, pendingOccurrence,
      terminalEffect.completed)
    val completedRoutes = update(current.durableRoute, pendingOccurrence,
      terminalEffect.dueRoute)
    val completedEmitted = update(current.emitted, pendingOccurrence,
      terminalEffect.emitted)
    val terminalState = applyScheduleCompletion(current, pendingOccurrence,
      current.jobRevision.get(pendingJob))
    val claimable = scheduleClaimEligible(current)
    val claimJob = if (claimable.contains(JobA)) JobA
      else if (claimable.contains(JobB)) JobB else JobC
    val claimed = applyScheduleClaim(current, claimJob, node)
    val driveEffect = driveDecision(current, node)
    val branch = driveEffect.branch
    val active = if (branch == KernelRecurrence)
      dueEvaluation.with("pulseActions", driveEffect.nextActions)
        .with("progressCounter", driveEffect.progressAfter)
        .with("driveProgressBefore", driveEffect.progressBefore)
        .with("driveProgressAfter", driveEffect.progressAfter)
        .with("lastDrive", DriveRecurrence)
    else if (branch == KernelTerminal) terminalState.with("pulseActions", driveEffect.nextActions)
      .with("progressCounter", driveEffect.progressAfter)
      .with("driveProgressBefore", driveEffect.progressBefore)
      .with("driveProgressAfter", driveEffect.progressAfter)
      .with("lastDrive", DriveTerminal).with("lastOutcome", ScheduleCompleted)
    else if (branch == KernelMaterialize) materializedState
      .with("pulseActions", driveEffect.nextActions)
      .with("progressCounter", driveEffect.progressAfter)
      .with("driveProgressBefore", driveEffect.progressBefore)
      .with("driveProgressAfter", driveEffect.progressAfter)
      .with("lastDrive", DriveMaterialized).with("lastOutcome", Materialized)
    else if (branch == KernelClaim) claimed.with("pulseActions", driveEffect.nextActions)
      .with("progressCounter", driveEffect.progressAfter)
      .with("driveProgressBefore", driveEffect.progressBefore)
      .with("driveProgressAfter", driveEffect.progressAfter)
      .with("lastDrive", DriveClaimed).with("lastOutcome", DriveClaimCommitted)
    else if (branch == KernelPaused) current.with("activePulses", 0).with("pulseExited", true)
      .with("driveProgressBefore", current.progressCounter).with("driveProgressAfter", current.progressCounter)
      .with("lastDrive", DrivePaused).with("lastOutcome", PulseExited)
    else if (branch == KernelBudget) current.with("pulseExited", true)
      .with("activePulses", 0).with("driveProgressBefore", current.progressCounter)
      .with("driveProgressAfter", current.progressCounter)
      .with("lastDrive", DriveBudgetExhausted).with("lastOutcome", PulseExited)
    else if (branch == KernelConflict) current.with("activePulses", driveEffect.nextActive)
      .with("pulseExited", true).with("driveProgressBefore", driveEffect.progressBefore)
      .with("driveProgressAfter", driveEffect.progressAfter)
      .with("lastDrive", DriveConflict).with("lastOutcome", MaterializeConflict)
    else if (branch == KernelFuture) current.with("activePulses", driveEffect.nextActive)
      .with("pulseExited", true).with("driveProgressBefore", driveEffect.progressBefore)
      .with("driveProgressAfter", driveEffect.progressAfter)
      .with("lastDrive", DriveFuture).with("lastOutcome", PulseExited)
    else current.with("activePulses", driveEffect.nextActive).with("pulseExited", true)
      .with("driveProgressBefore", current.progressCounter).with("driveProgressAfter", current.progressCounter)
      .with("lastDrive", DriveNoWork).with("lastOutcome", PulseExited)
    active.with("lastDriveBranch", driveEffect.branch)
      .with("lastDriveWork", driveEffect.work).with("lastDriveStop", driveEffect.stop)
  }

  action DriveInput(node: Node, expectedActive: int, expectedActions: int): bool = {
    all {
      expectedActive == state.activePulses and expectedActions == state.pulseActions,
      state' = applyDriveTransition(state, node),
    }
  }


  action Drive = { nondet node = NODES.oneOf(); DriveInput(node, state.activePulses, state.pulseActions) }

  action ExitPulse = all {
    state' = state.with("activePulses", 0).with("pulseExited", true).with("lastOutcome", PulseExited)
  }

  action ValidateCronInput(form: CronForm): bool = {
    val accepted = form == PortableFiveField
    all {
      state' = state.with("cronAccepted", accepted).with("lastOutcome", if (accepted) CronAccepted else CronRejected),
    }
  }


  action ValidateCron = {
    nondet form = Set(PortableFiveField, SecondsField, YearField, AliasForm, TimezoneForm, ProviderExtension).oneOf()
    ValidateCronInput(form)
  }

  action step = any {
    Advance, EvaluateMisfire, SelectMaterialize, Materialize, Complete, SetWake, LoseWake, DuplicateWake,
    StaleWake, SetPause, SetEnabled, SetOverlap, StartPulse, Drive, ExitPulse, ValidateCron,
  }

  val deterministic_occurrence_witness = state.lastOutcome == FireOnceEmitted or state.lastOutcome == CatchUpEmitted
  val skip_witness = state.lastOutcome == Skipped
  val fire_once_witness = state.lastOutcome == FireOnceEmitted
  val catch_up_witness = state.lastOutcome == CatchUpEmitted
  val lost_wake_witness = state.lastOutcome == WakeLost
  val duplicate_wake_witness = state.lastOutcome == WakeDuplicate
  val stale_wake_witness = state.lastOutcome == WakeStale
  val pause_witness = state.lastOutcome == PauseChanged
  val enabled_witness = state.lastOutcome == ScheduleEnabledChanged
  val active_pulse_witness = state.lastOutcome == PulseStarted
  val pulse_exit_witness = state.lastOutcome == PulseExited
  val cron_rejection_witness = state.lastOutcome == CronRejected
  val cron_acceptance_witness = state.lastOutcome == CronAccepted
  val long_downtime_fire_once_witness = state.lastOutcome == FireOnceEmitted
    and state.lastBacklog >= 4 and state.emissionCount == 1
    and state.skippedRemainder == state.lastBacklog - 1 and state.nextDue > state.now
  val long_downtime_skip_witness = state.lastOutcome == Skipped
    and state.lastBacklog >= 4 and state.emissionCount == 0
    and state.skippedRemainder == state.lastBacklog and state.nextDue > state.now
  val long_downtime_catch_up_witness = state.lastOutcome == CatchUpEmitted
    and state.lastBacklog >= 4 and state.emissionCount == state.catchUpLimit
    and state.skippedRemainder == state.lastBacklog - state.emissionCount
    and state.nextDue > state.now
  val drive_authoritative_progress_witness = (state.lastDrive == DriveRecurrence
      or state.lastDrive == DriveMaterialized or state.lastDrive == DriveTerminal)
    and state.driveProgressAfter > state.driveProgressBefore
  val drive_terminal_path_witness = OCCURRENCES.exists(occ => state.completed.get(occ))
    and state.progressCounter >= 3
  val secondary_scope_claim_witness = state.lastDrive == DriveClaimed
    and state.jobState.get(JobC) == Leased and state.jobRevision.get(JobC) == 1
    and state.jobGeneration.get(JobC) == 1 and state.jobFence.get(JobC) == 1
    and state.jobToken.get(JobC) == 3 and state.jobLeaseUntil.get(JobC) == 3
    and not(state.jobDueRoute.get(JobC)) and not(state.jobFairRoute.get(JobC))
    and state.jobLeaseRoute.get(JobC) and not(state.jobWakeRoute.get(JobC))
    and state.jobAttempts.get(JobC) == 1 and state.jobAttemptId.get(JobC) == 1
    and state.fairPermits.get(JobC) == MAX_CONCURRENCY_PER_SCOPE - 1
    and state.fairPermits.get(JobA) == MAX_CONCURRENCY_PER_SCOPE - 1
    and state.fairRate.get(JobC) == MAX_RATE_PER_SCOPE - 1
    and state.fairRate.get(JobA) == MAX_RATE_PER_SCOPE - 1
    and state.fairInFlight.get(JobC) == 1 and state.fairInFlight.get(JobA) == 1
    and state.fairServed.get(JobC) == 1 and state.fairServed.get(JobA) == 1
    and state.orderInFlight.get(OrderB) and state.orderOwner.get(OrderB) == JobC
  val primary_exhaustion_rejects_secondary_witness = state.lastDrive == DriveFuture
    and state.jobState.get(JobC) == Scheduled and state.jobRevision.get(JobC) == 0
    and state.jobGeneration.get(JobC) == 0 and state.jobFence.get(JobC) == 0
    and state.jobToken.get(JobC) == 0 and state.jobAttempts.get(JobC) == 0
    and state.jobDueRoute.get(JobC) and state.jobFairRoute.get(JobC)
    and not(state.jobLeaseRoute.get(JobC)) and state.jobWakeRoute.get(JobC)
    and state.fairPermits.get(JobC) == MAX_CONCURRENCY_PER_SCOPE
    and state.fairPermits.get(JobA) == 0 and state.fairInFlight.get(JobC) == 0
    and state.fairInFlight.get(JobA) == 0 and not(state.orderInFlight.get(OrderB))

  run long_downtime_cursor_contracts = {
    val overdue = initialState.with("now", OCCURRENCE_STEP * 4)
    val skipped = evaluateMisfireState(overdue, Skip, 2)
    val fire = evaluateMisfireState(overdue, FireOnce, 2)
    val caught = evaluateMisfireState(overdue, CatchUp, 2)
    val skippedAgain = evaluateMisfireState(skipped, Skip, 2)
    val fireAgain = evaluateMisfireState(fire, FireOnce, 2)
    val caughtAgain = evaluateMisfireState(caught, CatchUp, 2)
    all {
      assert(skipped.nextDue > skipped.now and skipped.emissionCount == 0
        and skipped.skippedRemainder == 4),
      assert(fire.nextDue > fire.now and fire.emissionCount == 1
        and fire.skippedRemainder == 3
        and fire.occurrenceIdentity.get(Occ1) == OCCURRENCE_STEP * 4),
      assert(caught.nextDue > caught.now and caught.emissionCount == 2
        and caught.skippedRemainder == 2
        and Set(caught.occurrenceIdentity.get(Occ1), caught.occurrenceIdentity.get(Occ2))
          == Set(OCCURRENCE_STEP, OCCURRENCE_STEP * 2)),
      assert(skippedAgain == skipped.with("lastBacklog", 0).with("skippedRemainder", 0)
        .with("lastEvaluationNow", skipped.now).with("lastOutcome", NotDue)),
      assert(fireAgain == fire.with("lastBacklog", 0).with("skippedRemainder", 0)
        .with("lastEvaluationNow", fire.now).with("lastOutcome", NotDue)),
      assert(caughtAgain == caught.with("lastBacklog", 0).with("skippedRemainder", 0)
        .with("lastEvaluationNow", caught.now).with("lastOutcome", NotDue)),
    }
  }

  run wake_cannot_fabricate_work = all {
    assert(initialState.wakePending == false),
    assert(initialState.durableRoute.get(Occ1) == false),
  }

}
