/// Typed MBT boundary for schedule, occurrence, wake, and Drive behavior.
/// Commands carry cron/misfire policy, exact materialization read authority,
/// wake revision/token, policy changes, and pulse budgets. Each command freezes
/// the authoritative prestate decision before the schedule action mutates state.
module job_schedule_wake_mbt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_schedule_wake.* from "./job-schedule-wake"

  type Command = ScheduleAdvance({ amount: int })
    | ScheduleEvaluate({ mode: Misfire, catchUpLimit: int, now: int, nextDue: int })
    | ScheduleSelectMaterialize({ occurrence: Occurrence, reader: Node, revision: int })
    | ScheduleMaterialize({ occurrence: Occurrence, contender: Node, revision: int })
    | ScheduleComplete({ occurrence: Occurrence, job: JobId, revision: int })
    | ScheduleWake({ revision: int, token: int, lose: bool, duplicate: bool })
    | SchedulePolicy({ enabled: bool, paused: bool, overlap: bool })
    | ScheduleCron({ form: CronForm })
    | SchedulePulse({ active: int, actions: int })
    | ScheduleDrive({ node: Node, active: int, actions: int })

  /// Immutable result of one exact command.  Drive carries the authoritative
  /// kernel branch, work, stop reason and progress rather than a post-state
  /// guess based on cursor or pending work.
  type LastTransition = { command: Command, class: ResultClass,
    outcome: ScheduleOutcome, occurrence: Occurrence, drive: DriveResult,
    branch: DriveKernelBranch, work: DriveWork, stop: DriveStopReason,
    progressBefore: int, progressAfter: int, emissionCount: int,
    skipped: int, nextDue: int, post: ScheduleState }
  type CommandResult = ScheduleApplied(LastTransition) | ScheduleRejected(LastTransition)
    | ScheduleConflictResult(LastTransition) | ScheduleFuture(LastTransition)
    | ScheduleNoWork(LastTransition)

  var lastCommand: Command
  var lastCommandResult: CommandResult
  var lastTransition: LastTransition

  type StateProjection = { state: ScheduleState, command: Command,
    transition: LastTransition, result: CommandResult }
  def mbtProjection(current: ScheduleState): StateProjection = {
    state: current, command: lastCommand, transition: lastTransition,
    result: lastCommandResult,
  }

  pure def commandOccurrence(command) = match command {
    | ScheduleSelectMaterialize(input) => input.occurrence
    | ScheduleMaterialize(input) => input.occurrence
    | ScheduleComplete(input) => input.occurrence
    | _ => Occ1
  }
  pure def driveResultFor(branch) = if (branch == KernelRecurrence) DriveRecurrence
    else if (branch == KernelMaterialize) DriveMaterialized
    else if (branch == KernelClaim) DriveClaimed
    else if (branch == KernelTerminal) DriveTerminal
    else if (branch == KernelConflict) DriveConflict
    else if (branch == KernelPaused) DrivePaused
    else if (branch == KernelBudget) DriveBudgetExhausted
    else if (branch == KernelFuture) DriveFuture else DriveNoWork
  def transitionFor(command) = {
    val driveEffect = match command {
      | ScheduleDrive(input) => currentDriveEffect(input.node)
      | _ => { branch: KernelNoWork, work: DriveNoImmediateWork,
          class: RejectedClass, stop: StopNoWork, accepted: false,
          progressBefore: state.progressCounter, progressAfter: state.progressCounter,
          nextActions: state.pulseActions, nextActive: state.activePulses }
    }
    val evaluation = match command {
      | ScheduleEvaluate(input) => evaluateMisfireState(state, input.mode, input.catchUpLimit)
      | ScheduleDrive(_) => evaluateMisfireState(state, state.misfire, state.catchUpLimit)
      | _ => state
    }
    val materializeAllowed = match command {
      | ScheduleMaterialize(input) => materializeKernel(state.materializePending,
          input.revision, state.materializeRevision, state.revision,
          input.contender, state.materializeReader,
          state.materializeOtherReader, state.enabled, state.paused,
          state.emitted.get(input.occurrence), state.materialized.get(input.occurrence),
          state.overlap, state.jobState.get(state.occurrenceJob.get(input.occurrence)) == Leased).allowed
      | _ => true
    }
    val completionAllowed = match command {
      | ScheduleComplete(input) => state.materialized.get(input.occurrence)
          and state.occurrenceJob.get(input.occurrence) == input.job
          and state.jobRevision.get(input.job) == input.revision
      | _ => true
    }
    val wakeAllowed = match command {
      | ScheduleWake(input) => if (input.lose) true else if (input.duplicate)
          state.wakePending and durableWork
        else input.revision == state.revision and input.token == state.wakeToken
          and wakeRequirement
      | _ => true
    }
    val cronAllowed = match command {
      | ScheduleCron(input) => input.form == PortableFiveField | _ => true
    }
    val pulseAllowed = match command {
      | SchedulePulse(_) => state.activePulses < MAX_ACTIVE_PULSES | _ => true
    }
    val post = match command {
      | ScheduleAdvance(input) => state.with("now", state.now + input.amount)
          .with("lastOutcome", TimeAdvanced)
      | ScheduleEvaluate(input) => evaluateMisfireState(state, input.mode, input.catchUpLimit)
      | ScheduleSelectMaterialize(input) => state.with("materializePending", true)
          .with("materializeOccurrence", input.occurrence).with("materializeRevision", state.revision)
          .with("materializeReader", input.reader)
          .with("materializeOtherReader", if (input.reader == NodeA) NodeB else NodeA)
          .with("materializeCommitted", false).with("lastOutcome", MaterializeSelected)
      | ScheduleMaterialize(input) => applyMaterialization(state, input.occurrence,
          input.contender, input.revision)
      | ScheduleComplete(input) => applyScheduleCompletion(state, input.occurrence, input.revision)
      | ScheduleWake(input) => if (input.lose) state.with("wakePending", false)
          .with("lastOutcome", WakeLost)
        else if (input.duplicate) state.with("wakePending", wakeAllowed)
          .with("lastOutcome", if (wakeAllowed) WakeDuplicate else WakeStale)
        else if (wakeAllowed) state.with("wakePending", true)
          .with("wakeAt", if (durableWork) state.now else state.nextDue)
          .with("wakeRevision", state.revision).with("wakeToken", state.wakeToken + 1)
          .with("lastOutcome", WakeSet)
        else state.with("lastOutcome", WakeStale)
      | SchedulePolicy(input) => state.with("enabled", input.enabled)
          .with("paused", input.paused).with("overlap", input.overlap)
          .with("lastOutcome", PauseChanged)
      | ScheduleCron(input) => state.with("cronAccepted", cronAllowed)
          .with("lastOutcome", if (cronAllowed) CronAccepted else CronRejected)
      | SchedulePulse(_) => state.with("activePulses",
          if (pulseAllowed) state.activePulses + 1 else 0)
          .with("pulseActions", if (pulseAllowed) 0 else state.pulseActions)
          .with("pulseExited", not(pulseAllowed))
          .with("lastOutcome", if (pulseAllowed) PulseStarted else PulseExited)
      | ScheduleDrive(input) => applyDriveTransition(state, input.node)
    }
    val outcome = match command {
      | ScheduleAdvance(_) => TimeAdvanced
      | ScheduleEvaluate(_) => post.lastOutcome
      | ScheduleSelectMaterialize(_) => MaterializeSelected
      | ScheduleMaterialize(_) => if (materializeAllowed) Materialized else MaterializeConflict
      | ScheduleComplete(_) => if (completionAllowed) ScheduleCompleted else CompletionConflict
      | ScheduleWake(input) => if (input.lose) WakeLost
          else if (input.duplicate) (if (wakeAllowed) WakeDuplicate else WakeStale)
          else if (wakeAllowed) WakeSet else WakeStale
      | SchedulePolicy(_) => PauseChanged
      | ScheduleCron(_) => if (cronAllowed) CronAccepted else CronRejected
      | SchedulePulse(_) => if (pulseAllowed) PulseStarted else PulseExited
      | ScheduleDrive(_) => if (driveEffect.branch == KernelMaterialize) Materialized
          else if (driveEffect.branch == KernelTerminal) ScheduleCompleted
          else if (driveEffect.branch == KernelClaim) DriveClaimCommitted
          else if (driveEffect.branch == KernelConflict) MaterializeConflict
          else if (driveEffect.branch == KernelRecurrence) post.lastOutcome
          else PulseExited
    }
    val class = match command {
      | ScheduleDrive(_) => driveEffect.class
      | _ => if (not(materializeAllowed) or not(completionAllowed)) ConflictClass
          else if (not(wakeAllowed) or not(cronAllowed) or not(pulseAllowed)) RejectedClass
          else AppliedClass
    }
    val drive = driveResultFor(driveEffect.branch)
    val emissionCount = match command {
      | ScheduleEvaluate(_) => evaluation.emissionCount
      | ScheduleDrive(_) => if (driveEffect.branch == KernelRecurrence) evaluation.emissionCount
          else if (driveEffect.branch == KernelTerminal) state.emissionCount - 1
          else state.emissionCount
      | ScheduleComplete(_) => if (completionAllowed) state.emissionCount - 1 else state.emissionCount
      | _ => state.emissionCount
    }
    { command: command, class: class, outcome: post.lastOutcome,
      occurrence: commandOccurrence(command), drive: drive, branch: driveEffect.branch,
      work: driveEffect.work, stop: driveEffect.stop,
      progressBefore: driveEffect.progressBefore, progressAfter: driveEffect.progressAfter,
      emissionCount: emissionCount,
      skipped: if (match command { | ScheduleEvaluate(_) => true
          | ScheduleDrive(_) => driveEffect.branch == KernelRecurrence | _ => false })
        evaluation.skippedRemainder else state.skippedRemainder,
      nextDue: post.nextDue, post: post }
  }
  pure def resultFor(transition) = match transition.command {
      | ScheduleDrive(_) => if (transition.branch == KernelFuture) ScheduleFuture(transition)
        else if (transition.branch == KernelNoWork) ScheduleNoWork(transition)
        else if (transition.class == ConflictClass) ScheduleConflictResult(transition)
        else ScheduleApplied(transition)
      | _ => if (transition.class == ConflictClass) ScheduleConflictResult(transition)
        else if (transition.class == RejectedClass) ScheduleRejected(transition)
        else ScheduleApplied(transition)
    }

  pure def scheduleClassFor(transition) = match transition.command {
    | ScheduleDrive(_) => if (transition.branch == KernelConflict) ConflictClass
        else if (transition.branch == KernelPaused or transition.branch == KernelBudget
          or transition.branch == KernelFuture or transition.branch == KernelNoWork)
          RejectedClass else AppliedClass
    | _ => if (transition.outcome == MaterializeConflict
          or transition.outcome == CompletionConflict) ConflictClass
        else if (transition.outcome == WakeStale or transition.outcome == CronRejected
          or transition.outcome == PulseExited) RejectedClass else AppliedClass
  }

  pure val initialCommand = ScheduleAdvance({ amount: 0 })
  pure val initialTransition = { command: initialCommand, class: AppliedClass,
    outcome: Initialised, occurrence: Occ1, drive: DriveNoWork,
    branch: KernelNoWork, work: DriveNoImmediateWork, stop: StopNoWork,
    progressBefore: 0, progressAfter: 0, emissionCount: 0, skipped: 0,
    nextDue: OCCURRENCE_STEP, post: initialState }

  action mbtInit = all { init, lastCommand' = initialCommand,
    lastTransition' = initialTransition,
    lastCommandResult' = ScheduleApplied(initialTransition) }
  action dispatch(command: Command): bool = match command {
    | ScheduleAdvance(input) => all { input.amount >= 0, AdvanceInput(input.amount),
        lastCommand' = command }
    | ScheduleEvaluate(input) => all { input.catchUpLimit > 0,
        input.catchUpLimit <= MAX_OCCURRENCES,
        EvaluateMisfireInput(input.mode, input.catchUpLimit, input.now, input.nextDue),
        lastCommand' = command }
    | ScheduleSelectMaterialize(input) => all { OCCURRENCES.contains(input.occurrence),
        input.revision >= 0,
        SelectMaterializeInput(input.occurrence, input.reader, input.revision),
        lastCommand' = command }
    | ScheduleMaterialize(input) => all { OCCURRENCES.contains(input.occurrence),
        MaterializeInput(input.occurrence, input.contender, input.revision),
        lastCommand' = command }
    | ScheduleComplete(input) => all { JOBS.contains(input.job),
        CompleteInput(input.occurrence, input.job, input.revision), lastCommand' = command }
    | ScheduleWake(input) => all {
        if (input.lose) LoseWake else if (input.duplicate) DuplicateWake
          else SetWakeInput(input.revision, input.token),
        lastCommand' = command }
    | SchedulePolicy(input) => all {
        SetPolicyInput(input.enabled, input.paused, input.overlap), lastCommand' = command }
    | ScheduleCron(input) => all { ValidateCronInput(input.form), lastCommand' = command }
    | SchedulePulse(input) => all { input.active >= 0,
        StartPulseInput(input.active, input.actions), lastCommand' = command }
    | ScheduleDrive(input) => all { input.active >= 0, input.actions >= 0,
        DriveInput(input.node, input.active, input.actions), lastCommand' = command }
  }

  action mbtStep(command: Command): bool = {
    val transition = transitionFor(command)
    all { dispatch(command), lastCommandResult' = resultFor(transition),
      lastTransition' = transition }
  }
  action mbtObserve = all {
    state' = state, lastCommand' = lastCommand,
    lastTransition' = lastTransition,
    lastCommandResult' = resultFor(lastTransition),
  }

  action mbtDispatchNondet = any {
    mbtStep(ScheduleAdvance({ amount: OCCURRENCE_STEP })),
    mbtStep(ScheduleEvaluate({ mode: state.misfire, catchUpLimit: state.catchUpLimit,
      now: state.now, nextDue: state.nextDue })),
    mbtStep(ScheduleSelectMaterialize({ occurrence: state.materializeOccurrence,
      reader: state.materializeReader, revision: state.revision })),
    mbtStep(ScheduleMaterialize({ occurrence: state.materializeOccurrence,
      contender: state.materializeReader, revision: state.materializeRevision })),
    mbtStep(ScheduleComplete({ occurrence: state.materializeOccurrence,
      job: state.occurrenceJob.get(state.materializeOccurrence),
      revision: state.jobRevision.get(state.occurrenceJob.get(state.materializeOccurrence)) })),
    mbtStep(ScheduleWake({ revision: state.wakeRevision, token: state.wakeToken,
      lose: false, duplicate: false })),
    mbtStep(SchedulePolicy({ enabled: state.enabled, paused: state.paused,
      overlap: state.overlap })),
    mbtStep(ScheduleCron({ form: PortableFiveField })),
    mbtStep(SchedulePulse({ active: state.activePulses, actions: state.pulseActions })),
    mbtStep(ScheduleDrive({ node: NodeA, active: state.activePulses,
      actions: state.pulseActions })),
  }
  action mbtNondetStep = any { mbtDispatchNondet, mbtObserve }

  action fixedPortableCron = mbtStep(ScheduleCron({ form: PortableFiveField }))
  action fixedPortableCronTrace = fixedPortableCron
  val fixed_portable_cron_witness = state == initialState.with("cronAccepted", true)
      .with("lastOutcome", CronAccepted)
    and lastCommandResult == ScheduleApplied({ command:
      ScheduleCron({ form: PortableFiveField }), class: AppliedClass,
      outcome: CronAccepted, occurrence: Occ1, drive: DriveNoWork,
      branch: KernelNoWork, work: DriveNoImmediateWork, stop: StopNoWork,
      progressBefore: 0, progressAfter: 0, emissionCount: 0, skipped: 0,
      nextDue: OCCURRENCE_STEP, post: initialState.with("cronAccepted", true)
        .with("lastOutcome", CronAccepted) })

  val inv_mbt_identity = lastTransition.command == lastCommand
    and lastTransition.occurrence == commandOccurrence(lastCommand)
  val inv_mbt_post = lastTransition.post == state
  val inv_mbt_outcome = lastTransition.outcome == state.lastOutcome
  val inv_mbt_result = lastCommandResult == resultFor(lastTransition)
  val inv_mbt_class = lastTransition.class == scheduleClassFor(lastTransition)
  val inv_mbt_semantics = inv_mbt_outcome and inv_mbt_result and inv_mbt_class
  val mbtInv = inv and inv_mbt_identity and inv_mbt_post and inv_mbt_semantics
}
