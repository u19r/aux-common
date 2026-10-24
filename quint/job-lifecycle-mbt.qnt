/// Typed model-based-test boundary for the authoritative lifecycle machine.
///
/// Each command carries the authority or policy input a Rust driver must send.
/// `mbtStep` snapshots the exact command result from the immutable prestate and
/// dispatches the imported authoritative action atomically. Observation only
/// serializes that LastTransition; mutable post-state is never a result oracle.
module job_lifecycle_mbt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_lifecycle.* from "./job-lifecycle"

  type AuthorityInput = { job: JobId, node: Node, revision: int, generation: int,
    fence: int, token: int, leaseUntil: int, operation: OperationId }
  type CancelPhase = CancelScheduled | RequestLeased | CommitLeased
  type Command = LifecycleEnqueue({ job: JobId, dueAt: int, operation: OperationId,
      withDedupe: bool, fingerprint: int })
    | LifecycleSelectClaim({ job: JobId, reader: Node, revision: int })
    | LifecycleClaim({ job: JobId, contender: Node, revision: int })
    | LifecycleRenew(AuthorityInput)
    | LifecycleCheckpoint({ authority: AuthorityInput, bytes: int })
    | LifecycleHandle({ authority: AuthorityInput, handler: HandlerResult })
    | LifecycleComplete(AuthorityInput)
    | LifecycleExpose({ job: JobId, operation: OperationId, revision: int, generation: int })
    | LifecycleCancel({ authority: AuthorityInput, phase: CancelPhase })
    | LifecycleAdvance({ amount: int }) | LifecycleExpire({ job: JobId, lease: bool })
    | LifecycleUnknown({ authority: AuthorityInput, committed: bool })
    | LifecycleReconcile({ job: JobId, operation: OperationId, observed: StoreResult })
    | LifecycleCorrupt({ job: JobId, kind: RecordKind })
    | LifecycleRepair({ job: JobId, revision: int, operation: OperationId })
    | LifecycleRedrive({ job: JobId, expectedRevision: int,
        expectedOperation: OperationId, reuseExecution: bool })

  // The transition is the command-correlated authority record. It is written
  // in the same MBT step as the authoritative family action. A later observe
  // step only serializes this immutable record; it never consults mutable job
  // or meta state to reconstruct what the command returned.
  type LastTransition = { command: Command, class: ResultClass, result: StoreResult,
    outcome: LifecycleOutcome, detail: CompletionDetail, enqueue: EnqueueDisposition, job: JobId,
    operation: OperationId }
  type CommandResult = LifecycleApplied(LastTransition)
    | LifecycleRejected(LastTransition) | LifecycleConflict(LastTransition)
    | LifecycleUnknownResult(LastTransition) | LifecycleDetailOmitted(LastTransition)

  var lastCommand: Command
  var lastCommandResult: CommandResult
  var lastTransition: LastTransition

  type StateProjection = { jobs: JobId -> Job, meta: Meta, command: Command,
    transition: LastTransition, result: CommandResult }

  def mbtProjection(currentJobs: JobId -> Job, currentMeta: Meta): StateProjection = {
    jobs: currentJobs,
    meta: currentMeta,
    command: lastCommand,
    transition: lastTransition,
    result: lastCommandResult,
  }

  pure def commandJob(command) = match command {
    | LifecycleEnqueue(input) => input.job | LifecycleSelectClaim(input) => input.job
    | LifecycleClaim(input) => input.job | LifecycleRenew(input) => input.job
    | LifecycleCheckpoint(input) => input.authority.job
    | LifecycleHandle(input) => input.authority.job | LifecycleComplete(input) => input.job
    | LifecycleExpose(input) => input.job | LifecycleCancel(input) => input.authority.job
    | LifecycleAdvance(_) => JobA | LifecycleExpire(input) => input.job
    | LifecycleUnknown(input) => input.authority.job | LifecycleReconcile(input) => input.job
    | LifecycleCorrupt(input) => input.job | LifecycleRepair(input) => input.job
    | LifecycleRedrive(input) => input.job
  }
  pure def commandOperation(command) = match command {
    | LifecycleEnqueue(input) => input.operation | LifecycleRenew(input) => input.operation
    | LifecycleCheckpoint(input) => input.authority.operation
    | LifecycleHandle(input) => input.authority.operation
    | LifecycleComplete(input) => input.operation | LifecycleExpose(input) => input.operation
    | LifecycleCancel(input) => input.authority.operation
    | LifecycleUnknown(input) => input.authority.operation
    | LifecycleReconcile(input) => input.operation | LifecycleRepair(input) => input.operation
    | LifecycleRedrive(input) => input.expectedOperation
    | _ => OperationA
  }

  pure def commandFamily(command) = match command {
    | LifecycleEnqueue(_) => "LifecycleEnqueue"
    | LifecycleSelectClaim(_) => "LifecycleSelectClaim"
    | LifecycleClaim(_) => "LifecycleClaim"
    | LifecycleRenew(_) => "LifecycleRenew"
    | LifecycleCheckpoint(_) => "LifecycleCheckpoint"
    | LifecycleHandle(_) => "LifecycleHandle"
    | LifecycleComplete(_) => "LifecycleComplete"
    | LifecycleExpose(_) => "LifecycleExpose"
    | LifecycleCancel(_) => "LifecycleCancel"
    | LifecycleAdvance(_) => "LifecycleAdvance"
    | LifecycleExpire(_) => "LifecycleExpire"
    | LifecycleUnknown(_) => "LifecycleUnknown"
    | LifecycleReconcile(_) => "LifecycleReconcile"
    | LifecycleCorrupt(_) => "LifecycleCorrupt"
    | LifecycleRepair(_) => "LifecycleRepair"
    | LifecycleRedrive(_) => "LifecycleRedrive"
  }

  pure def isPermanentHandle(command) = match command {
    | LifecycleHandle(input) => input.authority.job == JobB and input.handler == Permanent
    | _ => false
  }
  def exact(input) = {
    val current = jobs.get(input.job)
    current.state == Leased and not(blocked(input.job))
      and exactAuthority(current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId,
        input.node, input.revision, input.generation, input.fence, input.token,
        input.leaseUntil, input.operation, meta.now)
  }
  // A committed cooperative-cancellation marker supersedes worker outcome
  // authority. Leased acknowledgement and control-plane expiry recovery can
  // consume that marker; renew, checkpoint, handler, completion, and unknown
  // worker commit paths must fail their authority check.
  def workerExact(input) = exact(input) and not(jobs.get(input.job).cancelRequested)
  def transitionFor(command) = {
    val job = commandJob(command)
    val current = jobs.get(job)
    val values = match command {
      | LifecycleEnqueue(input) => {
          // Fingerprints are producer-side command tokens; JobSystem compares
          // the durable immutable record fields instead.  The connector's
          // fixed payload and scheduled timestamp make this compatibility
          // relation explicit in the model.
          val present = current.state != Absent
          val identical = present and current.record == Valid and not(input.withDedupe)
            and input.dueAt == current.dueAt
          val disposition = if (not(present)) Inserted
            else if (identical) AlreadyPresent else JobIdConflict
          val keyConflict = input.withDedupe and meta.dedupeActive and input.job != meta.dedupeJob
          val blockedInput = blocked(input.job)
          val inserted = not(blockedInput) and disposition == Inserted and not(keyConflict)
            and current.record != UnknownVersion
          val replay = not(blockedInput) and disposition == AlreadyPresent
          { class: if (inserted or replay) AppliedClass
              else if (not(blockedInput) and disposition == JobIdConflict) RejectedClass
              else ConflictClass,
            result: if (inserted or replay) Committed
              else if (not(blockedInput) and disposition == JobIdConflict) Rejected else Conflict,
            outcome: if (inserted and input.dueAt > meta.now and input.withDedupe)
              EnqueueDedupeCommitted else if (inserted and input.dueAt > meta.now)
              EnqueueFutureCommitted else if (inserted) EnqueueCommitted
              else if (replay) EnqueueAlreadyPresent
              else if (not(blockedInput) and disposition == JobIdConflict) EnqueueJobIdConflict
              else if (keyConflict) EnqueueDedupeConflict else EnqueueRejected,
            detail: NoCompletionDetail }
        }
      | LifecycleSelectClaim(_) => { class: AppliedClass, result: Committed,
          outcome: ClaimSelected, detail: NoCompletionDetail }
      | LifecycleClaim(input) => {
          val allowed = not(blocked(input.job)) and meta.claimPending
            and input.revision == meta.claimRevision and input.contender == meta.claimReader
            and current.record == Valid and current.state != Leased and current.dueRoute
            and input.revision == current.revision and current.dueAt <= meta.now
            and current.attempts < MAX_ATTEMPTS
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (allowed) ClaimCommitted else ClaimConflict,
            detail: NoCompletionDetail }
        }
      | LifecycleRenew(input) => { class: if (workerExact(input)) AppliedClass else ConflictClass,
          result: if (workerExact(input)) Committed else Conflict,
          outcome: if (workerExact(input)) Renewed else RenewRejected, detail: NoCompletionDetail }
      | LifecycleCheckpoint(input) => {
          val allowed = workerExact(input.authority) and input.bytes <= MAX_CHECKPOINT_BYTES
          val bounded = input.bytes <= MAX_CHECKPOINT_BYTES
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (allowed) CheckpointCommitted else if (not(bounded))
              CheckpointBoundRejected else CheckpointAuthorityRejected,
            detail: NoCompletionDetail }
        }
      | LifecycleHandle(input) => {
          val authority = workerExact(input.authority)
          val retry = authority and isRetryable(input.handler) and current.attempts < MAX_ATTEMPTS
          val dead = authority and (input.handler == Permanent
            or (isRetryable(input.handler) and not(retry)))
          { class: if (authority) AppliedClass else ConflictClass,
            result: if (authority) Committed else Conflict,
            outcome: if (authority and input.handler == Success) CompletionDeleted
              else if (retry and input.handler == Transient) RetryTransient
              else if (retry and input.handler == Throttled) RetryThrottled
              else if (retry) RetryAmbiguous else if (dead) PermanentDeadLetter
              else CompletionRejected, detail: NoCompletionDetail }
        }
      | LifecycleComplete(input) => { class: if (workerExact(input)) AppliedClass else ConflictClass,
          result: if (workerExact(input)) Committed else Conflict,
          outcome: if (workerExact(input)) CompletionDeleted else CompletionRejected,
          detail: NoCompletionDetail }
      | LifecycleExpose(input) => {
          val allowed = not(blocked(input.job)) and meta.completionPending
            and not(meta.unknownPending and input.job == meta.unknownJob)
            and current.state == Absent and not(current.payload) and not(current.dueRoute)
            and not(current.fairRoute) and not(current.leaseRoute) and not(current.wakeRoute)
            and input.job == meta.completionJob and input.operation == meta.completionOperation
            and input.revision == meta.completionRevision
            and input.generation == meta.completionGeneration
            and current.operationId == input.operation and current.revision == input.revision
            and current.generation == input.generation
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (allowed) CompletionDeleted else CompletionRejected,
            detail: if (allowed) completionDetailAt(completionReceiptCount)
              else NoCompletionDetail }
        }
      | LifecycleCancel(input) => {
          val scheduled = input.phase == CancelScheduled and not(blocked(job))
            and (current.state == Scheduled or current.state == RetryWaiting)
            and exactIdentity(current.node, current.revision, current.generation,
              current.fence, current.token, current.leaseUntil, current.operationId,
              input.authority.node, input.authority.revision, input.authority.generation,
              input.authority.fence, input.authority.token, input.authority.leaseUntil,
              input.authority.operation)
          // Repeating a request is an idempotent marker write. It retains the
          // same cancellation authority and therefore remains exact even
          // after the marker is already present.
          val requested = input.phase == RequestLeased and exact(input.authority)
          val committed = input.phase == CommitLeased and current.cancelRequested
            and exact(input.authority)
          val allowed = scheduled or requested or committed
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (scheduled) CancelCommitted else if (requested) CancelRequested
              else if (committed) LeasedCancelled else CompletionRejected,
            detail: NoCompletionDetail }
        }
      | LifecycleAdvance(_) => { class: AppliedClass, result: Committed,
          outcome: TimeAdvanced, detail: NoCompletionDetail }
      | LifecycleExpire(input) => {
          val allowed = if (input.lease) not(blocked(input.job))
              and current.state == Leased
              and current.leaseUntil <= meta.now
            else not(blocked(input.job))
              and (current.state == Scheduled or current.state == RetryWaiting)
              and current.record == Valid and current.expiresAt <= meta.now
          val cancelled = input.lease and allowed and current.cancelRequested
          val retry = input.lease and allowed and not(cancelled) and current.expiresAt > meta.now
            and current.attempts < MAX_ATTEMPTS
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (cancelled) LeasedCancelled else if (retry) LeaseExpired else if (allowed and input.lease)
              PermanentDeadLetter else if (allowed) ScheduledExpired else CompletionRejected,
            detail: NoCompletionDetail }
        }
      | LifecycleUnknown(input) => { class: if (workerExact(input.authority)) UnknownClass else ConflictClass,
          result: if (workerExact(input.authority)) Unknown else Conflict,
          outcome: if (workerExact(input.authority) and input.committed) UnknownAfterCommit
            else if (workerExact(input.authority)) UnknownBeforeCommit else CompletionRejected,
          detail: NoCompletionDetail }
      | LifecycleReconcile(input) => {
          val exactAuthorityReadback = current.operationId == meta.unknownOperation
            and current.node == meta.unknownNode and current.generation == meta.unknownGeneration
            and current.fence == meta.unknownFence and current.token == meta.unknownToken
            and (if (meta.unknownAfterCommit) current.state == Absent
              and current.revision == meta.unknownRevision + 1 and current.leaseUntil == 0
              else current.state == Leased and current.revision == meta.unknownRevision
                and current.leaseUntil == meta.unknownLeaseUntil)
          val authorityChanged = current.revision != (if (meta.unknownAfterCommit)
            meta.unknownRevision + 1 else meta.unknownRevision)
          val exactRead = meta.unknownPending and input.job == meta.unknownJob
            and input.operation == meta.unknownOperation and input.observed == meta.unknownReadback
            and (if (input.observed == AuthorityChanged) authorityChanged
              else exactAuthorityReadback)
          val committed = exactRead and meta.unknownAfterCommit and input.observed == Committed
          { class: if (exactRead) AppliedClass else ConflictClass,
            result: if (exactRead) Committed else Conflict,
            outcome: if (not(exactRead)) CompletionRejected
              else if (input.observed == AuthorityChanged) UnknownAuthorityChanged
              else if (meta.unknownAfterCommit) UnknownReconciled else UnknownConflictReconciled,
            detail: if (committed) completionDetailAt(completionReceiptCount)
              else NoCompletionDetail }
        }
      | LifecycleCorrupt(input) => {
          val eligible = current.record == Valid and current.state != Leased
            and not(blocked(input.job))
          val applied = eligible and input.kind != UnknownVersion
          val quarantined = eligible and input.kind == UnknownVersion
          { class: if (applied) AppliedClass
              else if (quarantined) RejectedClass else ConflictClass,
            result: if (applied) Committed else if (quarantined) Rejected else Conflict,
            outcome: if (quarantined) UnknownVersionQuarantined
              else if (applied) CorruptQuarantined else RepairConflict,
            detail: NoCompletionDetail }
        }
      | LifecycleRepair(input) => {
          val allowed = repairAllowed(current, meta.unknownPending, meta.unknownJob,
            meta.unknownVersionJobs.contains(input.job), input.job, input.revision,
            input.operation)
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (allowed) RepairCommitted else RepairConflict,
            detail: NoCompletionDetail }
        }
      | LifecycleRedrive(input) => {
          val effect = redriveKernel(current.state, current.record, blocked(job),
            current.revision, current.operationId, input.expectedRevision,
            input.expectedOperation, current.generation, current.fence,
            current.token, current.executionId, input.reuseExecution, meta.now)
          { class: if (effect.allowed) AppliedClass
              else if (effect.authorityConflict) ConflictClass else RejectedClass,
            result: if (effect.allowed) Committed
              else if (effect.authorityConflict) Conflict else Rejected,
            outcome: if (effect.allowed) Redriven
              else if (effect.authorityConflict) RedriveConflict else RedriveRejected,
            detail: NoCompletionDetail }
        }
    }
    val enqueue = match command {
      | LifecycleEnqueue(input) => {
          val present = current.state != Absent
          val identical = present and current.record == Valid and not(input.withDedupe)
            and input.dueAt == current.dueAt
          if (blocked(input.job)) NotEnqueue
          else if (not(present)) Inserted
          else if (identical) AlreadyPresent else JobIdConflict
        }
      | _ => NotEnqueue
    }
    { command: command, class: values.class, result: values.result,
      outcome: values.outcome, detail: values.detail, enqueue: enqueue, job: job,
      operation: commandOperation(command) }
  }
  pure def resultFor(transition) = if (transition.detail == CompletionDetailOmitted)
    LifecycleDetailOmitted(transition)
  else if (transition.class == UnknownClass) LifecycleUnknownResult(transition)
  else if (transition.class == ConflictClass) LifecycleConflict(transition)
  else if (transition.class == RejectedClass) LifecycleRejected(transition)
  else LifecycleApplied(transition)

  pure val initialCommand = LifecycleAdvance({ amount: 0 })
  pure val initialTransition = { command: initialCommand, class: AppliedClass, result: Committed,
    outcome: Initialised, detail: NoCompletionDetail, enqueue: NotEnqueue, job: JobA,
    operation: OperationA }

  action mbtInit = all {
    init,
    lastCommand' = initialCommand,
    lastTransition' = initialTransition,
    lastCommandResult' = LifecycleApplied(initialTransition),
  }

  action dispatch(command: Command): bool = match command {
    | LifecycleEnqueue(input) => all { JOBS.contains(input.job), input.dueAt >= 0,
        EnqueueInput(input.job, input.dueAt, input.operation, input.withDedupe,
          input.fingerprint),
        lastCommand' = command }
    | LifecycleSelectClaim(input) => all { JOBS.contains(input.job), input.revision >= 0,
        SelectClaimInput(input.job, input.reader, input.revision), lastCommand' = command }
    | LifecycleClaim(input) => all { JOBS.contains(input.job), input.revision >= 0,
        ClaimInput(input.job, input.contender, input.revision), lastCommand' = command }
    | LifecycleRenew(input) => all { JOBS.contains(input.job), input.leaseUntil >= 0,
        RenewInput(input.job, input.node, input.revision, input.generation, input.fence,
          input.token, input.leaseUntil, input.operation), lastCommand' = command }
    | LifecycleCheckpoint(input) => all { input.bytes >= 0,
        CheckpointInput(input.authority.job, input.authority.node, input.authority.revision,
          input.authority.generation, input.authority.fence, input.authority.token,
          input.authority.leaseUntil, input.authority.operation, input.bytes),
        lastCommand' = command }
    | LifecycleHandle(input) => all { JOBS.contains(input.authority.job),
        HandleInput(input.authority.job, input.authority.node, input.authority.revision,
          input.authority.generation, input.authority.fence, input.authority.token,
          input.authority.leaseUntil, input.authority.operation, input.handler),
        lastCommand' = command }
    | LifecycleComplete(input) => all { JOBS.contains(input.job),
        CompleteInput(input.job, input.node, input.revision, input.generation, input.fence,
          input.token, input.leaseUntil, input.operation), lastCommand' = command }
    | LifecycleExpose(input) => all { JOBS.contains(input.job), input.revision >= 0,
        ExposeCompletionInput(input.job, input.operation, input.revision, input.generation),
        lastCommand' = command }
    | LifecycleCancel(input) => all { JOBS.contains(input.authority.job),
        (if (input.phase == CancelScheduled)
          CancelInput(input.authority.job, input.authority.node, input.authority.revision,
            input.authority.generation, input.authority.fence, input.authority.token,
            input.authority.leaseUntil, input.authority.operation)
        else if (input.phase == RequestLeased)
          RequestCancelInput(input.authority.job, input.authority.node, input.authority.revision,
            input.authority.generation, input.authority.fence, input.authority.token,
            input.authority.leaseUntil, input.authority.operation)
        else CancelLeasedInput(input.authority.job, input.authority.node,
          input.authority.revision, input.authority.generation, input.authority.fence,
          input.authority.token, input.authority.leaseUntil, input.authority.operation)),
        lastCommand' = command }
    | LifecycleAdvance(input) => all { input.amount >= 0, AdvanceTimeInput(input.amount),
        lastCommand' = command }
    | LifecycleExpire(input) => all { JOBS.contains(input.job),
        if (input.lease) ExpireLeaseInput(input.job) else ExpireScheduledInput(input.job),
        lastCommand' = command }
    | LifecycleUnknown(input) => all { JOBS.contains(input.authority.job),
        UnknownCompletionInput(input.authority.job, input.authority.node,
          input.authority.revision, input.authority.generation, input.authority.fence,
          input.authority.token, input.authority.leaseUntil, input.authority.operation,
          input.committed), lastCommand' = command }
    | LifecycleReconcile(input) => all { JOBS.contains(input.job),
        ReconcileUnknownInput(input.job, input.operation, input.observed), lastCommand' = command }
    | LifecycleCorrupt(input) => all { JOBS.contains(input.job),
        CorruptRecordInput(input.job, input.kind), lastCommand' = command }
    | LifecycleRepair(input) => all { JOBS.contains(input.job), input.revision >= 0,
        RepairInput(input.job, input.revision, input.operation), lastCommand' = command }
    | LifecycleRedrive(input) => all { JOBS.contains(input.job),
        RedriveInput(input.job, input.expectedRevision, input.expectedOperation,
          input.reuseExecution), lastCommand' = command }
  }

  action mbtStep(command: Command): bool = {
    val transition = transitionFor(command)
    all {
      dispatch(command),
      lastCommandResult' = resultFor(transition),
      lastTransition' = transition,
    }
  }

  action mbtObserve = {
    all { jobs' = jobs, meta' = meta, lastCommand' = lastCommand,
      lastTransition' = lastTransition,
      lastCommandResult' = resultFor(lastTransition) }
  }

  pure def authorityFor(job, current) = { job: job, node: current.node,
    revision: current.revision, generation: current.generation, fence: current.fence,
    token: current.token, leaseUntil: current.leaseUntil, operation: current.operationId }

  action mbtDispatchNondet = any {
    mbtStep(LifecycleEnqueue({ job: JobC, dueAt: meta.now, operation: OperationA,
      withDedupe: false, fingerprint: 3 })),
    mbtStep(LifecycleSelectClaim({ job: meta.claimJob, reader: meta.claimReader,
      revision: meta.claimRevision })),
    mbtStep(LifecycleClaim({ job: meta.claimJob, contender: meta.claimReader,
      revision: meta.claimRevision })),
    mbtStep(LifecycleRenew(authorityFor(JobB, jobs.get(JobB)))),
    mbtStep(LifecycleCheckpoint({ authority: authorityFor(JobB, jobs.get(JobB)),
      bytes: MAX_CHECKPOINT_BYTES })),
    mbtStep(LifecycleHandle({ authority: authorityFor(JobB, jobs.get(JobB)), handler: Transient })),
    mbtStep(LifecycleComplete(authorityFor(JobB, jobs.get(JobB)))),
    mbtStep(LifecycleExpose({ job: meta.completionJob, operation: meta.completionOperation,
      revision: meta.completionRevision, generation: meta.completionGeneration })),
    mbtStep(LifecycleCancel({ authority: authorityFor(JobB, jobs.get(JobB)), phase: RequestLeased })),
    mbtStep(LifecycleAdvance({ amount: 1 })),
    mbtStep(LifecycleExpire({ job: JobB, lease: true })),
    mbtStep(LifecycleUnknown({ authority: authorityFor(JobB, jobs.get(JobB)), committed: true })),
    mbtStep(LifecycleReconcile({ job: meta.unknownJob, operation: meta.unknownOperation,
      observed: meta.unknownReadback })),
    // Repair authenticates the record with its separately durable operation
    // marker. JobA is seeded with that marker; enqueue-created JobC is not.
    mbtStep(LifecycleCorrupt({ job: JobA, kind: Corrupt })),
    if (jobs.get(JobA).record == Corrupt)
      mbtStep(LifecycleRepair({ job: JobA, revision: jobs.get(JobA).revision,
        operation: jobs.get(JobA).operationId }))
    else mbtStep(LifecycleRepair({ job: JobA, revision: jobs.get(JobA).revision + 1,
      operation: jobs.get(JobA).operationId })),
    mbtStep(LifecycleRedrive({ job: JobB,
      expectedRevision: jobs.get(JobB).revision,
      expectedOperation: jobs.get(JobB).operationId, reuseExecution: false })),
  }

  action mbtNondetStep = any { mbtDispatchNondet, mbtObserve }

  // `mbtNondetStep` is intentionally exploratory: bounded random traces can
  // select any valid command, but they are not a coverage proof. This
  // deterministic chain gives the connector one model-directed sequence in
  // which every command family is a real `mbtStep` and therefore is decoded
  // from the serialized `lastCommand` by the Rust driver.
  action fixedCommandCoverageChain =
    if (lastCommand == initialCommand)
      mbtStep(LifecycleEnqueue({ job: JobC, dueAt: meta.now, operation: OperationA,
        withDedupe: false, fingerprint: 3 }))
    else if (commandFamily(lastCommand) == "LifecycleEnqueue")
      mbtStep(LifecycleHandle({ authority: authorityFor(JobB, jobs.get(JobB)), handler: Permanent }))
    else if (isPermanentHandle(lastCommand) and jobs.get(JobB).state == DeadLettered)
      mbtStep(LifecycleSelectClaim({ job: JobC, reader: NodeA,
        revision: jobs.get(JobC).revision }))
    else if (commandFamily(lastCommand) == "LifecycleSelectClaim"
        and jobs.get(JobC).state == Scheduled)
      mbtStep(LifecycleClaim({ job: JobC, contender: NodeA,
        revision: jobs.get(JobC).revision }))
    else if (commandFamily(lastCommand) == "LifecycleClaim"
        and jobs.get(JobC).state == Leased and jobs.get(JobC).revision == 1)
      mbtStep(LifecycleRenew(authorityFor(JobC, jobs.get(JobC))))
    else if (commandFamily(lastCommand) == "LifecycleRenew")
      mbtStep(LifecycleCheckpoint({ authority: authorityFor(JobC, jobs.get(JobC)), bytes: 1 }))
    else if (commandFamily(lastCommand) == "LifecycleCheckpoint")
      mbtStep(LifecycleHandle({ authority: authorityFor(JobC, jobs.get(JobC)), handler: Transient }))
    else if (jobs.get(JobC).state == RetryWaiting and jobs.get(JobC).dueAt > meta.now)
      mbtStep(LifecycleAdvance({ amount: 1 }))
    else if (commandFamily(lastCommand) == "LifecycleAdvance" and meta.now == 1)
      mbtStep(LifecycleSelectClaim({ job: JobC, reader: NodeA,
        revision: jobs.get(JobC).revision }))
    else if (commandFamily(lastCommand) == "LifecycleSelectClaim"
        and jobs.get(JobC).state == RetryWaiting)
      mbtStep(LifecycleClaim({ job: JobC, contender: NodeA,
        revision: jobs.get(JobC).revision }))
    else if (commandFamily(lastCommand) == "LifecycleClaim"
        and jobs.get(JobC).state == Leased and jobs.get(JobC).attempts > 1)
      mbtStep(LifecycleComplete(authorityFor(JobC, jobs.get(JobC))))
    else if (commandFamily(lastCommand) == "LifecycleComplete"
        and jobs.get(JobC).state == Absent)
      mbtStep(LifecycleExpose({ job: JobC, operation: meta.completionOperation,
        revision: meta.completionRevision, generation: meta.completionGeneration }))
    else if (commandFamily(lastCommand) == "LifecycleExpose")
      mbtStep(LifecycleRedrive({ job: JobB, expectedRevision: jobs.get(JobB).revision,
        expectedOperation: jobs.get(JobB).operationId, reuseExecution: false }))
    else if (commandFamily(lastCommand) == "LifecycleRedrive"
        and jobs.get(JobB).state == Scheduled)
      mbtStep(LifecycleSelectClaim({ job: JobB, reader: NodeA,
        revision: jobs.get(JobB).revision }))
    else if (commandFamily(lastCommand) == "LifecycleSelectClaim"
        and jobs.get(JobB).state == Scheduled)
      mbtStep(LifecycleClaim({ job: JobB, contender: NodeA,
        revision: jobs.get(JobB).revision }))
    else if (commandFamily(lastCommand) == "LifecycleClaim"
        and jobs.get(JobB).state == Leased)
      mbtStep(LifecycleUnknown({ authority: authorityFor(JobB, jobs.get(JobB)), committed: false }))
    else if (commandFamily(lastCommand) == "LifecycleUnknown")
      mbtStep(LifecycleReconcile({ job: meta.unknownJob, operation: meta.unknownOperation,
        observed: meta.unknownReadback }))
    else if (commandFamily(lastCommand) == "LifecycleReconcile")
      mbtStep(LifecycleAdvance({ amount: 3 }))
    else if (commandFamily(lastCommand) == "LifecycleAdvance" and meta.now == 4)
      mbtStep(LifecycleExpire({ job: JobB, lease: true }))
    else if (commandFamily(lastCommand) == "LifecycleExpire"
        and jobs.get(JobB).state == RetryWaiting)
      mbtStep(LifecycleCancel({ authority: authorityFor(JobB, jobs.get(JobB)),
        phase: CancelScheduled }))
    else if (commandFamily(lastCommand) == "LifecycleCancel"
        and jobs.get(JobB).state == Cancelled)
      mbtStep(LifecycleCorrupt({ job: JobA, kind: Corrupt }))
    else if (commandFamily(lastCommand) == "LifecycleCorrupt"
        and jobs.get(JobA).record == Corrupt)
      mbtStep(LifecycleRepair({ job: JobA, revision: jobs.get(JobA).revision,
        operation: jobs.get(JobA).operationId }))
    else mbtStep(LifecycleAdvance({ amount: 0 }))
  action fixedCommandCoverageTrace = fixedCommandCoverageChain

  action fixedZeroAdvance = mbtStep(LifecycleAdvance({ amount: 0 }))
  action fixedZeroAdvanceTrace = fixedZeroAdvance
  val fixed_zero_advance_witness = meta.now == 0
    and lastCommand == LifecycleAdvance({ amount: 0 })
    and lastCommandResult == LifecycleApplied({ command: LifecycleAdvance({ amount: 0 }),
      class: AppliedClass, result: Committed, outcome: TimeAdvanced, detail: NoCompletionDetail,
      enqueue: NotEnqueue, job: JobA, operation: OperationA }) and jobs == initialJobs
      and meta == initialMeta.with("lastOutcome", TimeAdvanced)
  action fixedConflictCommand = mbtStep(LifecycleComplete(
    authorityFor(JobB, jobs.get(JobB)).with("token", jobs.get(JobB).token + 1)))
  action fixedUnknownCommand = mbtStep(LifecycleUnknown({
    authority: authorityFor(JobB, jobs.get(JobB)), committed: false }))
  action fixedConflictTrace =
    if (lastCommand == initialCommand) fixedConflictCommand
    else mbtObserve
  action fixedUnknownTrace = fixedUnknownCommand
  action fixedUnknownAfterCommand = mbtStep(LifecycleUnknown({
    authority: authorityFor(JobB, jobs.get(JobB)), committed: true }))
  action fixedUnknownAfterTrace = fixedUnknownAfterCommand
  action fixedUnknownReconcileChain =
    if (not(meta.unknownPending))
      mbtStep(LifecycleUnknown({
        authority: authorityFor(JobB, jobs.get(JobB)), committed: false }))
    else mbtStep(LifecycleReconcile({ job: meta.unknownJob,
      operation: meta.unknownOperation, observed: meta.unknownReadback }))
  action fixedUnknownReconcileTrace = fixedUnknownReconcileChain

  // Handler retry clears the model token. The next claim therefore starts
  // the per-job token label sequence at three again.
  action fixedLifecycleRetryReclaimChain = {
    val current = jobs.get(JobB)
    if (current.state == Leased)
      mbtStep(LifecycleHandle({ authority: authorityFor(JobB, current), handler: Transient }))
    else if (current.state == RetryWaiting and current.dueAt > meta.now)
      mbtStep(LifecycleAdvance({ amount: current.dueAt - meta.now }))
    else if (commandFamily(lastCommand) == "LifecycleAdvance")
      mbtStep(LifecycleSelectClaim({ job: JobB, reader: NodeA,
        revision: current.revision }))
    else if (commandFamily(lastCommand) == "LifecycleSelectClaim")
      mbtStep(LifecycleClaim({ job: JobB, contender: NodeA,
        revision: current.revision }))
    else mbtStep(LifecycleAdvance({ amount: 0 }))
  }
  action fixedLifecycleRetryReclaimTrace = fixedLifecycleRetryReclaimChain

  // Lease expiry retains the model token progression. The next claim must
  // therefore receive the next label (six), unlike a handler retry.
  action fixedLifecycleExpiryReclaimChain = {
    val current = jobs.get(JobB)
    if (current.state == Leased and current.leaseUntil > meta.now)
      mbtStep(LifecycleAdvance({ amount: current.leaseUntil - meta.now }))
    else if (commandFamily(lastCommand) == "LifecycleAdvance" and current.state == Leased)
      mbtStep(LifecycleExpire({ job: JobB, lease: true }))
    else if (current.state == RetryWaiting
        and commandFamily(lastCommand) != "LifecycleSelectClaim")
      mbtStep(LifecycleSelectClaim({ job: JobB, reader: NodeA,
        revision: current.revision }))
    else if (commandFamily(lastCommand) == "LifecycleSelectClaim")
      mbtStep(LifecycleClaim({ job: JobB, contender: NodeA,
        revision: current.revision }))
    else mbtStep(LifecycleAdvance({ amount: 0 }))
  }
  action fixedLifecycleExpiryReclaimTrace = fixedLifecycleExpiryReclaimChain

  action fixedCancellationExpiryChain = {
    val current = jobs.get(JobB)
    if (current.state == Leased and not(current.cancelRequested))
      mbtStep(LifecycleCancel({ authority: authorityFor(JobB, current), phase: RequestLeased }))
    else if (current.state == Leased and current.leaseUntil > meta.now)
      mbtStep(LifecycleAdvance({ amount: current.leaseUntil - meta.now }))
    else if (current.state == Leased)
      mbtStep(LifecycleExpire({ job: JobB, lease: true }))
    else mbtStep(LifecycleAdvance({ amount: 0 }))
  }
  action fixedCancellationExpiryTrace = fixedCancellationExpiryChain
  val fixed_cancellation_expiry_witness = jobs.get(JobB).state == Cancelled
    and not(jobs.get(JobB).cancelRequested) and not(jobs.get(JobB).leaseRoute)
    and not(jobs.get(JobB).dueRoute) and not(jobs.get(JobB).fairRoute)
    and meta.committedTerminalJobs.contains(JobB) and meta.lastOutcome == LeasedCancelled

  val fixed_conflict_witness = lastCommandResult == LifecycleConflict({ command: lastCommand,
    class: ConflictClass,
    result: Conflict, outcome: CompletionRejected, detail: NoCompletionDetail,
    enqueue: NotEnqueue, job: JobB, operation: OperationA }) and jobs == initialJobs
  val fixed_unknown_witness = lastCommandResult == LifecycleUnknownResult({ command: lastCommand,
    class: UnknownClass,
    result: Unknown, outcome: UnknownBeforeCommit, detail: NoCompletionDetail,
    enqueue: NotEnqueue, job: JobB, operation: OperationA })
  val fixed_unknown_after_witness = lastCommandResult == LifecycleUnknownResult({ command: lastCommand,
    class: UnknownClass, result: Unknown, outcome: UnknownAfterCommit, detail: NoCompletionDetail,
    enqueue: NotEnqueue, job: JobB, operation: OperationA })

  action fixedScopedRepairTrace =
    if (jobs.get(JobA).record == Valid)
      mbtStep(LifecycleCorrupt({ job: JobA, kind: Corrupt }))
    else if (not(meta.unknownPending))
      mbtStep(LifecycleUnknown({ authority: authorityFor(JobB, jobs.get(JobB)),
        committed: false }))
    else mbtStep(LifecycleRepair({ job: JobA,
      revision: jobs.get(JobA).revision, operation: jobs.get(JobA).operationId }))
  val fixed_scoped_repair_witness = jobs.get(JobA).record == Valid
    and jobs.get(JobA).revision == 3 and meta.unknownPending
    and meta.unknownJob == JobB and meta.unknownOperation == OperationA
    and jobs.get(JobB) == initialJobs.get(JobB) and meta.unrelatedProgress == 1
    and jobs.get(JobC) == initialJobs.get(JobC)
    and lastCommand == LifecycleRepair({ job: JobA, revision: 2,
      operation: OperationA })
    and lastCommandResult == LifecycleApplied({ command: lastCommand,
      class: AppliedClass, result: Committed, outcome: RepairCommitted,
      detail: NoCompletionDetail, enqueue: NotEnqueue, job: JobA,
      operation: OperationA })

  action fixedQuarantinedRepairTrace =
    if (jobs.get(JobC).state == Absent)
      mbtStep(LifecycleEnqueue({ job: JobC, dueAt: meta.now, operation: OperationA,
        withDedupe: false, fingerprint: 3 }))
    else if (not(meta.unknownVersionJobs.contains(JobC)))
      mbtStep(LifecycleCorrupt({ job: JobC, kind: UnknownVersion }))
    else mbtStep(LifecycleRepair({ job: JobC,
      revision: jobs.get(JobC).revision, operation: jobs.get(JobC).operationId }))
  val fixed_quarantined_repair_witness = meta.unknownVersionJobs.contains(JobC)
    and jobs.get(JobC).state == Scheduled
    and jobs.get(JobC).record == Valid
    and jobs.get(JobC).revision == 0
    and jobs.get(JobC).payload
    and jobs.get(JobC).dueRoute and jobs.get(JobC).fairRoute
    and jobs.get(JobC).wakeRoute and not(jobs.get(JobC).leaseRoute)
    and lastCommandResult == LifecycleConflict({ command: lastCommand,
      class: ConflictClass, result: Conflict, outcome: RepairConflict,
      detail: NoCompletionDetail, enqueue: NotEnqueue, job: JobC,
      operation: OperationA })

  action fixedStaleRepairTrace =
    if (jobs.get(JobC).state == Absent)
      mbtStep(LifecycleEnqueue({ job: JobC, dueAt: meta.now, operation: OperationA,
        withDedupe: false, fingerprint: 3 }))
    else if (jobs.get(JobC).record == Valid)
      mbtStep(LifecycleCorrupt({ job: JobC, kind: Corrupt }))
    else mbtStep(LifecycleRepair({ job: JobC,
      revision: jobs.get(JobC).revision - 1, operation: jobs.get(JobC).operationId }))
  val fixed_stale_repair_witness = jobs.get(JobC).record == Corrupt
    and jobs.get(JobC).revision == 1
    and lastCommandResult == LifecycleConflict({ command: lastCommand,
      class: ConflictClass, result: Conflict, outcome: RepairConflict,
      detail: NoCompletionDetail, enqueue: NotEnqueue, job: JobC,
      operation: OperationA })

  action fixedLifecycleRedriveChain = {
    val current = jobs.get(JobB)
    if (current.state == Leased)
      mbtStep(LifecycleHandle({ authority: authorityFor(JobB, current), handler: Permanent }))
    else mbtStep(LifecycleRedrive({ job: JobB,
      expectedRevision: current.revision, expectedOperation: current.operationId,
      reuseExecution: false }))
  }
  action fixedLifecycleRedriveTrace = fixedLifecycleRedriveChain

  action fixedLifecycleStaleRedriveChain = {
    val current = jobs.get(JobB)
    if (current.state == Leased)
      mbtStep(LifecycleHandle({ authority: authorityFor(JobB, current), handler: Permanent }))
    else mbtStep(LifecycleRedrive({ job: JobB,
      expectedRevision: current.revision - 1, expectedOperation: current.operationId,
      reuseExecution: false }))
  }
  action fixedLifecycleStaleRedriveTrace = fixedLifecycleStaleRedriveChain

  action fixedLifecycleWrongOperationRedriveChain = {
    val current = jobs.get(JobB)
    if (current.state == Leased)
      mbtStep(LifecycleHandle({ authority: authorityFor(JobB, current), handler: Permanent }))
    else mbtStep(LifecycleRedrive({ job: JobB,
      expectedRevision: current.revision, expectedOperation: OperationB,
      reuseExecution: false }))
  }
  action fixedLifecycleWrongOperationRedriveTrace = fixedLifecycleWrongOperationRedriveChain

  action fixedLifecycleDuplicateRedriveChain = {
    val current = jobs.get(JobB)
    if (current.state == Leased)
      mbtStep(LifecycleHandle({ authority: authorityFor(JobB, current), handler: Permanent }))
    else if (current.state == DeadLettered)
      mbtStep(LifecycleRedrive({ job: JobB,
        expectedRevision: current.revision, expectedOperation: current.operationId,
        reuseExecution: false }))
    else mbtStep(LifecycleRedrive({ job: JobB,
      expectedRevision: current.revision - 1, expectedOperation: current.operationId,
      reuseExecution: false }))
  }
  action fixedLifecycleDuplicateRedriveTrace = fixedLifecycleDuplicateRedriveChain

  action fixedLifecycleNonterminalRedriveTrace = mbtStep(LifecycleRedrive({ job: JobA,
    expectedRevision: jobs.get(JobA).revision,
    expectedOperation: jobs.get(JobA).operationId, reuseExecution: false }))

  action fixedLifecycleQuarantinedRedriveChain =
    if (not(meta.unknownVersionJobs.contains(JobA)))
      mbtStep(LifecycleCorrupt({ job: JobA, kind: UnknownVersion }))
    else mbtStep(LifecycleRedrive({ job: JobA,
      expectedRevision: jobs.get(JobA).revision,
      expectedOperation: jobs.get(JobA).operationId, reuseExecution: false }))
  action fixedLifecycleQuarantinedRedriveTrace = fixedLifecycleQuarantinedRedriveChain

  action fixedLifecycleCorruptRedriveChain =
    if (jobs.get(JobA).record == Valid)
      mbtStep(LifecycleCorrupt({ job: JobA, kind: Corrupt }))
    else mbtStep(LifecycleRedrive({ job: JobA,
      expectedRevision: jobs.get(JobA).revision,
      expectedOperation: jobs.get(JobA).operationId, reuseExecution: false }))
  action fixedLifecycleCorruptRedriveTrace = fixedLifecycleCorruptRedriveChain

  val fixed_lifecycle_redrive_applied_witness = jobs.get(JobB).state == Scheduled
    and jobs.get(JobB).revision == 3 and jobs.get(JobB).generation == 2
    and jobs.get(JobB).executionId == 3 and jobs.get(JobB).expiresAt == MAX_JOB_AGE_TICKS
    and lastTransition.class == AppliedClass and lastTransition.result == Committed
    and lastTransition.outcome == Redriven
  val fixed_lifecycle_stale_redrive_conflict_witness = jobs.get(JobB).state == DeadLettered
    and lastTransition.class == ConflictClass and lastTransition.result == Conflict
    and lastTransition.outcome == RedriveConflict
  val fixed_lifecycle_wrong_operation_redrive_conflict_witness =
    fixed_lifecycle_stale_redrive_conflict_witness
  val fixed_lifecycle_duplicate_redrive_conflict_witness = jobs.get(JobB).state == Scheduled
    and lastTransition.class == ConflictClass and lastTransition.result == Conflict
    and lastTransition.outcome == RedriveConflict
  val fixed_lifecycle_nonterminal_redrive_rejected_witness = jobs == initialJobs
    and lastTransition.class == RejectedClass and lastTransition.result == Rejected
    and lastTransition.outcome == RedriveRejected
  val fixed_lifecycle_quarantined_redrive_rejected_witness =
    meta.unknownVersionJobs.contains(JobA) and jobs == initialJobs
    and lastTransition.class == RejectedClass and lastTransition.result == Rejected
    and lastTransition.outcome == RedriveRejected
  val fixed_lifecycle_corrupt_redrive_rejected_witness = jobs.get(JobA).record == Corrupt
    and jobs.get(JobA).state == Scheduled
    and lastTransition.class == RejectedClass and lastTransition.result == Rejected
    and lastTransition.outcome == RedriveRejected

  val mbtInv = inv and lastTransition.job == commandJob(lastCommand)
    and lastTransition.operation == commandOperation(lastCommand)
    and lastTransition.command == lastCommand
    and lastTransition.result == meta.lastResult
    and lastTransition.outcome == meta.lastOutcome
    and lastTransition.detail == meta.completionDetail
    and lastTransition.enqueue == meta.lastEnqueueDisposition
    and lastCommandResult == resultFor(lastTransition)
}
