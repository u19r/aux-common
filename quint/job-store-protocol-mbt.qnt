/// Typed MBT boundary for the authoritative atomic store protocol.
/// Commands carry routing, lease authority, unknown-readback, repair, resource,
/// and completion-cap inputs. Dispatch atomically records the prestate decision
/// and invokes the imported store action; observation only serializes it.
module job_store_protocol_mbt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_store_protocol.* from "./job-store-protocol"

  type AuthorityInput = { job: JobId, node: Node, revision: int, generation: int,
    fence: int, token: int, leaseUntil: int, operation: OperationId }
  type ResourceInput = { payloadBytes: int, manifestBytes: int, chunkBytes: int,
    digestBytes: int, checkpointBytes: int }
  type Command = StoreEnqueue({ job: JobId, operation: OperationId,
      resources: ResourceInput, fingerprint: int })
    | StoreSelectClaim({ job: JobId, reader: Node, revision: int })
    | StoreClaim({ job: JobId, contender: Node, revision: int }) | StoreRenew(AuthorityInput)
    | StoreComplete(AuthorityInput)
    | StoreDeadLetter({ authority: AuthorityInput, handler: HandlerResult })
    | StoreRedrive({ job: JobId, revision: int, operation: OperationId,
        reuseExecution: bool })
    | StoreUnknown({ authority: AuthorityInput, committed: bool })
    | StoreReconcile({ job: JobId, operation: OperationId, observed: StoreResult })
    | StoreCorrupt({ job: JobId, kind: RecordKind })
    | StoreDropRoute({ job: JobId, due: bool, fair: bool, lease: bool, wake: bool })
    | StoreRepair({ job: JobId, revision: int, operation: OperationId })
    | StorePurge({ job: JobId, revision: int })
    | StoreAdvance({ amount: int }) | StoreExpire({ job: JobId })

  // Written atomically with the command dispatch. Observation serializes this
  // immutable record and never reclassifies a command from mutable store meta.
  type LastTransition = { command: Command, class: ResultClass, result: StoreResult,
    outcome: StoreOutcome, detail: CompletionDetail, enqueue: EnqueueDisposition, job: JobId,
    operation: OperationId }
  type CommandResult = StoreApplied(LastTransition) | StoreRejected(LastTransition)
    | StoreConflictResult(LastTransition) | StoreUnknownResult(LastTransition)
    | StoreDetailOmitted(LastTransition)

  var lastCommand: Command
  var lastCommandResult: CommandResult
  var lastTransition: LastTransition

  type StateProjection = { records: JobId -> Record, meta: Meta, command: Command,
    transition: LastTransition, result: CommandResult }
  def mbtProjection(currentRecords: JobId -> Record,
      currentMeta: Meta): StateProjection = { records: currentRecords, meta: currentMeta,
        command: lastCommand, transition: lastTransition, result: lastCommandResult }

  pure def commandJob(command) = match command {
    | StoreEnqueue(input) => input.job | StoreSelectClaim(input) => input.job
    | StoreClaim(input) => input.job | StoreRenew(input) => input.job
    | StoreComplete(input) => input.job | StoreUnknown(input) => input.authority.job
    | StoreDeadLetter(input) => input.authority.job | StoreRedrive(input) => input.job
    | StoreReconcile(input) => input.job | StoreCorrupt(input) => input.job
    | StoreDropRoute(input) => input.job | StoreRepair(input) => input.job
    | StorePurge(input) => input.job | StoreAdvance(_) => JobA | StoreExpire(input) => input.job
  }
  pure def commandOperation(command) = match command {
    | StoreEnqueue(input) => input.operation | StoreRenew(input) => input.operation
    | StoreComplete(input) => input.operation | StoreUnknown(input) => input.authority.operation
    | StoreDeadLetter(input) => input.authority.operation
    | StoreRedrive(input) => input.operation
    | StoreReconcile(input) => input.operation | StoreRepair(input) => input.operation
    | _ => OperationA
  }
  def exact(input) = {
    val current = records.get(input.job)
    not(storeBlocked(meta, input.job)) and current.leased and current.kind == Valid
      and exactAuthority(current.node, current.revision, current.generation,
        current.fence, current.token, current.leaseUntil, current.operationId,
        input.node, input.revision, input.generation, input.fence, input.token,
        input.leaseUntil, input.operation, meta.now)
  }
  def transitionFor(command) = {
    val job = commandJob(command)
    val current = records.get(job)
    val values = match command {
      | StoreEnqueue(input) => {
          val r = input.resources
          val within = r.payloadBytes >= 0 and r.payloadBytes <= MAX_INLINE_PAYLOAD_BYTES
            and r.manifestBytes >= 0 and r.manifestBytes <= MAX_MANIFEST_BYTES
            and r.chunkBytes >= 0 and r.chunkBytes <= MAX_CHUNK_BYTES
            and r.digestBytes >= 0 and r.digestBytes <= MAX_DIGEST_BYTES
            and r.checkpointBytes >= 0 and r.checkpointBytes <= MAX_CHECKPOINT_BYTES
          val present = current.enqueueFingerprint != 0
          val disposition = stableEnqueueDisposition(present,
            current.enqueueFingerprint, input.fingerprint)
          val blockedInput = storeBlocked(meta, input.job)
          val inserted = within and input.fingerprint > 0 and not(blockedInput)
            and disposition == Inserted
          val replay = within and not(blockedInput) and disposition == AlreadyPresent
          val conflict = not(blockedInput) and present and within and not(replay)
          { class: if (inserted or replay) AppliedClass
              else if (conflict or not(within)) RejectedClass else ConflictClass,
            result: if (inserted or replay) Committed
              else if (conflict or not(within)) Rejected else Conflict,
            outcome: if (inserted) AtomicEnqueue else if (replay) EnqueueAlreadyPresent
              else if (conflict) EnqueueJobIdConflict
              else if (blockedInput) ConflictNoMutation else PayloadRejected,
            detail: NoCompletionDetail }
        }
      | StoreSelectClaim(_) => { class: AppliedClass, result: Committed,
          outcome: ClaimSelected, detail: NoCompletionDetail }
      | StoreClaim(input) => {
          val allowed = not(storeBlocked(meta, input.job)) and meta.claimPending
            and input.revision == meta.claimRevision and input.contender == meta.claimReader
            and current.exists and current.kind == Valid and current.payload
            and current.dueRoute and not(current.leased) and input.revision == current.revision
            and meta.now < current.expiresAt
            and not(meta.unknownVersionJobs.contains(input.job))
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (allowed) ClaimAtomicCommit else ClaimConflictNoMutation,
            detail: NoCompletionDetail }
        }
      | StoreRenew(input) => { class: if (exact(input)) AppliedClass else ConflictClass,
          result: if (exact(input)) Committed else Conflict,
          outcome: if (exact(input)) LeaseRenewed else LeaseRenewConflict,
          detail: NoCompletionDetail }
      | StoreComplete(input) => { class: if (exact(input)) AppliedClass else ConflictClass,
          result: if (exact(input)) Committed else Conflict,
          outcome: if (exact(input)) CompletionDeletedAllKeys else ConflictNoMutation,
          detail: if (exact(input)) completionDetailAt(meta.completionReceipts)
            else NoCompletionDetail }
      | StoreDeadLetter(input) => {
          val authority = input.authority
          val effect = applyStoreDeadLetter(records, meta, authority.job, authority.node,
            authority.revision, authority.generation, authority.fence, authority.token,
            authority.leaseUntil, authority.operation, input.handler)
          { class: if (effect.meta.lastResult == Committed) AppliedClass
              else if (effect.meta.lastResult == Rejected) RejectedClass else ConflictClass,
            result: effect.meta.lastResult, outcome: effect.meta.lastOutcome,
            detail: NoCompletionDetail }
        }
      | StoreRedrive(input) => {
          val effect = applyStoreRedrive(records, meta, input.job, input.revision,
            input.operation, input.reuseExecution)
          { class: if (effect.meta.lastResult == Committed) AppliedClass
              else if (effect.meta.lastResult == Rejected) RejectedClass else ConflictClass,
            result: effect.meta.lastResult, outcome: effect.meta.lastOutcome,
            detail: NoCompletionDetail }
        }
      | StoreUnknown(input) => { class: if (exact(input.authority)) UnknownClass else ConflictClass,
          result: if (exact(input.authority)) Unknown else Conflict,
          outcome: if (exact(input.authority)) UnknownCommitRequiresReconcile
            else ConflictNoMutation, detail: NoCompletionDetail }
      | StoreReconcile(input) => {
          val exactIdentityReadback = current.operationId == meta.unknownOperation
            and current.node == meta.unknownNode and current.generation == meta.unknownGeneration
            and current.fence == meta.unknownFence and current.token == meta.unknownToken
            and (if (input.observed == Committed) not(current.exists)
              and current.revision == meta.unknownRevision + 1 and current.leaseUntil == 0
              and not(current.permitHeld) and not(current.rateHeld) and current.inFlight == 0
              else current.exists and current.leased
                and current.revision == meta.unknownRevision
                and current.leaseUntil == meta.unknownLeaseUntil
                and current.permitHeld and current.rateHeld and current.inFlight == 1)
          val authorityChanged = current.revision != meta.unknownRevision
            and current.revision != meta.unknownRevision + 1
          val exactRead = meta.unknownPending and input.job == meta.unknownJob
            and input.operation == meta.unknownOperation and input.observed == meta.unknownReadback
            and (if (input.observed == AuthorityChanged) authorityChanged
              else exactIdentityReadback)
          val committed = exactRead and input.observed == Committed
          { class: if (exactRead) AppliedClass else ConflictClass,
            result: if (exactRead) Committed else Conflict,
            outcome: if (not(exactRead)) ConflictNoMutation
              else if (input.observed == Committed) ReconciledCommitted
              else if (input.observed == Conflict) ReconciledConflict
              else ReconciledAuthorityChanged,
            detail: if (committed) completionDetailAt(meta.completionReceipts)
              else NoCompletionDetail }
        }
      | StoreCorrupt(input) => { class: if (input.kind == UnknownVersion)
            RejectedClass else AppliedClass,
          result: if (input.kind == UnknownVersion) Rejected else Committed,
          outcome: if (input.kind == UnknownVersion) UnknownVersionQuarantined
            else if (input.kind == Missing) MissingIndexDiscovered else CorruptQuarantined,
          detail: NoCompletionDetail }
      | StoreDropRoute(input) => {
          val allowed = dropRoutesAllowed(records, meta, input.job,
            input.due, input.fair, input.lease, input.wake)
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (allowed and current.exists) MissingIndexDiscovered
              else if (allowed) DanglingRecordCreated else ConflictNoMutation,
            detail: NoCompletionDetail }
        }
      | StoreRepair(input) => {
          val allowed = not(storeBlocked(meta, input.job)) and current.exists
            and (current.state == Scheduled or current.state == RetryWaiting)
            and current.kind == Corrupt and input.revision == current.revision
            and input.operation == current.operationId
            and not(meta.unknownVersionJobs.contains(input.job))
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (allowed) RepairCommitted else RepairRevisionConflict,
            detail: NoCompletionDetail }
        }
      | StorePurge(input) => {
          val allowed = not(storeBlocked(meta, input.job)) and not(current.exists)
            and (current.dueRoute or current.fairRoute or current.leaseRoute or current.wakeRoute)
            and input.revision == current.revision
          { class: if (allowed) AppliedClass else ConflictClass,
            result: if (allowed) Committed else Conflict,
            outcome: if (allowed) DanglingIndexPurged else ConflictNoMutation,
            detail: NoCompletionDetail }
        }
      | StoreAdvance(_) => { class: AppliedClass, result: Committed,
          outcome: TimeAdvanced, detail: NoCompletionDetail }
      | StoreExpire(_) => { class: AppliedClass, result: Committed,
          outcome: if (current.expiresAt <= meta.now) HandlerDeadLetter
            else LeaseExpiredToReady, detail: NoCompletionDetail }
    }
    val enqueue = match command {
      | StoreEnqueue(input) => {
          val r = input.resources
          val within = r.payloadBytes >= 0 and r.payloadBytes <= MAX_INLINE_PAYLOAD_BYTES
            and r.manifestBytes >= 0 and r.manifestBytes <= MAX_MANIFEST_BYTES
            and r.chunkBytes >= 0 and r.chunkBytes <= MAX_CHUNK_BYTES
            and r.digestBytes >= 0 and r.digestBytes <= MAX_DIGEST_BYTES
            and r.checkpointBytes >= 0 and r.checkpointBytes <= MAX_CHECKPOINT_BYTES
          if (storeBlocked(meta, input.job)
              or not(within)) NotEnqueue
          else stableEnqueueDisposition(current.enqueueFingerprint != 0,
            current.enqueueFingerprint, input.fingerprint)
        }
      | _ => NotEnqueue
    }
    { command: command, class: values.class, result: values.result,
      outcome: values.outcome, detail: values.detail, enqueue: enqueue, job: job,
      operation: commandOperation(command) }
  }
  pure def resultFor(transition) = if (transition.detail == CompletionDetailOmitted)
    StoreDetailOmitted(transition)
  else if (transition.class == UnknownClass) StoreUnknownResult(transition)
  else if (transition.class == ConflictClass) StoreConflictResult(transition)
  else if (transition.class == RejectedClass) StoreRejected(transition)
  else StoreApplied(transition)
  pure val initialCommand = StoreAdvance({ amount: 0 })
  pure val initialTransition = { command: initialCommand, class: AppliedClass, result: Committed,
    outcome: Initialised, detail: NoCompletionDetail, enqueue: NotEnqueue, job: JobA,
    operation: OperationA }

  action mbtInit = all { init, lastCommand' = initialCommand,
    lastTransition' = initialTransition,
    lastCommandResult' = StoreApplied(initialTransition) }
  action dispatch(command: Command): bool = match command {
    | StoreEnqueue(input) => all { JOBS.contains(input.job), input.resources.payloadBytes >= 0,
        EnqueueAtomicInput(input.job, input.operation, input.resources.payloadBytes,
          input.resources.manifestBytes, input.resources.chunkBytes,
          input.resources.digestBytes, input.resources.checkpointBytes,
          input.fingerprint), lastCommand' = command }
    | StoreSelectClaim(input) => all { JOBS.contains(input.job), input.revision >= 0,
        SelectClaimInput(input.job, input.reader, input.revision), lastCommand' = command }
    | StoreClaim(input) => all { JOBS.contains(input.job),
        ClaimInput(input.job, input.contender, input.revision), lastCommand' = command }
    | StoreRenew(input) => all { JOBS.contains(input.job),
        RenewInput(input.job, input.node, input.revision, input.generation, input.fence,
          input.token, input.leaseUntil, input.operation), lastCommand' = command }
    | StoreComplete(input) => all { JOBS.contains(input.job),
        CompleteInput(input.job, input.node, input.revision, input.generation, input.fence,
          input.token, input.leaseUntil, input.operation), lastCommand' = command }
    | StoreDeadLetter(input) => all { JOBS.contains(input.authority.job),
        DeadLetterInput(input.authority.job, input.authority.node,
          input.authority.revision, input.authority.generation, input.authority.fence,
          input.authority.token, input.authority.leaseUntil, input.authority.operation,
          input.handler), lastCommand' = command }
    | StoreRedrive(input) => all { JOBS.contains(input.job),
        RedriveInput(input.job, input.revision, input.operation, input.reuseExecution),
        lastCommand' = command }
    | StoreUnknown(input) => all { JOBS.contains(input.authority.job),
        UnknownCommitInput(input.authority.job, input.authority.node,
          input.authority.revision, input.authority.generation, input.authority.fence,
          input.authority.token, input.authority.leaseUntil, input.authority.operation,
          input.committed), lastCommand' = command }
    | StoreReconcile(input) => all { JOBS.contains(input.job),
        ReconcileInput(input.job, input.operation, input.observed), lastCommand' = command }
    | StoreCorrupt(input) => all { JOBS.contains(input.job),
        CorruptRecordInput(input.job, input.kind), lastCommand' = command }
    | StoreDropRoute(input) => all { JOBS.contains(input.job),
        DropRoutesInput(input.job, input.due, input.fair, input.lease, input.wake),
        lastCommand' = command }
    | StoreRepair(input) => all { JOBS.contains(input.job), input.revision >= 0,
        RepairInput(input.job, input.revision, input.operation), lastCommand' = command }
    | StorePurge(input) => all { JOBS.contains(input.job),
        PurgeDanglingInput(input.job, input.revision), lastCommand' = command }
    | StoreAdvance(input) => all { input.amount >= 0, AdvanceTimeInput(input.amount),
        lastCommand' = command }
    | StoreExpire(input) => all { JOBS.contains(input.job), ExpireLeaseInput(input.job),
        lastCommand' = command }
  }

  action mbtStep(command: Command): bool = {
    val transition = transitionFor(command)
    all { dispatch(command), lastCommandResult' = resultFor(transition),
      lastTransition' = transition }
  }
  action mbtObserve = {
    all { records' = records, meta' = meta, lastCommand' = lastCommand,
      lastTransition' = lastTransition,
      lastCommandResult' = resultFor(lastTransition) }
  }

  pure def authorityFor(job, current) = { job: job, node: current.node,
    revision: current.revision, generation: current.generation, fence: current.fence,
    token: current.token, leaseUntil: current.leaseUntil, operation: current.operationId }
  pure def boundedResources = { payloadBytes: MAX_INLINE_PAYLOAD_BYTES,
    manifestBytes: MAX_MANIFEST_BYTES, chunkBytes: MAX_CHUNK_BYTES,
    digestBytes: MAX_DIGEST_BYTES, checkpointBytes: MAX_CHECKPOINT_BYTES }

  action mbtDispatchNondet = any {
    mbtStep(StoreEnqueue({ job: JobC, operation: OperationA,
      resources: boundedResources, fingerprint: 3 })),
    mbtStep(StoreSelectClaim({ job: meta.claimJob, reader: meta.claimReader,
      revision: meta.claimRevision })),
    mbtStep(StoreClaim({ job: meta.claimJob, contender: meta.claimReader,
      revision: meta.claimRevision })),
    mbtStep(StoreRenew(authorityFor(JobB, records.get(JobB)))),
    mbtStep(StoreComplete(authorityFor(JobB, records.get(JobB)))),
    mbtStep(StoreDeadLetter({ authority: authorityFor(JobB, records.get(JobB)),
      handler: Permanent })),
    mbtStep(StoreRedrive({ job: JobB, revision: records.get(JobB).revision,
      operation: records.get(JobB).operationId, reuseExecution: false })),
    mbtStep(StoreUnknown({ authority: authorityFor(JobB, records.get(JobB)), committed: true })),
    mbtStep(StoreReconcile({ job: meta.unknownJob, operation: meta.unknownOperation,
      observed: meta.unknownReadback })),
    mbtStep(StoreCorrupt({ job: JobA, kind: Corrupt })),
    mbtStep(StoreDropRoute({ job: JobA, due: true, fair: false, lease: false, wake: false })),
    mbtStep(StoreRepair({ job: JobA, revision: records.get(JobA).revision,
      operation: records.get(JobA).operationId })),
    mbtStep(StorePurge({ job: JobC, revision: records.get(JobC).revision })),
    mbtStep(StoreAdvance({ amount: 1 })),
    mbtStep(StoreExpire({ job: JobB })),
  }
  action mbtNondetStep = any { mbtDispatchNondet, mbtObserve }

  pure val zeroResources = { payloadBytes: 0, manifestBytes: 0, chunkBytes: 0,
    digestBytes: 0, checkpointBytes: 0 }
  action fixedZeroByteEnqueue = mbtStep(StoreEnqueue({ job: JobC,
    operation: OperationD, resources: zeroResources, fingerprint: 3 }))
  action fixedZeroByteEnqueueTrace = fixedZeroByteEnqueue
  pure val fixedZeroRecord = initialRecords.get(JobC).with("exists", true)
    .with("state", Scheduled).with("kind", Valid)
    .with("revision", initialRecords.get(JobC).revision + 1)
    .with("payload", true).with("payloadBytes", 0).with("manifestBytes", 0)
    .with("chunkBytes", 0).with("digestBytes", 0).with("checkpointBytes", 0)
    .with("enqueueFingerprint", 3)
    .with("executionId", 1)
    .with("expiresAt", MAX_JOB_AGE_TICKS)
    .with("operationId", OperationD).with("dueRoute", true).with("fairRoute", true)
    .with("wakeRoute", true).with("leaseRoute", false).with("leased", false)
    .with("dangling", false)
  pure val fixedZeroRecords = update(initialRecords, JobC, fixedZeroRecord)
  pure val fixedZeroMeta = initialMeta.with("wakeWatermark", true)
    .with("transactionChecks", 1).with("transactionMutations", 6)
    .with("transactionBytes", 6).with("lastResult", Committed)
    .with("lastOutcome", AtomicEnqueue).with("lastEnqueueDisposition", Inserted)
  val fixed_zero_byte_enqueue_witness = records == fixedZeroRecords and meta == fixedZeroMeta
    and lastCommandResult == StoreApplied({ command: lastCommand,
      class: AppliedClass, result: Committed,
      outcome: AtomicEnqueue, detail: NoCompletionDetail, enqueue: Inserted, job: JobC,
      operation: OperationD })
  action fixedRejectedCommand = mbtStep(StoreEnqueue({ job: JobC,
    operation: OperationD, resources: zeroResources.with("payloadBytes",
      MAX_INLINE_PAYLOAD_BYTES + 1), fingerprint: 3 }))
  action fixedConflictCommand = mbtStep(StoreComplete(
    authorityFor(JobB, records.get(JobB)).with("token", records.get(JobB).token + 1)))
  action fixedUnknownCommand = mbtStep(StoreUnknown({
    authority: authorityFor(JobB, records.get(JobB)), committed: false }))
  action fixedUnknownDropChain =
    if (not(meta.unknownVersionJobs.contains(JobA)))
      mbtStep(StoreCorrupt({ job: JobA, kind: UnknownVersion }))
    else mbtStep(StoreDropRoute({ job: JobA, due: true, fair: true,
      lease: false, wake: true }))
  action fixedRejectedTrace = fixedRejectedCommand
  action fixedConflictTrace = fixedConflictCommand
  action fixedUnknownTrace = fixedUnknownCommand
  action fixedUnknownDropTrace = fixedUnknownDropChain

  action fixedTerminalReplayRedriveChain = {
    val current = records.get(JobB)
    if (current.leased)
      mbtStep(StoreDeadLetter({ authority: authorityFor(JobB, current),
        handler: Permanent }))
    else if (current.state == DeadLettered and meta.lastOutcome == HandlerDeadLetter)
      mbtStep(StoreEnqueue({ job: JobB, operation: OperationA,
        resources: boundedResources.with("checkpointBytes", 0),
        fingerprint: current.enqueueFingerprint }))
    else mbtStep(StoreRedrive({ job: JobB, revision: current.revision,
      operation: current.operationId, reuseExecution: false }))
  }
  action fixedTerminalReplayRedriveTrace = fixedTerminalReplayRedriveChain

  action fixedStaleRedriveChain = {
    val current = records.get(JobB)
    if (current.leased)
      mbtStep(StoreDeadLetter({ authority: authorityFor(JobB, current),
        handler: Permanent }))
    else mbtStep(StoreRedrive({ job: JobB, revision: current.revision - 1,
      operation: current.operationId, reuseExecution: false }))
  }
  action fixedStaleRedriveTrace = fixedStaleRedriveChain

  action fixedWrongOperationRedriveChain = {
    val current = records.get(JobB)
    if (current.leased)
      mbtStep(StoreDeadLetter({ authority: authorityFor(JobB, current),
        handler: Permanent }))
    else mbtStep(StoreRedrive({ job: JobB, revision: current.revision,
      operation: OperationB, reuseExecution: false }))
  }
  action fixedWrongOperationRedriveTrace = fixedWrongOperationRedriveChain

  action fixedDuplicateRedriveChain = {
    val current = records.get(JobB)
    if (current.leased)
      mbtStep(StoreDeadLetter({ authority: authorityFor(JobB, current),
        handler: Permanent }))
    else if (current.state == DeadLettered)
      mbtStep(StoreRedrive({ job: JobB, revision: current.revision,
        operation: current.operationId, reuseExecution: false }))
    else mbtStep(StoreRedrive({ job: JobB, revision: current.revision - 1,
      operation: current.operationId, reuseExecution: false }))
  }
  action fixedDuplicateRedriveTrace = fixedDuplicateRedriveChain

  action fixedNonterminalRedriveTrace = mbtStep(StoreRedrive({ job: JobA,
    revision: records.get(JobA).revision, operation: records.get(JobA).operationId,
    reuseExecution: false }))

  action fixedQuarantinedRedriveChain =
    if (not(meta.unknownVersionJobs.contains(JobA)))
      mbtStep(StoreCorrupt({ job: JobA, kind: UnknownVersion }))
    else mbtStep(StoreRedrive({ job: JobA, revision: records.get(JobA).revision,
      operation: records.get(JobA).operationId, reuseExecution: false }))
  action fixedQuarantinedRedriveTrace = fixedQuarantinedRedriveChain
  val fixed_rejected_witness = lastCommandResult == StoreRejected({ command: lastCommand,
    class: RejectedClass,
    result: Rejected, outcome: PayloadRejected, detail: NoCompletionDetail,
    enqueue: NotEnqueue, job: JobC, operation: OperationD }) and records == initialRecords
  val fixed_conflict_witness = lastCommandResult == StoreConflictResult({ command: lastCommand,
    class: ConflictClass,
    result: Conflict, outcome: ConflictNoMutation, detail: NoCompletionDetail,
    enqueue: NotEnqueue, job: JobB, operation: OperationA }) and records == initialRecords
  val fixed_unknown_witness = lastCommandResult == StoreUnknownResult({ command: lastCommand,
    class: UnknownClass,
    result: Unknown, outcome: UnknownCommitRequiresReconcile, detail: NoCompletionDetail,
    enqueue: NotEnqueue, job: JobB, operation: OperationA })
  val fixed_unknown_drop_witness = meta.unknownVersionJobs.contains(JobA)
    and records == initialRecords
    and lastCommand == StoreDropRoute({ job: JobA, due: true, fair: true,
      lease: false, wake: true })
    and lastCommandResult == StoreConflictResult({ command: lastCommand,
      class: ConflictClass, result: Conflict, outcome: ConflictNoMutation,
      detail: NoCompletionDetail, enqueue: NotEnqueue, job: JobA,
      operation: OperationA })
  val fixed_terminal_replay_witness = records.get(JobB).state == DeadLettered
    and records.get(JobB).failureRecorded and records.get(JobB).dlqRoute
    and lastTransition.class == AppliedClass and lastTransition.result == Committed
    and lastTransition.outcome == EnqueueAlreadyPresent
    and lastTransition.enqueue == AlreadyPresent
  val fixed_redrive_applied_witness = records.get(JobB).state == Scheduled
    and records.get(JobB).revision == 3 and records.get(JobB).executionId == 2
    and records.get(JobB).enqueueFingerprint == 11 and records.get(JobB).payload
    and records.get(JobB).checkpointBytes == 0
    and not(records.get(JobB).failureRecorded) and not(records.get(JobB).dlqRoute)
    and lastTransition.class == AppliedClass and lastTransition.result == Committed
    and lastTransition.outcome == RedriveCommitted
  val fixed_stale_redrive_conflict_witness = records.get(JobB).state == DeadLettered
    and lastTransition.class == ConflictClass and lastTransition.result == Conflict
    and lastTransition.outcome == RedriveConflict
  val fixed_wrong_operation_redrive_conflict_witness =
    fixed_stale_redrive_conflict_witness
  val fixed_nonterminal_redrive_rejected_witness = records == initialRecords
    and lastTransition.class == RejectedClass and lastTransition.result == Rejected
    and lastTransition.outcome == RedriveRejected
  val fixed_quarantined_redrive_rejected_witness =
    meta.unknownVersionJobs.contains(JobA) and records == initialRecords
    and lastTransition.class == RejectedClass and lastTransition.result == Rejected
    and lastTransition.outcome == RedriveRejected
  val fixed_duplicate_redrive_conflict_witness = records.get(JobB).state == Scheduled
    and records.get(JobB).revision == 3 and lastTransition.class == ConflictClass
    and lastTransition.result == Conflict and lastTransition.outcome == RedriveConflict

  val mbtInv = inv and lastTransition.job == commandJob(lastCommand)
    and lastTransition.operation == commandOperation(lastCommand)
    and lastTransition.command == lastCommand
    and lastTransition.result == meta.lastResult
    and lastTransition.outcome == meta.lastOutcome
    and lastTransition.detail == meta.lastDetail
    and lastTransition.enqueue == meta.lastEnqueueDisposition
    and lastCommandResult == resultFor(lastTransition)
}
