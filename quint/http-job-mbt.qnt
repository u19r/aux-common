/// Typed MBT boundary for per-item HTTP execution.
/// Commands carry exact batch membership, lease/operation identity, input and
/// secret flags, authorization, request safety checks, transport/status,
/// Retry-After, duplicate/omission choices, and engine-owned retry intent.
/// Results are frozen with the command; mutable item and batch globals are
/// never consulted by observation.
module http_job_mbt {
  import bg_jobs_types.* from "./bg-jobs-types"
  import http_job.* from "./http-job"

  type AuthorityInput = { job: JobId, node: Node, revision: int, generation: int,
    fence: int, token: int, leaseUntil: int, operation: OperationId,
    executionId: int, attemptId: int }
  type Command = HttpPrepare({ members: Set[JobId] })
    | HttpInput({ job: JobId, secret: bool, bodyBytes: int,
        destinationValid: bool })
    | HttpAuthorize({ job: JobId, auth: AuthResult })
    | HttpProject({ job: JobId, includeSecret: bool })
    | HttpExecute({ authority: AuthorityInput, status: HttpStatus,
        transport: TransportResult, retryAfter: int })
    | HttpRetryCommand({ job: JobId, owner: RetryOwner })
    | HttpDuplicate({ job: JobId })
    | HttpOmit({ job: JobId })

  /// Immutable command-correlated authority and output.  Observation is a
  /// serialization step only; it never consults a later `lastItem` or item.
  type LastTransition = { command: Command, class: ResultClass, outcome: HttpOutcome,
    affected: Set[JobId], job: JobId, operation: OperationId,
    result: BatchResult, owner: RetryOwner, retryAfter: int,
    members: Set[JobId], results: JobId -> BatchResult }
  type CommandResult = HttpApplied({ transition: LastTransition,
      result: BatchResult, owner: RetryOwner, retryAfter: int })
    | HttpRejected({ transition: LastTransition, result: BatchResult })
    | HttpRetryResult({ transition: LastTransition, owner: RetryOwner,
        retryAfter: int })
    | HttpBatchResult({ transition: LastTransition, members: Set[JobId],
        results: JobId -> BatchResult })

  var lastCommand: Command
  var lastCommandResult: CommandResult
  var lastTransition: LastTransition

  type StateProjection = { items: JobId -> Item, meta: Meta, command: Command,
    transition: LastTransition, result: CommandResult }
  def mbtProjection(currentItems: JobId -> Item,
      currentMeta: Meta): StateProjection = { items: currentItems, meta: currentMeta,
        command: lastCommand, transition: lastTransition, result: lastCommandResult }

  pure def commandJob(command) = match command {
    | HttpPrepare(input) => if (input.members.size() == 0) JobA
        else if (input.members.contains(JobA)) JobA
        else if (input.members.contains(JobB)) JobB else JobC
    | HttpInput(input) => input.job | HttpAuthorize(input) => input.job
    | HttpProject(input) => input.job | HttpExecute(input) => input.authority.job
    | HttpRetryCommand(input) => input.job | HttpDuplicate(input) => input.job
    | HttpOmit(input) => input.job
  }
  pure def commandAffected(command) = match command {
    | HttpPrepare(input) => input.members | _ => Set(commandJob(command))
  }
  pure def commandOperation(command) = match command {
    | HttpExecute(input) => input.authority.operation | _ => OperationA
  }
  def transitionFor(command) = {
    val job = commandJob(command)
    val current = items.get(job)
    val execution = match command {
      | HttpExecute(input) => {
          val valid = httpExecutionAllowed(current, input.authority.node,
            input.authority.revision, input.authority.generation, input.authority.fence,
            input.authority.token, input.authority.leaseUntil, input.authority.operation,
            input.authority.executionId, input.authority.attemptId)
          httpExecutionEffect(current, valid, input.status, input.transport, input.retryAfter)
        }
      | _ => { valid: true, result: current.result, outcome: Initialised,
          owner: current.retryOwner, retryAfter: current.retryAfter }
    }
    val allowed = match command {
      | HttpInput(input) => current.member and current.result == ItemMissing
          and not(current.attemptExecuted)
          and input.bodyBytes <= MAX_INLINE_PAYLOAD_BYTES and input.destinationValid
      | HttpAuthorize(input) => current.member and current.result == ItemMissing
          and not(current.attemptExecuted) and current.destinationValid
          and current.bodyBytes <= MAX_INLINE_PAYLOAD_BYTES and input.auth == Authorised
      | HttpProject(input) => not(input.includeSecret) and current.member
          and current.result == ItemMissing and not(current.attemptExecuted)
          and not(current.invalidInput) and current.auth == Authorised
          and current.destinationValid and current.bodyBytes <= MAX_INLINE_PAYLOAD_BYTES
      | HttpExecute(_) => execution.valid
      | HttpRetryCommand(input) => httpRetryAllowed(current, input.owner)
      | HttpDuplicate(_) => current.member
          and (current.result == ItemMissing or current.result == ItemRetry)
      | HttpOmit(_) => httpOmissionAllowed(current)
      | _ => true
    }
    val outcome = match command {
      | HttpPrepare(_) => BatchPrepared
      | HttpInput(_) => if (allowed) Initialised else InvalidInputRejected
      | HttpAuthorize(_) => if (allowed) Initialised else AuthorisationRejected
      | HttpProject(_) => if (allowed) Initialised else ProjectionRejected
      | HttpExecute(_) => execution.outcome
      | HttpRetryCommand(_) => if (allowed) HttpRetry else ProjectionRejected
      | HttpDuplicate(_) => if (allowed) DuplicateDelivered else ProjectionRejected
      | HttpOmit(_) => if (allowed) ItemOmitted else ProjectionRejected
    }
    val result = match command {
      | HttpInput(_) => if (not(current.member) or current.result != ItemMissing
          or current.attemptExecuted) current.result
          else if (allowed) ItemMissing else ItemDeadLetter
      | HttpAuthorize(_) => if (not(current.member) or current.result != ItemMissing
          or current.attemptExecuted) current.result
          else if (allowed) current.result else ItemDeadLetter
      | HttpProject(_) => if (allowed) ItemMissing else current.result
      | HttpExecute(_) => execution.result
      | HttpRetryCommand(_) => if (allowed) ItemMissing else current.result
      | HttpOmit(_) => if (allowed) ItemRetry else current.result
      | _ => current.result
    }
    val owner = match command {
      | HttpExecute(_) => execution.owner
      | HttpOmit(_) => if (allowed) EngineOwnsRetry else current.retryOwner
      | HttpRetryCommand(_) => if (allowed) NoRetry else current.retryOwner
      | _ => current.retryOwner
    }
    val retryAfter = match command {
      | HttpExecute(_) => execution.retryAfter | _ => current.retryAfter
    }
    val members = match command { | HttpPrepare(input) => input.members | _ => meta.batchMembers }
    val results = match command {
      | HttpPrepare(input) => input.members.fold(Map(), (acc, member) =>
          acc.put(member, ItemMissing))
      | _ => updateBatchResult(meta.batchResults, meta.batchMembers, job, result)
    }
    { command: command, class: if (allowed) AppliedClass else RejectedClass,
      outcome: outcome, affected: commandAffected(command), job: job,
      operation: commandOperation(command), result: result, owner: owner,
      retryAfter: retryAfter, members: members, results: results }
  }
  pure def resultFor(transition) = if (transition.outcome == BatchPrepared)
    HttpBatchResult({ transition: transition, members: transition.members,
      results: transition.results })
  else if (transition.outcome == HttpRetry or transition.outcome == TransportRetry
      or transition.outcome == RetryAfterObserved)
    HttpRetryResult({ transition: transition,
      owner: transition.owner, retryAfter: transition.retryAfter })
  else if (transition.outcome == InvalidInputRejected
      or transition.outcome == AuthorisationRejected or transition.outcome == ProjectionRejected)
    HttpRejected({ transition: transition,
      result: transition.result })
  else HttpApplied({ transition: transition,
    result: transition.result, owner: transition.owner,
    retryAfter: transition.retryAfter })

  pure def httpClassFor(outcome) = if (outcome == InvalidInputRejected
      or outcome == AuthorisationRejected or outcome == ProjectionRejected)
    RejectedClass else AppliedClass

  pure val initialCommand = HttpPrepare({ members: Set() })
  pure val initialTransition = { command: initialCommand, class: AppliedClass,
    outcome: Initialised, affected: Set(), job: JobA, operation: OperationA,
    result: ItemMissing, owner: NoRetry, retryAfter: 0,
    members: Set(), results: Map() }

  action mbtInit = all { init, lastCommand' = initialCommand,
    lastTransition' = initialTransition,
    lastCommandResult' = HttpApplied({ transition: initialTransition,
      result: ItemMissing, owner: NoRetry, retryAfter: 0 }) }
  action dispatch(command: Command): bool = match command {
    | HttpPrepare(input) => all { input.members.size() <= MAX_BATCH_ITEMS,
        PrepareBatchInput(input.members), lastCommand' = command }
    | HttpInput(input) => all { JOBS.contains(input.job), input.bodyBytes >= 0,
        ReceiveInputFor(input.job, input.secret, input.bodyBytes,
          input.destinationValid), lastCommand' = command }
    | HttpAuthorize(input) => all { JOBS.contains(input.job),
        AuthorizeInput(input.job, input.auth), lastCommand' = command }
    | HttpProject(input) => all { JOBS.contains(input.job),
        CheckRequestProjectionInput(input.job, input.includeSecret), lastCommand' = command }
    | HttpExecute(input) => all { JOBS.contains(input.authority.job),
        ExecuteInput(input.authority.job, input.authority.node, input.authority.revision,
          input.authority.generation, input.authority.fence, input.authority.token,
          input.authority.leaseUntil, input.authority.operation,
          input.authority.executionId, input.authority.attemptId, input.status,
          input.transport, input.retryAfter), lastCommand' = command }
    | HttpRetryCommand(input) => all { JOBS.contains(input.job),
        RetryInput(input.job, input.owner), lastCommand' = command }
    | HttpDuplicate(input) => all { JOBS.contains(input.job),
        DuplicateDeliveryInput(input.job), lastCommand' = command }
    | HttpOmit(input) => all { JOBS.contains(input.job),
        OmitItemInput(input.job), lastCommand' = command }
  }

  action mbtStep(command: Command): bool = {
    val transition = transitionFor(command)
    all { dispatch(command), lastCommandResult' = resultFor(transition),
      lastTransition' = transition }
  }
  action mbtObserve = all {
    items' = items, meta' = meta, lastCommand' = lastCommand,
    lastTransition' = lastTransition,
    lastCommandResult' = resultFor(lastTransition),
  }

  pure def authorityFor(job, current) = { job: job, node: current.node,
    revision: current.revision, generation: current.generation, fence: current.fence,
    token: current.token, leaseUntil: current.leaseUntil, operation: current.operation,
    executionId: current.executionId, attemptId: current.attemptId }

  action mbtDispatchNondet = any {
    mbtStep(HttpPrepare({ members: Set(JobA, JobB) })),
    mbtStep(HttpInput({ job: meta.lastItem,
      secret: true, bodyBytes: MAX_INLINE_PAYLOAD_BYTES, destinationValid: true })),
    mbtStep(HttpAuthorize({ job: meta.lastItem, auth: Authorised })),
    mbtStep(HttpAuthorize({ job: meta.lastItem, auth: Denied })),
    mbtStep(HttpAuthorize({ job: meta.lastItem, auth: MissingSecret })),
    mbtStep(HttpAuthorize({ job: meta.lastItem, auth: SignFailure })),
    mbtStep(HttpProject({ job: meta.lastItem, includeSecret: false })),
    mbtStep(HttpProject({ job: meta.lastItem, includeSecret: true })),
    mbtStep(HttpExecute({ authority: authorityFor(meta.lastItem, items.get(meta.lastItem)),
      status: Status429, transport: TransportOk, retryAfter: MAX_RETRY_AFTER_TICKS })),
    mbtStep(HttpRetryCommand({ job: meta.lastItem, owner: EngineOwnsRetry })),
    mbtStep(HttpDuplicate({ job: meta.lastItem })),
    mbtStep(HttpOmit({ job: meta.lastItem })),
  }
  action mbtNondetStep = any { mbtDispatchNondet, mbtObserve }

  action fixedJobCPrepare = mbtStep(HttpPrepare({ members: Set(JobC) }))
  action fixedJobCPrepareTrace = fixedJobCPrepare
  pure val fixedJobCItems = JOBS.fold(initialItems, (current, job) => update(current,
    job, current.get(job).with("member", job == JobC)
      .with("attempts", if (job == JobC) 1 else 0)
      .with("attemptExecuted", false).with("result", ItemMissing)))
  pure val fixedJobCMeta = initialMeta.with("batchMembers", Set(JobC))
    .with("batchResults", Map(JobC -> ItemMissing)).with("lastOutcome", BatchPrepared)
  val fixed_job_c_prepare_witness = items == fixedJobCItems and meta == fixedJobCMeta
    and lastCommandResult == HttpBatchResult({ transition: { command:
      HttpPrepare({ members: Set(JobC) }), class: AppliedClass,
      outcome: BatchPrepared, affected: Set(JobC), job: JobC, operation: OperationA,
      result: ItemMissing, owner: NoRetry, retryAfter: 0,
      members: Set(JobC), results: Map(JobC -> ItemMissing) },
      members: Set(JobC), results: Map(JobC -> ItemMissing) })

  val inv_mbt_identity = lastTransition.command == lastCommand
    and lastTransition.affected == commandAffected(lastCommand)
    and lastTransition.job == commandJob(lastCommand)
    and lastTransition.operation == commandOperation(lastCommand)
  val inv_mbt_semantics = lastCommandResult == resultFor(lastTransition)
    and lastTransition.outcome == meta.lastOutcome
    and lastTransition.class == httpClassFor(lastTransition.outcome)
  val inv_mbt_batch_output = lastTransition.members == meta.batchMembers
    and lastTransition.results == meta.batchResults
  val inv_mbt_item_output = lastTransition.result == items.get(lastTransition.job).result
    and lastTransition.owner == items.get(lastTransition.job).retryOwner
    and lastTransition.retryAfter == items.get(lastTransition.job).retryAfter
  val mbtInv = inv and inv_mbt_identity and inv_mbt_semantics
    and inv_mbt_batch_output and inv_mbt_item_output
}
