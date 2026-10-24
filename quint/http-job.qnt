/// Bounded HTTP job execution and result classification.
///
/// The library owns request validation and execution, not durable persistence.
/// `HttpProject` therefore models a production request/job safety check rather
/// than a durable codec or event record. A batch records exact item membership
/// and each item's attempt/result. An execution identity remains stable across
/// retries and an attempt identity changes per invocation. Authorization,
/// destination, body, retry-after, transport/engine retry ownership, duplicate
/// delivery, and omission are all explicit choices; the model does not claim
/// to model HTTP wire bytes or cryptographic signing.
module http_job {
  import bg_jobs_types.* from "./bg-jobs-types"

  type Item = {
    job: JobId,
    member: bool,
    node: Node,
    revision: int,
    generation: int,
    fence: int,
    token: int,
    leaseUntil: int,
    operation: OperationId,
    executionId: int,
    attemptId: int,
    attempts: int,
    attemptExecuted: bool,
    inputSecret: bool,
    idempotencyHeader: int,
    destinationValid: bool,
    invalidInput: bool,
    bodyBytes: int,
    auth: AuthResult,
    status: HttpStatus,
    transport: TransportResult,
    retryAfter: int,
    retryOwner: RetryOwner,
    result: BatchResult,
    duplicate: bool,
    omitted: bool,
    outcomePresent: bool,
    outcomeJob: JobId,
    outcomeAttemptId: int,
    outcomeRevision: int,
    outcomeGeneration: int,
    outcomeFence: int,
    outcomeToken: int,
    outcomeLeaseUntil: int,
    outcomeOperation: OperationId,
  }

  /// Ephemeral metadata returned by the library's diagnostic projection.
  /// These fields are an observable receipt, not durable job state; only
  /// bounded sizes are exposed and all request content remains absent.
  type RequestDiagnostic = {
    headerCount: int,
    bodyBytes: int,
    includesUrl: bool,
    includesHeaders: bool,
    includesBody: bool,
  }

  type Meta = {
    batchMembers: Set[JobId],
    batchResults: JobId -> BatchResult,
    lastItem: JobId,
    lastOutcome: HttpOutcome,
    engineRetries: int,
    transportRetries: int,
    lastProjection: RequestDiagnostic,
  }

  type HttpOutcome = Initialised | BatchPrepared | InvalidInputRejected
    | AuthorisationRejected | HttpSuccess | HttpRetry | HttpDeadLetter | TransportRetry
    | DuplicateDelivered | ItemOmitted | RetryAfterObserved | ProjectionRejected

  type HttpExecutionEffect = { valid: bool, result: BatchResult,
    outcome: HttpOutcome, owner: RetryOwner, retryAfter: int }

  var items: JobId -> Item
  var meta: Meta

  pure def makeItem(job, execution, attempt) = {
    job: job,
    member: false,
    node: NodeA,
    revision: 1,
    generation: 1,
    fence: 2,
    token: 3,
    leaseUntil: 3,
    operation: OperationA,
    executionId: execution,
    attemptId: attempt,
    attempts: 0,
    attemptExecuted: false,
    inputSecret: false,
    idempotencyHeader: 0,
    destinationValid: true,
    invalidInput: false,
    bodyBytes: 0,
    auth: Authorised,
    status: Status2xx,
    transport: TransportOk,
    retryAfter: 0,
    retryOwner: NoRetry,
    result: ItemMissing,
    duplicate: false,
    omitted: false,
    outcomePresent: false,
    outcomeJob: job,
    outcomeAttemptId: 0,
    outcomeRevision: 0,
    outcomeGeneration: 0,
    outcomeFence: 0,
    outcomeToken: 0,
    outcomeLeaseUntil: 0,
    outcomeOperation: OperationA,
  }

  pure def initialItems = Map(JobA -> makeItem(JobA, 1, 1), JobB -> makeItem(JobB, 2, 1),
    JobC -> makeItem(JobC, 3, 1))
  pure def initialMeta = {
    batchMembers: Set(),
    batchResults: Map(),
    lastItem: JobA,
    lastOutcome: Initialised,
    engineRetries: 0,
    transportRetries: 0,
    lastProjection: safeRequestDiagnostic(makeItem(JobA, 1, 1)),
  }

  /// The library-owned projection is intentionally metadata-only. It is
  /// separate from durable job state because this crate does not own storage.
  pure def safeRequestDiagnostic(current) = {
    headerCount: 0,
    bodyBytes: current.bodyBytes,
    includesUrl: false,
    includesHeaders: false,
    includesBody: false,
  }

  pure def requestDiagnosticSafe(projection) = not(projection.includesUrl)
    and not(projection.includesHeaders) and not(projection.includesBody)
    and projection.headerCount >= 0 and projection.bodyBytes >= 0
    and projection.bodyBytes <= MAX_INLINE_PAYLOAD_BYTES

  def memberItems = meta.batchMembers
  def unresolvedItems = memberItems.filter(job => items.get(job).result == ItemMissing
    and not(items.get(job).attemptExecuted))
  def retryableStatus(status) = statusIsRetryable(status)
  pure def updateBatchResult(results, members, job, result) =
    if (members.contains(job)) update(results, job, result) else results

  pure def httpExecutionAllowed(current, presentedNode, presentedRevision,
      presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
      presentedOperation, presentedExecution, presentedAttempt) =
    exactAuthority(current.node, current.revision, current.generation,
      current.fence, current.token, current.leaseUntil, current.operation,
      presentedNode, presentedRevision, presentedGeneration, presentedFence,
      presentedToken, presentedLeaseUntil, presentedOperation, 0)
      and presentedExecution == current.executionId and presentedAttempt == current.attemptId
      and current.member and not(current.attemptExecuted) and current.result == ItemMissing
      and current.auth == Authorised
      and current.destinationValid and current.bodyBytes <= MAX_INLINE_PAYLOAD_BYTES
      and current.idempotencyHeader == current.executionId

  pure def httpExecutionEffect(current, valid, status, transport,
      retryAfter) = {
    val transportRetry = valid and transport != TransportOk
    val engineRetry = valid and transport == TransportOk and retryableStatus(status)
    val retry = (transportRetry or engineRetry) and current.attempts < MAX_ATTEMPTS
    { valid: valid,
      result: if (not(valid)) current.result else if (retry) ItemRetry
        else if (statusIsSuccess(status) and not(transportRetry)) ItemSuccess
        else ItemDeadLetter,
      outcome: if (not(valid)) InvalidInputRejected
        else if (retry and engineRetry and retryAfter != 0) RetryAfterObserved
        else if (retry) HttpRetry
        else if (statusIsSuccess(status) and not(transportRetry)) HttpSuccess
        else HttpDeadLetter,
      owner: if (not(valid)) current.retryOwner
        else if (retry) EngineOwnsRetry else NoRetry,
      retryAfter: if (valid) clampRetryAfter(retryAfter) else current.retryAfter }
  }

  pure def httpOmissionAllowed(current) = current.member
    and current.result == ItemMissing and not(current.attemptExecuted)
    and current.attempts < MAX_ATTEMPTS

  pure def httpRetryAllowed(current, owner) = owner == current.retryOwner
    and current.member and current.retryOwner == EngineOwnsRetry
    and current.attempts < MAX_ATTEMPTS

  pure def retriedItem(current) = current.with("result", ItemMissing)
    .with("attempts", current.attempts + 1).with("attemptId", current.attemptId + 1)
    .with("idempotencyHeader", 0)
    .with("outcomePresent", false).with("attemptExecuted", false)
    .with("retryOwner", NoRetry).with("duplicate", false).with("omitted", false)

  pure def omittedItem(current) = current.with("omitted", true).with("result", ItemRetry)
    .with("retryOwner", EngineOwnsRetry).with("attemptExecuted", true)

  /// The executor's identity header is an opaque value derived from the
  /// stable execution ID. This is a consistency check only; the library does
  /// not persist the request or credentials.
  val inv_idempotency = JOBS.forall(job =>
    items.get(job).idempotencyHeader == 0
      or items.get(job).idempotencyHeader == items.get(job).executionId
  )
  val inv_secret_projection = requestDiagnosticSafe(meta.lastProjection)
  val inv_batch_membership = meta.batchMembers.forall(job => items.get(job).member
    and meta.batchResults.keys().contains(job)
    and meta.batchResults.get(job) == items.get(job).result)
    and meta.batchResults.keys().forall(job => meta.batchMembers.contains(job))
  val inv_attempt_identity = JOBS.forall(job => items.get(job).executionId > 0
    and items.get(job).attemptId > 0 and items.get(job).attempts >= 0
    and items.get(job).attempts <= MAX_ATTEMPTS
    and (items.get(job).outcomePresent implies items.get(job).attemptExecuted))
  val inv_retry_ownership = meta.transportRetries == 0 and JOBS.forall(job =>
    items.get(job).retryOwner != EngineOwnsRetry or items.get(job).omitted
      or items.get(job).transport != TransportOk or statusIsRetryable(items.get(job).status))
  val inv_bounds = JOBS.forall(job => items.get(job).bodyBytes >= 0
    and items.get(job).bodyBytes <= MAX_INLINE_PAYLOAD_BYTES
    and items.get(job).retryAfter >= 0 and items.get(job).retryAfter <= MAX_RETRY_AFTER_TICKS)
  val inv_classification = JOBS.forall(job =>
    items.get(job).result != ItemSuccess or (items.get(job).status == Status2xx
      and items.get(job).transport == TransportOk and items.get(job).auth == Authorised)
  )
  val inv_scoped_outcome = JOBS.forall(job => not(items.get(job).outcomePresent) or (
    items.get(job).outcomeJob == job
      and items.get(job).outcomeAttemptId == items.get(job).attemptId
      and items.get(job).outcomeRevision == items.get(job).revision
      and items.get(job).outcomeGeneration == items.get(job).generation
      and items.get(job).outcomeFence == items.get(job).fence
      and items.get(job).outcomeToken == items.get(job).token
      and items.get(job).outcomeLeaseUntil == items.get(job).leaseUntil
      and items.get(job).outcomeOperation == items.get(job).operation))
  val inv_terminal_immutable = JOBS.forall(job =>
    (items.get(job).result == ItemSuccess or items.get(job).result == ItemDeadLetter)
      implies items.get(job).outcomePresent or items.get(job).invalidInput
        or items.get(job).auth != Authorised)
  val inv_delivery_guards = JOBS.forall(job =>
    (items.get(job).duplicate implies items.get(job).member
      and (items.get(job).result == ItemMissing or items.get(job).result == ItemRetry))
    and (items.get(job).omitted implies items.get(job).member
      and items.get(job).result == ItemRetry
      and items.get(job).retryOwner == EngineOwnsRetry
      and items.get(job).attemptExecuted and items.get(job).attempts < MAX_ATTEMPTS))
  val inv_one_execution_per_attempt = JOBS.forall(job =>
    not(items.get(job).attemptExecuted) or items.get(job).result != ItemMissing)
  val inv_omission_retry_progress = JOBS.forall(job => not(items.get(job).omitted)
    or (items.get(job).retryOwner == EngineOwnsRetry
      and items.get(job).result == ItemRetry and items.get(job).attempts < MAX_ATTEMPTS))
  val inv = and {
    inv_idempotency,
    inv_secret_projection,
    inv_batch_membership,
    inv_attempt_identity,
    inv_retry_ownership,
    inv_bounds,
    inv_classification,
    inv_scoped_outcome,
    inv_terminal_immutable,
    inv_delivery_guards,
    inv_one_execution_per_attempt,
    inv_omission_retry_progress,
  }
  val inv_except_idempotency = and {
    inv_secret_projection,
    inv_batch_membership, inv_attempt_identity,
    inv_retry_ownership, inv_bounds, inv_classification, inv_scoped_outcome,
    inv_terminal_immutable, inv_delivery_guards, inv_one_execution_per_attempt,
    inv_omission_retry_progress,
  }
  val inv_http_safety = inv_idempotency and inv_secret_projection
  val inv_except_http_safety = and {
    inv_batch_membership, inv_attempt_identity,
    inv_retry_ownership, inv_bounds, inv_classification, inv_scoped_outcome,
    inv_terminal_immutable, inv_delivery_guards, inv_one_execution_per_attempt,
    inv_omission_retry_progress,
  }

  action init = all {
    items' = initialItems,
    meta' = initialMeta,
  }

  action PrepareBatchInput(members: Set[JobId]): bool = {
    val prepared = JOBS.fold(items, (currentItems, job) =>
      update(currentItems, job, currentItems.get(job).with("member", members.contains(job))
        .with("attempts", if (members.contains(job)) 1 else 0)
        .with("attemptExecuted", false).with("result", ItemMissing)))
    val results = members.fold(Map(), (currentResults, job) =>
      currentResults.put(job, ItemMissing))
    all {
      meta.batchMembers.size() == 0,
      members.subseteq(JOBS) and members.size() <= MAX_BATCH_ITEMS,
      items' = prepared,
      meta' = meta.with("batchMembers", members).with("batchResults", results)
        .with("lastOutcome", BatchPrepared),
    }
  }


  action PrepareBatch = PrepareBatchInput(Set(JobA, JobB))

  action ReceiveInputFor(job: JobId, secret: bool, body: int,
      destinationValid: bool): bool = {
    val current = items.get(job)
    val eligible = current.member and current.result == ItemMissing
      and not(current.attemptExecuted)
    val valid = eligible and body <= MAX_INLINE_PAYLOAD_BYTES and destinationValid
    val result = if (valid) ItemMissing else ItemDeadLetter
    all {
      items' = if (eligible) update(items, job, current.with("inputSecret", secret)
        .with("bodyBytes", if (body <= MAX_INLINE_PAYLOAD_BYTES) body else 0)
        .with("invalidInput", not(valid)).with("destinationValid", destinationValid)
        .with("idempotencyHeader", 0)
        .with("duplicate", false).with("omitted", false).with("result", result)) else items,
      meta' = meta.with("batchResults", if (eligible)
          updateBatchResult(meta.batchResults, meta.batchMembers, job, result)
        else meta.batchResults)
        .with("lastItem", job).with("lastOutcome", if (valid) Initialised else InvalidInputRejected),
    }
  }


  action ReceiveInput = {
    nondet job = unresolvedItems.oneOf()
    nondet secret = bools.oneOf()
    nondet body = Set(0, MAX_INLINE_PAYLOAD_BYTES, MAX_INLINE_PAYLOAD_BYTES + 1).oneOf()
    nondet destinationValid = bools.oneOf()
    ReceiveInputFor(job, secret, body, destinationValid)
  }

  action AuthorizeInput(job: JobId, auth: AuthResult): bool = {
    val current = items.get(job)
    val eligible = current.member and current.result == ItemMissing
      and not(current.attemptExecuted)
    val allowed = eligible and current.destinationValid and current.bodyBytes <= MAX_INLINE_PAYLOAD_BYTES
      and auth == Authorised
    val itemResult = if (not(eligible)) current.result
      else if (allowed) current.result else ItemDeadLetter
    val result = current.with("auth", auth)
      .with("idempotencyHeader", if (allowed) current.executionId else 0)
      .with("result", itemResult)
      .with("duplicate", false).with("omitted", false)
    all {
      items' = if (eligible) update(items, job, result) else items,
      meta' = meta.with("batchResults", updateBatchResult(meta.batchResults, meta.batchMembers, job, itemResult))
        .with("lastItem", job).with("lastOutcome", if (allowed) Initialised else AuthorisationRejected),
    }
  }


  action Authorize = {
    nondet job = unresolvedItems.oneOf()
    nondet auth = Set(Authorised, Denied, MissingSecret, SignFailure).oneOf()
    AuthorizeInput(job, auth)
  }

  action CheckRequestProjectionInput(job: JobId, includeSecret: bool): bool = {
    val current = items.get(job)
    val projection = safeRequestDiagnostic(current)
    val allowed = not(includeSecret) and requestDiagnosticSafe(projection)
      and current.member and not(current.invalidInput)
      and current.result == ItemMissing and not(current.attemptExecuted)
      and current.auth == Authorised and current.destinationValid
      and current.bodyBytes <= MAX_INLINE_PAYLOAD_BYTES
    all {
      items' = items,
      meta' = meta.with("batchResults", if (allowed)
        updateBatchResult(meta.batchResults, meta.batchMembers, job, ItemMissing) else meta.batchResults)
        .with("lastItem", job).with("lastOutcome", if (allowed)
        Initialised else ProjectionRejected)
        .with("lastProjection", if (allowed) projection else meta.lastProjection),
    }
  }


  action CheckRequestProjection = {
    nondet job = unresolvedItems.oneOf()
    CheckRequestProjectionInput(job, false)
  }

  action ExecuteInput(job: JobId, presentedNode: Node, presentedRevision: int,
      presentedGeneration: int, presentedFence: int, presentedToken: int,
      presentedLeaseUntil: int, presentedOperation: OperationId,
      presentedExecution: int, presentedAttempt: int, status: HttpStatus,
      transport: TransportResult, retryAfter: int): bool = {
    val current = items.get(job)
    val valid = httpExecutionAllowed(current, presentedNode, presentedRevision,
      presentedGeneration, presentedFence, presentedToken, presentedLeaseUntil,
      presentedOperation, presentedExecution, presentedAttempt)
    val effect = httpExecutionEffect(current, valid, status, transport, retryAfter)
    val attempted = current.with("status", status).with("transport", transport)
      .with("retryAfter", effect.retryAfter)
      .with("retryOwner", effect.owner).with("result", effect.result).with("outcomePresent", valid)
      .with("attemptExecuted", if (valid) true else current.attemptExecuted)
      .with("outcomeJob", job).with("outcomeAttemptId", current.attemptId)
      .with("outcomeRevision", current.revision).with("outcomeGeneration", current.generation)
      .with("outcomeFence", current.fence).with("outcomeToken", current.token)
      .with("outcomeLeaseUntil", current.leaseUntil).with("outcomeOperation", current.operation)
      .with("duplicate", false).with("omitted", false)
    all {
      items' = if (valid) update(items, job, attempted) else items,
      meta' = meta.with("batchResults", updateBatchResult(meta.batchResults, meta.batchMembers,
          job, effect.result))
        .with("lastItem", job).with("engineRetries", meta.engineRetries)
        .with("transportRetries", meta.transportRetries)
        .with("lastOutcome", effect.outcome),
    }
  }


  action Execute = {
    nondet job = unresolvedItems.oneOf()
    nondet status = Set(Status2xx, Status408, Status425, Status429, Status4xx, Status5xx).oneOf()
    nondet transport = Set(TransportOk, Timeout, ConnectFailure, InvalidResponse).oneOf()
    nondet retryAfter = Set(-1, 0, MAX_RETRY_AFTER_TICKS, MAX_RETRY_AFTER_TICKS + 1).oneOf()
    val current = items.get(job)
    ExecuteInput(job, current.node, current.revision, current.generation, current.fence,
      current.token, current.leaseUntil, current.operation, current.executionId,
      current.attemptId, status, transport, retryAfter)
  }

  // Rejected execution presents the same complete authority vocabulary as an
  // accepted execution.  It is a distinct command so random exploration can
  // exercise both the happy path and wrong-job/stale rejection without making
  // the exact authorized tuple vanishingly rare.
  action ExecuteRejected = {
    nondet job = unresolvedItems.oneOf()
    nondet presentedJob = JOBS.oneOf()
    nondet node = NODES.oneOf()
    nondet presentedRevision = authorityChoices(items.get(job).revision).oneOf()
    nondet presentedGeneration = authorityChoices(items.get(job).generation).oneOf()
    nondet presentedFence = authorityChoices(items.get(job).fence).oneOf()
    nondet presentedToken = authorityChoices(items.get(job).token).oneOf()
    nondet presentedLeaseUntil = authorityChoices(items.get(job).leaseUntil).oneOf()
    nondet operation = OPERATIONS.oneOf()
    val current = items.get(job)
    val authority = presentedJob == job and exactAuthority(current.node, current.revision,
      current.generation, current.fence, current.token, current.leaseUntil,
      current.operation, node, presentedRevision, presentedGeneration,
      presentedFence, presentedToken, presentedLeaseUntil, operation, 0)
    all {
      not(authority),
      items' = items,
      meta' = meta.with("lastItem", job).with("lastOutcome", ProjectionRejected),
    }
  }

  action RetryInput(job: JobId, owner: RetryOwner): bool = {
    val current = items.get(job)
    val allowed = httpRetryAllowed(current, owner)
    val retried = retriedItem(current)
    all {
      items' = if (allowed) update(items, job, retried) else items,
      meta' = meta.with("batchResults", if (allowed)
        updateBatchResult(meta.batchResults, meta.batchMembers, job, ItemMissing) else meta.batchResults)
        .with("lastItem", job)
        .with("engineRetries", if (allowed) meta.engineRetries + 1 else meta.engineRetries)
        .with("lastOutcome", if (allowed) HttpRetry else ProjectionRejected),
    }
  }


  action Retry = {
    nondet job = memberItems.filter(candidate => items.get(candidate).result == ItemRetry).oneOf()
    RetryInput(job, EngineOwnsRetry)
  }

  action DuplicateDeliveryInput(job: JobId): bool = {
    val current = items.get(job)
    all {
      items' = if (current.member and (current.result == ItemMissing or current.result == ItemRetry))
        update(items, job, current.with("duplicate", true)) else items,
      meta' = meta.with("lastItem", job).with("lastOutcome",
        if (current.member and (current.result == ItemMissing or current.result == ItemRetry))
          DuplicateDelivered else ProjectionRejected),
    }
  }


  action DuplicateDelivery = {
    nondet job = unresolvedItems.oneOf()
    DuplicateDeliveryInput(job)
  }

  action OmitItemInput(job: JobId): bool = {
    val current = items.get(job)
    val allowed = httpOmissionAllowed(current)
    all {
      items' = if (allowed) update(items, job,
        omittedItem(current)) else items,
      meta' = meta.with("batchResults", if (allowed)
        updateBatchResult(meta.batchResults, meta.batchMembers, job, ItemRetry)
        else meta.batchResults).with("lastItem", job)
        .with("lastOutcome", if (allowed) ItemOmitted else ProjectionRejected),
    }
  }


  action OmitItem = {
    nondet job = unresolvedItems.oneOf()
    OmitItemInput(job)
  }

  action OmissionRetryWitnessStep = if (meta.batchMembers.size() == 0)
    PrepareBatchInput(Set(JobA))
  else if (not(items.get(JobA).inputSecret))
    ReceiveInputFor(JobA, true, 1, true)
  else if (items.get(JobA).omitted)
    RetryInput(JobA, EngineOwnsRetry)
  else OmitItemInput(JobA)

  action step = any {
    PrepareBatch, ReceiveInput, Authorize, CheckRequestProjection, Execute, ExecuteRejected, Retry,
    DuplicateDelivery, OmitItem,
  }

  val status_success_witness = meta.lastOutcome == HttpSuccess
  val status_retry_witness = meta.lastOutcome == HttpRetry or meta.lastOutcome == RetryAfterObserved
  val status_dead_letter_witness = meta.lastOutcome == HttpDeadLetter
  val omission_retry_rearmed_witness = items.get(JobA).attempts == 2
    and items.get(JobA).attemptId == 2 and not(items.get(JobA).attemptExecuted)
    and items.get(JobA).result == ItemMissing and items.get(JobA).retryOwner == NoRetry
    and not(items.get(JobA).omitted) and meta.engineRetries == 1
  val transport_timeout_witness = JOBS.exists(job => items.get(job).transport == Timeout)
  val transport_connect_witness = JOBS.exists(job => items.get(job).transport == ConnectFailure)
  val transport_invalid_witness = JOBS.exists(job => items.get(job).transport == InvalidResponse)
  val retry_after_witness = meta.lastOutcome == RetryAfterObserved
  val auth_failure_witness = meta.lastOutcome == AuthorisationRejected
  val partial_batch_witness = meta.batchMembers.size() > 0 and meta.batchResults.keys().contains(JobA)
  val stable_idempotency_witness = JOBS.exists(job => items.get(job).executionId > 0
    and items.get(job).attemptId > items.get(job).executionId)

  run retry_owner_is_single = all {
    assert(httpRetryOwner(Status429, TransportOk) == EngineOwnsRetry),
    assert(httpRetryOwner(Status2xx, Timeout) == EngineOwnsRetry),
    assert(httpRetryOwner(Status2xx, TransportOk) == NoRetry),
    assert(clampRetryAfter(MAX_RETRY_AFTER_TICKS + 1) == MAX_RETRY_AFTER_TICKS),
    assert(clampRetryAfter(-1) == RETRY_AFTER_FALLBACK_TICKS),
  }

  run independent_payload_bound = all {
    assert(MAX_INLINE_PAYLOAD_BYTES == 972800),
    assert(MAX_RETRY_AFTER_TICKS < MAX_INLINE_PAYLOAD_BYTES),
  }

  run retry_and_batch_guards = all {
    assert(initialMeta.transportRetries == 0),
    assert(initialItems.get(JobA).executionId == 1),
    assert(initialItems.get(JobA).attemptId == 1),
    assert(not(initialItems.get(JobC).member)),
    assert(clampRetryAfter(MAX_RETRY_AFTER_TICKS + 1) == MAX_RETRY_AFTER_TICKS),
    assert(initialItems.get(JobA).idempotencyHeader == 0),
  }

  run one_execution_requires_an_explicit_new_attempt = {
    val fresh = makeItem(JobA, 7, 3).with("member", true).with("attempts", 1)
      .with("idempotencyHeader", 7)
    val executed = fresh.with("attemptExecuted", true).with("result", ItemRetry)
      .with("retryOwner", EngineOwnsRetry)
    val retried = retriedItem(executed)
    val omitted = omittedItem(fresh)
    all {
      assert(httpExecutionAllowed(fresh, fresh.node, fresh.revision, fresh.generation,
        fresh.fence, fresh.token, fresh.leaseUntil, fresh.operation,
        fresh.executionId, fresh.attemptId)),
      assert(not(httpExecutionAllowed(executed, executed.node, executed.revision,
        executed.generation, executed.fence, executed.token, executed.leaseUntil,
        executed.operation, executed.executionId, executed.attemptId))),
      assert(retried.attemptId == executed.attemptId + 1
        and not(retried.attemptExecuted) and retried.result == ItemMissing),
      assert(omitted.result == ItemRetry and omitted.retryOwner == EngineOwnsRetry
        and omitted.attemptExecuted
        and not(httpExecutionAllowed(omitted, omitted.node, omitted.revision,
          omitted.generation, omitted.fence, omitted.token, omitted.leaseUntil,
          omitted.operation, omitted.executionId, omitted.attemptId))),
    }
  }
}
