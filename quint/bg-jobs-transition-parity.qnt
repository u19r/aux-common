/// Cross-family parity over authoritative reducers and complete contract state.
module bg_jobs_transition_parity {
  import bg_jobs_types.* from "./bg-jobs-types"
  import job_schedule_wake as schedule from "./job-schedule-wake"
  import job_fair_dispatch as fair from "./job-fair-dispatch"
  import job_lifecycle as lifecycle from "./job-lifecycle"
  import job_store_protocol as store from "./job-store-protocol"
  import bg_jobs_system as composite from "./bg-jobs-system"

  pure def occurrenceFor(job) = if (job == JobA) Occ1 else if (job == JobB) Occ2 else Occ3

  pure def compositeJobsFrom(family, base) = JOBS.mapBy(job => {
    val state = family.jobState.get(job)
    base.jobs.get(job).with("state", state).with("record", Valid)
      .with("payload", state != Absent).with("revision", family.jobRevision.get(job))
      .with("enqueueFingerprint", if (state == Absent) 0
        else max(1, family.jobExecutionId.get(job)))
      .with("payloadBytes", if (state == Absent) 0
        else max(1, family.jobExecutionId.get(job)))
      .with("manifestBytes", if (state == Absent) 0
        else max(1, family.jobExecutionId.get(job) + 1))
      .with("chunkBytes", if (state == Absent) 0
        else max(1, family.jobExecutionId.get(job) + 2))
      .with("digestBytes", if (state == Absent) 0
        else max(1, family.jobExecutionId.get(job) + 3))
      .with("checkpointBytes", 0).with("dlqRoute", state == DeadLettered)
      .with("generation", family.jobGeneration.get(job))
      .with("fence", family.jobFence.get(job)).with("token", family.jobToken.get(job))
      .with("leaseUntil", family.jobLeaseUntil.get(job)).with("node", family.jobNode.get(job))
      .with("dueRoute", family.jobDueRoute.get(job))
      .with("fairRoute", family.jobFairRoute.get(job))
      .with("leaseRoute", family.jobLeaseRoute.get(job))
      .with("wakeRoute", family.jobWakeRoute.get(job))
      .with("attempts", family.jobAttempts.get(job))
      .with("attemptId", family.jobAttemptId.get(job))
      .with("executionId", family.jobExecutionId.get(job))
      .with("dueAt", family.now).with("expiresAt", family.now + MAX_JOB_AGE_TICKS)
      .with("failureRecorded", state == DeadLettered)
      .with("occurrence", occurrenceFor(job))
      .with("completionReceipt", false).with("completionPending", false)
  })

  pure def compositeFromFamily(family) = {
    val base = composite::initialSystem
    val selected = if (family.jobState.get(JobA) == Leased) JobA
      else if (family.jobState.get(JobB) == Leased) JobB
      else if (family.jobState.get(JobC) == Leased) JobC else JobA
    base.with("jobs", compositeJobsFrom(family, base))
      .with("emitted", family.emitted).with("emissionCount", family.emissionCount)
      .with("occurrenceIdentity", family.occurrenceIdentity)
      .with("previousIdentity", family.previousIdentity)
      .with("materialized", family.materialized).with("completed", family.completed)
      .with("durableRoute", family.durableRoute)
      .with("scheduleRevision", family.revision).with("watermark", family.watermark)
      .with("nextDue", family.nextDue).with("scheduleMisfire", family.misfire)
      .with("catchUpLimit", family.catchUpLimit).with("lastBacklog", family.lastBacklog)
      .with("skippedRemainder", family.skippedRemainder)
      .with("lastEvaluationNow", family.lastEvaluationNow).with("now", family.now)
      .with("scheduleEnabled", family.enabled).with("paused", family.paused)
      .with("overlap", family.overlap).with("wakePending", family.wakePending)
      .with("wakeToken", family.wakeToken).with("wakeAt", family.wakeAt)
      .with("materializePending", family.materializePending)
      .with("materializeOccurrence", family.materializeOccurrence)
      .with("materializeRevision", family.materializeRevision)
      .with("materializeReader", family.materializeReader)
      .with("selectedJob", selected).with("selectedScope", family.fairScope.get(selected))
      .with("selectedHead", family.fairOrder.get(selected)).with("claimPending", false)
      .with("fairReady", family.fairReady).with("fairPriority", family.fairPriority)
      .with("fairHead", family.fairOrder).with("fairOrder", family.fairOrder)
      .with("fairPermits", family.fairPermits).with("fairRate", family.fairRate)
      .with("fairInFlight", family.fairInFlight).with("fairServed", family.fairServed)
      .with("fairCost", family.fairCost).with("fairWeight", family.fairWeight)
      .with("fairOrdering", family.fairOrdering)
      .with("orderHead", family.orderHead).with("orderInFlight", family.orderInFlight)
      .with("orderOwner", family.orderOwner).with("fairCritical", family.fairCritical)
      .with("fairDefault", family.fairDefault).with("fairBulk", family.fairBulk)
      .with("fairCycle", family.fairCycle).with("lastClaimNode", family.lastClaimNode)
      .with("activePulses", family.activePulses).with("pulseActions", family.pulseActions)
      .with("progressCounter", family.progressCounter)
      .with("driveProgressBefore", family.driveProgressBefore)
      .with("driveProgressAfter", family.driveProgressAfter)
  }

  pure def familyTerminalJobs(current) = JOBS.filter(job =>
    current.completed.get(occurrenceFor(job)))
  pure def familyCompletionJob(current) = if (current.completed.get(Occ1)) JobA
    else if (current.completed.get(Occ2)) JobB else JobC
  pure def familySelectedJob(current) = if (current.jobState.get(JobA) == Leased) JobA
    else if (current.jobState.get(JobB) == Leased) JobB
    else if (current.jobState.get(JobC) == Leased) JobC else JobA

  pure def familyProjection(current) = {
    enabled: current.enabled, paused: current.paused, overlap: current.overlap,
    misfire: current.misfire, now: current.now, emitted: current.emitted,
    emissionCount: current.emissionCount, occurrenceJob: current.occurrenceJob,
    occurrenceIdentity: current.occurrenceIdentity, previousIdentity: current.previousIdentity,
    materialized: current.materialized, completed: current.completed,
    durableRoute: current.durableRoute, revision: current.revision,
    watermark: current.watermark, nextDue: current.nextDue,
    catchUpLimit: current.catchUpLimit, lastBacklog: current.lastBacklog,
    skippedRemainder: current.skippedRemainder, lastEvaluationNow: current.lastEvaluationNow,
    jobState: current.jobState, jobRevision: current.jobRevision,
    jobRecord: JOBS.mapBy(_ => Valid),
    jobPayload: JOBS.mapBy(job => current.jobState.get(job) != Absent),
    jobDueAt: JOBS.mapBy(_ => current.now),
    jobDeadline: JOBS.mapBy(_ => current.now + MAX_JOB_AGE_TICKS),
    jobFailure: JOBS.mapBy(job => current.jobState.get(job) == DeadLettered),
    jobGeneration: current.jobGeneration, jobFence: current.jobFence,
    jobToken: current.jobToken, jobLeaseUntil: current.jobLeaseUntil,
    jobNode: current.jobNode, jobDueRoute: current.jobDueRoute,
    jobFairRoute: current.jobFairRoute, jobLeaseRoute: current.jobLeaseRoute,
    jobWakeRoute: current.jobWakeRoute, jobAttempts: current.jobAttempts,
    jobAttemptId: current.jobAttemptId, jobExecutionId: current.jobExecutionId,
    jobOperation: JOBS.mapBy(_ => OperationA),
    completionReceipt: JOBS.mapBy(_ => false),
    completionPending: JOBS.mapBy(job => familyTerminalJobs(current).contains(job)),
    completionRevision: JOBS.mapBy(job => if (familyTerminalJobs(current).contains(job))
      current.jobRevision.get(job) else 0),
    completionGeneration: JOBS.mapBy(job => if (familyTerminalJobs(current).contains(job))
      current.jobGeneration.get(job) else 0),
    wakePending: current.wakePending, wakeToken: current.wakeToken, wakeAt: current.wakeAt,
    materializePending: current.materializePending,
    materializeOccurrence: current.materializeOccurrence,
    materializeRevision: current.materializeRevision,
    materializeReader: current.materializeReader,
    fairReady: current.fairReady, fairScope: current.fairScope,
    fairPriority: current.fairPriority, fairCost: current.fairCost,
    fairPayloadBytes: current.fairCost,
    fairBlock: JOBS.mapBy(_ => Unblocked),
    fairCapacity: JOBS.mapBy(_ => MAX_CONCURRENCY_PER_SCOPE),
    fairWeight: current.fairWeight, fairOrder: current.fairOrder,
    fairOrdering: current.fairOrdering, fairPermits: current.fairPermits,
    fairRate: current.fairRate, fairInFlight: current.fairInFlight,
    fairServed: current.fairServed, orderHead: current.orderHead,
    orderInFlight: current.orderInFlight, orderOwner: current.orderOwner,
    fairCritical: current.fairCritical, fairDefault: current.fairDefault,
    fairBulk: current.fairBulk, fairCycle: current.fairCycle,
    selectedJob: familySelectedJob(current),
    selectedScope: current.fairScope.get(familySelectedJob(current)),
    selectedHead: if (familyTerminalJobs(current).contains(familySelectedJob(current))) 0
      else current.fairOrder.get(familySelectedJob(current)),
    claimPending: false, lastClaimNode: current.lastClaimNode,
    terminalJobs: familyTerminalJobs(current),
    terminalDeletedJobs: JOBS.filter(job => current.jobState.get(job) == Absent
      and familyTerminalJobs(current).contains(job)),
    deadLetteredJobs: JOBS.filter(job => current.jobState.get(job) == DeadLettered),
    completionDetail: NoCompletionDetail,
    completionDetailJob: if (familyTerminalJobs(current).size() > 0)
      familyCompletionJob(current) else JobA,
    completionOmissions: 0,
    progressCounter: current.progressCounter, pulseActions: current.pulseActions,
    activePulses: current.activePulses, pulseExited: current.pulseExited,
    driveProgressBefore: current.driveProgressBefore,
    driveProgressAfter: current.driveProgressAfter,
    driveResult: current.lastDriveBranch, driveBranch: current.lastDriveBranch,
    driveWork: current.lastDriveWork,
    driveStop: current.lastDriveStop,
  }

  pure def compositeProjection(current) = {
    enabled: current.scheduleEnabled, paused: current.paused, overlap: current.overlap,
    misfire: current.scheduleMisfire, now: current.now, emitted: current.emitted,
    emissionCount: current.emissionCount, occurrenceJob: current.occurrenceJob,
    occurrenceIdentity: current.occurrenceIdentity, previousIdentity: current.previousIdentity,
    materialized: current.materialized, completed: current.completed,
    durableRoute: current.durableRoute,
    revision: current.scheduleRevision, watermark: current.watermark, nextDue: current.nextDue,
    catchUpLimit: current.catchUpLimit, lastBacklog: current.lastBacklog,
    skippedRemainder: current.skippedRemainder, lastEvaluationNow: current.lastEvaluationNow,
    jobState: JOBS.mapBy(job => current.jobs.get(job).state),
    jobRevision: JOBS.mapBy(job => current.jobs.get(job).revision),
    jobRecord: JOBS.mapBy(job => current.jobs.get(job).record),
    jobPayload: JOBS.mapBy(job => current.jobs.get(job).payload),
    jobDueAt: JOBS.mapBy(job => current.jobs.get(job).dueAt),
    jobDeadline: JOBS.mapBy(job => current.jobs.get(job).expiresAt),
    jobFailure: JOBS.mapBy(job => current.jobs.get(job).failureRecorded),
    jobGeneration: JOBS.mapBy(job => current.jobs.get(job).generation),
    jobFence: JOBS.mapBy(job => current.jobs.get(job).fence),
    jobToken: JOBS.mapBy(job => current.jobs.get(job).token),
    jobLeaseUntil: JOBS.mapBy(job => current.jobs.get(job).leaseUntil),
    jobNode: JOBS.mapBy(job => current.jobs.get(job).node),
    jobDueRoute: JOBS.mapBy(job => current.jobs.get(job).dueRoute),
    jobFairRoute: JOBS.mapBy(job => current.jobs.get(job).fairRoute),
    jobLeaseRoute: JOBS.mapBy(job => current.jobs.get(job).leaseRoute),
    jobWakeRoute: JOBS.mapBy(job => current.jobs.get(job).wakeRoute),
    jobAttempts: JOBS.mapBy(job => current.jobs.get(job).attempts),
    jobAttemptId: JOBS.mapBy(job => current.jobs.get(job).attemptId),
    jobExecutionId: JOBS.mapBy(job => current.jobs.get(job).executionId),
    jobOperation: JOBS.mapBy(job => current.jobs.get(job).operationId),
    completionReceipt: JOBS.mapBy(job => current.jobs.get(job).completionReceipt),
    completionPending: JOBS.mapBy(job => current.jobs.get(job).completionPending),
    completionRevision: JOBS.mapBy(job => current.jobs.get(job).completionRevision),
    completionGeneration: JOBS.mapBy(job => current.jobs.get(job).completionGeneration),
    wakePending: current.wakePending, wakeToken: current.wakeToken, wakeAt: current.wakeAt,
    materializePending: current.materializePending,
    materializeOccurrence: current.materializeOccurrence,
    materializeRevision: current.materializeRevision,
    materializeReader: current.materializeReader,
    fairReady: current.fairReady,
    fairScope: JOBS.mapBy(job => composite::jobScope(job)),
    fairPriority: current.fairPriority, fairCost: current.fairCost,
    fairPayloadBytes: current.fairPayloadBytes, fairBlock: current.fairBlock,
    fairCapacity: JOBS.mapBy(_ => MAX_CONCURRENCY_PER_SCOPE),
    fairWeight: current.fairWeight, fairOrder: current.fairOrder,
    fairOrdering: current.fairOrdering, fairPermits: current.fairPermits,
    fairRate: current.fairRate, fairInFlight: current.fairInFlight,
    fairServed: current.fairServed, orderHead: current.orderHead,
    orderInFlight: current.orderInFlight, orderOwner: current.orderOwner,
    fairCritical: current.fairCritical, fairDefault: current.fairDefault,
    fairBulk: current.fairBulk, fairCycle: current.fairCycle,
    selectedJob: current.selectedJob, selectedScope: current.selectedScope,
    selectedHead: current.selectedHead, claimPending: current.claimPending,
    lastClaimNode: current.lastClaimNode,
    terminalJobs: current.committedTerminalJobs,
    terminalDeletedJobs: JOBS.filter(job => current.jobs.get(job).state == Absent
      and current.committedTerminalJobs.contains(job)),
    deadLetteredJobs: JOBS.filter(job => current.jobs.get(job).state == DeadLettered),
    completionDetail: current.completionDetail,
    completionDetailJob: current.completionDetailJob,
    completionOmissions: current.completionOmissions,
    progressCounter: current.progressCounter, pulseActions: current.pulseActions,
    activePulses: current.activePulses,
    pulseExited: current.activePulses == 0 and (current.lastDriveBranch == KernelPaused
      or current.lastDriveBranch == KernelBudget or current.lastDriveBranch == KernelConflict
      or current.lastDriveBranch == KernelFuture or current.lastDriveBranch == KernelNoWork),
    driveProgressBefore: current.driveProgressBefore,
    driveProgressAfter: current.driveProgressAfter,
    driveResult: current.lastDriveBranch, driveBranch: current.lastDriveBranch,
    driveWork: current.lastDriveWork,
    driveStop: current.lastDriveStop,
  }

  pure def familyDriveContract(before, after, node) = {
    val decision = schedule::driveDecision(before, node)
    { class: decision.class, accepted: decision.accepted,
      branch: after.lastDriveBranch, work: after.lastDriveWork,
      stop: after.lastDriveStop, progressBefore: after.driveProgressBefore,
      progressAfter: after.driveProgressAfter, nextActions: after.pulseActions,
      nextActive: after.activePulses }
  }

  pure def compositeDriveContract(before, after) = {
    val decision = composite::compositeDriveDecision(before)
    { class: decision.class, accepted: decision.accepted,
      branch: after.lastDriveBranch, work: after.lastDriveWork,
      stop: after.lastDriveStop, progressBefore: after.driveProgressBefore,
      progressAfter: after.driveProgressAfter, nextActions: after.pulseActions,
      nextActive: after.activePulses }
  }

  pure def storeTerminalProjection(effect, job) = {
    val record = effect.records.get(job)
    { absent: not(record.exists), revision: record.revision,
      generation: record.generation, fence: record.fence, token: record.token,
      node: record.node, operation: record.operationId, leaseUntil: record.leaseUntil,
      payload: record.payload, dueRoute: record.dueRoute, fairRoute: record.fairRoute,
      leaseRoute: record.leaseRoute, wakeRoute: record.wakeRoute,
      fairReleased: not(record.permitHeld) and not(record.rateHeld) and record.inFlight == 0,
      completionReceipts: effect.meta.completionReceipts,
      completionDetail: effect.meta.completionDetail,
      committed: effect.meta.committedTerminalJobs.contains(job),
      wakePending: effect.meta.wakeWatermark,
      class: if (effect.meta.lastResult == Committed) AppliedClass else ConflictClass }
  }

  pure def compositeTerminalProjection(current, job) = {
    val record = current.jobs.get(job)
    val group = current.fairOrdering.get(job)
    { absent: record.state == Absent, revision: record.revision,
      generation: record.generation, fence: record.fence, token: record.token,
      node: record.node, operation: record.operationId, leaseUntil: record.leaseUntil,
      payload: record.payload, dueRoute: record.dueRoute, fairRoute: record.fairRoute,
      leaseRoute: record.leaseRoute, wakeRoute: record.wakeRoute,
      fairReleased: current.fairPermits.get(job) == MAX_CONCURRENCY_PER_SCOPE
        and current.fairRate.get(job) == MAX_RATE_PER_SCOPE
        and current.fairInFlight.get(job) == 0 and not(current.orderInFlight.get(group)),
      completionReceipts: JOBS.filter(candidate =>
        current.jobs.get(candidate).completionReceipt).size(),
      completionDetail: current.completionDetail,
      committed: current.committedTerminalJobs.contains(job),
      wakePending: current.wakePending,
      class: if (current.lastResult == Committed) AppliedClass else ConflictClass }
  }

  pure def fairMapFromScopes(currentScopes, project) = Map(
    JobA -> project(currentScopes.get(ScopeA)),
    JobB -> project(currentScopes.get(ScopeB)),
    JobC -> project(currentScopes.get(ScopeA1)))

  pure def mappedCompositeFailurePrestate(storeRecord, fairClaim) = {
    val base = composite::initialSystem
    val baseJob = base.jobs.get(JobB)
    val leased = baseJob.with("state", Leased).with("record", storeRecord.kind)
      .with("payload", storeRecord.payload).with("revision", storeRecord.revision)
      .with("generation", storeRecord.generation).with("fence", storeRecord.fence)
      .with("token", storeRecord.token).with("leaseUntil", storeRecord.leaseUntil)
      .with("node", storeRecord.node).with("operationId", storeRecord.operationId)
      .with("executionId", storeRecord.executionId).with("attemptId", storeRecord.attemptId)
      .with("attempts", storeRecord.attempts).with("dueRoute", storeRecord.dueRoute)
      .with("fairRoute", storeRecord.fairRoute).with("leaseRoute", storeRecord.leaseRoute)
      .with("wakeRoute", storeRecord.wakeRoute)
      .with("enqueueFingerprint", storeRecord.enqueueFingerprint)
      .with("payloadBytes", storeRecord.payloadBytes)
      .with("manifestBytes", storeRecord.manifestBytes)
      .with("chunkBytes", storeRecord.chunkBytes)
      .with("digestBytes", storeRecord.digestBytes)
      .with("checkpointBytes", storeRecord.checkpointBytes)
      .with("failureRecorded", false).with("dlqRoute", false)
      .with("occurrence", Occ2)
    base.with("jobs", update(base.jobs, JobB, leased))
      .with("emitted", update(base.emitted, Occ2, true)).with("emissionCount", 2)
      .with("occurrenceIdentity", update(base.occurrenceIdentity, Occ2, 1))
      .with("materialized", update(base.materialized, Occ2, true))
      .with("durableRoute", update(base.durableRoute, Occ2, true))
      .with("scheduleRevision", 2).with("selectedJob", JobB).with("selectedScope", ScopeB)
      .with("selectedHead", fairClaim.orders.get(OrderB).head).with("claimPending", false)
      .with("fairReady", fairMapFromScopes(fairClaim.scopes, scope => scope.ready))
      .with("fairPermits", fairMapFromScopes(fairClaim.scopes, scope => scope.permits))
      .with("fairRate", fairMapFromScopes(fairClaim.scopes, scope => scope.rate))
      .with("fairInFlight", fairMapFromScopes(fairClaim.scopes, scope => scope.inFlight))
      .with("fairServed", fairMapFromScopes(fairClaim.scopes, scope => scope.servedCost))
      .with("orderHead", fairClaim.orders.keys().mapBy(group => fairClaim.orders.get(group).head))
      .with("orderInFlight", fairClaim.orders.keys().mapBy(group =>
        fairClaim.orders.get(group).inFlight))
      .with("orderOwner", fairClaim.orders.keys().mapBy(group => fairClaim.orders.get(group).owner))
      .with("fairCritical", fairClaim.meta.criticalWindow)
      .with("fairDefault", fairClaim.meta.defaultWindow)
      .with("fairBulk", fairClaim.meta.bulkWindow).with("fairCycle", fairClaim.meta.cycle)
      .with("httpBatchMembers", Set(JobB))
      .with("httpBatchResults", Map(JobB -> ItemMissing))
      .with("httpIdempotency", update(base.httpIdempotency, JobB, storeRecord.executionId))
      .with("httpAttemptExecuted", update(base.httpAttemptExecuted, JobB, false))
      .with("handlerJob", JobB).with("wakePending", true)
  }

  pure def lifecycleFailurePrestate(record) =
    lifecycle::makeJob(Leased, record.node, record.revision, 0, record.leaseUntil,
      record.executionId, record.attemptId, record.attempts)
      .with("generation", record.generation).with("fence", record.fence)
      .with("token", record.token).with("record", record.kind)
      .with("payload", record.payload).with("dueRoute", record.dueRoute)
      .with("fairRoute", record.fairRoute).with("leaseRoute", record.leaseRoute)
      .with("wakeRoute", record.wakeRoute).with("operationId", record.operationId)
      .with("checkpointBytes", record.checkpointBytes)
      .with("enqueueFingerprint", record.enqueueFingerprint)

  pure def lifecycleFailureJobs(record) =
    update(lifecycle::initialJobs, JobB, lifecycleFailurePrestate(record))

  pure def storeFailureProjection(effect, job) = {
    val record = effect.records.get(job)
    { state: record.state, revision: record.revision, generation: record.generation,
      fence: record.fence, token: record.token, node: record.node,
      operation: record.operationId, leaseUntil: record.leaseUntil,
      expiresAt: record.expiresAt,
      executionId: record.executionId, attemptId: record.attemptId,
      attempts: record.attempts, payload: record.payload,
      failureRecorded: record.failureRecorded, dlq: record.dlqRoute,
      deleted: not(record.exists), dueRoute: record.dueRoute,
      fairRoute: record.fairRoute, leaseRoute: record.leaseRoute,
      wakeRoute: record.wakeRoute,
      fairReleased: not(record.permitHeld) and not(record.rateHeld)
        and record.inFlight == 0,
      committed: effect.meta.committedTerminalJobs.contains(job),
      wakePending: effect.meta.wakeWatermark,
      applied: effect.meta.lastResult == Committed,
      deadLetterOutcome: effect.meta.lastOutcome == store::HandlerDeadLetter,
      detail: effect.meta.lastDetail }
  }

  pure def compositeFailureProjection(current, job) = {
    val record = current.jobs.get(job)
    val group = current.fairOrdering.get(job)
    { state: record.state, revision: record.revision, generation: record.generation,
      fence: record.fence, token: record.token, node: record.node,
      operation: record.operationId, leaseUntil: record.leaseUntil,
      expiresAt: record.expiresAt,
      executionId: record.executionId, attemptId: record.attemptId,
      attempts: record.attempts, payload: record.payload,
      failureRecorded: record.failureRecorded, dlq: record.dlqRoute,
      deleted: record.state == Absent, dueRoute: record.dueRoute,
      fairRoute: record.fairRoute, leaseRoute: record.leaseRoute,
      wakeRoute: record.wakeRoute,
      fairReleased: current.fairPermits.get(job) == MAX_CONCURRENCY_PER_SCOPE
        and current.fairRate.get(job) == MAX_RATE_PER_SCOPE
        and current.fairInFlight.get(job) == 0 and not(current.orderInFlight.get(group)),
      committed: current.committedTerminalJobs.contains(job),
      wakePending: current.wakePending, applied: current.lastResult == Committed,
      deadLetterOutcome: current.lastOutcome == composite::HandlerDeadLetter,
      detail: current.completionDetail }
  }

  pure def storeEvidenceProjection(record) = {
    fingerprint: record.enqueueFingerprint, payloadBytes: record.payloadBytes,
    manifestBytes: record.manifestBytes, chunkBytes: record.chunkBytes,
    digestBytes: record.digestBytes, checkpointBytes: record.checkpointBytes }

  pure def compositeEvidenceProjection(record) = {
    fingerprint: record.enqueueFingerprint, payloadBytes: record.payloadBytes,
    manifestBytes: record.manifestBytes, chunkBytes: record.chunkBytes,
    digestBytes: record.digestBytes, checkpointBytes: record.checkpointBytes }

  pure def immutableEvidenceProjection(record) = {
    fingerprint: record.enqueueFingerprint, payloadBytes: record.payloadBytes,
    manifestBytes: record.manifestBytes, chunkBytes: record.chunkBytes,
    digestBytes: record.digestBytes }

  pure def lifecycleFailureProjection(effect, job) = {
    val current = effect.jobs.get(job)
    { state: current.state, revision: current.revision, generation: current.generation,
    fence: current.fence, token: current.token, node: current.node,
    operation: current.operationId, leaseUntil: current.leaseUntil,
    executionId: current.executionId, attemptId: current.attemptId,
    attempts: current.attempts, payload: current.payload,
    enqueueFingerprint: current.enqueueFingerprint,
    checkpointBytes: current.checkpointBytes,
    expiresAt: current.expiresAt, failureRecorded: current.failureRecorded,
    dueRoute: current.dueRoute,
    fairRoute: current.fairRoute, leaseRoute: current.leaseRoute,
    wakeRoute: current.wakeRoute,
    committed: effect.meta.committedTerminalJobs.contains(job),
    applied: effect.meta.lastResult == Committed,
      detail: effect.meta.completionDetail }
  }

  pure def storeLifecycleFailureProjection(effect, job) = {
    val current = effect.records.get(job)
    { state: current.state, revision: current.revision, generation: current.generation,
      fence: current.fence, token: current.token, node: current.node,
      operation: current.operationId, leaseUntil: current.leaseUntil,
      expiresAt: current.expiresAt,
      executionId: current.executionId, attemptId: current.attemptId,
      attempts: current.attempts, payload: current.payload,
      enqueueFingerprint: current.enqueueFingerprint,
      checkpointBytes: current.checkpointBytes,
      failureRecorded: current.failureRecorded, dueRoute: current.dueRoute,
      fairRoute: current.fairRoute, leaseRoute: current.leaseRoute,
      wakeRoute: current.wakeRoute,
      committed: effect.meta.committedTerminalJobs.contains(job),
      applied: effect.meta.lastResult == Committed,
      detail: effect.meta.completionDetail }
  }

  pure def fairFailureProjection(effect, job) = {
    val queued = effect.jobs.get(job)
    val scope = effect.scopes.get(queued.scope)
    val primary = effect.scopes.get(scopePrimary(queued.scope))
    val order = effect.orders.get(queued.ordering)
    { state: queued.state, payload: queued.payload, dueRoute: queued.dueRoute,
      fairRoute: queued.fairRoute, childPermits: scope.permits,
      childRate: scope.rate, childInFlight: scope.inFlight,
      childServed: scope.servedCost, primaryPermits: primary.permits,
      primaryRate: primary.rate, primaryInFlight: primary.inFlight,
      primaryServed: primary.servedCost, orderHead: order.head,
      orderInFlight: order.inFlight, orderOwner: order.owner,
      critical: effect.meta.criticalWindow, default: effect.meta.defaultWindow,
      bulk: effect.meta.bulkWindow, cycle: effect.meta.cycle }
  }

  pure def compositeFairFailureProjection(current, job) = {
    val primary = composite::primaryJob(job)
    val group = current.fairOrdering.get(job)
    { state: current.jobs.get(job).state, payload: current.jobs.get(job).payload,
      dueRoute: current.jobs.get(job).dueRoute,
      fairRoute: current.jobs.get(job).fairRoute,
      childPermits: current.fairPermits.get(job), childRate: current.fairRate.get(job),
      childInFlight: current.fairInFlight.get(job), childServed: current.fairServed.get(job),
      primaryPermits: current.fairPermits.get(primary),
      primaryRate: current.fairRate.get(primary),
      primaryInFlight: current.fairInFlight.get(primary),
      primaryServed: current.fairServed.get(primary),
      orderHead: current.orderHead.get(group),
      orderInFlight: current.orderInFlight.get(group),
      orderOwner: current.orderOwner.get(group), critical: current.fairCritical,
      default: current.fairDefault, bulk: current.fairBulk, cycle: current.fairCycle }
  }

  pure def deadLetterParityCase(attempts, status, handler) = {
    val storeJob = store::initialRecords.get(JobB).with("attempts", attempts)
      .with("attemptId", attempts).with("enqueueFingerprint", 11)
      .with("payloadBytes", 12).with("manifestBytes", 13)
      .with("chunkBytes", 14).with("digestBytes", 15).with("checkpointBytes", 16)
    val storeRecords = update(store::initialRecords, JobB, storeJob)
    val storeEffect = store::applyStoreDeadLetter(storeRecords, store::initialMeta, JobB,
      storeJob.node, storeJob.revision, storeJob.generation, storeJob.fence,
      storeJob.token, storeJob.leaseUntil, storeJob.operationId, handler)
    val lifecycleBefore = lifecycleFailureJobs(storeJob)
    val lifecycleEffect = lifecycle::applyLifecycleHandler(lifecycleBefore,
      lifecycle::initialMeta, JobB, storeJob.node, storeJob.revision,
      storeJob.generation, storeJob.fence, storeJob.token, storeJob.leaseUntil,
      storeJob.operationId, handler)
    val fairClaim = fair::familyServiceTransition(fair::initialScopes,
      fair::initialJobs, fair::initialOrders, fair::initialMeta, JobB, false, false)
    val fairEffect = fair::familyReleaseTransition(fairClaim.scopes, fairClaim.jobs,
      fairClaim.orders, fairClaim.meta, JobB, ItemDeadLetter)
    val compositeBefore = mappedCompositeFailurePrestate(storeJob, fairClaim)
    val handled = composite::applyCompositeHttpResult(compositeBefore, JobB,
      status, TransportOk, 0)
    val compositeAfter = composite::applyCompositeHandler(handled, JobB)
    { storeBefore: storeJob, storeAfter: storeEffect,
      lifecycleBefore: lifecycleBefore, lifecycleAfter: lifecycleEffect,
      fairClaim: fairClaim, fairAfter: fairEffect,
      compositeBefore: compositeBefore, compositeHandled: handled,
      compositeAfter: compositeAfter }
  }

  pure def idleFamily = schedule::initialState.with("activePulses", 1)

  pure def emittedFamily = idleFamily
    .with("emitted", Map(Occ1 -> true, Occ2 -> false, Occ3 -> false))
    .with("emissionCount", 1)
    .with("occurrenceIdentity", Map(Occ1 -> 1, Occ2 -> 0, Occ3 -> 0))

  pure def materializedFamily = schedule::applyMaterialization(
    emittedFamily.with("materializePending", true).with("materializeOccurrence", Occ1)
      .with("materializeRevision", 0).with("materializeReader", NodeA)
      .with("materializeOtherReader", NodeB), Occ1, NodeA, 0)

  pure def claimedFamily = schedule::applyScheduleClaim(materializedFamily, JobA, NodeA)

  run authoritative_recurrence_materialization_and_claim_parity = {
    val overdue = idleFamily.with("now", OCCURRENCE_STEP * 4)
      .with("nextDue", OCCURRENCE_STEP).with("misfire", CatchUp).with("catchUpLimit", 2)
    val familyRecurrence = schedule::applyDriveTransition(overdue, NodeA)
    val compositeRecurrence = composite::applyCompositeDriveTransition(compositeFromFamily(overdue))
    val familyMaterialized = schedule::applyDriveTransition(emittedFamily, NodeA)
    val compositeMaterialized = composite::applyCompositeDriveTransition(
      compositeFromFamily(emittedFamily))
    val claimBefore = materializedFamily.with("activePulses", 1)
    val familyClaimed = schedule::applyDriveTransition(claimBefore, NodeA)
    val compositeClaimed = composite::applyCompositeDriveTransition(compositeFromFamily(claimBefore))
    all {
      assert(familyProjection(familyRecurrence) == compositeProjection(compositeRecurrence)),
      assert(familyDriveContract(overdue, familyRecurrence, NodeA)
        == compositeDriveContract(compositeFromFamily(overdue), compositeRecurrence)),
      assert(familyProjection(familyMaterialized) == compositeProjection(compositeMaterialized)),
      assert(familyDriveContract(emittedFamily, familyMaterialized, NodeA)
        == compositeDriveContract(compositeFromFamily(emittedFamily), compositeMaterialized)),
      assert(familyClaimed.jobState == JOBS.mapBy(job => compositeClaimed.jobs.get(job).state)),
      assert(familyClaimed.jobRevision == JOBS.mapBy(job => compositeClaimed.jobs.get(job).revision)),
      assert(familyClaimed.jobGeneration == JOBS.mapBy(job => compositeClaimed.jobs.get(job).generation)),
      assert(familyClaimed.jobFence == JOBS.mapBy(job => compositeClaimed.jobs.get(job).fence)),
      assert(familyClaimed.jobToken == JOBS.mapBy(job => compositeClaimed.jobs.get(job).token)),
      assert(familyClaimed.jobLeaseUntil == JOBS.mapBy(job => compositeClaimed.jobs.get(job).leaseUntil)),
      assert(familyClaimed.jobDueRoute == JOBS.mapBy(job => compositeClaimed.jobs.get(job).dueRoute)),
      assert(familyClaimed.jobFairRoute == JOBS.mapBy(job => compositeClaimed.jobs.get(job).fairRoute)),
      assert(familyClaimed.jobLeaseRoute == JOBS.mapBy(job => compositeClaimed.jobs.get(job).leaseRoute)),
      assert(familyClaimed.jobWakeRoute == JOBS.mapBy(job => compositeClaimed.jobs.get(job).wakeRoute)),
      assert(familyClaimed.fairPermits == compositeClaimed.fairPermits),
      assert(familyClaimed.fairRate == compositeClaimed.fairRate),
      assert(familyClaimed.fairInFlight == compositeClaimed.fairInFlight),
      assert(familyClaimed.fairServed == compositeClaimed.fairServed),
      assert(familyClaimed.orderInFlight == compositeClaimed.orderInFlight),
      assert(familyClaimed.fairCritical == compositeClaimed.fairCritical
        and familyClaimed.fairDefault == compositeClaimed.fairDefault
        and familyClaimed.fairBulk == compositeClaimed.fairBulk
        and familyClaimed.fairCycle == compositeClaimed.fairCycle),
      assert(familyClaimed.wakePending == compositeClaimed.wakePending),
      assert(familyClaimed.wakeToken == compositeClaimed.wakeToken),
      assert(familyClaimed.lastDriveBranch == compositeClaimed.lastDriveBranch
        and familyClaimed.lastDriveWork == compositeClaimed.lastDriveWork
        and familyClaimed.lastDriveStop == compositeClaimed.lastDriveStop
        and familyClaimed.progressCounter == compositeClaimed.progressCounter),
      assert(familyProjection(familyClaimed) == compositeProjection(compositeClaimed)),
      assert(familyDriveContract(claimBefore, familyClaimed, NodeA)
        == compositeDriveContract(compositeFromFamily(claimBefore), compositeClaimed)),
      assert(familyClaimed.lastDriveBranch == KernelClaim
        and familyClaimed.jobState.get(JobA) == Leased
        and familyClaimed.jobRevision.get(JobA) == claimBefore.jobRevision.get(JobA) + 1
        and familyClaimed.jobGeneration.get(JobA) == claimBefore.jobGeneration.get(JobA) + 1
        and familyClaimed.jobFence.get(JobA) == claimBefore.jobFence.get(JobA) + 1
        and familyClaimed.jobToken.get(JobA) == claimBefore.jobToken.get(JobA) + 3),
    }
  }

  run secondary_scope_claim_and_primary_exhaustion_parity = {
    val secondaryBefore = schedule::secondaryClaimState
    val secondaryFamily = schedule::applyDriveTransition(secondaryBefore, NodeA)
    val secondaryCompositeBefore = compositeFromFamily(secondaryBefore)
    val secondaryComposite = composite::applyCompositeDriveTransition(secondaryCompositeBefore)
    val secondaryF = familyProjection(secondaryFamily)
    val secondaryC = compositeProjection(secondaryComposite)
    val exhaustedBefore = secondaryBefore.with("fairPermits",
      update(secondaryBefore.fairPermits, JobA, 0))
    val exhaustedFamily = schedule::applyDriveTransition(exhaustedBefore, NodeA)
    val exhaustedCompositeBefore = compositeFromFamily(exhaustedBefore)
    val exhaustedComposite = composite::applyCompositeDriveTransition(exhaustedCompositeBefore)
    all {
      assert(secondaryF == secondaryC),
      assert(familyDriveContract(secondaryBefore, secondaryFamily, NodeA)
        == compositeDriveContract(secondaryCompositeBefore, secondaryComposite)),
      assert(secondaryFamily.lastDriveBranch == KernelClaim
        and secondaryFamily.jobState.get(JobC) == Leased
        and secondaryFamily.fairPermits.get(JobC) == MAX_CONCURRENCY_PER_SCOPE - 1
        and secondaryFamily.fairPermits.get(JobA) == MAX_CONCURRENCY_PER_SCOPE - 1
        and secondaryFamily.fairRate.get(JobC) == MAX_RATE_PER_SCOPE - 1
        and secondaryFamily.fairRate.get(JobA) == MAX_RATE_PER_SCOPE - 1
        and secondaryFamily.fairInFlight.get(JobC) == 1
        and secondaryFamily.fairInFlight.get(JobA) == 1
        and secondaryFamily.fairServed.get(JobC) == 1
        and secondaryFamily.fairServed.get(JobA) == 1
        and secondaryFamily.orderOwner.get(OrderB) == JobC),
      assert(familyProjection(exhaustedFamily) == compositeProjection(exhaustedComposite)),
      assert(familyDriveContract(exhaustedBefore, exhaustedFamily, NodeA)
        == compositeDriveContract(exhaustedCompositeBefore, exhaustedComposite)),
      assert(exhaustedFamily.lastDriveBranch == KernelFuture
        and exhaustedFamily.jobState.get(JobC) == Scheduled
        and exhaustedFamily.jobRevision.get(JobC) == exhaustedBefore.jobRevision.get(JobC)
        and exhaustedFamily.jobGeneration.get(JobC) == exhaustedBefore.jobGeneration.get(JobC)
        and exhaustedFamily.jobFence.get(JobC) == exhaustedBefore.jobFence.get(JobC)
        and exhaustedFamily.jobToken.get(JobC) == exhaustedBefore.jobToken.get(JobC)
        and exhaustedFamily.fairPermits == exhaustedBefore.fairPermits
        and exhaustedFamily.fairRate == exhaustedBefore.fairRate
        and exhaustedFamily.fairInFlight == exhaustedBefore.fairInFlight
        and exhaustedFamily.fairServed == exhaustedBefore.fairServed
        and exhaustedFamily.orderInFlight == exhaustedBefore.orderInFlight),
    }
  }

  run cost_weighted_service_and_terminal_parity = {
    val familyService = fair::familyServiceTransition(fair::initialScopes,
      fair::initialJobs, fair::initialOrders, fair::initialMeta, JobA, false, false)
    val compositeBefore = composite::initialSystem
    val compositeEffect = fairSelectedServiceKernel(true, JobA, ScopeA, ScopeA, Critical,
      compositeBefore.fairCost.get(JobA), false, true, true, false,
      composite::compositeFairPrestate(compositeBefore, JobA))
    val compositeService = composite::applyCompositeFairEffect(compositeBefore,
      JobA, NodeA, compositeEffect)
    val terminalBefore = claimedFamily.with("activePulses", 1)
    val familyTerminal = schedule::applyDriveTransition(terminalBefore, NodeA)
    val compositeTerminal = composite::applyCompositeDriveTransition(compositeFromFamily(terminalBefore))
    all {
      assert(familyService.allowed and compositeEffect.allowed
        and familyService.effect.registeredCost == compositeEffect.registeredCost
        and familyService.meta.criticalWindow == compositeService.fairCritical
        and familyService.meta.serviceTransitions
          == compositeService.fairCritical + compositeService.fairDefault + compositeService.fairBulk),
      assert(familyProjection(familyTerminal) == compositeProjection(compositeTerminal)),
      assert(familyDriveContract(terminalBefore, familyTerminal, NodeA)
        == compositeDriveContract(compositeFromFamily(terminalBefore), compositeTerminal)),
      assert(familyTerminal.lastDriveBranch == KernelTerminal
        and familyTerminal.jobState.get(JobA) == Absent
        and not(familyTerminal.orderInFlight.get(OrderA))),
    }
  }

  run full_capacity_terminal_detail_is_omitted = {
    val terminalBefore = compositeFromFamily(claimedFamily)
    val receiptB = terminalBefore.jobs.get(JobB).with("completionReceipt", true)
    val receiptC = terminalBefore.jobs.get(JobC).with("completionReceipt", true)
    val full = terminalBefore.with("jobs", update(update(terminalBefore.jobs,
      JobB, receiptB), JobC, receiptC))
    val terminal = composite::terminalSystemFrom(full, JobA, Absent, false, true,
      composite::CompletionCommitted)
    val job = terminal.jobs.get(JobA)
    val exposed = composite::exposeCompletionFrom(terminal, JobA, job.node,
      job.revision, job.generation, job.fence, job.token, job.leaseUntil, job.operationId)
    val storeJob = store::makeRecord(true, Valid,
      terminalBefore.jobs.get(JobA).revision, true, true, false, false, true, false)
    val storeAbsent = store::makeRecord(false, Valid, 0, false, false,
      false, false, false, false)
    val storeRecords = Map(JobA -> storeJob, JobB -> storeAbsent, JobC -> storeAbsent)
    val storeMeta = store::initialMeta.with("completionReceipts", MAX_COMPLETION_RECEIPTS)
      .with("committedTerminalJobs", Set(JobB, JobC))
    val storeTerminal = store::applyStoreCompletion(storeRecords, storeMeta, JobA,
      storeJob.node, storeJob.revision, storeJob.generation, storeJob.fence,
      storeJob.token, storeJob.leaseUntil, storeJob.operationId)
    all {
      assert(storeTerminal.allowed),
      assert(storeTerminalProjection(storeTerminal, JobA)
        == compositeTerminalProjection(exposed, JobA)),
      assert(exposed.completionDetail == CompletionDetailOmitted),
      assert(exposed.completionOmissions == full.completionOmissions + 1),
      assert(exposed.jobs.get(JobA).state == Absent
        and not(exposed.jobs.get(JobA).completionReceipt)
        and not(exposed.jobs.get(JobA).completionPending)),
    }
  }

  run every_drive_stop_branch_parity = {
    val conflictBefore = claimedFamily
      .with("materialized", Map(Occ1 -> false, Occ2 -> false, Occ3 -> false))
      .with("emitted", Map(Occ1 -> true, Occ2 -> false, Occ3 -> false))
      .with("activePulses", 1).with("overlap", false)
    val pausedBefore = idleFamily.with("paused", true)
    val budgetBefore = idleFamily.with("pulseActions", MAX_PULSE_ACTIONS)
    val futureBefore = idleFamily.with("nextDue", OCCURRENCE_STEP)
    val emptyBefore = idleFamily.with("nextDue", 0).with("enabled", false)
    val conflictF = schedule::applyDriveTransition(conflictBefore, NodeA)
    val conflictC = composite::applyCompositeDriveTransition(compositeFromFamily(conflictBefore))
    val pausedF = schedule::applyDriveTransition(pausedBefore, NodeA)
    val pausedC = composite::applyCompositeDriveTransition(compositeFromFamily(pausedBefore))
    val budgetF = schedule::applyDriveTransition(budgetBefore, NodeA)
    val budgetC = composite::applyCompositeDriveTransition(compositeFromFamily(budgetBefore))
    val futureF = schedule::applyDriveTransition(futureBefore, NodeA)
    val futureC = composite::applyCompositeDriveTransition(compositeFromFamily(futureBefore))
    val emptyF = schedule::applyDriveTransition(emptyBefore, NodeA)
    val emptyC = composite::applyCompositeDriveTransition(compositeFromFamily(emptyBefore))
    all {
      assert(conflictF.lastDriveBranch == KernelConflict),
      assert(familyProjection(conflictF) == compositeProjection(conflictC)),
      assert(familyDriveContract(conflictBefore, conflictF, NodeA)
        == compositeDriveContract(compositeFromFamily(conflictBefore), conflictC)),
      assert(pausedF.lastDriveBranch == KernelPaused
        and familyProjection(pausedF) == compositeProjection(pausedC)
        and familyDriveContract(pausedBefore, pausedF, NodeA)
          == compositeDriveContract(compositeFromFamily(pausedBefore), pausedC)),
      assert(budgetF.lastDriveBranch == KernelBudget
        and familyProjection(budgetF) == compositeProjection(budgetC)
        and familyDriveContract(budgetBefore, budgetF, NodeA)
          == compositeDriveContract(compositeFromFamily(budgetBefore), budgetC)),
      assert(futureF.lastDriveBranch == KernelFuture
        and familyProjection(futureF) == compositeProjection(futureC)
        and familyDriveContract(futureBefore, futureF, NodeA)
          == compositeDriveContract(compositeFromFamily(futureBefore), futureC)),
      assert(emptyF.lastDriveBranch == KernelNoWork
        and familyProjection(emptyF) == compositeProjection(emptyC)
        and familyDriveContract(emptyBefore, emptyF, NodeA)
          == compositeDriveContract(compositeFromFamily(emptyBefore), emptyC)),
    }
  }

  pure def deadLetterParityHolds(case) = {
    val storeAfter = case.storeAfter
    val compositeAfter = case.compositeAfter
    val storeRecord = storeAfter.records.get(JobB)
    val compositeRecord = compositeAfter.jobs.get(JobB)
    val storeDlq = JOBS.filter(job => storeAfter.records.get(job).dlqRoute)
    val compositeDlq = JOBS.filter(job => compositeAfter.jobs.get(job).state == DeadLettered)
    val storeDeleted = JOBS.filter(job => not(storeAfter.records.get(job).exists)
      and storeAfter.meta.committedTerminalJobs.contains(job))
    val compositeDeleted = JOBS.filter(job => compositeAfter.jobs.get(job).state == Absent
      and compositeAfter.committedTerminalJobs.contains(job))
    all {
      case.storeAfter.allowed,
      case.lifecycleAfter.allowed,
      case.fairClaim.allowed,
      case.fairAfter.allowed,
      storeFailureProjection(storeAfter, JobB)
        == compositeFailureProjection(compositeAfter, JobB),
      storeLifecycleFailureProjection(storeAfter, JobB)
        == lifecycleFailureProjection(case.lifecycleAfter, JobB),
      fairFailureProjection(case.fairAfter, JobB)
        == compositeFairFailureProjection(compositeAfter, JobB),
      storeDlq == compositeDlq,
      storeDeleted == compositeDeleted,
      storeEvidenceProjection(storeRecord)
        == storeEvidenceProjection(case.storeBefore),
      storeEvidenceProjection(storeRecord)
        == compositeEvidenceProjection(compositeRecord),
      compositeEvidenceProjection(compositeRecord)
        == compositeEvidenceProjection(case.compositeBefore.jobs.get(JobB)),
      storeEvidenceProjection(case.storeBefore) == {
        fingerprint: 11, payloadBytes: 12, manifestBytes: 13,
        chunkBytes: 14, digestBytes: 15, checkpointBytes: 16 },
      case.lifecycleAfter.meta.lastResult == Committed,
      case.lifecycleAfter.meta.lastOutcome == lifecycle::PermanentDeadLetter,
      case.lifecycleAfter.meta.committedTerminalJobs.contains(JobB),
      storeRecord.payload and compositeRecord.payload,
      storeRecord.failureRecorded and compositeRecord.failureRecorded,
      storeRecord.state == DeadLettered and compositeRecord.state == DeadLettered,
      storeRecord.revision == case.storeBefore.revision + 1,
      compositeRecord.revision == case.compositeBefore.jobs.get(JobB).revision + 1,
      storeRecord.attemptId == case.storeBefore.attemptId,
      storeRecord.attempts == case.storeBefore.attempts,
      compositeRecord.attemptId == case.compositeBefore.jobs.get(JobB).attemptId,
      compositeRecord.attempts == case.compositeBefore.jobs.get(JobB).attempts,
      not(compositeAfter.httpBatchMembers.contains(JobB)),
      not(compositeAfter.httpBatchResults.keys().contains(JobB)),
      compositeAfter.httpRetryOwners.get(JobB) == NoRetry,
      compositeAfter.httpIdempotency.get(JobB) == 0,
      not(compositeAfter.httpAttemptExecuted.get(JobB)),
      not(compositeAfter.httpSecretPersisted.get(JobB)),
      not(compositeAfter.httpDuplicate.get(JobB)),
      not(compositeAfter.httpOmitted.get(JobB)),
      not(compositeAfter.orderInFlight.get(OrderB)),
      compositeAfter.orderOwner.get(OrderB) == JobB,
      compositeAfter.orderHead.get(OrderB)
        == case.compositeBefore.orderHead.get(OrderB) + 1,
      storeAfter.meta.lastResult == Committed,
      storeAfter.meta.lastOutcome == store::HandlerDeadLetter,
      storeAfter.meta.lastDetail == NoCompletionDetail,
      compositeAfter.lastResult == Committed,
      compositeAfter.lastOutcome == composite::HandlerDeadLetter,
      compositeAfter.completionDetail == NoCompletionDetail,
    }
  }

  run immediate_permanent_failure_full_parity = {
    val case = deadLetterParityCase(1, Status4xx, Permanent)
    all {
      assert(case.compositeHandled.lastHandlerResult == Permanent),
      assert(case.compositeHandled.httpBatchResults.get(JobB) == ItemDeadLetter),
      assert(storeFailureProjection(case.storeAfter, JobB)
        == compositeFailureProjection(case.compositeAfter, JobB)),
      assert(storeLifecycleFailureProjection(case.storeAfter, JobB)
        == lifecycleFailureProjection(case.lifecycleAfter, JobB)),
      assert(fairFailureProjection(case.fairAfter, JobB)
        == compositeFairFailureProjection(case.compositeAfter, JobB)),
      assert(deadLetterParityHolds(case)),
    }
  }

  run exhausted_retry_dead_letter_full_parity = {
    val case = deadLetterParityCase(MAX_ATTEMPTS, Status429, Transient)
    all {
      assert(case.compositeHandled.lastHandlerResult == Transient),
      assert(case.compositeHandled.retryOwner == EngineOwnsRetry),
      assert(case.compositeHandled.httpBatchResults.get(JobB) == ItemRetry),
      assert(deadLetterParityHolds(case)),
    }
  }


  run redrive_clears_terminal_state_and_preserves_immutable_evidence = {
    val case = deadLetterParityCase(1, Status4xx, Permanent)
    // Request authority is captured from the known terminal transition, not
    // recovered from each current record and compared with itself.
    val expectedRevision = case.storeBefore.revision + 1
    val expectedOperation = case.storeBefore.operationId
    val storeRedrive = store::applyStoreRedrive(case.storeAfter.records,
      case.storeAfter.meta, JobB, expectedRevision, expectedOperation, false)
    val lifecycleRedrive = lifecycle::applyLifecycleRedrive(
      case.lifecycleAfter.jobs, case.lifecycleAfter.meta, JobB,
      expectedRevision, expectedOperation, false)
    val compositeRedrive = composite::applyCompositeRedrive(case.compositeAfter,
      JobB, expectedRevision, expectedOperation)
    val storeNext = storeRedrive.records.get(JobB)
    val lifecycleNext = lifecycleRedrive.jobs.get(JobB)
    val compositeNext = compositeRedrive.jobs.get(JobB)
    all {
      assert(storeRedrive.allowed and storeNext.state == Scheduled
        and lifecycleRedrive.allowed and lifecycleNext.state == Scheduled
        and compositeNext.state == Scheduled),
      assert(storeEvidenceProjection(storeNext)
        == compositeEvidenceProjection(compositeNext)),
      assert(immutableEvidenceProjection(storeNext)
        == immutableEvidenceProjection(case.storeBefore)),
      assert(immutableEvidenceProjection(compositeNext)
        == immutableEvidenceProjection(case.compositeBefore.jobs.get(JobB))),
      assert(immutableEvidenceProjection(storeNext)
        == immutableEvidenceProjection(compositeNext)),
      assert(storeNext.checkpointBytes == 0 and compositeNext.checkpointBytes == 0),
      assert(not(storeNext.failureRecorded) and not(storeNext.dlqRoute)
        and not(compositeNext.failureRecorded) and not(compositeNext.dlqRoute)),
      assert(not(storeRedrive.meta.committedTerminalJobs.contains(JobB))
        and not(lifecycleRedrive.meta.committedTerminalJobs.contains(JobB))
        and not(compositeRedrive.committedTerminalJobs.contains(JobB))),
      assert(storeNext.dueRoute and storeNext.fairRoute and storeNext.wakeRoute
        and compositeNext.dueRoute and compositeNext.fairRoute and compositeNext.wakeRoute),
      assert(not(storeNext.leaseRoute) and not(compositeNext.leaseRoute)
        and storeNext.attempts == 0 and compositeNext.attempts == 0
        and storeNext.attemptId == 0 and compositeNext.attemptId == 0),
      assert(storeLifecycleFailureProjection(storeRedrive, JobB)
        == lifecycleFailureProjection(lifecycleRedrive, JobB)),
      assert(storeNext.expiresAt == storeRedrive.meta.now + MAX_JOB_AGE_TICKS
        and lifecycleNext.expiresAt == lifecycleRedrive.meta.now + MAX_JOB_AGE_TICKS
        and compositeNext.expiresAt == compositeRedrive.now + MAX_JOB_AGE_TICKS
        and storeNext.expiresAt > storeRedrive.meta.now
        and lifecycleNext.expiresAt > lifecycleRedrive.meta.now
        and compositeNext.expiresAt > compositeRedrive.now),
      assert(not(compositeRedrive.httpBatchMembers.contains(JobB))
        and not(compositeRedrive.httpBatchResults.keys().contains(JobB))
        and compositeRedrive.httpRetryOwners.get(JobB) == NoRetry
        and compositeRedrive.httpIdempotency.get(JobB) == 0
        and not(compositeRedrive.orderInFlight.get(OrderB))),
      assert(storeFailureProjection(storeRedrive, JobB)
        == compositeFailureProjection(compositeRedrive, JobB)),
      assert(storeRedrive.meta.lastResult == Committed
        and storeRedrive.meta.lastOutcome == store::RedriveCommitted
        and storeRedrive.meta.lastDetail == NoCompletionDetail
        and compositeRedrive.lastResult == Committed
        and compositeRedrive.lastOutcome == composite::RedriveCommitted
        and compositeRedrive.completionDetail == NoCompletionDetail),
    }
  }
}
