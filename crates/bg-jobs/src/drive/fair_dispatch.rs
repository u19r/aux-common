//! Production-boundary fair-dispatch connector support.

use bytes::Bytes;

use crate::{
    batch::{Batch, BatchBuilder, BatchCompatibility, BatchItem, BatchLimits, BatchLimitsInput},
    codec::decode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    fairness::{
        FairCandidateInput, FairCandidateMetadata, FairDispatchOwner, FairnessBudget,
        FairnessBudgetInput,
    },
    ids::JobId,
    keys,
    model::{JobOutcome, NewJob},
    policy::RetryClass,
    store::JobStore,
    time::Timestamp,
};

/// Production fair-dispatch configuration used by the connector and by
/// callers that need to seed a deterministic candidate set.  The command
/// still creates/replaces the real durable job through
/// the low-level enqueue path;
/// the owner only records the fair and batch fields that the job codec does
/// not own.
#[cfg(all(test, not(target_family = "wasm")))]
#[derive(Clone, Debug)]
pub(crate) struct FairDispatchCandidateSpec {
    pub(crate) job_id: JobId,
    pub(crate) payload: Bytes,
    pub(crate) fairness: crate::policy::FairnessClass,
    pub(crate) volume_mode: crate::fairness::FairVolumeMode,
    pub(crate) priority: crate::policy::Priority,
    pub(crate) cost_units: std::num::NonZeroU16,
    pub(crate) scheduled_at: Timestamp,
    pub(crate) ordering_key: Option<crate::ids::OrderingKey>,
    pub(crate) ordering_position: u64,
    pub(crate) metadata: FairCandidateMetadata,
}

#[cfg(all(test, not(target_family = "wasm")))]
impl From<&FairDispatchCandidateSpec> for NewJob {
    fn from(spec: &FairDispatchCandidateSpec) -> Self {
        Self {
            job_id: spec.job_id,
            kind: spec.metadata.handler_kind.clone(),
            schema_version: spec.metadata.schema_version,
            payload: spec.payload.clone(),
            fairness: spec.fairness.clone(),
            ordering_key: spec.ordering_key.clone(),
            priority: spec.priority,
            scheduled_at: spec.scheduled_at,
            expires_at: None,
            retry_override: Some(crate::policy::RetrySelection::Custom(
                spec.metadata.retry_policy,
            )),
            deduplication: None,
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
impl From<&FairDispatchCandidateSpec> for FairCandidateInput {
    fn from(spec: &FairDispatchCandidateSpec) -> Self {
        Self {
            job_id: spec.job_id,
            fairness: spec.fairness.clone(),
            priority: spec.priority,
            cost_units: spec.cost_units,
            scheduled_at: spec.scheduled_at,
            payload_bytes: spec.payload.len(),
            ordering_key: spec.ordering_key.clone(),
            ordering_position: spec.ordering_position,
            block: None,
        }
    }
}

/// Configure one real candidate and its owner projection.  Reconfiguration
/// uses the public claim/complete lifecycle before enqueueing the replacement,
/// so no connector-only record mutation can bypass durable permits.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_configure<S: JobStore>(
    system: &JobSystem<S>,
    spec: FairDispatchCandidateSpec,
    now: Timestamp,
) -> JobResult<(), S::Error> {
    let budget = connector_budget()?;
    let mut owner = FairDispatchOwner::load(system)
        .await?
        .unwrap_or(FairDispatchOwner::try_new(budget)?);
    if owner.candidate_state(spec.job_id) == Some(crate::fairness::FairCandidateState::Leased) {
        return Err(JobSystemError::LeaseConflict);
    }
    if owner.has_leased_candidate() {
        return Err(JobSystemError::LeaseConflict);
    }
    let job = NewJob::from(&spec);
    match system.enqueue_impl(job.clone(), now).await {
        Ok(_) => {}
        Err(JobSystemError::JobIdConflict) => {
            let claim = system.claim(spec.job_id, now).await?;
            let code = crate::policy::OutcomeCode::try_new("fair_reconfigure")?;
            system
                .complete(claim, JobOutcome::Complete(code), now)
                .await?;
            system.enqueue_impl(job, now).await?;
        }
        Err(error) => return Err(error),
    }
    let candidate_scope: crate::fairness::FairScope = (&spec.fairness).into();
    owner.ensure_candidate(FairCandidateInput::from(&spec), spec.metadata)?;
    let _ = owner.set_scope_mode(&candidate_scope, spec.volume_mode);
    owner.save(system).await
}

/// Select through the canonical owner and then obtain the authoritative
/// durable claim.  A failed claim releases only the owner permit and leaves
/// the durable job untouched for the next command.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_select<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
) -> JobResult<(crate::fairness::FairPermit, crate::lifecycle::ClaimedJob), S::Error> {
    fair_dispatch_select_inner(system, job_id, now, false, SelectionObservation::Always).await
}

/// Low-volume dispatch shares the canonical claim path with ordinary select,
/// but the model only records selected metadata after a successful low-volume
/// attempt.  Keeping that distinction at the production boundary prevents a
/// connector from reconstructing selection state locally.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_low_volume<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
) -> JobResult<(crate::fairness::FairPermit, crate::lifecycle::ClaimedJob), S::Error> {
    fair_dispatch_select_inner(system, job_id, now, false, SelectionObservation::OnSuccess).await
}

#[cfg(all(test, not(target_family = "wasm")))]
#[derive(Clone, Copy)]
enum SelectionObservation {
    Always,
    OnSuccess,
    Never,
}

#[cfg(all(test, not(target_family = "wasm")))]
async fn fair_dispatch_select_inner<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
    hol_escape: bool,
    observation: SelectionObservation,
) -> JobResult<(crate::fairness::FairPermit, crate::lifecycle::ClaimedJob), S::Error> {
    let mut owner = FairDispatchOwner::load(system)
        .await?
        .ok_or(JobSystemError::NotFound)?;
    let claim_capacity = std::num::NonZeroU16::new(
        owner
            .budget()
            .max_concurrency_per_scope()
            .get()
            .min(u32::from(u16::MAX)) as u16,
    )
    .unwrap_or(std::num::NonZeroU16::MIN);
    let previous_selected = owner.selected();
    let (observe_success, observe_failure, restore_selected) = match observation {
        SelectionObservation::Always => (true, true, false),
        SelectionObservation::OnSuccess => (true, false, true),
        SelectionObservation::Never => (false, false, false),
    };
    let permit = match owner.select(job_id) {
        Ok(permit) => permit,
        Err(_) => {
            if observe_failure {
                let _ = owner.observe_selection_attempt(job_id, false);
                owner.save(system).await?;
            }
            return Err(JobSystemError::LeaseConflict);
        }
    };
    if observe_success && !owner.observe_selection_attempt(job_id, true) {
        let _ = owner.release(permit, crate::fairness::FairRelease::Conflict);
        owner.save(system).await?;
        return Err(JobSystemError::LeaseConflict);
    }
    if observe_success && !owner.record_selection(&permit) {
        return Err(JobSystemError::LeaseConflict);
    }
    if hol_escape {
        owner.record_hol_escape();
    }
    owner.save(system).await?;
    let claim = match system
        .claim_with_capacity(job_id, now, claim_capacity)
        .await
    {
        Ok(claim) => claim,
        Err(error) => {
            let _ = owner.release(permit, crate::fairness::FairRelease::Conflict);
            if observe_failure {
                let _ = owner.observe_selection_attempt(job_id, false);
            } else if restore_selected {
                owner.restore_selected(previous_selected);
            }
            owner.save(system).await?;
            return Err(error);
        }
    };
    Ok((permit, claim))
}

/// Selects a head-of-line escape through the same real claim path as ordinary
/// selection and records the durable escape counter on the canonical owner.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_hol_escape<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
) -> JobResult<(crate::fairness::FairPermit, crate::lifecycle::ClaimedJob), S::Error> {
    fair_dispatch_select_inner(system, job_id, now, true, SelectionObservation::Always).await
}

/// Apply a real lifecycle result and settle the canonical owner permit.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_release<S: JobStore>(
    system: &JobSystem<S>,
    permit: crate::fairness::FairPermit,
    claim: crate::lifecycle::ClaimedJob,
    result: crate::batch::BatchResult,
    now: Timestamp,
) -> JobResult<(), S::Error> {
    let release = match &result.outcome {
        JobOutcome::Complete(_) => crate::fairness::FairRelease::Complete,
        JobOutcome::DeadLetter { .. } => crate::fairness::FairRelease::DeadLetter,
        JobOutcome::Cancelled => crate::fairness::FairRelease::Cancelled,
        JobOutcome::Continue { .. } | JobOutcome::Retry { .. } => {
            crate::fairness::FairRelease::Retry
        }
    };
    let outcome = result.outcome;
    let mut owner = FairDispatchOwner::load(system)
        .await?
        .ok_or(JobSystemError::NotFound)?;
    owner
        .release(permit, release)
        .map_err(|_| JobSystemError::LeaseConflict)?;
    owner.save(system).await?;
    match outcome {
        JobOutcome::Complete(code) => {
            system
                .complete(claim, JobOutcome::Complete(code), now)
                .await?;
        }
        outcome => {
            system.apply_outcome(claim, outcome, now).await?;
        }
    }
    Ok(())
}

/// Performs one service unit through a real durable claim, then settles the
/// canonical fair permit as a service transition. This keeps service credit
/// and lifecycle retry state on the same production boundary as ordinary
/// selection/release.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_service<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    refill_rate: bool,
    now: Timestamp,
) -> JobResult<(), S::Error> {
    let mut owner = FairDispatchOwner::load(system)
        .await?
        .ok_or(JobSystemError::NotFound)?;
    let claim_capacity = std::num::NonZeroU16::new(
        owner
            .budget()
            .max_concurrency_per_scope()
            .get()
            .min(u32::from(u16::MAX)) as u16,
    )
    .unwrap_or(std::num::NonZeroU16::MIN);
    let permit = owner
        .select(job_id)
        .map_err(|_| JobSystemError::LeaseConflict)?;
    if !owner.observe_selection_attempt(job_id, true) {
        return Err(JobSystemError::LeaseConflict);
    }
    owner
        .settle_service(&permit, refill_rate)
        .map_err(|_| JobSystemError::LeaseConflict)?;
    owner.save(system).await?;
    let claim = match system
        .claim_with_capacity(job_id, now, claim_capacity)
        .await
    {
        Ok(claim) => claim,
        Err(error) => {
            let _ = owner.release(permit, crate::fairness::FairRelease::Conflict);
            let _ = owner.observe_selection_attempt(job_id, false);
            owner.save(system).await?;
            return Err(error);
        }
    };
    let outcome = JobOutcome::Retry {
        class: RetryClass::Transient,
        not_before: Some(now),
        code: crate::policy::OutcomeCode::try_new("fair_service")?,
    };
    system.apply_outcome(claim, outcome, now).await?;
    Ok(())
}

/// Apply one item through the real batch result validator, settle the durable
/// lifecycle authority, and publish the item result on the canonical owner.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_batch_item<S: JobStore>(
    system: &JobSystem<S>,
    batch: &Batch,
    permit: crate::fairness::FairPermit,
    claim: crate::lifecycle::ClaimedJob,
    result: crate::batch::BatchResult,
    now: Timestamp,
) -> JobResult<(), S::Error> {
    batch
        .apply_results(std::slice::from_ref(&result))
        .map_err(|_| JobSystemError::LeaseConflict)?;
    if result.attempt_id != claim.attempt_id() {
        return Err(JobSystemError::LeaseConflict);
    }
    let fair_result = fair_batch_item_state(&result.outcome);
    let job_id = claim.record().job_id;
    let mut owner = FairDispatchOwner::load(system)
        .await?
        .ok_or(JobSystemError::NotFound)?;
    let release = match &result.outcome {
        JobOutcome::Complete(_) => crate::fairness::FairRelease::Complete,
        JobOutcome::DeadLetter { .. } => crate::fairness::FairRelease::DeadLetter,
        JobOutcome::Cancelled => crate::fairness::FairRelease::Cancelled,
        JobOutcome::Continue { .. } | JobOutcome::Retry { .. } => {
            crate::fairness::FairRelease::Retry
        }
    };
    owner
        .release(permit, release)
        .map_err(|_| JobSystemError::LeaseConflict)?;
    if !owner.record_batch_result(job_id, fair_result) {
        return Err(JobSystemError::LeaseConflict);
    }
    owner.save(system).await?;
    match result.outcome {
        JobOutcome::Complete(code) => {
            system
                .complete(claim, JobOutcome::Complete(code), now)
                .await?;
        }
        outcome => {
            system.apply_outcome(claim, outcome, now).await?;
        }
    }
    Ok(())
}

#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_scratch<S: JobStore>(
    system: &JobSystem<S>,
    clear: bool,
    capacity: usize,
) -> JobResult<(), S::Error> {
    let mut owner = FairDispatchOwner::load(system)
        .await?
        .ok_or(JobSystemError::NotFound)?;
    if owner.scratch_capacity() != capacity {
        return Err(JobSystemError::LeaseConflict);
    }
    if clear {
        if !owner.batch_clearable() {
            return Err(JobSystemError::LeaseConflict);
        }
        owner.clear_batch();
    } else {
        if !owner.scratch_shrinkable() {
            return Err(JobSystemError::LeaseConflict);
        }
        owner.shrink_scratch();
    }
    owner.save(system).await
}

#[cfg(all(test, not(target_family = "wasm")))]
fn fair_batch_item_state(outcome: &JobOutcome) -> crate::fairness::FairBatchItemState {
    match outcome {
        JobOutcome::Complete(_) => crate::fairness::FairBatchItemState::Success,
        JobOutcome::DeadLetter { .. } => crate::fairness::FairBatchItemState::DeadLetter,
        JobOutcome::Cancelled => crate::fairness::FairBatchItemState::DeadLetter,
        JobOutcome::Continue { .. } | JobOutcome::Retry { .. } => {
            crate::fairness::FairBatchItemState::Retry
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) struct FairDispatchBatch {
    pub(crate) batch: Batch,
    pub(crate) claims: Vec<(crate::fairness::FairPermit, crate::lifecycle::ClaimedJob)>,
}

#[cfg(all(test, not(target_family = "wasm")))]
struct PendingBatchClaims {
    claims: Vec<(crate::fairness::FairPermit, crate::lifecycle::ClaimedJob)>,
}

#[cfg(all(test, not(target_family = "wasm")))]
impl PendingBatchClaims {
    fn new(permit: crate::fairness::FairPermit, claim: crate::lifecycle::ClaimedJob) -> Self {
        Self {
            claims: vec![(permit, claim)],
        }
    }

    fn push(&mut self, permit: crate::fairness::FairPermit, claim: crate::lifecycle::ClaimedJob) {
        self.claims.push((permit, claim));
    }

    async fn rollback<S: JobStore>(
        self,
        system: &JobSystem<S>,
        now: Timestamp,
    ) -> JobResult<(), S::Error> {
        let mut rollback_error = None;
        for (permit, claim) in self.claims {
            if let Err(error) = rollback_batch_claim(system, permit, claim, now).await
                && rollback_error.is_none()
            {
                rollback_error = Some(error);
            }
        }
        rollback_error.map_or(Ok(()), Err)
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
impl From<PendingBatchClaims> for Vec<(crate::fairness::FairPermit, crate::lifecycle::ClaimedJob)> {
    fn from(pending: PendingBatchClaims) -> Self {
        pending.claims
    }
}

/// Atomically forms a real bounded batch from two owner-selected durable
/// claims.  Any failed second claim or compatibility check rolls the first
/// claim back through the same retry transition and owner release path.
#[cfg(all(test, not(target_family = "wasm")))]
pub(crate) async fn fair_dispatch_batch_start<S: JobStore>(
    system: &JobSystem<S>,
    first: JobId,
    second: JobId,
    capacity: u16,
    now: Timestamp,
) -> JobResult<FairDispatchBatch, S::Error> {
    let owner = FairDispatchOwner::load(system)
        .await?
        .ok_or(JobSystemError::NotFound)?;
    let limits = prepare_batch_start(system, &owner, first, second, capacity, now).await?;
    let (first_permit, first_claim) =
        fair_dispatch_select_inner(system, first, now, false, SelectionObservation::Never).await?;
    let mut pending = PendingBatchClaims::new(first_permit, first_claim);
    let formed =
        form_batch_after_first_claim(system, first, second, capacity, now, limits, &mut pending)
            .await;
    match formed {
        Ok(batch) => Ok(FairDispatchBatch {
            batch,
            claims: pending.into(),
        }),
        Err(error) => rollback_batch_start_failure(system, pending, error, now).await,
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
async fn prepare_batch_start<S: JobStore>(
    system: &JobSystem<S>,
    owner: &FairDispatchOwner,
    first: JobId,
    second: JobId,
    capacity: u16,
    now: Timestamp,
) -> JobResult<BatchLimits, S::Error> {
    if batch_is_active(owner) || owner.scratch_capacity() != usize::from(capacity) {
        return Err(JobSystemError::LeaseConflict);
    }
    let max_items = std::num::NonZeroU16::new(capacity).ok_or(JobSystemError::Validation(
        crate::error::ValidationError::InvalidValue {
            field: "batch capacity",
        },
    ))?;
    let limits = BatchLimits::try_new(BatchLimitsInput {
        max_items,
        max_payload_bytes: nonzero_usize(crate::model::MAX_INLINE_PAYLOAD_BYTES),
        max_formation_delay: std::time::Duration::from_millis(4),
    })?;
    if owner.metadata(first).is_none() || owner.metadata(second).is_none() {
        return Err(JobSystemError::NotFound);
    }
    let first_item = batch_item_for_record::<S>(system, owner, first).await?;
    let second_item = batch_item_for_record::<S>(system, owner, second).await?;
    let mut preflight = BatchBuilder::try_new(first_item, limits, now)
        .map_err(|_| JobSystemError::LeaseConflict)?;
    preflight
        .try_add(second_item, now)
        .map_err(|_| JobSystemError::LeaseConflict)?;
    Ok(limits)
}

#[cfg(all(test, not(target_family = "wasm")))]
async fn form_batch_after_first_claim<S: JobStore>(
    system: &JobSystem<S>,
    first: JobId,
    second: JobId,
    capacity: u16,
    now: Timestamp,
    limits: BatchLimits,
    pending: &mut PendingBatchClaims,
) -> JobResult<Batch, S::Error> {
    let (second_permit, second_claim) =
        fair_dispatch_select_inner(system, second, now, false, SelectionObservation::Never).await?;
    pending.push(second_permit, second_claim);
    let Some((first_permit, first_claim)) = pending.claims.first() else {
        return Err(JobSystemError::LeaseConflict);
    };
    let Some((second_permit, second_claim)) = pending.claims.get(1) else {
        return Err(JobSystemError::LeaseConflict);
    };
    let mut owner = FairDispatchOwner::load(system)
        .await?
        .ok_or(JobSystemError::NotFound)?;
    let batch = build_claimed_batch::<S>(&owner, first_claim, second_claim, limits, now)?;
    if batch_is_active(&owner) || owner.scratch_capacity() != usize::from(capacity) {
        return Err(JobSystemError::LeaseConflict);
    }
    let members = [first, second].into_iter().collect();
    let first_auth_config = owner
        .metadata(first)
        .ok_or(JobSystemError::NotFound)?
        .auth_config;
    if !owner.record_selection(first_permit) || !owner.record_selection(second_permit) {
        return Err(JobSystemError::LeaseConflict);
    }
    owner.start_batch(
        <crate::fairness::FairScope as From<&crate::policy::FairnessClass>>::from(
            &first_claim.record().fairness,
        )
        .primary_scope(),
        first_auth_config,
        members,
        batch.payload_bytes(),
        batch.formed_at(),
        batch.deadline(),
    );
    owner.save(system).await?;
    Ok(batch)
}

#[cfg(all(test, not(target_family = "wasm")))]
fn build_claimed_batch<S: JobStore>(
    owner: &FairDispatchOwner,
    first_claim: &crate::lifecycle::ClaimedJob,
    second_claim: &crate::lifecycle::ClaimedJob,
    limits: BatchLimits,
    now: Timestamp,
) -> JobResult<Batch, S::Error> {
    let first_item = batch_item_for_claim::<S>(owner, first_claim)?;
    let second_item = batch_item_for_claim::<S>(owner, second_claim)?;
    let mut builder = BatchBuilder::try_new(first_item, limits, now)
        .map_err(|_| JobSystemError::LeaseConflict)?;
    builder
        .try_add(second_item, now)
        .map_err(|_| JobSystemError::LeaseConflict)?;
    Ok(builder.finish())
}

#[cfg(all(test, not(target_family = "wasm")))]
fn batch_is_active(owner: &FairDispatchOwner) -> bool {
    owner.batch_clearable() || (owner.scratch_capacity() > 0 && !owner.scratch_shrinkable())
}

#[cfg(all(test, not(target_family = "wasm")))]
fn batch_item_for_claim<S: JobStore>(
    owner: &FairDispatchOwner,
    claim: &crate::lifecycle::ClaimedJob,
) -> JobResult<BatchItem, S::Error> {
    let record = claim.record();
    let metadata = owner
        .metadata(record.job_id)
        .ok_or(JobSystemError::NotFound)?;
    Ok(BatchItem::from_record_metadata(
        record,
        metadata,
        claim.attempt_id(),
        claim.payload().clone(),
    ))
}

#[cfg(all(test, not(target_family = "wasm")))]
async fn batch_item_for_record<S: JobStore>(
    system: &JobSystem<S>,
    owner: &FairDispatchOwner,
    job_id: JobId,
) -> JobResult<BatchItem, S::Error> {
    let encoded = system
        .store()
        .get(keys::job_key(system.namespace(), &job_id)?)
        .await
        .map_err(JobSystemError::Store)?
        .ok_or(JobSystemError::NotFound)?;
    let record = decode_job_record(&encoded)?;
    let metadata = owner.metadata(job_id).ok_or(JobSystemError::NotFound)?;
    Ok(BatchItem::from_record_metadata(
        &record,
        metadata,
        // This preflight item is never submitted as a result. Give each
        // durable job a stable distinct token so formation can still reject
        // duplicate attempts before the real claims are acquired.
        (*job_id.as_bytes()).into(),
        Bytes::from(vec![0; record.payload.total_length as usize]),
    ))
}

#[cfg(all(test, not(target_family = "wasm")))]
impl BatchCompatibility {
    fn from_record_metadata(
        record: &crate::model::JobRecordV1,
        metadata: &FairCandidateMetadata,
    ) -> Self {
        Self {
            handler_kind: metadata.handler_kind.clone(),
            schema_version: metadata.schema_version,
            batch_key: metadata.batch_key,
            auth_config: metadata.auth_config,
            effect_mode: metadata.effect_mode,
            retry_policy: metadata.retry_policy,
            timeout: metadata.timeout,
            priority: record.priority,
            fairness: record.fairness.clone(),
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
impl BatchItem {
    fn from_record_metadata(
        record: &crate::model::JobRecordV1,
        metadata: &FairCandidateMetadata,
        attempt_id: crate::ids::AttemptId,
        payload: Bytes,
    ) -> Self {
        Self {
            job_id: record.job_id,
            execution_id: record.execution_id,
            attempt_id,
            payload,
            compatibility: BatchCompatibility::from_record_metadata(record, metadata),
            ordering_key: record.ordering_key.clone(),
            ordering_position: record.revision,
            enqueued_at: metadata.enqueued_at,
            batch_deadline: metadata.batch_deadline,
        }
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
async fn rollback_batch_claim<S: JobStore>(
    system: &JobSystem<S>,
    permit: crate::fairness::FairPermit,
    claim: crate::lifecycle::ClaimedJob,
    now: Timestamp,
) -> JobResult<(), S::Error> {
    let result = crate::batch::BatchResult {
        attempt_id: claim.attempt_id(),
        outcome: retry_outcome()?,
    };
    fair_dispatch_release(system, permit, claim, result, now).await
}

#[cfg(all(test, not(target_family = "wasm")))]
async fn rollback_batch_start_failure<S: JobStore>(
    system: &JobSystem<S>,
    pending: PendingBatchClaims,
    error: JobSystemError<S::Error>,
    now: Timestamp,
) -> JobResult<FairDispatchBatch, S::Error> {
    pending.rollback(system, now).await?;
    Err(error)
}

#[cfg(all(test, not(target_family = "wasm")))]
fn retry_outcome() -> Result<JobOutcome, crate::error::ValidationError> {
    Ok(JobOutcome::Retry {
        class: RetryClass::Transient,
        not_before: Some(Timestamp::ZERO),
        code: crate::policy::OutcomeCode::try_new("batch_retry")?,
    })
}

#[cfg(all(test, not(target_family = "wasm")))]
fn connector_budget() -> Result<FairnessBudget, crate::error::ValidationError> {
    FairnessBudget::try_new(FairnessBudgetInput {
        candidate_window: nonzero_u32(3),
        max_concurrency_per_scope: nonzero_u32(2),
        max_rate_per_scope: nonzero_u32(3),
        max_low_volume_service: nonzero_u32(1),
        max_payload_bytes: nonzero_usize(crate::model::MAX_INLINE_PAYLOAD_BYTES),
        max_cost_units: nonzero_u16(2),
    })
}

fn nonzero_u16(value: u16) -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(value).unwrap_or(std::num::NonZeroU16::MIN)
}

fn nonzero_u32(value: u32) -> std::num::NonZeroU32 {
    std::num::NonZeroU32::new(value).unwrap_or(std::num::NonZeroU32::MIN)
}

fn nonzero_usize(value: usize) -> std::num::NonZeroUsize {
    std::num::NonZeroUsize::new(value).unwrap_or(std::num::NonZeroUsize::MIN)
}
