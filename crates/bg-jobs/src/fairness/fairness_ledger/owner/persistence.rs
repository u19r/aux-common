//! Durable load, checked save, and persisted-state validation.

use bytes::Bytes;

use super::{
    constants::FAIR_OWNER_MARKER,
    state::{FairBatchItemState, FairBatchState, FairDispatchOwner},
};
use crate::{
    codec::{ValueCodec, ValueTag},
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreDataError},
    fairness::FairCandidateState,
    keys,
    store::{Check, JobStore, Mutation, StoreKey, StoreTransaction},
    time::Timestamp,
};

impl FairDispatchOwner {
    /// Loads the canonical owner from namespace state. The fair owner is
    /// advisory accounting, but scoped service history and candidate states
    /// remain durable. The aggregate low-volume allowance starts a new drive
    /// with outstanding reservations still charged.
    pub(crate) async fn load<S: JobStore>(
        system: &JobSystem<S>,
    ) -> JobResult<Option<Self>, S::Error> {
        let key = keys::fair_state_key(system.namespace())?;
        let Some(encoded) = load_value(system, key).await? else {
            return Ok(None);
        };
        let body = decode_value(&encoded)?;
        let mut owner = Self::decode(body)?;
        if let Some(state) = owner
            .ledger
            .scopes
            .get_mut(&crate::fairness::FairScope::LowVolume)
        {
            state.served = u64::from(state.in_flight);
        }
        owner.loaded_value = Some(encoded);
        Ok(Some(owner))
    }

    /// Stores the full owner with a checked replacement. A competing owner
    /// receives the normal transition conflict instead of overwriting state.
    pub(crate) async fn save<S: JobStore>(
        &mut self,
        system: &JobSystem<S>,
    ) -> JobResult<(), S::Error> {
        self.compact_terminal_candidates();
        let key = keys::fair_state_key(system.namespace())?;
        let value = encode_value(self)?;
        let expected_old = self.loaded_value.clone();
        let transaction =
            build_save_transaction(system, key.clone(), expected_old.as_ref(), &value)?;
        crate::transition::commit_transition(
            system,
            transaction,
            key,
            expected_old.as_ref(),
            Some(&value),
            crate::transition::TransitionConflict::LeaseConflict,
        )
        .await?;
        self.loaded_value = Some(value);
        Ok(())
    }

    pub(super) fn validate_persisted_state(&self) -> Result<(), StoreDataError> {
        self.validate_service_accounting()?;
        if !self.batch.active {
            return validate_inactive_batch(&self.batch);
        }
        validate_active_batch(self)
    }
}

async fn load_value<S: JobStore>(
    system: &JobSystem<S>,
    key: StoreKey,
) -> JobResult<Option<Bytes>, S::Error> {
    system.store().get(key).await.map_err(JobSystemError::Store)
}

fn decode_value(encoded: &[u8]) -> Result<&[u8], StoreDataError> {
    let (tag, body) = ValueCodec::decode_body(encoded)?;
    if tag != ValueTag::FairReady || !body.starts_with(FAIR_OWNER_MARKER) {
        return Err(StoreDataError::Malformed("fair owner value"));
    }
    Ok(&body[FAIR_OWNER_MARKER.len()..])
}

fn encode_value(owner: &FairDispatchOwner) -> Result<Bytes, StoreDataError> {
    let mut body = Vec::with_capacity(FAIR_OWNER_MARKER.len() + 1024);
    body.extend_from_slice(FAIR_OWNER_MARKER);
    body.extend_from_slice(&owner.encode()?);
    ValueCodec::encode(ValueTag::FairReady, &body)
}

fn build_save_transaction<S: JobStore>(
    system: &JobSystem<S>,
    key: StoreKey,
    expected_old: Option<&Bytes>,
    value: &Bytes,
) -> JobResult<StoreTransaction, S::Error> {
    let checks = match expected_old {
        Some(expected) => vec![Check::Value(key.clone(), expected.clone())],
        None => vec![Check::Absent(key.clone())],
    };
    crate::transition::checked_transaction(system, checks, vec![Mutation::Put(key, value.clone())])
}

fn validate_inactive_batch(batch: &FairBatchState) -> Result<(), StoreDataError> {
    if batch.members.is_empty()
        && batch.results.is_empty()
        && batch.scratch_size == 0
        && batch.payload_bytes == 0
        && batch.formed_at == Timestamp::ZERO
        && batch.deadline == Timestamp::ZERO
    {
        Ok(())
    } else {
        Err(StoreDataError::Malformed("fair owner inactive batch state"))
    }
}

fn validate_active_batch(owner: &FairDispatchOwner) -> Result<(), StoreDataError> {
    validate_batch_shape(&owner.batch)?;
    for job_id in &owner.batch.members {
        validate_batch_member(owner, *job_id)?;
    }
    validate_batch_time(&owner.batch)?;
    validate_selected(owner)
}

fn validate_batch_shape(batch: &FairBatchState) -> Result<(), StoreDataError> {
    if batch.members.is_empty() {
        return Err(StoreDataError::Malformed("fair owner batch members"));
    }
    if batch.members.len() != batch.results.len()
        || batch
            .results
            .keys()
            .any(|job_id| !batch.members.contains(job_id))
    {
        return Err(StoreDataError::Malformed("fair owner batch results"));
    }
    if batch.scratch_size != batch.members.len() || batch.scratch_size > batch.scratch_capacity {
        return Err(StoreDataError::Malformed("fair owner batch scratch"));
    }
    Ok(())
}

fn validate_batch_member(
    owner: &FairDispatchOwner,
    job_id: crate::ids::JobId,
) -> Result<(), StoreDataError> {
    let result = owner
        .batch
        .results
        .get(&job_id)
        .ok_or(StoreDataError::Malformed("fair owner batch results"))?;
    let candidate = owner.ledger.candidates.get(&job_id);
    let metadata = owner.metadata.get(&job_id);
    if matches!(result, FairBatchItemState::Missing) {
        validate_missing_batch_member(candidate, metadata)?;
    }
    if let Some(record) = candidate
        && record.candidate.scope.primary_scope() != owner.batch.scope
    {
        return Err(StoreDataError::Malformed("fair owner batch scope"));
    }
    if let Some(metadata) = metadata
        && (metadata.auth_config != owner.batch.auth_config
            || metadata.batch_deadline < owner.batch.deadline)
    {
        return Err(StoreDataError::Malformed("fair owner batch metadata"));
    }
    Ok(())
}

fn validate_missing_batch_member(
    candidate: Option<&crate::fairness::fairness_ledger::state::CandidateRecord>,
    metadata: Option<&super::state::FairCandidateMetadata>,
) -> Result<(), StoreDataError> {
    let candidate_is_leased = match candidate {
        Some(record) => match record.state {
            FairCandidateState::Leased => true,
            FairCandidateState::Absent
            | FairCandidateState::Scheduled
            | FairCandidateState::RetryWaiting
            | FairCandidateState::DeadLettered
            | FairCandidateState::Cancelled => false,
        },
        None => false,
    };
    if !candidate_is_leased {
        return Err(StoreDataError::Malformed("fair owner batch candidate"));
    }
    if metadata.is_none() {
        return Err(StoreDataError::Malformed("fair owner batch metadata"));
    }
    Ok(())
}

fn validate_batch_time(batch: &FairBatchState) -> Result<(), StoreDataError> {
    if batch.formed_at > batch.deadline {
        return Err(StoreDataError::Malformed("fair owner batch time"));
    }
    Ok(())
}

fn validate_selected(owner: &FairDispatchOwner) -> Result<(), StoreDataError> {
    if !owner.batch.members.contains(&owner.selected.job_id) {
        return Err(StoreDataError::Malformed("fair owner batch selection"));
    }
    if let Some(selected) = owner.ledger.candidates.get(&owner.selected.job_id)
        && (selected.candidate.scope != owner.selected.scope
            || selected.candidate.cost_units.get() != owner.selected.cost_units)
    {
        return Err(StoreDataError::Malformed("fair owner batch selection"));
    }
    Ok(())
}
