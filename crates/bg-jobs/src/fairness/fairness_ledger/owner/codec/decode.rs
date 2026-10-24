//! Decoding of the versioned fair-owner state.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use super::{
    super::{
        super::state::{CandidateRecord, OrderRecord},
        state::{FairBatchState, FairCandidateMetadata, FairDispatchOwner, FairSelectionSnapshot},
    },
    wire::{
        Reader, batch_result_state_from_byte, candidate_state_from_byte, nonzero_u16, nonzero_u32,
        nonzero_usize, priority_from_byte, read_block, read_count, read_scope,
        volume_mode_from_byte,
    },
};
use crate::{
    batch::{AuthConfigId, BatchKey},
    codec::decode_effect_mode,
    error::StoreDataError,
    fairness::{
        FairCandidate, FairnessBudget, FairnessBudgetInput, FairnessLedger, PriorityDeficit,
        ScopeState,
    },
    ids::{JobId, JobKind, OrderingKey},
    model::MAX_COST_UNITS,
    time::Timestamp,
};

impl FairDispatchOwner {
    pub(in crate::fairness::fairness_ledger::owner) fn decode(
        encoded: &[u8],
    ) -> Result<Self, StoreDataError> {
        let mut reader = Reader::new(encoded);
        let ledger = decode_ledger(&mut reader)?;
        let metadata = decode_metadata(&mut reader)?;
        let batch = decode_batch(&mut reader)?;
        let hol_escapes = reader.u64()?;
        let selected = decode_selection(&mut reader)?;
        reader.finish()?;
        let owner = Self {
            ledger,
            metadata,
            batch,
            hol_escapes,
            selected,
            loaded_value: None,
        };
        owner.validate_persisted_state()?;
        Ok(owner)
    }
}

fn decode_ledger(reader: &mut Reader<'_>) -> Result<FairnessLedger, StoreDataError> {
    read_header(reader)?;
    let budget = decode_budget(reader)?;
    let mut ledger = FairnessLedger::new(budget);
    ledger.priority = decode_priority(reader)?;
    ledger.service_clock = reader.u128()?;
    decode_scopes(reader, &mut ledger)?;
    decode_orders(reader, &mut ledger)?;
    decode_candidates(reader, &mut ledger)?;
    ledger.rebuild_ready_counts();
    Ok(ledger)
}

fn read_header(reader: &mut Reader<'_>) -> Result<(), StoreDataError> {
    if reader.take(3)? != b"FDS" || reader.u8()? != super::constants::FAIR_OWNER_VERSION {
        return Err(StoreDataError::Malformed("fair owner version"));
    }
    Ok(())
}

fn decode_budget(reader: &mut Reader<'_>) -> Result<FairnessBudget, StoreDataError> {
    FairnessBudget::try_new(FairnessBudgetInput {
        candidate_window: nonzero_u32(reader.u32()?, "candidate window")?,
        max_concurrency_per_scope: nonzero_u32(reader.u32()?, "scope concurrency")?,
        max_rate_per_scope: nonzero_u32(reader.u32()?, "scope rate")?,
        max_low_volume_service: nonzero_u32(reader.u32()?, "low volume service")?,
        max_payload_bytes: nonzero_usize(reader.u64()?, "payload bytes")?,
        max_cost_units: nonzero_u16(reader.u16()?, "cost units")?,
    })
    .map_err(|_| StoreDataError::Malformed("fair owner budget"))
}

fn decode_priority(reader: &mut Reader<'_>) -> Result<PriorityDeficit, StoreDataError> {
    Ok(PriorityDeficit::from_parts(
        reader.u64()?,
        reader.u64()?,
        reader.u64()?,
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
        reader.u32()?,
    ))
}

fn decode_scopes(
    reader: &mut Reader<'_>,
    ledger: &mut FairnessLedger,
) -> Result<(), StoreDataError> {
    for _ in 0..read_count(reader)? {
        let (scope, state) = decode_scope(reader)?;
        if ledger.scopes.insert(scope, state).is_some() {
            return Err(StoreDataError::Malformed("fair owner duplicate scope"));
        }
    }
    Ok(())
}

fn decode_scope(reader: &mut Reader<'_>) -> Result<(crate::FairScope, ScopeState), StoreDataError> {
    let scope = read_scope(reader)?;
    let state = ScopeState {
        mode: volume_mode_from_byte(reader.u8()?)?,
        ready_count: 0,
        head: reader.u64()?,
        order: reader.u64()?,
        cost: nonzero_u16(reader.u16()?, "scope cost")?,
        block: read_block(reader)?,
        weight: nonzero_u16(reader.u16()?, "scope weight")?,
        served: reader.u64()?,
        service: read_service_accounting(reader)?,
        own_service: read_service_accounting(reader)?,
        child_service_clock: reader.u128()?,
        in_flight: reader.u32()?,
        permits: reader.u32()?,
        rate: reader.u32()?,
        quiet_dwell: reader.u32()?,
        errors: reader.u128()?,
        acquisitions: reader.u64()?,
        releases: reader.u64()?,
    };
    Ok((scope, state))
}

fn decode_orders(
    reader: &mut Reader<'_>,
    ledger: &mut FairnessLedger,
) -> Result<(), StoreDataError> {
    for _ in 0..read_count(reader)? {
        let ordering = OrderingKey::try_new(reader.bytes()?)?;
        let order = decode_order(reader)?;
        if ledger.orders.insert(ordering, order).is_some() {
            return Err(StoreDataError::Malformed("fair owner duplicate order"));
        }
    }
    Ok(())
}

fn decode_order(reader: &mut Reader<'_>) -> Result<OrderRecord, StoreDataError> {
    Ok(OrderRecord {
        head: reader.u64()?,
        owner: JobId::try_from_slice(reader.fixed_array::<16>()?)?,
        in_flight: reader.u8()? != 0,
        acquisitions: reader.u64()?,
        releases: reader.u64()?,
    })
}

fn decode_candidates(
    reader: &mut Reader<'_>,
    ledger: &mut FairnessLedger,
) -> Result<(), StoreDataError> {
    for _ in 0..read_count(reader)? {
        let (job_id, record) = decode_candidate(reader, ledger)?;
        if ledger.candidates.insert(job_id, record).is_some() {
            return Err(StoreDataError::Malformed("fair owner duplicate candidate"));
        }
    }
    Ok(())
}

fn decode_candidate(
    reader: &mut Reader<'_>,
    ledger: &FairnessLedger,
) -> Result<(JobId, CandidateRecord), StoreDataError> {
    let job_id = JobId::try_from_slice(reader.fixed_array::<16>()?)?;
    let scope = read_scope(reader)?;
    if !ledger.scopes.contains_key(&scope) || !ledger.scopes.contains_key(&scope.primary_scope()) {
        return Err(StoreDataError::Malformed("fair owner candidate scope"));
    }
    let candidate = FairCandidate {
        job_id,
        scope,
        priority: priority_from_byte(reader.u8()?)?,
        cost_units: nonzero_u16(reader.u16()?, "candidate cost")?,
        scheduled_at: Timestamp::from_millis(reader.i64()?),
        payload_bytes: usize::try_from(reader.u64()?)
            .map_err(|_| StoreDataError::LengthOverflow)?,
        ordering_key: reader
            .optional_bytes()?
            .map(OrderingKey::try_new)
            .transpose()?,
        ordering_position: reader.u64()?,
        block: read_block(reader)?,
    };
    let state = candidate_state_from_byte(reader.u8()?)?;
    let service_transitions = reader.u64()?;
    let acquisition_generation = crate::fairness::FairPermitGeneration::from_u64(reader.u64()?);
    Ok((
        job_id,
        CandidateRecord {
            candidate,
            state,
            service_transitions,
            acquisition_generation,
        },
    ))
}

fn decode_metadata(
    reader: &mut Reader<'_>,
) -> Result<BTreeMap<JobId, FairCandidateMetadata>, StoreDataError> {
    let mut metadata = BTreeMap::new();
    for _ in 0..read_count(reader)? {
        let (job_id, value) = decode_metadata_entry(reader)?;
        if metadata.insert(job_id, value).is_some() {
            return Err(StoreDataError::Malformed("fair owner duplicate metadata"));
        }
    }
    Ok(metadata)
}

fn decode_metadata_entry(
    reader: &mut Reader<'_>,
) -> Result<(JobId, FairCandidateMetadata), StoreDataError> {
    let job_id = JobId::try_from_slice(reader.fixed_array::<16>()?)?;
    let handler_kind = JobKind::try_new(reader.text()?)?;
    let schema_version = nonzero_u16(reader.u16()?, "schema version")?;
    let batch_key = BatchKey::new(reader.u64()?);
    let auth_config = AuthConfigId::new(reader.u64()?);
    let effect_mode = decode_effect_mode(reader.u8()?)
        .map_err(|_| StoreDataError::Malformed("fair owner effect mode"))?;
    let retry_policy = super::wire::read_retry(reader)?;
    let timeout = Duration::from_nanos(reader.u64()?);
    let enqueued_at = Timestamp::from_millis(reader.i64()?);
    let batch_deadline = Timestamp::from_millis(reader.i64()?);
    Ok((
        job_id,
        FairCandidateMetadata {
            handler_kind,
            schema_version,
            batch_key,
            auth_config,
            effect_mode,
            retry_policy,
            timeout,
            enqueued_at,
            batch_deadline,
        },
    ))
}

fn decode_batch(reader: &mut Reader<'_>) -> Result<FairBatchState, StoreDataError> {
    let active = reader.u8()? != 0;
    let scope = read_scope(reader)?;
    let auth_config = AuthConfigId::new(reader.u64()?);
    let members = decode_batch_members(reader)?;
    let results = decode_batch_results(reader)?;
    Ok(FairBatchState {
        active,
        scope,
        auth_config,
        members,
        results,
        scratch_size: decode_usize(reader)?,
        scratch_capacity: decode_usize(reader)?,
        payload_bytes: decode_usize(reader)?,
        formed_at: Timestamp::from_millis(reader.i64()?),
        deadline: Timestamp::from_millis(reader.i64()?),
    })
}

fn decode_usize(reader: &mut Reader<'_>) -> Result<usize, StoreDataError> {
    usize::try_from(reader.u64()?).map_err(|_| StoreDataError::LengthOverflow)
}

fn decode_batch_members(reader: &mut Reader<'_>) -> Result<BTreeSet<JobId>, StoreDataError> {
    let mut members = BTreeSet::new();
    for _ in 0..read_count(reader)? {
        if !members.insert(JobId::try_from_slice(reader.fixed_array::<16>()?)?) {
            return Err(StoreDataError::Malformed(
                "fair owner duplicate batch member",
            ));
        }
    }
    Ok(members)
}

fn decode_batch_results(
    reader: &mut Reader<'_>,
) -> Result<BTreeMap<JobId, super::super::state::FairBatchItemState>, StoreDataError> {
    let mut results = BTreeMap::new();
    for _ in 0..read_count(reader)? {
        let job_id = JobId::try_from_slice(reader.fixed_array::<16>()?)?;
        let result = batch_result_state_from_byte(reader.u8()?)?;
        if results.insert(job_id, result).is_some() {
            return Err(StoreDataError::Malformed(
                "fair owner duplicate batch result",
            ));
        }
    }
    Ok(results)
}

fn decode_selection(reader: &mut Reader<'_>) -> Result<FairSelectionSnapshot, StoreDataError> {
    let job_id = JobId::try_from_slice(reader.fixed_array::<16>()?)?;
    let scope = read_scope(reader)?;
    let cost_units = reader.u16()?;
    if cost_units > MAX_COST_UNITS {
        return Err(StoreDataError::Malformed("fair owner selected cost"));
    }
    Ok(FairSelectionSnapshot {
        job_id,
        scope,
        cost_units,
    })
}

fn read_service_accounting(
    reader: &mut Reader<'_>,
) -> Result<crate::fairness::service_accounting::ServiceAccounting, StoreDataError> {
    let cost = reader.u64()?;
    let origin = reader.u128()?;
    let base_cost = reader.u64()?;
    if base_cost > cost {
        return Err(StoreDataError::Malformed("fair service cost baseline"));
    }
    Ok(crate::fairness::service_accounting::ServiceAccounting {
        cost,
        origin,
        base_cost,
    })
}
