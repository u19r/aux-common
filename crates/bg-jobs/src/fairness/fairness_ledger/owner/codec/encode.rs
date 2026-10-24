//! Encoding of the versioned fair-owner state.

use super::{
    super::{
        super::state::CandidateRecord,
        state::{FairBatchState, FairCandidateMetadata, FairDispatchOwner},
    },
    wire::{
        Writer, batch_result_state_byte, candidate_state_byte, priority_byte, volume_mode_byte,
        write_block, write_count, write_optional_bytes, write_retry, write_scope,
    },
};
use crate::{codec::encode_effect_mode, error::StoreDataError};

impl FairDispatchOwner {
    pub(in crate::fairness::fairness_ledger::owner) fn encode(
        &self,
    ) -> Result<Vec<u8>, StoreDataError> {
        let mut writer = Writer::with_capacity(2_048);
        write_header(&mut writer, self);
        write_scopes(&mut writer, self)?;
        write_orders(&mut writer, self)?;
        write_candidates(&mut writer, self)?;
        write_metadata(&mut writer, self)?;
        write_batch(&mut writer, &self.batch)?;
        write_selection(&mut writer, self)?;
        Ok(writer.bytes)
    }
}

fn write_header(writer: &mut Writer, owner: &FairDispatchOwner) {
    writer.fixed(b"FDS");
    writer.u8(super::constants::FAIR_OWNER_VERSION);
    let budget = owner.ledger.budget;
    writer.u32(budget.candidate_window.get());
    writer.u32(budget.max_concurrency_per_scope.get());
    writer.u32(budget.max_rate_per_scope.get());
    writer.u32(budget.max_low_volume_service.get());
    writer.u64(budget.max_payload_bytes.get() as u64);
    writer.u16(budget.max_cost_units.get());
    let priority = owner.ledger.priority;
    writer.u64(priority.critical_served());
    writer.u64(priority.default_served());
    writer.u64(priority.bulk_served());
    writer.u32(priority.critical_window());
    writer.u32(priority.default_window());
    writer.u32(priority.bulk_window());
    writer.u32(priority.cycle());
    writer.u128(owner.ledger.service_clock);
}

fn write_scopes(writer: &mut Writer, owner: &FairDispatchOwner) -> Result<(), StoreDataError> {
    write_count(writer, owner.ledger.scopes.len())?;
    for (scope, state) in &owner.ledger.scopes {
        write_scope(writer, scope)?;
        write_scope_state(writer, state);
    }
    Ok(())
}

fn write_scope_state(writer: &mut Writer, state: &crate::fairness::ScopeState) {
    writer.u8(volume_mode_byte(state.mode));
    writer.u64(state.head);
    writer.u64(state.order);
    writer.u16(state.cost.get());
    write_block(writer, state.block);
    writer.u16(state.weight.get());
    writer.u64(state.served);
    write_service_accounting(writer, &state.service);
    write_service_accounting(writer, &state.own_service);
    writer.u128(state.child_service_clock);
    writer.u32(state.in_flight);
    writer.u32(state.permits);
    writer.u32(state.rate);
    writer.u32(state.quiet_dwell);
    writer.u128(state.errors);
    writer.u64(state.acquisitions);
    writer.u64(state.releases);
}

fn write_orders(writer: &mut Writer, owner: &FairDispatchOwner) -> Result<(), StoreDataError> {
    write_count(writer, owner.ledger.orders.len())?;
    for (ordering, order) in &owner.ledger.orders {
        writer.bytes(ordering.as_bytes())?;
        writer.u64(order.head);
        writer.fixed(order.owner.as_bytes());
        writer.u8(u8::from(order.in_flight));
        writer.u64(order.acquisitions);
        writer.u64(order.releases);
    }
    Ok(())
}

fn write_candidates(writer: &mut Writer, owner: &FairDispatchOwner) -> Result<(), StoreDataError> {
    write_count(writer, owner.ledger.candidates.len())?;
    for (job_id, record) in &owner.ledger.candidates {
        writer.fixed(job_id.as_bytes());
        write_candidate(writer, record)?;
    }
    Ok(())
}

fn write_candidate(writer: &mut Writer, record: &CandidateRecord) -> Result<(), StoreDataError> {
    let candidate = &record.candidate;
    write_scope(writer, &candidate.scope)?;
    writer.u8(priority_byte(candidate.priority));
    writer.u16(candidate.cost_units.get());
    writer.i64(candidate.scheduled_at.as_millis());
    writer.u64(candidate.payload_bytes as u64);
    write_optional_bytes(
        writer,
        candidate
            .ordering_key
            .as_ref()
            .map(crate::ids::OrderingKey::as_bytes),
    )?;
    writer.u64(candidate.ordering_position);
    write_block(writer, candidate.block);
    writer.u8(candidate_state_byte(record.state));
    writer.u64(record.service_transitions);
    writer.u64(
        record
            .acquisition_generation
            .map_or(0, |generation| generation.get()),
    );
    Ok(())
}

fn write_metadata(writer: &mut Writer, owner: &FairDispatchOwner) -> Result<(), StoreDataError> {
    write_count(writer, owner.metadata.len())?;
    for (job_id, metadata) in &owner.metadata {
        writer.fixed(job_id.as_bytes());
        write_metadata_entry(writer, metadata)?;
    }
    Ok(())
}

fn write_metadata_entry(
    writer: &mut Writer,
    metadata: &FairCandidateMetadata,
) -> Result<(), StoreDataError> {
    writer.text(metadata.handler_kind.as_str())?;
    writer.u16(metadata.schema_version.get());
    writer.u64(metadata.batch_key.get());
    writer.u64(metadata.auth_config.get());
    writer.u8(encode_effect_mode(metadata.effect_mode));
    write_retry(writer, metadata.retry_policy)?;
    writer.u64(metadata.timeout.as_nanos() as u64);
    writer.i64(metadata.enqueued_at.as_millis());
    writer.i64(metadata.batch_deadline.as_millis());
    Ok(())
}

fn write_batch(writer: &mut Writer, batch: &FairBatchState) -> Result<(), StoreDataError> {
    writer.u8(u8::from(batch.active));
    write_scope(writer, &batch.scope)?;
    writer.u64(batch.auth_config.get());
    write_batch_members(writer, batch)?;
    write_batch_results(writer, batch)?;
    writer.u64(batch.scratch_size as u64);
    writer.u64(batch.scratch_capacity as u64);
    writer.u64(batch.payload_bytes as u64);
    writer.i64(batch.formed_at.as_millis());
    writer.i64(batch.deadline.as_millis());
    Ok(())
}

fn write_batch_members(writer: &mut Writer, batch: &FairBatchState) -> Result<(), StoreDataError> {
    write_count(writer, batch.members.len())?;
    for job_id in &batch.members {
        writer.fixed(job_id.as_bytes());
    }
    Ok(())
}

fn write_batch_results(writer: &mut Writer, batch: &FairBatchState) -> Result<(), StoreDataError> {
    write_count(writer, batch.results.len())?;
    for (job_id, result) in &batch.results {
        writer.fixed(job_id.as_bytes());
        writer.u8(batch_result_state_byte(*result));
    }
    Ok(())
}

fn write_selection(writer: &mut Writer, owner: &FairDispatchOwner) -> Result<(), StoreDataError> {
    writer.u64(owner.hol_escapes);
    writer.fixed(owner.selected.job_id.as_bytes());
    write_scope(writer, &owner.selected.scope)?;
    writer.u16(owner.selected.cost_units);
    Ok(())
}

fn write_service_accounting(
    writer: &mut Writer,
    service: &crate::fairness::service_accounting::ServiceAccounting,
) {
    writer.u64(service.cost);
    writer.u128(service.origin);
    writer.u64(service.base_cost);
}
