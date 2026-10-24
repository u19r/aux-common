use std::{
    collections::BTreeSet,
    num::NonZeroU16,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::{
    FairBatchItemState, FairCandidateMetadata, FairDispatchOwner,
    codec::{Reader, read_scope},
};
use crate::{
    batch::{AuthConfigId, BatchKey},
    engine::JobSystem,
    error::{JobSystemError, StoreDataError},
    fairness::{FairCandidateInput, FairScope},
    ids::{FairnessKey, JobId, JobKind, Namespace, OrderingKey, OwnerId},
    policy::{EffectMode, FairnessClass, FairnessPath, FairnessPolicy, Priority, RetryPolicy},
    test_helper::{FakeStore, FakeStoreError},
    time::Timestamp,
};

fn owner_bytes() -> Vec<u8> {
    FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid")
        .encode()
        .expect("owner encodes")
}

const METADATA_EFFECT_MODE_OFFSET: usize = 145;
fn metadata_job_id() -> JobId {
    JobId::from([7; 16])
}

fn owner_with_metadata(effect_mode: EffectMode) -> FairDispatchOwner {
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");
    owner.metadata.insert(
        metadata_job_id(),
        FairCandidateMetadata {
            handler_kind: JobKind::try_new("email").expect("handler kind is valid"),
            schema_version: NonZeroU16::MIN,
            batch_key: BatchKey::new(1),
            auth_config: AuthConfigId::new(1),
            effect_mode,
            retry_policy: RetryPolicy::preset(crate::policy::RetryPreset::Network),
            timeout: Duration::from_secs(1),
            enqueued_at: Timestamp::ZERO,
            batch_deadline: Timestamp::from_millis(4),
        },
    );
    owner
}

fn owner_with_ready_candidate(fairness: FairnessClass) -> FairDispatchOwner {
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");
    let job_id = JobId::from([8; 16]);
    owner
        .ensure_candidate(
            FairCandidateInput {
                job_id,
                fairness,
                priority: Priority::Default,
                cost_units: NonZeroU16::MIN,
                scheduled_at: Timestamp::ZERO,
                payload_bytes: 1,
                ordering_key: Some(OrderingKey::try_new([8]).expect("ordering key is valid")),
                ordering_position: 1,
                block: None,
            },
            FairCandidateMetadata {
                handler_kind: JobKind::try_new("email").expect("handler kind is valid"),
                schema_version: NonZeroU16::MIN,
                batch_key: BatchKey::new(1),
                auth_config: AuthConfigId::new(1),
                effect_mode: EffectMode::Idempotent,
                retry_policy: RetryPolicy::preset(crate::policy::RetryPreset::Network),
                timeout: Duration::from_secs(1),
                enqueued_at: Timestamp::ZERO,
                batch_deadline: Timestamp::ZERO,
            },
        )
        .expect("candidate is valid");
    owner
}

fn owner_with_active_batch() -> FairDispatchOwner {
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");
    owner.start_batch(
        crate::fairness::FairScope::LowVolume,
        AuthConfigId::new(1),
        BTreeSet::from([JobId::from([7; 16]), JobId::from([8; 16])]),
        0,
        Timestamp::ZERO,
        Timestamp::from_millis(10),
    );
    owner
}

#[derive(Clone, Copy)]
enum DuplicateSection {
    Order,
    Metadata,
    BatchMember,
    BatchResult,
}

fn duplicate_wire_entry(mut encoded: Vec<u8>, section: DuplicateSection) -> Vec<u8> {
    let (count_offset, entry_start, entry_end) = wire_section_offsets(&encoded, section);
    let count = u32::from_be_bytes(
        encoded[count_offset..count_offset + 4]
            .try_into()
            .expect("wire count is four bytes"),
    );
    encoded[count_offset..count_offset + 4].copy_from_slice(&(count + 1).to_be_bytes());
    let entry = encoded[entry_start..entry_end].to_vec();
    encoded.splice(entry_end..entry_end, entry);
    encoded
}

fn wire_section_offsets(encoded: &[u8], section: DuplicateSection) -> (usize, usize, usize) {
    let mut reader = Reader::new(encoded);
    reader.take(4).expect("owner header is present");
    for _ in 0..4 {
        reader.u32().expect("budget field is present");
    }
    reader.u64().expect("payload budget is present");
    reader.u16().expect("cost budget is present");
    for _ in 0..3 {
        reader.u64().expect("priority counter is present");
    }
    for _ in 0..4 {
        reader.u32().expect("priority window is present");
    }

    reader.u128().expect("virtual service clock is present");
    let scope_count = reader.u32().expect("scope count is present");
    for _ in 0..scope_count {
        read_scope_state(&mut reader);
    }

    let order_count_offset = reader.offset;
    let order_count = reader.u32().expect("order count is present");
    let order_start = reader.offset;
    for _ in 0..order_count {
        skip_order(&mut reader);
    }
    let order_end = reader.offset;
    if matches!(section, DuplicateSection::Order) {
        return (order_count_offset, order_start, order_end);
    }

    let candidate_count = reader.u32().expect("candidate count is present");
    for _ in 0..candidate_count {
        skip_candidate(&mut reader);
    }

    let metadata_count_offset = reader.offset;
    let metadata_count = reader.u32().expect("metadata count is present");
    let metadata_start = reader.offset;
    for _ in 0..metadata_count {
        skip_metadata(&mut reader);
    }
    let metadata_end = reader.offset;
    if matches!(section, DuplicateSection::Metadata) {
        return (metadata_count_offset, metadata_start, metadata_end);
    }

    reader.u8().expect("batch active flag is present");
    read_scope(&mut reader).expect("batch scope is valid");
    reader.u64().expect("batch auth config is present");
    let member_count_offset = reader.offset;
    let member_count = reader.u32().expect("batch member count is present");
    let member_start = reader.offset;
    for _ in 0..member_count {
        reader
            .fixed_array::<16>()
            .expect("batch member id is present");
    }
    let member_end = reader.offset;
    if matches!(section, DuplicateSection::BatchMember) {
        return (member_count_offset, member_start, member_end);
    }

    let result_count_offset = reader.offset;
    let result_count = reader.u32().expect("batch result count is present");
    let result_start = reader.offset;
    for _ in 0..result_count {
        reader
            .fixed_array::<16>()
            .expect("batch result id is present");
        reader.u8().expect("batch result state is present");
    }
    let result_end = reader.offset;
    (result_count_offset, result_start, result_end)
}

fn read_scope_state(reader: &mut Reader<'_>) {
    read_scope(reader).expect("scope is valid");
    reader.u8().expect("volume mode is present");
    reader.u64().expect("scope head is present");
    reader.u64().expect("scope order is present");
    reader.u16().expect("scope cost is present");
    reader.u8().expect("scope block is present");
    reader.u16().expect("scope weight is present");
    reader.u64().expect("scope served count is present");
    reader.u64().expect("scope served cost is present");
    reader.u128().expect("scope service origin is present");
    reader.u64().expect("scope service base cost is present");
    reader.u64().expect("scope direct service cost is present");
    reader
        .u128()
        .expect("scope direct service origin is present");
    reader
        .u64()
        .expect("scope direct service base cost is present");
    reader.u128().expect("scope child service clock is present");
    for _ in 0..4 {
        reader.u32().expect("scope capacity field is present");
    }
    reader.u128().expect("scope error is present");
    reader.u64().expect("scope acquisitions are present");
    reader.u64().expect("scope releases are present");
}

fn skip_order(reader: &mut Reader<'_>) {
    reader.bytes().expect("ordering key is present");
    reader.u64().expect("order head is present");
    reader.fixed_array::<16>().expect("order owner is present");
    reader.u8().expect("order flight flag is present");
    reader.u64().expect("order acquisitions are present");
    reader.u64().expect("order releases are present");
}

fn skip_candidate(reader: &mut Reader<'_>) {
    reader.fixed_array::<16>().expect("candidate id is present");
    read_scope(reader).expect("candidate scope is valid");
    reader.u8().expect("candidate priority is present");
    reader.u16().expect("candidate cost is present");
    reader.u64().expect("candidate schedule is present");
    reader.u64().expect("candidate payload is present");
    reader.optional_bytes().expect("candidate order is present");
    reader.u64().expect("candidate order position is present");
    reader.u8().expect("candidate block is present");
    reader.u8().expect("candidate state is present");
    reader.u64().expect("candidate service count is present");
    reader
        .u64()
        .expect("candidate acquisition generation is present");
}

fn skip_metadata(reader: &mut Reader<'_>) {
    reader.fixed_array::<16>().expect("metadata id is present");
    reader.text().expect("metadata handler kind is present");
    reader.u16().expect("metadata schema version is present");
    reader.u64().expect("metadata batch key is present");
    reader.u64().expect("metadata auth config is present");
    reader.u8().expect("metadata effect mode is present");
    reader.u16().expect("metadata retry attempts are present");
    reader.u64().expect("metadata retry age is present");
    reader.u64().expect("metadata minimum backoff is present");
    reader.u64().expect("metadata maximum backoff is present");
    reader.u32().expect("metadata retry multiplier is present");
    reader.u64().expect("metadata timeout is present");
    reader.i64().expect("metadata enqueue time is present");
    reader.i64().expect("metadata batch deadline is present");
}

#[test]
fn given_legacy_fair_owner_versions_when_decoded_then_they_are_rejected() {
    let current = owner_bytes();

    for version in 1..current[3] {
        let mut previous = current.clone();
        previous[3] = version;
        assert!(
            matches!(
                FairDispatchOwner::decode(&previous),
                Err(StoreDataError::Malformed("fair owner version"))
            ),
            "version {version} must not be accepted"
        );
    }
}

#[test]
fn given_current_fair_owner_bytes_when_decoded_then_they_round_trip() {
    let encoded = owner_bytes();

    let decoded = FairDispatchOwner::decode(&encoded).expect("current owner decodes");

    assert_eq!(decoded.encode().expect("decoded owner re-encodes"), encoded);
}

#[test]
fn given_superseded_fair_owner_index_bytes_when_decoded_then_they_are_rejected() {
    let mut encoded = owner_with_ready_candidate(FairnessClass::LowVolume)
        .encode()
        .expect("owner encodes");
    encoded[3] = 4;

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner version"))
    ));
}

#[test]
fn given_a_superseded_owner_with_a_forged_bulk_ready_count_when_decoded_then_it_is_rejected() {
    let current = owner_with_ready_candidate(FairnessClass::LowVolume)
        .encode()
        .expect("owner encodes");
    // Version 5 stored the now-deleted bulk-ready summary after max_cost_units.
    let mut encoded = Vec::with_capacity(current.len() + 4);
    encoded.extend_from_slice(&current[..30]);
    encoded.extend_from_slice(&u32::MAX.to_be_bytes());
    encoded.extend_from_slice(&current[30..]);
    encoded[3] = 5;

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner version"))
    ));
}

#[test]
fn given_ready_candidate_when_owner_round_trips_then_ready_is_reconstructed() {
    let owner = owner_with_ready_candidate(FairnessClass::LowVolume);
    let encoded = owner.encode().expect("owner encodes");
    let decoded = FairDispatchOwner::decode(&encoded).expect("owner decodes");

    let snapshot = decoded
        .ledger()
        .scope_snapshot(&FairScope::LowVolume)
        .expect("candidate scope exists");
    assert!(snapshot.ready);
}

#[test]
fn given_a_leased_candidate_when_owner_round_trips_then_ready_is_derived_from_its_state() {
    let job_id = JobId::from([8; 16]);
    let mut owner = owner_with_ready_candidate(FairnessClass::LowVolume);
    owner.select(job_id).expect("candidate leases");

    let encoded = owner.encode().expect("owner encodes");
    let decoded = FairDispatchOwner::decode(&encoded).expect("owner decodes");
    let snapshot = decoded
        .ledger()
        .scope_snapshot(&FairScope::LowVolume)
        .expect("candidate scope exists");

    assert!(!snapshot.ready);
}

#[test]
fn given_a_candidate_with_an_unknown_scope_when_owner_decodes_then_it_is_rejected() {
    let primary = FairnessKey::try_new([1]).expect("primary key is valid");
    let mut encoded =
        owner_with_ready_candidate(FairnessClass::from(FairnessPath::new(primary, None)))
            .encode()
            .expect("owner encodes");
    let scope_bytes = [1, 0, 0, 0, 1, 1, 0];
    let first = encoded
        .windows(scope_bytes.len())
        .position(|window| window == scope_bytes)
        .expect("scope is encoded");
    let second = encoded[first + 1..]
        .windows(scope_bytes.len())
        .position(|window| window == scope_bytes)
        .map(|offset| first + 1 + offset)
        .expect("candidate scope is encoded");
    encoded[second + 5] = 2;

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner candidate scope"))
    ));
}

#[test]
fn given_an_eligible_subset_when_selecting_due_then_foreign_candidates_remain_unchanged() {
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");
    let foreign_job = JobId::from([1; 16]);
    let eligible_job = JobId::from([2; 16]);
    let metadata = || FairCandidateMetadata {
        handler_kind: JobKind::try_new("email").expect("handler kind is valid"),
        schema_version: NonZeroU16::MIN,
        batch_key: BatchKey::new(1),
        auth_config: AuthConfigId::new(1),
        effect_mode: EffectMode::Idempotent,
        retry_policy: RetryPolicy::preset(crate::policy::RetryPreset::Network),
        timeout: Duration::from_secs(1),
        enqueued_at: Timestamp::ZERO,
        batch_deadline: Timestamp::ZERO,
    };
    for job_id in [foreign_job, eligible_job] {
        owner
            .ensure_candidate(
                crate::fairness::FairCandidateInput {
                    job_id,
                    fairness: crate::policy::FairnessClass::low_volume(),
                    priority: Priority::Default,
                    cost_units: NonZeroU16::MIN,
                    scheduled_at: Timestamp::ZERO,
                    payload_bytes: 0,
                    ordering_key: None,
                    ordering_position: 0,
                    block: None,
                },
                metadata(),
            )
            .expect("candidate is valid");
    }

    let before = owner.candidate_snapshot(foreign_job);
    let eligible = BTreeSet::from([eligible_job]);
    let permit = owner
        .select_next_due_in(Timestamp::ZERO, &eligible)
        .expect("eligible selection succeeds")
        .expect("eligible candidate is due");

    assert_eq!(permit.job_id(), eligible_job);
    assert_eq!(owner.candidate_snapshot(foreign_job), before);
    assert_eq!(
        owner.candidate_state(foreign_job),
        Some(crate::fairness::FairCandidateState::Scheduled)
    );
}

#[test]
fn given_inactive_low_volume_batch_when_owner_round_trips_then_scope_is_preserved() {
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");
    owner.start_batch(
        crate::fairness::FairScope::LowVolume,
        AuthConfigId::new(7),
        BTreeSet::new(),
        0,
        Timestamp::from_millis(10),
        Timestamp::from_millis(20),
    );
    owner.clear_batch();
    assert!(!owner.batch().active);
    assert_eq!(owner.batch().scope, crate::fairness::FairScope::LowVolume);

    let encoded = owner.encode().expect("owner encodes");
    let decoded = FairDispatchOwner::decode(&encoded).expect("owner decodes");

    assert_eq!(decoded.batch().scope, crate::fairness::FairScope::LowVolume);
}

#[test]
fn given_each_effect_mode_when_owner_metadata_round_trips_then_wire_bytes_are_stable() {
    for (byte, mode) in [
        (0, EffectMode::ReadOnly),
        (1, EffectMode::Idempotent),
        (2, EffectMode::AtLeastOnce),
        (3, EffectMode::Fenced),
    ] {
        let encoded = owner_with_metadata(mode).encode().expect("owner encodes");
        assert_eq!(encoded[METADATA_EFFECT_MODE_OFFSET], byte);

        let decoded = FairDispatchOwner::decode(&encoded).expect("owner decodes");
        assert_eq!(
            decoded
                .metadata(metadata_job_id())
                .expect("metadata exists")
                .effect_mode,
            mode
        );
        assert_eq!(decoded.encode().expect("decoded owner re-encodes"), encoded);
    }
}

#[test]
fn given_unknown_owner_effect_mode_byte_when_decoded_then_it_fails_closed() {
    let mut encoded = owner_with_metadata(EffectMode::AtLeastOnce)
        .encode()
        .expect("owner encodes");
    encoded[METADATA_EFFECT_MODE_OFFSET] = 0xff;

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner effect mode"))
    ));
}

#[test]
fn given_duplicate_order_wire_entries_when_owner_decodes_then_it_is_rejected() {
    let encoded = owner_with_ready_candidate(FairnessClass::LowVolume)
        .encode()
        .expect("owner encodes");
    let encoded = duplicate_wire_entry(encoded, DuplicateSection::Order);

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner duplicate order"))
    ));
}

#[test]
fn given_duplicate_metadata_wire_entries_when_owner_decodes_then_it_is_rejected() {
    let encoded = owner_with_metadata(EffectMode::Idempotent)
        .encode()
        .expect("owner encodes");
    let encoded = duplicate_wire_entry(encoded, DuplicateSection::Metadata);

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner duplicate metadata"))
    ));
}

#[test]
fn given_duplicate_batch_member_wire_entries_when_owner_decodes_then_it_is_rejected() {
    let encoded = owner_with_active_batch().encode().expect("owner encodes");
    let encoded = duplicate_wire_entry(encoded, DuplicateSection::BatchMember);

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed(
            "fair owner duplicate batch member"
        ))
    ));
}

#[test]
fn given_duplicate_batch_result_wire_entries_when_owner_decodes_then_it_is_rejected() {
    let encoded = owner_with_active_batch().encode().expect("owner encodes");
    let encoded = duplicate_wire_entry(encoded, DuplicateSection::BatchResult);

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed(
            "fair owner duplicate batch result"
        ))
    ));
}

#[test]
fn given_an_active_batch_with_a_missing_result_when_owner_decodes_then_it_is_rejected() {
    let mut owner = owner_with_active_batch();
    owner.batch.results.remove(&JobId::from([8; 16]));
    let encoded = owner.encode().expect("owner encodes");

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner batch results"))
    ));
}

#[test]
fn given_an_active_batch_with_an_extra_result_when_owner_decodes_then_it_is_rejected() {
    let mut owner = owner_with_active_batch();
    owner
        .batch
        .results
        .insert(JobId::from([9; 16]), FairBatchItemState::Success);
    let encoded = owner.encode().expect("owner encodes");

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner batch results"))
    ));
}

#[test]
fn given_an_active_batch_member_without_a_candidate_when_owner_decodes_then_it_is_rejected() {
    let encoded = owner_with_active_batch().encode().expect("owner encodes");

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner batch candidate"))
    ));
}

#[test]
fn given_an_active_empty_batch_when_owner_decodes_then_it_is_rejected() {
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");
    owner.start_batch(
        crate::fairness::FairScope::LowVolume,
        AuthConfigId::new(1),
        BTreeSet::new(),
        0,
        Timestamp::ZERO,
        Timestamp::ZERO,
    );
    let encoded = owner.encode().expect("owner encodes");

    assert!(matches!(
        FairDispatchOwner::decode(&encoded),
        Err(StoreDataError::Malformed("fair owner batch members"))
    ));
}

#[test]
fn given_unknown_owner_save_before_commit_then_retry_commits_with_three_store_calls() {
    let store = CountingOwnerStore::new();
    store
        .inner
        .queue_unknown_before_commit()
        .expect("unknown outcome is queued");
    let system = owner_system(store.clone());
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");

    crate::test_helper::block_on(owner.save(&system)).expect("owner retry commits");

    assert_eq!(store.calls(), 3, "unknown, reconcile get, retry commit");
}

#[test]
fn given_unknown_owner_save_after_commit_then_reconciliation_observes_the_value_with_two_calls() {
    let store = CountingOwnerStore::new();
    store
        .inner
        .queue_unknown_after_commit()
        .expect("unknown outcome is queued");
    let system = owner_system(store.clone());
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");

    crate::test_helper::block_on(owner.save(&system)).expect("owner reconciliation succeeds");

    assert_eq!(store.calls(), 2, "unknown commit, reconciliation get");
}

#[test]
fn given_two_unresolved_unknown_owner_saves_then_reconciliation_stops_at_four_calls() {
    let store = CountingOwnerStore::new();
    store
        .inner
        .queue_unknown_before_commit()
        .expect("first unknown outcome is queued");
    store
        .inner
        .queue_unknown_before_commit()
        .expect("second unknown outcome is queued");
    let system = owner_system(store.clone());
    let mut owner = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");

    let result = crate::test_helper::block_on(owner.save(&system));

    assert!(matches!(result, Err(JobSystemError::UnknownCommit)));
    assert_eq!(store.calls(), 4, "two unknown commit/reconciliation pairs");
}

#[test]
fn given_two_owners_loaded_from_one_snapshot_when_the_stale_owner_saves_then_it_conflicts() {
    let store = CountingOwnerStore::new();
    let system = owner_system(store.clone());
    let mut initial = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");
    crate::test_helper::block_on(initial.save(&system)).expect("initial owner persists");

    let mut first = crate::test_helper::block_on(FairDispatchOwner::load(&system))
        .expect("first owner loads")
        .expect("owner exists");
    let mut stale = crate::test_helper::block_on(FairDispatchOwner::load(&system))
        .expect("stale owner loads")
        .expect("owner exists");
    first.record_hol_escape();
    stale.record_hol_escape();

    crate::test_helper::block_on(first.save(&system)).expect("first owner saves");

    assert!(
        matches!(
            crate::test_helper::block_on(stale.save(&system)),
            Err(JobSystemError::LeaseConflict)
        ),
        "a stale owner must not adopt a fresh durable snapshot before its check"
    );
    let current = crate::test_helper::block_on(FairDispatchOwner::load(&system))
        .expect("current owner loads")
        .expect("owner remains persisted");
    assert_eq!(current.hol_escapes(), 1);
}

#[test]
fn given_an_existing_owner_when_unknown_precedes_commit_then_loaded_value_is_reconciled() {
    let store = CountingOwnerStore::new();
    let system = owner_system(store.clone());
    let mut initial = FairDispatchOwner::try_new(crate::fairness::FairnessBudget::tiny())
        .expect("tiny budget is valid");
    crate::test_helper::block_on(initial.save(&system)).expect("initial owner persists");

    let mut owner = crate::test_helper::block_on(FairDispatchOwner::load(&system))
        .expect("owner loads")
        .expect("owner exists");
    owner.record_hol_escape();
    store
        .inner
        .queue_unknown_before_commit()
        .expect("unknown outcome is queued");

    crate::test_helper::block_on(owner.save(&system))
        .expect("existing owner reconciles and retries");

    let current = crate::test_helper::block_on(FairDispatchOwner::load(&system))
        .expect("current owner loads")
        .expect("owner remains persisted");
    assert_eq!(current.hol_escapes(), 1);
}

#[test]
fn given_settled_low_volume_service_when_owner_loads_then_next_drive_can_reserve_again() {
    let system = owner_system(CountingOwnerStore::new());
    let mut owner = owner_with_ready_candidate(FairnessClass::low_volume());
    let job_id = JobId::from([8; 16]);
    let permit = owner.select(job_id).expect("first service is admitted");
    owner
        .release(permit, crate::fairness::FairRelease::Retry)
        .expect("service settles");
    assert_eq!(
        owner.select(job_id),
        Err(crate::fairness::FairnessRejection::LowVolumeCapacity)
    );
    crate::test_helper::block_on(owner.save(&system))
        .expect("later reservation persists settlement");

    let mut loaded = crate::test_helper::block_on(FairDispatchOwner::load(&system))
        .expect("owner loads")
        .expect("owner exists");
    loaded
        .select(job_id)
        .expect("settled service does not exhaust a new drive");
}

#[test]
fn given_live_low_volume_reservation_when_owner_loads_then_capacity_remains_charged() {
    let system = owner_system(CountingOwnerStore::new());
    let mut owner = owner_with_ready_candidate(FairnessClass::low_volume());
    let job_id = JobId::from([8; 16]);
    owner.select(job_id).expect("live service is admitted");
    crate::test_helper::block_on(owner.save(&system)).expect("reservation persists");

    let mut loaded = crate::test_helper::block_on(FairDispatchOwner::load(&system))
        .expect("owner loads")
        .expect("owner exists");
    let snapshot = loaded
        .ledger
        .scope_snapshot(&FairScope::LowVolume)
        .expect("scope exists");
    assert_eq!(snapshot.served, 1);
    assert_eq!(snapshot.in_flight, 1);
    assert_eq!(
        loaded.select(job_id),
        Err(crate::fairness::FairnessRejection::OrderingHead)
    );
    assert!(loaded.reconcile_leased_candidate(job_id, Timestamp::ZERO));
    loaded
        .select(job_id)
        .expect("authoritative settlement restores service");
}

#[test]
fn given_settled_scoped_service_when_owner_loads_then_cross_drive_history_is_preserved() {
    let system = owner_system(CountingOwnerStore::new());
    let fairness = FairnessClass::Scoped(FairnessPath::new(
        FairnessKey::try_new([1]).expect("primary"),
        None,
    ));
    let mut owner = owner_with_ready_candidate(fairness);
    let job_id = JobId::from([8; 16]);
    let permit = owner.select(job_id).expect("service is admitted");
    let scope = permit.scope().clone();
    owner
        .release(permit, crate::fairness::FairRelease::Retry)
        .expect("service settles");
    let before = owner.ledger.scope_snapshot(&scope).expect("scope exists");
    crate::test_helper::block_on(owner.save(&system)).expect("settlement persists");

    let loaded = crate::test_helper::block_on(FairDispatchOwner::load(&system))
        .expect("owner loads")
        .expect("owner exists");
    let after = loaded.ledger.scope_snapshot(&scope).expect("scope remains");
    assert_eq!(after.served, before.served);
    assert_eq!(after.served_cost, before.served_cost);
    assert_eq!(after.in_flight, before.in_flight);
}

fn owner_system(store: CountingOwnerStore) -> JobSystem<CountingOwnerStore> {
    JobSystem::new(
        store,
        crate::JobCatalog::from_registry(
            crate::test_helper::registry(FairnessPolicy::low_volume()),
        ),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([46; 16]),
        crate::test_helper::wake_scheduler(),
    )
}

#[derive(Clone)]
struct CountingOwnerStore {
    inner: FakeStore,
    calls: Arc<AtomicUsize>,
}

impl CountingOwnerStore {
    fn new() -> Self {
        Self {
            inner: FakeStore::new(),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn count_call(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl crate::store::JobStore for CountingOwnerStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, key: crate::store::StoreKey) -> Result<Option<bytes::Bytes>, Self::Error> {
        self.count_call();
        self.inner.get(key).await
    }

    async fn get_many(
        &self,
        keys: &[crate::store::StoreKey],
    ) -> Result<Vec<Option<bytes::Bytes>>, Self::Error> {
        self.count_call();
        self.inner.get_many(keys).await
    }

    async fn read_range(
        &self,
        request: crate::store::RangeRequest,
    ) -> Result<crate::store::RangePage, Self::Error> {
        self.count_call();
        self.inner.read_range(request).await
    }

    async fn commit(
        &self,
        transaction: &crate::store::StoreTransaction,
    ) -> Result<crate::store::CommitOutcome, Self::Error> {
        self.count_call();
        self.inner.commit(transaction).await
    }
}

#[test]
fn given_rebased_service_when_owner_round_trips_then_late_scope_keeps_its_position() {
    use crate::fairness::FairRelease;
    let primary = FairnessKey::try_new([1]).unwrap();
    let mut owner =
        owner_with_ready_candidate(FairnessClass::from(FairnessPath::new(primary, None)));
    let old = JobId::from([8; 16]);
    for _ in 0..64 {
        let permit = owner.ledger.select(old).unwrap();
        owner.ledger.release(permit, FairRelease::Retry).unwrap();
    }
    owner
        .ensure_candidate(
            FairCandidateInput {
                job_id: JobId::from([9; 16]),
                fairness: FairnessClass::from(FairnessPath::new(
                    FairnessKey::try_new([2]).unwrap(),
                    None,
                )),
                priority: Priority::Default,
                cost_units: NonZeroU16::MIN,
                scheduled_at: Timestamp::ZERO,
                payload_bytes: 1,
                ordering_key: None,
                ordering_position: 0,
                block: None,
            },
            owner.metadata.get(&old).unwrap().clone(),
        )
        .unwrap();
    let permit = owner.ledger.select(JobId::from([9; 16])).unwrap();
    owner.ledger.release(permit, FairRelease::Retry).unwrap();
    let clock = owner.ledger.service_clock;
    let encoded = owner.encode().unwrap();
    let mut restored = FairDispatchOwner::decode(&encoded).unwrap();
    assert_eq!(restored.ledger.service_clock, clock);
    assert_eq!(
        restored
            .ledger
            .scope_snapshots()
            .map(|(_, s)| s.served_cost)
            .sum::<u64>(),
        65
    );
    let mut selected = Vec::new();
    for _ in 0..4 {
        let permit = restored
            .ledger
            .select_next_due(Timestamp::ZERO)
            .unwrap()
            .unwrap();
        selected.push(permit.job_id());
        restored.ledger.release(permit, FairRelease::Retry).unwrap();
    }
    assert_eq!(selected.iter().filter(|id| **id == old).count(), 2);
}
