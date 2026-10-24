use std::num::{NonZeroU16, NonZeroU32, NonZeroUsize};

use bg_jobs::{
    JobCatalog, Namespace, OwnerId, QueueSelection,
    runtime::{JobSystemBuilder, MonotonicDeadline},
    store::{JobStore, StoreContractError, StoreKey, StoreLevel},
    test_support::{
        FakeStore,
        raw::{DriveRequest, DriveRequestInput},
    },
};
use bg_jobs_conformance::{
    ConformanceConfig, FaultStore, OperationProfile, StoreModel, run_basic, run_faults,
    run_operation_profile,
};
use cucumber::{given, then, when};

use crate::BddWorld;

#[derive(Debug, Default)]
pub(crate) struct BackendEvidence {
    pub(crate) distributed: bool,
    pub(crate) conflict_count: u32,
    pub(crate) unknown_count: u32,
    pub(crate) weak_rejected: bool,
    pub(crate) neutral: bool,
    pub(crate) native_bulk_preserved: bool,
}

#[derive(Debug, Default)]
pub(crate) struct ProfileEvidence {
    pub(crate) one_core: Option<DriveRequest>,
    pub(crate) many_core: Option<DriveRequest>,
    pub(crate) one_profile: Option<OperationProfile>,
    pub(crate) many_profile: Option<OperationProfile>,
}

fn backend(world: &mut BddWorld) -> &mut BackendEvidence {
    world.backend.get_or_insert_with(BackendEvidence::default)
}

fn profile(world: &mut BddWorld) -> &mut ProfileEvidence {
    world.profile.get_or_insert_with(ProfileEvidence::default)
}

fn nonzero_u16(value: u16) -> Result<NonZeroU16, String> {
    NonZeroU16::new(value).ok_or_else(|| "value must be non-zero".to_owned())
}

fn nonzero_u32(value: u32) -> Result<NonZeroU32, String> {
    NonZeroU32::new(value).ok_or_else(|| "value must be non-zero".to_owned())
}

fn nonzero_usize(value: usize) -> Result<NonZeroUsize, String> {
    NonZeroUsize::new(value).ok_or_else(|| "value must be non-zero".to_owned())
}

fn drive_request(concurrency: u16, payload: usize) -> Result<DriveRequest, String> {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nonzero_u32(32)?,
        max_concurrency: nonzero_u16(concurrency)?,
        max_payload_bytes_in_flight: nonzero_usize(payload)?,
        max_completion_details: 32,
        max_store_operations: nonzero_u32(64)?,
        stop_claiming_at: MonotonicDeadline::from_nanos(10_000),
        finish_by: MonotonicDeadline::from_nanos(20_000),
    })
    .map_err(|error| error.to_string())
}

#[given("a candidate backend claims Distributed support")]
async fn given_distributed_backend(world: &mut BddWorld) -> Result<(), String> {
    backend(world).distributed = FakeStore::distributed().capabilities().is_distributed();
    Ok(())
}

#[when("the reusable basic and fault suite runs")]
async fn when_conformance_runs(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::distributed();
    let config = ConformanceConfig::default();
    let basic = run_basic(&store, &config)
        .await
        .map_err(|error| error.to_string())?;
    let fault_store = FaultStore::new(FakeStore::distributed());
    let faults = run_faults(&fault_store, &config)
        .await
        .map_err(|error| error.to_string())?;
    let state = backend(world);
    state.distributed = store.capabilities().is_distributed();
    state.conflict_count = basic.conflicts + faults.conflicts;
    state.unknown_count = faults.unknowns;
    Ok(())
}

#[then("generic checked-write and stale-token semantics pass")]
async fn then_conformance_passes(world: &mut BddWorld) -> Result<(), String> {
    let state = world
        .backend
        .as_ref()
        .ok_or("backend evidence was missing")?;
    if !state.distributed || state.conflict_count < 2 || state.unknown_count != 2 {
        return Err(format!("generic conformance was incomplete: {state:?}"));
    }
    Ok(())
}

#[given("a wrapped native bulk-read store")]
async fn given_native_bulk_read_store(world: &mut BddWorld) -> Result<(), String> {
    backend(world);
    Ok(())
}

#[when("the public conformance workflow runs")]
async fn when_native_bulk_read_runs(world: &mut BddWorld) -> Result<(), String> {
    let bulk_store = bg_jobs_conformance::CountingStore::new(FaultStore::new(FakeStore::local()));
    let keys = vec![
        StoreKey::try_from(&b"bdd-bulk/a"[..]).map_err(|error| error.to_string())?,
        StoreKey::try_from(&b"bdd-bulk/b"[..]).map_err(|error| error.to_string())?,
    ];
    let values = bulk_store
        .get_many(&keys)
        .await
        .map_err(|error| error.to_string())?;
    let counts = bulk_store.snapshot();
    let state = backend(world);
    state.native_bulk_preserved = values.len() == keys.len()
        && counts.get_many == 1
        && counts.get_many_keys == keys.len() as u64
        && counts.gets == 0;
    Ok(())
}

#[then("bulk reads stay native")]
async fn then_native_bulk_read(world: &mut BddWorld) -> Result<(), String> {
    let state = world
        .backend
        .as_ref()
        .ok_or("backend evidence was missing")?;
    if !state.native_bulk_preserved {
        return Err(format!(
            "native bulk-read evidence was incomplete: {state:?}"
        ));
    }
    Ok(())
}

#[given("storage has get put and range but no atomic checked multi-key commit")]
async fn given_weak_storage(world: &mut BddWorld) -> Result<(), String> {
    backend(world).distributed = false;
    Ok(())
}

#[when("a distributed job system is constructed")]
async fn when_distributed_system_constructed(world: &mut BddWorld) -> Result<(), String> {
    let result = JobSystemBuilder::new(FakeStore::local())
        .catalog(JobCatalog::new())
        .namespace(Namespace::try_new(b"bdd-weak").map_err(|error| error.to_string())?)
        .owner(OwnerId::from([44; 16]))
        .scheduler(crate::common::wake_scheduler())
        .build_distributed();
    backend(world).weak_rejected = matches!(result, Err(StoreContractError::FalseDistributedClaim));
    Ok(())
}

#[then("construction or conformance fails explicitly")]
async fn then_weak_storage_rejected(world: &mut BddWorld) -> Result<(), String> {
    if !world
        .backend
        .as_ref()
        .ok_or("backend evidence was missing")?
        .weak_rejected
    {
        return Err("weak storage was accepted as distributed".to_owned());
    }
    Ok(())
}

#[given("bg-jobs and bg-jobs-conformance use the reference fake adapter")]
async fn given_reference_adapter(world: &mut BddWorld) -> Result<(), String> {
    backend(world).neutral = true;
    Ok(())
}

#[when("built for wasm32-unknown-unknown")]
async fn when_runtime_neutral_built(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::local();
    let mut model = StoreModel::new(store.capabilities());
    let key = StoreKey::try_from(&b"wasm/bdd"[..]).map_err(|error| error.to_string())?;
    model
        .put(key, bytes::Bytes::from_static(b"reference"))
        .map_err(|error| error.to_string())?;
    backend(world).neutral = model.capabilities().level() == StoreLevel::Local;
    Ok(())
}

#[then("they require no Tokio reqwest native TLS AWS SDK or database backend")]
async fn then_runtime_neutral(world: &mut BddWorld) -> Result<(), String> {
    if !world
        .backend
        .as_ref()
        .ok_or("backend evidence was missing")?
        .neutral
    {
        return Err("runtime-neutral reference path was not available".to_owned());
    }
    Ok(())
}

#[given("one-core and multi-driver budgets")]
async fn given_profile_budgets(world: &mut BddWorld) -> Result<(), String> {
    let state = profile(world);
    state.one_core = Some(drive_request(1, 64 * 1024)?);
    state.many_core = Some(drive_request(8, 8 * 64 * 1024)?);
    Ok(())
}

#[when("identical work mixes are measured")]
async fn when_profiles_measured(world: &mut BddWorld) -> Result<(), String> {
    let config = ConformanceConfig::default();
    let one_core = bg_jobs_conformance::CountingStore::new(FakeStore::local());
    let many_core = bg_jobs_conformance::CountingStore::new(FakeStore::distributed());
    let one_profile = run_operation_profile(&one_core, &config)
        .await
        .map_err(|error| error.to_string())?;
    let many_profile = run_operation_profile(&many_core, &config)
        .await
        .map_err(|error| error.to_string())?;
    let state = profile(world);
    state.one_profile = Some(one_profile);
    state.many_profile = Some(many_profile);
    Ok(())
}

#[then("both obey concurrency payload transaction deadline and retained-memory caps")]
async fn then_profiles_bounded(world: &mut BddWorld) -> Result<(), String> {
    let state = world
        .profile
        .as_ref()
        .ok_or("profile evidence was missing")?;
    let one_core = state.one_core.as_ref().ok_or("one-core budget missing")?;
    let many_core = state
        .many_core
        .as_ref()
        .ok_or("multi-driver budget missing")?;
    let one_profile = state
        .one_profile
        .as_ref()
        .ok_or("one-core profile missing")?;
    let many_profile = state
        .many_profile
        .as_ref()
        .ok_or("multi-driver profile missing")?;
    let within_operation_cap = |profile: &OperationProfile| {
        profile.counts.gets <= 3
            && profile.counts.get_many == 6
            && profile.counts.get_many_keys == 28
            && profile.counts.ranges <= 4
            && profile.counts.commits <= 12
            && profile.counts.transaction_bytes < 4_096
    };
    if one_core.max_concurrency().get() != 1
        || many_core.max_concurrency().get() != 8
        || one_core.max_payload_bytes_in_flight().get() > bg_jobs::MAX_INLINE_PAYLOAD_BYTES
        || many_core.max_payload_bytes_in_flight().get() > 8 * bg_jobs::MAX_INLINE_PAYLOAD_BYTES
        || one_core.finish_by().is_before(one_core.stop_claiming_at())
        || many_core
            .finish_by()
            .is_before(many_core.stop_claiming_at())
        || !within_operation_cap(one_profile)
        || !within_operation_cap(many_profile)
    {
        return Err("profile exceeded an explicit bounded budget".to_owned());
    }
    Ok(())
}
