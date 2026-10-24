use bg_jobs::test_support::codec::{ValueCodec, ValueTag};
use types::{JobId, Node};

use super::{
    driver::{StoreProtocolDriver, parse_command},
    persist, types,
};
use crate::CountingStore;

#[test]
fn given_quint_rendered_store_commands_when_parsed_then_all_families_are_preserved() {
    let commands = [
        "StoreEnqueue({ fingerprint: 3, job: JobC, operation: OperationA, resources: { \
         checkpointBytes: 65536, chunkBytes: 65536, digestBytes: 64, manifestBytes: 4096, \
         payloadBytes: 972800 } })",
        "StoreSelectClaim({ job: JobA, reader: NodeA, revision: 1 })",
        "StoreClaim({ contender: NodeA, job: JobA, revision: 1 })",
        "StoreRenew({ fence: 2, generation: 1, job: JobB, leaseUntil: 3, node: NodeA, operation: \
         OperationA, revision: 1, token: 3 })",
        "StoreComplete({ fence: 2, generation: 1, job: JobB, leaseUntil: 3, node: NodeA, \
         operation: OperationA, revision: 1, token: 3 })",
        "StoreDeadLetter({ authority: { fence: 2, generation: 1, job: JobB, leaseUntil: 3, node: \
         NodeA, operation: OperationA, revision: 1, token: 3 }, handler: Permanent })",
        "StoreRedrive({ job: JobB, operation: OperationA, reuseExecution: false, revision: 2 })",
        "StoreUnknown({ authority: { fence: 2, generation: 1, job: JobB, leaseUntil: 3, node: \
         NodeA, operation: OperationA, revision: 1, token: 3 }, committed: true })",
        "StoreReconcile({ job: JobA, observed: Rejected, operation: OperationA })",
        "StoreCorrupt({ job: JobA, kind: Corrupt })",
        "StoreDropRoute({ due: true, fair: false, job: JobA, lease: false, wake: false })",
        "StoreRepair({ job: JobA, operation: OperationA, revision: 1 })",
        "StorePurge({ job: JobC, revision: 0 })",
        "StoreAdvance({ amount: 1 })",
        "StoreExpire({ job: JobB })",
    ];

    for rendered in commands {
        assert!(
            parse_command(rendered).is_ok(),
            "failed to parse {rendered}"
        );
    }
}

#[test]
fn given_deleted_connector_receipt_when_projecting_then_store_state_remains_authoritative() {
    let driver = StoreProtocolDriver::try_default().expect("connector setup");
    let key = persist::receipt_key(&driver.namespace, &JobId::JobA).expect("receipt key");

    driver
        .store
        .delete_raw(&key)
        .expect("delete receipt shadow");

    let projection = driver.projection().expect("projection from store");
    assert_eq!(projection.records[&JobId::JobA].revision, 1);
    assert_eq!(
        projection.records[&JobId::JobA].state,
        types::JobState::Scheduled
    );
}

#[test]
fn given_a_sidecar_authority_mismatch_when_projecting_then_core_lease_remains_authoritative() {
    let driver = StoreProtocolDriver::try_default().expect("connector setup");
    let job = JobId::JobB;
    let route =
        persist::read_route(&driver.store, &driver.namespace, &job).expect("route should decode");
    let encoded =
        ValueCodec::encode(ValueTag::Operation, &route.encode()).expect("route should encode");
    driver
        .store
        .put_raw(
            persist::route_key(&driver.namespace, &job).expect("route key"),
            encoded,
        )
        .expect("route should be replaceable in fake store");

    let mut operation = persist::read_operation(&driver.store, &driver.namespace, &job)
        .expect("operation should decode")
        .expect("operation should be present");
    operation.fence_high_water = 99;
    driver
        .store
        .put_raw(
            persist::operation_key(&driver.namespace, &job).expect("operation key"),
            operation.encode().expect("operation should encode"),
        )
        .expect("operation should be replaceable in fake store");

    let projection = driver.projection().expect("projection from store");
    let record = &projection.records[&job];
    assert_eq!(record.node, Node::NodeA);
    assert_eq!(record.generation, 1);
    assert_eq!(record.fence, 1);
    assert_eq!(record.token, 3);
    assert_eq!(record.lease_until, 3);
}

#[test]
fn given_connector_state_when_read_then_sidecars_use_one_ordered_bulk_read() {
    let driver = StoreProtocolDriver::try_default().expect("connector setup");
    let store = CountingStore::new(driver.store.clone());

    let state = persist::StoredState::read(&store, &driver.namespace, &JobId::JobA)
        .expect("state should decode");

    assert!(state.core.is_some());
    assert!(state.operation_present);
    assert!(state.route_present);
    assert!(!state.fault_present);
    let counts = store.snapshot();
    assert_eq!(counts.gets, 0);
    assert_eq!(counts.get_many, 1);
    assert_eq!(counts.get_many_keys, 4);
}
