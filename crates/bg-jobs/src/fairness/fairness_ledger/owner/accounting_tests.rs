use std::num::NonZeroU16;

use super::state::FairDispatchOwner;
use crate::{
    error::StoreDataError,
    fairness::{FairCandidateInput, FairScope, FairnessBudget},
    ids::{FairnessKey, JobId},
    policy::{FairnessClass, FairnessPath, Priority},
    time::Timestamp,
};

fn owner() -> (FairDispatchOwner, FairScope, FairScope) {
    let child = FairScope::Scoped {
        primary: FairnessKey::try_new([1]).unwrap(),
        secondary: Some(FairnessKey::try_new([2]).unwrap()),
    };
    let mut owner = FairDispatchOwner::try_new(FairnessBudget::tiny()).unwrap();
    owner
        .ledger
        .upsert_candidate(FairCandidateInput {
            job_id: JobId::from([1; 16]),
            fairness: FairnessClass::from(FairnessPath::new(
                FairnessKey::try_new([1]).unwrap(),
                Some(FairnessKey::try_new([2]).unwrap()),
            )),
            priority: Priority::Default,
            cost_units: NonZeroU16::MIN,
            scheduled_at: Timestamp::ZERO,
            payload_bytes: 1,
            ordering_key: None,
            ordering_position: 0,
            block: None,
        })
        .unwrap();
    (owner, child.primary_scope(), child)
}

#[test]
fn given_inconsistent_aggregate_when_decoding_saved_owner_then_cost_is_rejected() {
    for direct in [false, true] {
        let (mut owner, primary, child) = owner();
        if direct {
            owner
                .ledger
                .scopes
                .get_mut(&primary)
                .unwrap()
                .own_service
                .cost = 1;
        } else {
            owner.ledger.scopes.get_mut(&child).unwrap().service.cost = 1;
        }
        let bytes = owner.encode().unwrap();
        assert!(matches!(
            FairDispatchOwner::decode(&bytes),
            Err(StoreDataError::Malformed("fair owner aggregate service"))
        ));
    }
}

#[test]
fn given_non_primary_own_service_when_decoding_saved_owner_then_state_is_rejected() {
    for field in 0..4 {
        let (mut owner, _, child) = owner();
        let state = owner.ledger.scopes.get_mut(&child).unwrap();
        match field {
            0 => state.own_service.cost = 1,
            1 => state.own_service.origin = 1,
            2 => {
                state.own_service.cost = 1;
                state.own_service.base_cost = 1;
            }
            _ => state.child_service_clock = 1,
        }
        let bytes = owner.encode().unwrap();
        assert!(matches!(
            FairDispatchOwner::decode(&bytes),
            Err(StoreDataError::Malformed("fair owner non-primary service"))
        ));
    }
}

#[test]
fn given_compacted_child_history_when_decoding_saved_owner_then_aggregate_is_retained() {
    let (mut owner, primary, child) = owner();
    owner.ledger.scopes.get_mut(&primary).unwrap().service.cost = 20;
    owner
        .ledger
        .scopes
        .get_mut(&primary)
        .unwrap()
        .own_service
        .cost = 5;
    owner.ledger.scopes.get_mut(&child).unwrap().service.cost = 7;
    let bytes = owner.encode().unwrap();
    let decoded = FairDispatchOwner::decode(&bytes).unwrap();
    assert_eq!(decoded.ledger.scopes[&primary].service.cost, 20);
    assert_eq!(decoded.ledger.scopes[&child].service.cost, 7);
}

#[test]
fn given_near_maximum_cost_when_claim_conflicts_then_saved_accounting_remains_valid() {
    let (mut owner, primary, child) = owner();
    let direct_id = JobId::from([2; 16]);
    owner
        .ledger
        .upsert_candidate(FairCandidateInput {
            job_id: direct_id,
            fairness: FairnessClass::from(FairnessPath::new(
                FairnessKey::try_new([1]).unwrap(),
                None,
            )),
            priority: Priority::Default,
            cost_units: NonZeroU16::MIN,
            scheduled_at: Timestamp::ZERO,
            payload_bytes: 1,
            ordering_key: None,
            ordering_position: 0,
            block: None,
        })
        .unwrap();
    owner.ledger.scopes.get_mut(&primary).unwrap().service.cost = u64::MAX;
    owner
        .ledger
        .scopes
        .get_mut(&primary)
        .unwrap()
        .own_service
        .cost = u64::MAX - 1;
    owner.ledger.scopes.get_mut(&child).unwrap().service.cost = 1;
    let before = owner.encode().unwrap();
    assert_eq!(
        owner.ledger.select(direct_id).unwrap_err(),
        crate::fairness::FairnessRejection::ScopeCapacity
    );
    assert_eq!(
        owner.encode().unwrap(),
        before,
        "overflow rejection must not advance clocks or capacity"
    );
    assert!(FairDispatchOwner::decode(&before).is_ok());
    owner.ledger.scopes.get_mut(&primary).unwrap().service.cost -= 1;
    owner
        .ledger
        .scopes
        .get_mut(&primary)
        .unwrap()
        .own_service
        .cost -= 1;
    let permit = owner.ledger.select(direct_id).unwrap();
    owner
        .ledger
        .release(permit, crate::fairness::FairRelease::Conflict)
        .unwrap();
    assert_eq!(owner.ledger.scopes[&primary].service.cost, u64::MAX - 1);
    assert_eq!(owner.ledger.scopes[&primary].own_service.cost, u64::MAX - 2);
    assert_eq!(owner.ledger.scopes[&child].service.cost, 1);
    assert!(FairDispatchOwner::decode(&owner.encode().unwrap()).is_ok());
}

#[test]
fn given_overflowing_retained_sum_when_decoding_saved_owner_then_aggregate_is_rejected() {
    let (mut owner, primary, child) = owner();
    owner.ledger.scopes.get_mut(&primary).unwrap().service.cost = u64::MAX;
    owner
        .ledger
        .scopes
        .get_mut(&primary)
        .unwrap()
        .own_service
        .cost = u64::MAX;
    owner.ledger.scopes.get_mut(&child).unwrap().service.cost = 1;
    let bytes = owner.encode().unwrap();
    assert!(matches!(
        FairDispatchOwner::decode(&bytes),
        Err(StoreDataError::Malformed("fair owner aggregate service"))
    ));
}
