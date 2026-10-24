use std::num::{NonZeroU16, NonZeroU32, NonZeroUsize};

use crate::{
    fairness::{
        FairCandidateInput, FairRelease, FairScope, FairnessBudget, FairnessBudgetInput,
        FairnessLedger,
    },
    ids::{FairnessKey, JobId},
    policy::{FairnessClass, FairnessPath, Priority},
    time::Timestamp,
};

fn ledger() -> FairnessLedger {
    FairnessLedger::new(
        FairnessBudget::try_new(FairnessBudgetInput {
            candidate_window: NonZeroU32::new(4).unwrap(),
            max_concurrency_per_scope: NonZeroU32::new(2).unwrap(),
            max_rate_per_scope: NonZeroU32::new(16).unwrap(),
            max_low_volume_service: NonZeroU32::MIN,
            max_payload_bytes: NonZeroUsize::new(1024).unwrap(),
            max_cost_units: NonZeroU16::new(2).unwrap(),
        })
        .unwrap(),
    )
}

fn candidate(id: u8, parent: u8, child: Option<u8>) -> FairCandidateInput {
    FairCandidateInput {
        job_id: JobId::from([id; 16]),
        fairness: FairnessClass::from(FairnessPath::new(
            FairnessKey::try_new([parent]).unwrap(),
            child.map(|id| FairnessKey::try_new([id]).unwrap()),
        )),
        priority: Priority::Default,
        cost_units: NonZeroU16::MIN,
        scheduled_at: Timestamp::ZERO,
        payload_bytes: 1,
        ordering_key: None,
        ordering_position: 0,
        block: None,
    }
}

fn serve(ledger: &mut FairnessLedger, now: Timestamp) -> JobId {
    let permit = ledger
        .select_next_due(now)
        .unwrap()
        .expect("due work makes progress");
    let id = permit.job_id();
    ledger.release(permit, FairRelease::Retry).unwrap();
    id
}

fn scope(parent: u8, child: Option<u8>) -> FairScope {
    FairScope::from(&candidate(1, parent, child).fairness)
}

#[test]
fn given_mature_scope_when_new_primary_joins_then_both_progress_without_historical_credit() {
    let mut ledger = ledger();
    ledger.add_candidate(candidate(1, 1, None)).unwrap();
    for _ in 0..64 {
        assert_eq!(serve(&mut ledger, Timestamp::ZERO), JobId::from([1; 16]));
    }
    ledger.add_candidate(candidate(2, 2, None)).unwrap();
    let ids: Vec<_> = (0..4)
        .map(|_| serve(&mut ledger, Timestamp::ZERO))
        .collect();
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([1; 16])).count(),
        2
    );
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([2; 16])).count(),
        2
    );
    assert_eq!(
        ledger.scope_snapshot(&scope(1, None)).unwrap().served_cost,
        66
    );
    assert_eq!(
        ledger.scope_snapshot(&scope(2, None)).unwrap().served_cost,
        2
    );
}

#[test]
fn given_idle_primary_when_its_work_becomes_due_then_it_does_not_bank_service_credit() {
    let mut ledger = ledger();
    ledger.add_candidate(candidate(1, 1, None)).unwrap();
    let mut sleeping = candidate(2, 2, None);
    sleeping.scheduled_at = Timestamp::from_millis(1000);
    ledger.add_candidate(sleeping).unwrap();
    for _ in 0..64 {
        assert_eq!(serve(&mut ledger, Timestamp::ZERO), JobId::from([1; 16]));
    }
    let ids: Vec<_> = (0..4)
        .map(|_| serve(&mut ledger, Timestamp::from_millis(1000)))
        .collect();
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([1; 16])).count(),
        2
    );
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([2; 16])).count(),
        2
    );
}

#[test]
fn given_mature_child_when_new_sibling_joins_then_parent_clock_preserves_child_fairness() {
    let mut ledger = ledger();
    ledger.add_candidate(candidate(1, 1, Some(1))).unwrap();
    for _ in 0..64 {
        serve(&mut ledger, Timestamp::ZERO);
    }
    ledger.add_candidate(candidate(2, 1, Some(2))).unwrap();
    let ids: Vec<_> = (0..4)
        .map(|_| serve(&mut ledger, Timestamp::ZERO))
        .collect();
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([1; 16])).count(),
        2
    );
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([2; 16])).count(),
        2
    );
    assert_eq!(
        ledger.scope_snapshot(&scope(1, None)).unwrap().served_cost,
        68
    );
}

#[test]
fn given_rebased_primary_when_weight_changes_then_existing_cost_and_progress_are_preserved() {
    let mut ledger = ledger();
    ledger.add_candidate(candidate(1, 1, None)).unwrap();
    for _ in 0..64 {
        serve(&mut ledger, Timestamp::ZERO);
    }
    ledger.add_candidate(candidate(2, 2, None)).unwrap();
    for _ in 0..4 {
        serve(&mut ledger, Timestamp::ZERO);
    }
    assert!(ledger.set_scope_weight(&scope(1, None), NonZeroU16::new(2).unwrap()));
    // The second scope already had one turn owing before the weight changed.
    // Preserve that position, then compare a complete 2:1 service period.
    assert_eq!(serve(&mut ledger, Timestamp::ZERO), JobId::from([2; 16]));
    let ids: Vec<_> = (0..30)
        .map(|_| serve(&mut ledger, Timestamp::ZERO))
        .collect();
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([1; 16])).count(),
        20
    );
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([2; 16])).count(),
        10
    );
    assert_eq!(
        ledger.scope_snapshot(&scope(1, None)).unwrap().served_cost,
        86
    );
}

#[test]
fn given_rebased_scope_when_claim_conflicts_then_cost_is_undone_and_work_remains_fair() {
    let mut ledger = ledger();
    ledger.add_candidate(candidate(1, 1, None)).unwrap();
    for _ in 0..64 {
        serve(&mut ledger, Timestamp::ZERO);
    }
    ledger.add_candidate(candidate(2, 2, None)).unwrap();
    let permit = ledger.select_next_due(Timestamp::ZERO).unwrap().unwrap();
    assert_eq!(permit.job_id(), JobId::from([2; 16]));
    ledger.release(permit, FairRelease::Conflict).unwrap();
    assert_eq!(
        ledger.scope_snapshot(&scope(2, None)).unwrap().served_cost,
        0
    );
    let ids: Vec<_> = (0..4)
        .map(|_| serve(&mut ledger, Timestamp::ZERO))
        .collect();
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([1; 16])).count(),
        2
    );
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([2; 16])).count(),
        2
    );
}

#[test]
fn given_low_volume_work_when_scoped_service_matures_then_it_does_not_pin_the_service_clock() {
    let mut ledger = ledger();
    ledger.add_candidate(candidate(1, 1, None)).unwrap();
    let mut low = candidate(3, 3, None);
    low.fairness = FairnessClass::LowVolume;
    low.scheduled_at = Timestamp::from_millis(1000);
    ledger.add_candidate(low).unwrap();
    for _ in 0..64 {
        serve(&mut ledger, Timestamp::ZERO);
    }
    ledger.add_candidate(candidate(2, 2, None)).unwrap();
    for _ in 0..4 {
        serve(&mut ledger, Timestamp::from_millis(1000));
    }
    assert!(ledger.service_clock > 60 * u128::from(crate::fairness::NORMALIZATION_SCALE));
}

#[test]
fn given_direct_parent_and_child_work_when_child_joins_then_both_keep_making_progress() {
    let mut ledger = ledger();
    ledger.add_candidate(candidate(1, 1, None)).unwrap();
    for _ in 0..64 {
        serve(&mut ledger, Timestamp::ZERO);
    }
    ledger.add_candidate(candidate(2, 1, Some(2))).unwrap();
    let ids: Vec<_> = (0..8)
        .map(|_| serve(&mut ledger, Timestamp::ZERO))
        .collect();
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([1; 16])).count(),
        4
    );
    assert_eq!(
        ids.iter().filter(|id| **id == JobId::from([2; 16])).count(),
        4
    );
    assert_eq!(
        ledger.scope_snapshot(&scope(1, None)).unwrap().served_cost,
        72
    );
    assert_eq!(ledger.scope_snapshot(&scope(1, None)).unwrap().served, 68);
}

#[test]
fn given_direct_parent_service_when_child_claim_conflicts_then_parent_service_count_is_unchanged() {
    let mut ledger = ledger();
    ledger.add_candidate(candidate(1, 1, None)).unwrap();
    for _ in 0..64 {
        serve(&mut ledger, Timestamp::ZERO);
    }
    ledger.add_candidate(candidate(2, 1, Some(2))).unwrap();
    let permit = ledger.select_next_due(Timestamp::ZERO).unwrap().unwrap();
    assert_eq!(permit.job_id(), JobId::from([2; 16]));
    ledger.release(permit, FairRelease::Conflict).unwrap();
    let parent = ledger.scope_snapshot(&scope(1, None)).unwrap();
    assert_eq!(parent.served, 64);
    assert_eq!(parent.served_cost, 64);
    let ids: Vec<_> = (0..4)
        .map(|_| serve(&mut ledger, Timestamp::ZERO))
        .collect();
    assert!(ids.contains(&JobId::from([1; 16])) && ids.contains(&JobId::from([2; 16])));
}
