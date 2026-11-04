use std::num::NonZeroU64;

use super::{
    CatalogManifest, CatalogRevision,
    ledger::{CatalogLedger, ScheduleProgress, SeedProgress},
};
use crate::ids::{JobId, ScheduleId};

fn ledger() -> CatalogLedger {
    let manifest = CatalogManifest::try_new(
        CatalogRevision::from(NonZeroU64::MIN),
        vec![
            JobId::from([1; 16]),
            JobId::from([2; 16]),
            JobId::from([3; 16]),
        ],
        vec![ScheduleId::from([4; 16])],
    )
    .unwrap();
    let mut ledger = CatalogLedger::adopt_manifest(None, &manifest);
    ledger
        .seeds
        .insert(JobId::from([2; 16]), SeedProgress::Pending([9; 32]));
    ledger
        .seeds
        .insert(JobId::from([3; 16]), SeedProgress::Completed([8; 32]));
    let mut cursor = crate::ScheduleCursor::new(Some(crate::Timestamp::from_millis(123)), true);
    assert!(cursor.mark_started(0, 0));
    ledger.schedules.insert(
        ScheduleId::from([4; 16]),
        ScheduleProgress::Current {
            digest: [7; 32],
            cursor,
        },
    );
    ledger
}

#[test]
fn given_current_progress_when_catalog_roundtrips_or_advances_then_matching_seed_state_is_preserved()
 {
    let ledger = ledger();
    let decoded = CatalogLedger::decode(&ledger.encode().unwrap()).unwrap();
    assert_eq!(decoded, ledger);
    let manifest = CatalogManifest::try_new(
        CatalogRevision::from(NonZeroU64::new(2).unwrap()),
        vec![JobId::from([3; 16]), JobId::from([5; 16])],
        Vec::new(),
    )
    .unwrap();
    let advanced = CatalogLedger::adopt_manifest(Some(decoded), &manifest);
    assert_eq!(advanced.seeds.len(), 2);
    assert_eq!(
        advanced.seeds[&JobId::from([3; 16])],
        SeedProgress::Completed([8; 32])
    );
    assert_eq!(
        advanced.seeds[&JobId::from([5; 16])],
        SeedProgress::Uninitialized
    );
}

#[test]
fn given_malformed_catalog_when_decoding_then_no_partial_or_noncanonical_value_is_accepted() {
    let encoded = ledger().encode().unwrap();
    for end in 0..encoded.len() {
        assert!(
            CatalogLedger::decode(&encoded[..end]).is_err(),
            "truncation {end}"
        );
    }
    for (index, value) in [(0, 2), (12, 255), (29, 255)] {
        let mut corrupt = encoded.to_vec();
        corrupt[index] = value;
        assert!(
            CatalogLedger::decode(&corrupt).is_err(),
            "corruption at {index}"
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(CatalogLedger::decode(&trailing).is_err());
    let mut duplicate = encoded.to_vec();
    duplicate[30..46].copy_from_slice(&encoded[13..29]);
    assert!(CatalogLedger::decode(&duplicate).is_err());
}
