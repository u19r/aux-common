use std::num::NonZeroU64;

use super::{CatalogManifest, CatalogRevision};
use crate::ids::{JobId, ScheduleId};

#[test]
fn given_equivalent_membership_when_constructing_manifests_then_order_is_canonical() {
    let revision = CatalogRevision::from(NonZeroU64::MIN);
    let left = CatalogManifest::try_new(
        revision,
        vec![JobId::from([2; 16]), JobId::from([1; 16])],
        vec![ScheduleId::from([4; 16]), ScheduleId::from([3; 16])],
    )
    .unwrap();
    let right = CatalogManifest::try_new(
        revision,
        vec![JobId::from([1; 16]), JobId::from([2; 16])],
        vec![ScheduleId::from([3; 16]), ScheduleId::from([4; 16])],
    )
    .unwrap();
    assert_eq!(left, right);
    assert_eq!(left.revision().get(), 1);
    assert_eq!(left.seed_ids().len(), 2);
    assert_eq!(left.schedule_ids().len(), 2);
}

#[test]
fn given_duplicate_configured_identities_when_constructing_manifest_then_they_are_rejected() {
    let revision = CatalogRevision::from(NonZeroU64::MIN);
    assert!(CatalogManifest::try_new(revision, vec![JobId::from([1; 16]); 2], Vec::new()).is_err());
    assert!(
        CatalogManifest::try_new(revision, Vec::new(), vec![ScheduleId::from([1; 16]); 2]).is_err()
    );
    assert!(CatalogManifest::try_new(revision, Vec::new(), Vec::new()).is_ok());
}
