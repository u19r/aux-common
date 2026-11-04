use std::collections::BTreeMap;

use super::CatalogManifest;
use crate::{
    ids::{JobId, ScheduleId},
    schedule::ScheduleCursor,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum SeedProgress {
    Uninitialized,
    Pending([u8; 32]),
    Completed([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ScheduleProgress {
    Uninitialized,
    Current {
        digest: [u8; 32],
        cursor: ScheduleCursor,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CatalogLedger {
    pub(super) manifest: CatalogManifest,
    pub(super) seeds: BTreeMap<JobId, SeedProgress>,
    pub(super) schedules: BTreeMap<ScheduleId, ScheduleProgress>,
}

impl CatalogLedger {
    pub(super) fn adopt_manifest(previous: Option<Self>, manifest: &CatalogManifest) -> Self {
        let (mut previous_seeds, mut previous_schedules) = previous
            .map(|value| (value.seeds, value.schedules))
            .unwrap_or_default();
        let seeds = manifest
            .seed_ids()
            .iter()
            .copied()
            .map(|id| {
                let progress = previous_seeds
                    .remove(&id)
                    .unwrap_or(SeedProgress::Uninitialized);
                (id, progress)
            })
            .collect();
        let schedules = manifest
            .schedule_ids()
            .iter()
            .copied()
            .map(|id| {
                (
                    id,
                    previous_schedules
                        .remove(&id)
                        .unwrap_or(ScheduleProgress::Uninitialized),
                )
            })
            .collect();
        Self {
            manifest: manifest.clone(),
            seeds,
            schedules,
        }
    }
}
