use super::CatalogRevision;
use crate::{
    error::ValidationError,
    ids::{JobId, ScheduleId},
};

/// Complete configured seed and schedule membership for one namespace.
///
/// Membership is independent of a worker's registered handler subset. Keep
/// supported disabled entries when their completion/cursor state must survive.
/// Removing an ID requires a newer revision. While present, an ID identifies
/// one immutable definition; a changed definition requires a new ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogManifest {
    revision: CatalogRevision,
    seed_ids: Vec<JobId>,
    schedule_ids: Vec<ScheduleId>,
}

impl CatalogManifest {
    /// Validates unique identities and canonicalizes their order. Storage
    /// capacity is validated against the chosen adapter before persistence.
    pub fn try_new(
        revision: CatalogRevision,
        mut seed_ids: Vec<JobId>,
        mut schedule_ids: Vec<ScheduleId>,
    ) -> Result<Self, ValidationError> {
        seed_ids.sort_unstable();
        schedule_ids.sort_unstable();
        validate_unique(&seed_ids)?;
        validate_unique(&schedule_ids)?;
        Ok(Self {
            revision,
            seed_ids,
            schedule_ids,
        })
    }

    pub(super) fn max_encoded_bytes(&self) -> Result<usize, crate::error::StoreDataError> {
        self.seed_ids
            .len()
            .checked_mul(super::constants::MAX_SEED_PROGRESS_BYTES)
            .and_then(|seeds| {
                self.schedule_ids
                    .len()
                    .checked_mul(super::constants::MAX_SCHEDULE_PROGRESS_BYTES)
                    .and_then(|schedules| seeds.checked_add(schedules))
            })
            .and_then(|entries| entries.checked_add(super::constants::CATALOG_HEADER_BYTES))
            .ok_or(crate::error::StoreDataError::LengthOverflow)
    }

    pub const fn revision(&self) -> CatalogRevision {
        self.revision
    }

    pub fn seed_ids(&self) -> &[JobId] {
        &self.seed_ids
    }

    pub fn schedule_ids(&self) -> &[ScheduleId] {
        &self.schedule_ids
    }
}

fn validate_unique<T: PartialEq>(identities: &[T]) -> Result<(), ValidationError> {
    if identities.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ValidationError::InvalidValue {
            field: "duplicate catalog identity",
        });
    }
    Ok(())
}
