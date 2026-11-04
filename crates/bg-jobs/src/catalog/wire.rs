use std::{collections::BTreeMap, num::NonZeroU64};

use bytes::Bytes;

use super::{
    CatalogManifest, CatalogRevision,
    constants::CATALOG_VERSION,
    ledger::{CatalogLedger, ScheduleProgress, SeedProgress},
};
use crate::{
    error::StoreDataError,
    ids::{JobId, ScheduleId},
    schedule::{CATALOG_CURSOR_BYTES, ScheduleCursor},
};

impl CatalogLedger {
    pub(super) fn encode(&self) -> Result<Bytes, StoreDataError> {
        let seed_count =
            u32::try_from(self.seeds.len()).map_err(|_| StoreDataError::LengthOverflow)?;
        let schedule_count = u32::try_from(self.manifest.schedule_ids().len())
            .map_err(|_| StoreDataError::LengthOverflow)?;
        let mut value = Vec::with_capacity(self.manifest.max_encoded_bytes()?);
        value.push(CATALOG_VERSION);
        value.extend_from_slice(&self.manifest.revision().get().to_be_bytes());
        value.extend_from_slice(&seed_count.to_be_bytes());
        for (id, progress) in &self.seeds {
            value.extend_from_slice(id.as_bytes());
            let (state, digest) = match progress {
                SeedProgress::Uninitialized => (0, None),
                SeedProgress::Pending(digest) => (1, Some(digest)),
                SeedProgress::Completed(digest) => (2, Some(digest)),
            };
            value.push(state);
            if let Some(digest) = digest {
                value.extend_from_slice(digest);
            }
        }
        value.extend_from_slice(&schedule_count.to_be_bytes());
        self.write_schedules(&mut value);
        Ok(Bytes::from(value))
    }

    fn write_schedules(&self, value: &mut Vec<u8>) {
        for (id, progress) in &self.schedules {
            value.extend_from_slice(id.as_bytes());
            match progress {
                ScheduleProgress::Uninitialized => value.push(0),
                ScheduleProgress::Current { digest, cursor } => {
                    value.push(1);
                    value.extend_from_slice(digest);
                    value.extend_from_slice(&cursor.encode_catalog_cursor());
                }
            }
        }
    }

    pub(super) fn decode(value: &[u8]) -> Result<Self, StoreDataError> {
        let mut reader = CatalogReader { remaining: value };
        if reader.read_array::<1>()?[0] != CATALOG_VERSION {
            return Err(StoreDataError::Malformed("catalog version"));
        }
        let revision = NonZeroU64::new(u64::from_be_bytes(reader.read_array()?))
            .ok_or(StoreDataError::Malformed("catalog revision"))?;
        let seeds = reader.read_seeds()?;
        let schedules = reader.read_schedules()?;
        if !reader.remaining.is_empty() {
            return Err(StoreDataError::Malformed("catalog trailing bytes"));
        }
        let manifest = CatalogManifest::try_new(
            CatalogRevision::from(revision),
            seeds.keys().copied().collect(),
            schedules.keys().copied().collect(),
        )
        .map_err(|_| StoreDataError::Malformed("catalog membership"))?;
        Ok(Self {
            manifest,
            seeds,
            schedules,
        })
    }
}

struct CatalogReader<'a> {
    remaining: &'a [u8],
}

impl CatalogReader<'_> {
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], StoreDataError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(N)
            .ok_or(StoreDataError::Truncated)?;
        self.remaining = remaining;
        value.try_into().map_err(|_| StoreDataError::Truncated)
    }

    fn read_count(&mut self, minimum_width: usize) -> Result<usize, StoreDataError> {
        let count = u32::from_be_bytes(self.read_array()?) as usize;
        if count > self.remaining.len() / minimum_width {
            return Err(StoreDataError::Truncated);
        }
        Ok(count)
    }

    fn read_schedules(&mut self) -> Result<BTreeMap<ScheduleId, ScheduleProgress>, StoreDataError> {
        let count = self.read_count(17)?;
        let mut schedules = BTreeMap::new();
        for _ in 0..count {
            let id = ScheduleId::from(self.read_array::<16>()?);
            if schedules
                .last_key_value()
                .is_some_and(|(previous, _)| *previous >= id)
            {
                return Err(StoreDataError::Malformed("catalog schedule order"));
            }
            let progress = match self.read_array::<1>()?[0] {
                0 => ScheduleProgress::Uninitialized,
                1 => ScheduleProgress::Current {
                    digest: self.read_array()?,
                    cursor: ScheduleCursor::decode_catalog_cursor(
                        &self.read_array::<CATALOG_CURSOR_BYTES>()?,
                    )?,
                },
                _ => return Err(StoreDataError::Malformed("catalog schedule state")),
            };
            schedules.insert(id, progress);
        }
        Ok(schedules)
    }

    fn read_seeds(&mut self) -> Result<BTreeMap<JobId, SeedProgress>, StoreDataError> {
        let count = self.read_count(17)?;
        let mut seeds = BTreeMap::new();
        for _ in 0..count {
            let id = JobId::from(self.read_array::<16>()?);
            if seeds
                .last_key_value()
                .is_some_and(|(previous, _)| *previous >= id)
            {
                return Err(StoreDataError::Malformed("catalog seed order"));
            }
            let state = self.read_array::<1>()?[0];
            let progress = match state {
                0 => SeedProgress::Uninitialized,
                1 => SeedProgress::Pending(self.read_array()?),
                2 => SeedProgress::Completed(self.read_array()?),
                _ => return Err(StoreDataError::Malformed("catalog seed state")),
            };
            seeds.insert(id, progress);
        }
        Ok(seeds)
    }
}
