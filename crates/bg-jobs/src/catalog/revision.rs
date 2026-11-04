use std::num::NonZeroU64;

/// A monotonically increasing revision of the complete namespace manifest.
/// All workers sharing a namespace use the same revision and membership,
/// independently of their local handler registrations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CatalogRevision(NonZeroU64);

impl From<NonZeroU64> for CatalogRevision {
    fn from(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl CatalogRevision {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}
