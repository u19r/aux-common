use std::time::Duration;

pub(crate) const MAX_PRESIGN_EXPIRY: Duration = Duration::from_hours(168);
pub(crate) const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
