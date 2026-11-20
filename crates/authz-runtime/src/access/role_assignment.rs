use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveRoleAssignment {
    pub principal_id: Option<String>,
    pub role_id: String,
    pub scope_type: Option<String>,
    pub scope_id: Option<String>,
    #[serde(serialize_with = "serialize_expiration")]
    pub expires_at: Option<Timestamp>,
}

impl EffectiveRoleAssignment {
    pub fn is_active_at(&self, now: Timestamp) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

// Preserve the existing RFC 3339 wire precision: whole seconds, milliseconds,
// microseconds, or nanoseconds, including trailing zeroes in each group.
fn serialize_expiration<S>(value: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    let Some(value) = value else {
        return serializer.serialize_none();
    };
    let nanoseconds = value.subsec_nanosecond();
    let precision = if nanoseconds == 0 {
        0
    } else if nanoseconds % 1_000_000 == 0 {
        3
    } else if nanoseconds % 1_000 == 0 {
        6
    } else {
        9
    };
    serializer.collect_str(&format_args!("{value:.precision$}"))
}
