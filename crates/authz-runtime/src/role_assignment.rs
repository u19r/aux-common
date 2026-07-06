use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveRoleAssignment {
    pub principal_id: Option<String>,
    pub role_id: String,
    pub scope_type: Option<String>,
    pub scope_id: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl EffectiveRoleAssignment {
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expires_at| expires_at >= now)
    }
}
