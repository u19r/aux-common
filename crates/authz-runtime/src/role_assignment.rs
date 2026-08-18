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
        self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::EffectiveRoleAssignment;

    #[test]
    fn expiry_at_evaluation_time_is_inactive() {
        let now = Utc.timestamp_opt(1_000, 0).single().expect("timestamp");
        let assignment = EffectiveRoleAssignment {
            principal_id: None,
            role_id: "reader".to_string(),
            scope_type: Some("tenant".to_string()),
            scope_id: None,
            expires_at: Some(now),
        };

        assert!(!assignment.is_active_at(now));
        assert!(assignment.is_active_at(now - chrono::Duration::seconds(1)));
    }
}
