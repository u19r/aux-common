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
