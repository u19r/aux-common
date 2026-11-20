use jiff::Timestamp;

use super::EffectiveRoleAssignment;

#[test]
fn expiry_at_evaluation_time_is_inactive() {
    let now = Timestamp::from_second(1_000).expect("timestamp");
    let assignment = EffectiveRoleAssignment {
        principal_id: None,
        role_id: "reader".to_string(),
        scope_type: Some("tenant".to_string()),
        scope_id: None,
        expires_at: Some(now),
    };

    assert!(!assignment.is_active_at(now));
    assert!(assignment.is_active_at(now - jiff::SignedDuration::from_secs(1)));
}

#[test]
fn given_expiration_when_serialized_then_preserves_rfc3339_precision() {
    for (input, expected) in [
        ("2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z"),
        ("2000-01-01T00:00:00.1Z", "2000-01-01T00:00:00.100Z"),
        ("2000-01-01T00:00:00.1234Z", "2000-01-01T00:00:00.123400Z"),
        (
            "2000-01-01T00:00:00.1234567Z",
            "2000-01-01T00:00:00.123456700Z",
        ),
        ("1969-12-31T23:59:59.1Z", "1969-12-31T23:59:59.100Z"),
        ("2000-01-01T01:00:00+01:00", "2000-01-01T00:00:00Z"),
    ] {
        let value = serde_json::json!({
            "principal_id": null,
            "role_id": "reader",
            "scope_type": null,
            "scope_id": null,
            "expires_at": input,
        });
        let assignment: EffectiveRoleAssignment =
            serde_json::from_value(value).expect("valid assignment");
        let encoded = serde_json::to_value(&assignment).expect("serialized assignment");
        assert_eq!(encoded["expires_at"], expected);
        assert_eq!(
            serde_json::from_value::<EffectiveRoleAssignment>(encoded).expect("round trip"),
            assignment,
        );
    }
}

#[test]
fn given_no_expiration_when_serialized_then_preserves_null() {
    let assignment = EffectiveRoleAssignment {
        principal_id: None,
        role_id: "reader".to_string(),
        scope_type: None,
        scope_id: None,
        expires_at: None,
    };
    let encoded = serde_json::to_value(&assignment).expect("serialized assignment");
    assert!(encoded["expires_at"].is_null());
    assert_eq!(
        serde_json::from_value::<EffectiveRoleAssignment>(encoded).expect("round trip"),
        assignment,
    );
}
