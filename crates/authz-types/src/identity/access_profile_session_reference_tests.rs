use super::{AccessProfileSessionReference, AccessProfileSessionReferenceError};

#[test]
fn session_id_validation_rejects_non_uuid_access_profile_ids() {
    assert_eq!(
        AccessProfileSessionReference::try_new("aps_not-a-uuid", "reader", 1)
            .expect_err("invalid session id"),
        AccessProfileSessionReferenceError::SessionIdInvalid
    );
}
