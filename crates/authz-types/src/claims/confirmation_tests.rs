use oauth_dpop::{AccessTokenConfirmation, JwkThumbprint};

use super::confirmation::ConfirmationClaim;

#[test]
fn given_confirmation_wire_matrix_when_decoding_then_preserves_binding_and_rejects_invalid_authority()
 {
    let jkt =
        JwkThumbprint::try_from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()).unwrap();
    let valid = format!(r#"{{"jkt":"{}","extension":true}}"#, jkt.as_str());
    let claim: ConfirmationClaim = serde_json::from_str(&valid).unwrap();
    assert_eq!(claim.normalize(), AccessTokenConfirmation::Dpop { jkt });
    assert!(!format!("{claim:?}").contains("AAAAAAAA"));
    for invalid in [
        r#"null"#,
        r#"[]"#,
        r#"{"jkt":null}"#,
        r#"{"jkt":"bad"}"#,
        r#"{"jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        r#"{"jkt":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","jwk":{}}"#,
    ] {
        assert!(serde_json::from_str::<ConfirmationClaim>(invalid).is_err());
    }
    assert_eq!(
        serde_json::from_str::<ConfirmationClaim>(r#"{"unknown":"bounded"}"#)
            .unwrap()
            .normalize(),
        AccessTokenConfirmation::Unsupported
    );
}
