use crate::{JwtDecodeErrorKind, PolicyErrorKind, VerificationPolicy};

#[test]
fn given_empty_configured_audience_list_when_building_policy_then_it_is_rejected() {
    let error = VerificationPolicy::generic_jwt()
        .audiences(Vec::<String>::new())
        .expect_err("an empty configured list cannot disable audience validation");
    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::PolicyInvalid(PolicyErrorKind::MissingAudience)
    );
}

#[test]
fn given_empty_member_when_building_audience_policy_then_it_is_not_filtered() {
    let error = VerificationPolicy::generic_jwt()
        .audiences(["first", "", "second"])
        .expect_err("malformed configuration must not be silently filtered");
    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::PolicyInvalid(PolicyErrorKind::EmptyValue("audience"))
    );
}

#[test]
fn given_unchecked_then_configured_audience_when_building_policy_then_the_last_choice_is_enforced()
{
    let policy = VerificationPolicy::generic_jwt()
        .issuer("https://issuer.example")
        .unwrap()
        .without_audience()
        .audience("second")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(policy.audiences, Some(vec!["second".into()]));
    let unchecked = VerificationPolicy::generic_jwt()
        .issuer("https://issuer.example")
        .unwrap()
        .audiences(["first", "second"])
        .unwrap()
        .without_audience()
        .build()
        .unwrap();
    assert!(unchecked.audiences.is_none());
}

#[test]
fn given_no_audience_choice_when_building_policy_then_the_required_configuration_is_missing() {
    let error = VerificationPolicy::generic_jwt()
        .issuer("https://issuer.example")
        .unwrap()
        .build()
        .expect_err("omitting policy is distinct from explicitly disabling it");
    assert_eq!(
        error.kind(),
        &JwtDecodeErrorKind::PolicyInvalid(PolicyErrorKind::MissingAudience)
    );
}
