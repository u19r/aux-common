use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;

use super::{AudienceRef, ClaimsPolicy, RegisteredClaimRefs};
use crate::{
    Audience, ClaimErrorKind, JwtDecodeErrorKind, PolicyErrorKind, RegisteredClaims,
    VerificationPolicy, error::Result,
};

const ISSUER: &str = "https://issuer.example";
const AUDIENCE: &str = "aux-api";
const NOW: i64 = 1_700_000_000;

#[test]
fn given_malformed_registered_claims_when_deserializing_then_rejects_claims() {
    // Given a required registered claim with the wrong JSON type.
    let value = json!({"iss": ISSUER, "exp": "later"});

    // When the decoded claims are converted into their typed representation.
    let result = ClaimsPolicy::registered_claims(&value);

    // Then malformed claims fail closed as a deserialization error.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Deserialize),
    );
}

#[test]
fn given_empty_issuer_when_validating_registered_claims_then_rejects_claim() {
    // Given claims with an empty issuer and otherwise valid time and audience
    // values.
    let claims = registered_claims(String::new(), Some(Audience::Single(AUDIENCE.into())));

    // When the registered claims are validated against the issuer policy.
    let result = claims_policy(&standard_policy()).validate_registered(&claims);

    // Then an empty issuer is an invalid claim, not an issuer mismatch.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("iss")),
    );
}

#[test]
fn given_invalid_audience_when_audience_is_not_required_then_rejects_claim() {
    // Given a policy that does not require an audience and an empty audience
    // array.
    let policy = no_audience_policy();
    let claims = registered_claims(ISSUER.to_owned(), Some(Audience::Multiple(Vec::new())));

    // When the registered claims are validated.
    let result = claims_policy(&policy).validate_registered(&claims);

    // Then an explicitly malformed audience is rejected even when it is
    // optional.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_missing_audience_when_audience_is_required_then_rejects_claim() {
    // Given a policy requiring an audience and claims that omit it.
    let claims = registered_claims(ISSUER.to_owned(), None);

    // When the registered claims are validated.
    let result = claims_policy(&standard_policy()).validate_registered(&claims);

    // Then the missing audience is rejected as malformed claims.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_empty_audience_when_audience_is_required_then_rejects_claim() {
    // Given a required audience represented by an empty string.
    let claims = registered_claims(ISSUER.to_owned(), Some(Audience::Single(String::new())));

    // When the registered claims are validated.
    let result = claims_policy(&standard_policy()).validate_registered(&claims);

    // Then an empty audience is rejected before audience matching.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_multiple_audiences_when_validating_claim_refs_then_accepts_expected_audience() {
    // Given a valid multi-audience claim containing the configured audience.
    let value = json!({
        "iss": ISSUER,
        "aud": ["other-api", AUDIENCE],
        "exp": NOW + 300,
        "iat": NOW - 10
    });
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // When the zero-copy registered claim view is validated.
    let result = claims_policy(&standard_policy()).validate_registered_refs(&refs);

    // Then matching one audience is sufficient and all values count toward azp
    // selection.
    assert!(result.is_ok());
    assert_eq!(refs.audience_count(), 2);
}

#[test]
fn given_multiple_audiences_when_expected_audience_is_absent_then_rejects_mismatch() {
    // Given a valid multi-audience claim that does not contain the configured
    // audience.
    let value = json!({
        "iss": ISSUER,
        "aud": ["other-api", "third-party"],
        "exp": NOW + 300,
        "iat": NOW - 10
    });
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // When the zero-copy registered claim view is validated.
    let result = claims_policy(&standard_policy()).validate_registered_refs(&refs);

    // Then the audience mismatch is reported without accepting an unrelated
    // value.
    assert_error(result, JwtDecodeErrorKind::AudienceMismatch);
}

#[test]
fn given_missing_audience_when_audience_is_not_required_then_accepts_claim_refs() {
    // Given a generic policy and a claim set with no audience.
    let value = json!({"iss": ISSUER, "exp": NOW + 300});
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // When the zero-copy registered claim view is validated.
    let result = claims_policy(&no_audience_policy()).validate_registered_refs(&refs);

    // Then omission is accepted when the policy explicitly makes audience
    // optional.
    assert!(result.is_ok());
    assert_eq!(refs.audience_count(), 0);
}

#[test]
fn given_wrong_issuer_when_validating_claim_refs_then_rejects_mismatch() {
    // Given a parsed claim view with an issuer different from policy.
    let value = json!({
        "iss": "https://other-issuer.example",
        "aud": AUDIENCE,
        "exp": NOW + 300,
        "iat": NOW - 10
    });
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // When the registered claim view is validated.
    let result = claims_policy(&standard_policy()).validate_registered_refs(&refs);

    // Then issuer equality remains mandatory on the fast path.
    assert_error(result, JwtDecodeErrorKind::IssuerMismatch);
}

#[test]
fn given_invalid_audience_when_audience_is_not_required_then_rejects_claim_refs() {
    // Given a zero-copy view with an empty multi-audience value.
    let refs = claim_refs(ISSUER, Some(AudienceRef::Multiple(Vec::new())));

    // When a policy that makes audience optional validates the view.
    let result = claims_policy(&no_audience_policy()).validate_registered_refs(&refs);

    // Then optional does not mean malformed audience values are accepted.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_missing_audience_when_audience_is_required_then_rejects_claim_refs() {
    // Given a zero-copy view with no audience value.
    let refs = claim_refs(ISSUER, None);

    // When a policy requiring audience validates the view.
    let result = claims_policy(&standard_policy()).validate_registered_refs(&refs);

    // Then missing audience is rejected before time checks run.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_missing_issuer_when_parsing_claim_refs_then_rejects_named_claim() {
    // Given a claim set with an expiration but no issuer.
    let value = json!({"exp": NOW + 300});

    // When the zero-copy registered claim view is parsed.
    let result = ClaimsPolicy::registered_claim_refs(&value);

    // Then issuer presence remains mandatory at the parsing boundary.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("iss")),
    );
}

#[test]
fn given_missing_expiration_when_parsing_claim_refs_then_rejects_named_claim() {
    // Given a claim set with an issuer but no expiration.
    let value = json!({"iss": ISSUER});

    // When the zero-copy registered claim view is parsed.
    let result = ClaimsPolicy::registered_claim_refs(&value);

    // Then expiration presence remains mandatory at the parsing boundary.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("exp")),
    );
}

#[test]
fn given_null_optional_time_claims_when_parsing_claim_refs_then_treats_them_as_absent() {
    // Given explicit null values for optional time claims.
    let value = json!({
        "iss": ISSUER,
        "exp": NOW + 300,
        "nbf": null,
        "iat": null
    });

    // When the zero-copy registered claim view is parsed.
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // Then null optional claims have the same absence semantics as omitted
    // claims.
    assert_eq!(refs.audience_count(), 0);
    assert!(
        claims_policy(&no_audience_policy())
            .validate_registered_refs(&refs)
            .is_ok()
    );
}

#[test]
fn given_non_integer_time_claim_when_parsing_claim_refs_then_rejects_named_claim() {
    // Given an optional time claim with a non-integer JSON value.
    let value = json!({"iss": ISSUER, "exp": NOW + 300, "iat": "soon"});

    // When the zero-copy registered claim view is parsed.
    let result = ClaimsPolicy::registered_claim_refs(&value);

    // Then time claims cannot bypass integer validation through the fast path.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("iat")),
    );
}

#[test]
fn given_non_string_audience_member_when_parsing_claim_refs_then_rejects_claim() {
    // Given an audience array containing a non-string member.
    let value = json!({"iss": ISSUER, "aud": [AUDIENCE, 7], "exp": NOW + 300});

    // When the zero-copy registered claim view is parsed.
    let result = ClaimsPolicy::registered_claim_refs(&value);

    // Then every audience member must carry the protocol's string
    // representation.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_non_array_non_string_audience_when_parsing_claim_refs_then_rejects_claim() {
    // Given an audience value with neither of the permitted JWT
    // representations.
    let value = json!({"iss": ISSUER, "aud": 7, "exp": NOW + 300});

    // When the zero-copy registered claim view is parsed.
    let result = ClaimsPolicy::registered_claim_refs(&value);

    // Then malformed audience JSON is rejected before policy matching.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_empty_audience_values_when_validating_claim_refs_then_rejects_claim() {
    // Given an audience array with an empty member.
    let value = json!({
        "iss": ISSUER,
        "aud": [""],
        "exp": NOW + 300,
        "iat": NOW - 10
    });
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // When the registered claim view is validated against a required audience.
    let result = claims_policy(&standard_policy()).validate_registered_refs(&refs);

    // Then an empty audience member is invalid even if the array is non-empty.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_empty_audience_array_when_validating_claim_refs_then_rejects_claim() {
    // Given an empty audience array.
    let value = json!({
        "iss": ISSUER,
        "aud": [],
        "exp": NOW + 300,
        "iat": NOW - 10
    });
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // When the registered claim view is validated against a required audience.
    let result = claims_policy(&standard_policy()).validate_registered_refs(&refs);

    // Then an empty audience list is invalid rather than a mismatch.
    assert_error(
        result,
        JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud")),
    );
}

#[test]
fn given_future_nbf_when_validating_claim_refs_then_rejects_not_yet_valid() {
    // Given a not-before timestamp beyond the policy leeway.
    let value = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": NOW + 300,
        "nbf": NOW + 31,
        "iat": NOW - 10
    });
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();
    let mut policy = standard_policy();
    policy.leeway = Duration::ZERO;

    // When the zero-copy registered claim view is validated.
    let result = claims_policy(&policy).validate_registered_refs(&refs);

    // Then the token cannot be used before its not-before boundary.
    assert_error(result, JwtDecodeErrorKind::NotYetValid);
}

#[test]
fn given_missing_iat_when_policy_requires_it_then_rejects_issued_at() {
    // Given valid issuer, audience, and expiration claims without iat.
    let value = json!({"iss": ISSUER, "aud": AUDIENCE, "exp": NOW + 300});
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // When the default policy requiring issued-at is applied.
    let result = claims_policy(&standard_policy()).validate_registered_refs(&refs);

    // Then missing freshness evidence is rejected.
    assert_error(result, JwtDecodeErrorKind::IssuedAtInvalid);
}

#[test]
fn given_missing_iat_when_policy_allows_it_then_accepts_claim_refs() {
    // Given a policy explicitly allowing missing issued-at and no max-age
    // requirement.
    let value = json!({"iss": ISSUER, "exp": NOW + 300});
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();

    // When the claim view is validated.
    let result = claims_policy(&no_audience_policy()).validate_registered_refs(&refs);

    // Then the configured policy, rather than an implicit default, controls
    // acceptance.
    assert!(result.is_ok());
}

#[test]
fn given_future_iat_when_validating_claim_refs_then_rejects_issued_at() {
    // Given an issued-at timestamp beyond the configured leeway.
    let value = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": NOW + 300,
        "iat": NOW + 1
    });
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();
    let mut policy = standard_policy();
    policy.leeway = Duration::ZERO;

    // When the zero-copy registered claim view is validated.
    let result = claims_policy(&policy).validate_registered_refs(&refs);

    // Then a token issued in the future is rejected.
    assert_error(result, JwtDecodeErrorKind::IssuedAtInvalid);
}

#[test]
fn given_expired_token_when_validating_claim_refs_then_rejects_expiration() {
    // Given an expiration at the current second with no leeway.
    let value = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": NOW,
        "iat": NOW - 1
    });
    let refs = ClaimsPolicy::registered_claim_refs(&value).unwrap();
    let mut policy = standard_policy();
    policy.leeway = Duration::ZERO;

    // When the zero-copy registered claim view is validated.
    let result = claims_policy(&policy).validate_registered_refs(&refs);

    // Then expiration is exclusive at the current second.
    assert_error(result, JwtDecodeErrorKind::Expired);
}

#[test]
fn given_missing_token_type_when_required_then_rejects_mismatch() {
    // Given a policy requiring a token type and claims that omit it.
    let value = json!({"client_id": "client-123"});

    // When token-specific claims are validated.
    let result = claims_policy(&standard_policy()).validate_token_type_and_client(&value, 1);

    // Then the token type requirement fails closed before client checks.
    assert_error(result, JwtDecodeErrorKind::TokenTypeMismatch);
}

#[test]
fn given_generic_policy_when_token_type_is_absent_then_accepts_token_specific_claims() {
    // Given a generic policy that intentionally disables token-type and client
    // requirements.
    let value = json!({});

    // When token-specific claims are validated.
    let result = claims_policy(&no_audience_policy()).validate_token_type_and_client(&value, 0);

    // Then generic JWT validation does not invent application-specific claims.
    assert!(result.is_ok());
}

#[test]
fn given_missing_client_id_when_client_is_required_then_rejects_mismatch() {
    // Given a valid token type but no configured client claim.
    let value = json!({"token_type": "access"});

    // When token-specific claims are validated.
    let result = claims_policy(&standard_policy()).validate_token_type_and_client(&value, 1);

    // Then a configured client requirement cannot be bypassed by omission.
    assert_error(result, JwtDecodeErrorKind::ClientMismatch);
}

#[test]
fn given_id_token_with_multiple_audiences_when_azp_matches_then_accepts_client() {
    // Given an ID token with multiple audiences and a matching authorized-party
    // claim.
    let policy = id_policy();
    let value = json!({"token_type": "id", "azp": "client-123"});

    // When token-specific claims are validated with the parsed audience count.
    let result = claims_policy(&policy).validate_token_type_and_client(&value, 2);

    // Then multi-audience ID tokens use azp as their client binding.
    assert!(result.is_ok());
}

#[test]
fn given_id_token_with_multiple_audiences_when_azp_is_missing_then_rejects_client() {
    // Given an ID token that supplies client_id but omits the required
    // authorized-party claim.
    let policy = id_policy();
    let value = json!({"token_type": "id", "client_id": "client-123"});

    // When token-specific claims are validated for multiple audiences.
    let result = claims_policy(&policy).validate_token_type_and_client(&value, 2);

    // Then client_id cannot substitute for azp in this security-sensitive case.
    assert_error(result, JwtDecodeErrorKind::ClientMismatch);
}

#[test]
fn given_single_audience_id_token_with_mismatched_azp_when_validating_then_rejects_client() {
    // Given a single-audience ID token whose client_id matches but whose
    // present azp names another party.
    let policy = id_policy();
    let value = json!({"token_type": "id", "client_id": "client-123", "azp": "other-client"});

    // When token-specific claims are validated.
    let result = claims_policy(&policy).validate_token_type_and_client(&value, 1);

    // Then a present azp must match even when the audience count is one.
    assert_error(result, JwtDecodeErrorKind::ClientMismatch);
}

#[test]
fn given_access_token_with_multiple_audiences_when_azp_mismatches_then_rejects_client() {
    // Given a multi-audience access token whose client_id matches but whose
    // azp names another authorized party.
    let policy = standard_policy();
    let value = json!({"token_type": "access", "client_id": "client-123", "azp": "other-client"});

    // When token-specific claims are validated.
    let result = claims_policy(&policy).validate_token_type_and_client(&value, 2);

    // Then the RFC 9068 authorized-party guard fails closed.
    assert_error(result, JwtDecodeErrorKind::ClientMismatch);
}

#[test]
fn given_access_token_with_multiple_audiences_when_azp_absent_then_rejects_client() {
    // Given a multi-audience access token that omits azp entirely.
    let policy = standard_policy();
    let value = json!({"token_type": "access", "client_id": "client-123"});

    // When token-specific claims are validated.
    let result = claims_policy(&policy).validate_token_type_and_client(&value, 2);

    // Then RFC 9068 requires azp for multiple audiences.
    assert_error(result, JwtDecodeErrorKind::ClientMismatch);
}

#[test]
fn given_single_audience_access_token_with_matching_azp_when_validating_then_accepts_client() {
    // Given a single-audience access token carrying only the RFC 9068 claim.
    let policy = standard_policy();
    let value = json!({"token_type": "access", "azp": "client-123"});

    // When token-specific claims are validated.
    let result = claims_policy(&policy).validate_token_type_and_client(&value, 1);

    // Then an azp-only token interoperates without a legacy client_id claim.
    assert!(result.is_ok());
}

#[test]
fn given_missing_nonce_when_nonce_is_required_then_rejects_mismatch() {
    // Given an ID-token policy with a nonce requirement and no nonce claim.
    let policy = id_policy_with_nonce();
    let value = json!({"token_type": "id", "client_id": "client-123"});

    // When token-specific claims are validated.
    let result = claims_policy(&policy).validate_token_type_and_client(&value, 1);

    // Then nonce binding cannot be bypassed by omission.
    assert_error(result, JwtDecodeErrorKind::NonceMismatch);
}

#[test]
fn given_time_before_unix_epoch_when_validating_then_rejects_issued_at() {
    // Given a valid claim set but a verifier clock before the Unix epoch.
    let claims = registered_claims(ISSUER.to_owned(), Some(Audience::Single(AUDIENCE.into())));
    let now = UNIX_EPOCH - Duration::from_secs(1);

    // When registered claims are validated with that clock.
    let result = ClaimsPolicy::new(&standard_policy(), now).validate_registered(&claims);

    // Then the clock error fails closed as an issued-at error.
    assert_error(result, JwtDecodeErrorKind::IssuedAtInvalid);
}

#[test]
fn given_leeway_beyond_i64_range_when_validating_then_rejects_policy() {
    // Given a public builder duration that cannot be represented in signed
    // claim seconds.
    let result = VerificationPolicy::generic_jwt()
        .issuer(ISSUER)
        .unwrap()
        .without_audience()
        .leeway(Duration::from_secs(i64::MAX as u64 + 1))
        .build();

    // Then the public policy boundary rejects the invalid duration precisely.
    assert_error(
        result,
        JwtDecodeErrorKind::PolicyInvalid(PolicyErrorKind::OutOfRange("leeway")),
    );
}

#[test]
fn given_max_age_beyond_i64_range_when_validating_then_rejects_policy() {
    // Given a public builder max-age that cannot be represented in signed claim
    // seconds.
    let result = VerificationPolicy::generic_jwt()
        .issuer(ISSUER)
        .unwrap()
        .without_audience()
        .max_issued_age(Duration::from_secs(i64::MAX as u64 + 1))
        .build();

    // Then the public policy boundary rejects the invalid duration precisely.
    assert_error(
        result,
        JwtDecodeErrorKind::PolicyInvalid(PolicyErrorKind::OutOfRange("max_issued_age")),
    );
}

#[test]
fn given_max_age_addition_overflow_when_validating_then_rejects_issued_at() {
    // Given an issued-at value at the signed integer limit and a positive
    // max-age.
    let mut policy = standard_policy();
    policy.leeway = Duration::ZERO;
    let claims_policy = ClaimsPolicy::new(&policy, unix_time(NOW));

    // When the max-age arithmetic is evaluated at its overflow boundary.
    let result = claims_policy.test_validate_max_age(i64::MAX, i64::MAX, 0);

    // Then overflow cannot turn an unverifiable token into an accepted one.
    assert_error(result, JwtDecodeErrorKind::IssuedAtInvalid);
}

fn standard_policy() -> VerificationPolicy {
    VerificationPolicy::access_token()
        .issuer(ISSUER)
        .unwrap()
        .audience(AUDIENCE)
        .unwrap()
        .client_id("client-123")
        .unwrap()
        .max_issued_age(Duration::from_secs(600))
        .build()
        .unwrap()
}

fn no_audience_policy() -> VerificationPolicy {
    VerificationPolicy::generic_jwt()
        .issuer(ISSUER)
        .unwrap()
        .without_audience()
        .allow_missing_issued_at()
        .build()
        .unwrap()
}

fn id_policy() -> VerificationPolicy {
    VerificationPolicy::id_token()
        .issuer(ISSUER)
        .unwrap()
        .audience(AUDIENCE)
        .unwrap()
        .client_id("client-123")
        .unwrap()
        .build()
        .unwrap()
}

fn id_policy_with_nonce() -> VerificationPolicy {
    VerificationPolicy::id_token()
        .issuer(ISSUER)
        .unwrap()
        .audience(AUDIENCE)
        .unwrap()
        .client_id("client-123")
        .unwrap()
        .nonce("nonce-123")
        .unwrap()
        .build()
        .unwrap()
}

fn claims_policy(policy: &VerificationPolicy) -> ClaimsPolicy<'_> {
    ClaimsPolicy::new(policy, unix_time(NOW))
}

fn registered_claims(iss: String, aud: Option<Audience>) -> RegisteredClaims {
    RegisteredClaims {
        iss,
        sub: Some("subject".into()),
        aud,
        exp: NOW + 300,
        nbf: None,
        iat: Some(NOW - 10),
        jti: None,
    }
}

fn claim_refs<'a>(iss: &'a str, aud: Option<AudienceRef<'a>>) -> RegisteredClaimRefs<'a> {
    RegisteredClaimRefs::from_test_parts(iss, aud, NOW + 300, None, Some(NOW - 10))
}

fn unix_time(seconds: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds as u64)
}

fn assert_error<T>(result: Result<T>, expected: JwtDecodeErrorKind) {
    let error = result.err().expect("expected validation to fail");
    assert_eq!(error.kind(), &expected);
}

#[test]
fn given_multiple_configured_audiences_when_validating_owned_and_borrowed_claims_then_either_matches()
 {
    let policy = VerificationPolicy::generic_jwt()
        .issuer(ISSUER)
        .unwrap()
        .audiences(["api-first", "api-second"])
        .unwrap()
        .build()
        .unwrap();
    for audience in [
        json!("api-first"),
        json!("api-second"),
        json!(["other", "api-second"]),
    ] {
        let body = json!({"iss":ISSUER,"aud":audience,"exp":NOW+300,"iat":NOW-10});
        let owned = ClaimsPolicy::registered_claims(&body).unwrap();
        let borrowed = ClaimsPolicy::registered_claim_refs(&body).unwrap();
        claims_policy(&policy).validate_registered(&owned).unwrap();
        claims_policy(&policy)
            .validate_registered_refs(&borrowed)
            .unwrap();
    }
    let body = json!({"iss":ISSUER,"aud":"other","exp":NOW+300,"iat":NOW-10});
    assert_error(
        claims_policy(&policy)
            .validate_registered(&ClaimsPolicy::registered_claims(&body).unwrap()),
        JwtDecodeErrorKind::AudienceMismatch,
    );
    assert_error(
        claims_policy(&policy)
            .validate_registered_refs(&ClaimsPolicy::registered_claim_refs(&body).unwrap()),
        JwtDecodeErrorKind::AudienceMismatch,
    );
}

#[test]
fn given_configured_audiences_when_audience_is_absent_or_empty_then_both_claim_paths_reject_it() {
    let policy = VerificationPolicy::generic_jwt()
        .issuer(ISSUER)
        .unwrap()
        .audiences(["api-first", "api-second"])
        .unwrap()
        .build()
        .unwrap();
    for body in [
        json!({"iss":ISSUER,"exp":NOW+300,"iat":NOW-10}),
        json!({"iss":ISSUER,"aud":"","exp":NOW+300,"iat":NOW-10}),
        json!({"iss":ISSUER,"aud":[],"exp":NOW+300,"iat":NOW-10}),
        json!({"iss":ISSUER,"aud":["api-second", ""],"exp":NOW+300,"iat":NOW-10}),
    ] {
        let owned = ClaimsPolicy::registered_claims(&body).unwrap();
        let borrowed = ClaimsPolicy::registered_claim_refs(&body).unwrap();
        let invalid = JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Invalid("aud"));
        assert_error(
            claims_policy(&policy).validate_registered(&owned),
            invalid.clone(),
        );
        assert_error(
            claims_policy(&policy).validate_registered_refs(&borrowed),
            invalid,
        );
    }
}
