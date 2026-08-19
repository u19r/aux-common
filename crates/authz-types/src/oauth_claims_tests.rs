use serde_json::{Map, Value, json};

use crate::{
    ClaimBoundsError, CustomClaims, NormalizedAudience, OAuthAccessTokenClaims,
    OAuthAccessTokenClaimsInput, Principal, PrincipalType, VerifiedClaimTree,
};

fn custom_claims() -> CustomClaims {
    let claims = serde_json::from_value(json!({
        "tenant_claim": {
            "null_value": null,
            "number": 1.0,
            "ordered": ["first", "second"]
        }
    }))
    .expect("test custom claims are valid");
    CustomClaims::try_new(claims).expect("test custom claims fit bounds")
}

fn access_token_claims() -> OAuthAccessTokenClaims {
    access_token_claims_with_scope(vec!["documents:read".to_string()])
        .expect("test claims are valid")
}

fn access_token_claims_with_scope(
    scope: Vec<String>,
) -> Result<OAuthAccessTokenClaims, ClaimBoundsError> {
    OAuthAccessTokenClaims::try_new(OAuthAccessTokenClaimsInput {
        issuer: "https://issuer.example.test".to_string(),
        subject: "user_123".to_string(),
        audience: NormalizedAudience::try_new(vec!["api.example.test".to_string()])
            .expect("test audience is valid"),
        expires_at: 1_800_000_000,
        issued_at: 1_700_000_000,
        not_before: None,
        token_id: "jti_123".to_string(),
        client_id: "client_123".to_string(),
        scope,
        tenant: "tenant_123".to_string(),
        principal_type: PrincipalType::User,
        auth_time: Some(1_699_999_000),
        acr: Some("urn:example:acr:mfa".to_string()),
        amr: vec!["pwd".to_string(), "otp".to_string()],
        nonce: Some("nonce_123".to_string()),
        authorized_party: Some("client_123".to_string()),
        access_token_hash: Some("access_hash".to_string()),
        code_hash: Some("code_hash".to_string()),
        permission_set_id: None,
        permission_set_revision: None,
        custom_claims: custom_claims(),
    })
}

#[test]
fn access_token_claims_round_trip_preserves_custom_json_and_scope_wire_format() {
    let claims = access_token_claims();

    let encoded = serde_json::to_value(&claims).expect("claims serialize");
    assert_eq!(encoded["scope"], "documents:read");
    assert_eq!(encoded["tenant_claim"]["null_value"], Value::Null);
    assert_eq!(encoded["tenant_claim"]["number"], json!(1.0));

    let decoded: OAuthAccessTokenClaims =
        serde_json::from_value(encoded).expect("claims deserialize");
    assert_eq!(decoded, claims);
}

#[test]
fn audience_accepts_standard_string_and_array_forms() {
    let one: NormalizedAudience =
        serde_json::from_value(json!("api.example.test")).expect("single audience deserializes");
    let many: NormalizedAudience = serde_json::from_value(json!(["api.example.test", "other"]))
        .expect("multiple audiences deserialize");

    assert_eq!(one.values, ["api.example.test"]);
    assert!(many.contains("other"));
    assert_eq!(
        serde_json::to_value(one).expect("audience serializes"),
        json!("api.example.test")
    );
}

#[test]
fn verified_tree_preserves_object_and_array_order_and_number_kind() {
    let tree: VerifiedClaimTree =
        serde_json::from_str(r#"{"first":null,"second":[1,1.0],"third":{"a":true,"b":false}}"#)
            .expect("tree is valid");
    let object = tree.value.as_object().expect("root is an object");

    assert_eq!(
        object.keys().collect::<Vec<_>>(),
        ["first", "second", "third"]
    );
    assert_eq!(tree.value["second"][0].as_i64(), Some(1));
    assert!(tree.value["second"][1].is_f64());
    assert_eq!(tree.value["first"], Value::Null);
}

#[test]
fn custom_claim_bounds_reject_excess_depth_cardinality_and_bytes() {
    let mut nested = Value::Null;
    for _ in 0..9 {
        nested = json!({ "nested": nested });
    }
    assert!(matches!(
        CustomClaims::try_new(Map::from_iter([(String::from("deep"), nested)])),
        Err(ClaimBoundsError::DepthExceeded { .. })
    ));

    assert!(matches!(
        CustomClaims::try_new(Map::from_iter([(
            String::from("wide"),
            Value::Array((0..129).map(Value::from).collect())
        )])),
        Err(ClaimBoundsError::MembersExceeded { .. })
    ));

    let many = (0..65)
        .map(|index| (format!("claim_{index}"), Value::Null))
        .collect();
    assert!(matches!(
        CustomClaims::try_new(many),
        Err(ClaimBoundsError::CustomClaimsExceeded { .. })
    ));

    assert!(matches!(
        CustomClaims::try_new(Map::from_iter([(
            String::from("large"),
            Value::Array((0..5).map(|_| Value::String("x".repeat(1_024))).collect())
        )])),
        Err(ClaimBoundsError::CustomClaimTooLarge { .. })
    ));

    let aggregate = (0..3)
        .map(|index| {
            (
                format!("claim_{index}"),
                Value::Array((0..3).map(|_| Value::String("x".repeat(1_024))).collect()),
            )
        })
        .collect();
    assert!(matches!(
        CustomClaims::try_new(aggregate),
        Err(ClaimBoundsError::CustomClaimsTooLarge { .. })
    ));
}

#[test]
fn access_token_scope_cardinality_is_bounded_like_other_arrays() {
    let claims =
        access_token_claims_with_scope((0..129).map(|index| format!("scope:{index}")).collect());
    assert!(matches!(
        claims,
        Err(ClaimBoundsError::MembersExceeded { kind: "array", .. })
    ));
}

#[test]
fn compact_jwt_limit_includes_header_payload_and_signature() {
    assert!(matches!(
        access_token_claims().validate_compact_jwt_size(&vec![b'x'; 16_384], 64),
        Err(ClaimBoundsError::CompactJwtTooLarge { .. })
    ));
}

#[test]
fn serialization_error_is_structural_and_never_contains_serializer_output() {
    let error = ClaimBoundsError::Serialization {
        context: crate::ClaimSerializationContext::CompactJwtPayload,
    };

    assert_eq!(
        error.to_string(),
        "claims could not be serialized for compact JWT payload"
    );
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn validated_principal_keeps_verified_tree_and_rejects_mismatched_kind() {
    let claims = access_token_claims();
    let verified_claims =
        VerifiedClaimTree::try_new(serde_json::to_value(&claims).expect("claims serialize"))
            .expect("verified claims fit bounds");
    let principal = crate::ValidatedPrincipal::try_from_access_token(
        &claims,
        Principal::User {
            id: "user_123".to_string(),
        },
        verified_claims,
    )
    .expect("principal matches token");
    assert_eq!(
        principal.verified_claims.value["tenant_claim"]["null_value"],
        Value::Null
    );

    assert!(matches!(
        crate::ValidatedPrincipal::try_from_access_token(
            &claims,
            Principal::ServicePrincipal {
                id: "user_123".to_string(),
            },
            VerifiedClaimTree::try_new(json!({})).expect("empty tree fits bounds"),
        ),
        Err(ClaimBoundsError::PrincipalMismatch)
    ));

    let mut altered = serde_json::to_value(&claims).expect("claims serialize");
    altered["tenant"] = json!("different-tenant");
    assert!(matches!(
        crate::ValidatedPrincipal::try_from_access_token(
            &claims,
            Principal::User {
                id: "user_123".to_string(),
            },
            VerifiedClaimTree::try_new(altered).expect("altered tree fits bounds"),
        ),
        Err(ClaimBoundsError::VerifiedClaimsMismatch)
    ));
}
