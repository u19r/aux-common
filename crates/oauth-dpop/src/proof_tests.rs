use serde_json::{Value, json};

use crate::{DpopAlgorithm, DpopTargetUri, DpopValidationInput, test_support::ProofKey};

const NOW: i64 = 1_800_000_000;

fn claims() -> Value {
    json!({"jti":"independent-request", "htm":"GET", "htu":"https://resource.example/a", "iat":NOW})
}

fn accepts(proof: &str, nonce_controls_freshness: bool) -> bool {
    let target = DpopTargetUri::parse_base("https://resource.example/a").unwrap();
    DpopValidationInput {
        proof,
        method: "GET",
        target_uri: &target,
        now_seconds: NOW,
        nonce_controls_freshness,
        algorithms: DpopAlgorithm::supported(),
    }
    .validate()
    .is_ok()
}

#[test]
fn given_signed_original_bytes_when_header_order_and_extensions_change_then_validates_losslessly() {
    let key = ProofKey::from_seed(1);
    for typ in [
        "dpop+jwt",
        "DPoP+JWT",
        "application/dpop+jwt",
        "APPLICATION/DPOP+JWT",
    ] {
        let header = format!(
            "{{ \"extension\":{{\"child\":true}}, \"jwk\":{}, \"typ\":\"{typ}\", \
             \"alg\":\"ES256\" }}",
            key.jwk()
        );
        let proof = key.sign_raw(&header, &claims().to_string());
        assert!(accepts(&proof, false));
    }
    let target = DpopTargetUri::parse_base("https://resource.example/a").unwrap();
    let proof = key.sign(&claims());
    let verified = DpopValidationInput {
        proof: &proof,
        method: "GET",
        target_uri: &target,
        now_seconds: NOW,
        nonce_controls_freshness: false,
        algorithms: DpopAlgorithm::supported(),
    }
    .validate()
    .unwrap();
    assert_eq!(verified.thumbprint(), &key.thumbprint());
}

#[test]
fn given_header_key_and_critical_attacks_when_authenticating_then_rejects_all_without_downgrade() {
    let key = ProofKey::from_seed(1);
    let header = json!({"typ":"dpop+jwt", "alg":"ES256", "jwk":key.jwk()});
    let attacks = [
        ("typ", json!("JWT")),
        ("typ", json!("dpop+jwt;charset=utf-8")),
        ("alg", json!("none")),
        ("alg", json!("HS256")),
        ("alg", json!("ES384")),
        ("jwk", json!({"kid":"remote"})),
        ("jwk", json!({"kty":"oct","k":"AAAA"})),
        ("b64", json!(false)),
        ("b64", json!(true)),
        ("crit", json!([])),
        ("crit", json!(["alg"])),
        ("crit", json!(["b64", "b64"])),
        ("crit", json!(["unknown"])),
    ];
    for (member, value) in attacks {
        let mut changed = header.clone();
        changed[member] = value;
        assert!(
            !accepts(
                &key.sign_raw(&changed.to_string(), &claims().to_string()),
                false
            ),
            "{member}"
        );
    }
    for (member, value) in [
        ("d", json!("private")),
        ("k", json!("symmetric")),
        ("crv", json!("P-384")),
        ("x", json!("AA")),
        ("y", json!("A".repeat(43))),
        ("alg", json!("RS256")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
    ] {
        let mut changed = header.clone();
        changed["jwk"][member] = value;
        assert!(
            !accepts(
                &key.sign_raw(&changed.to_string(), &claims().to_string()),
                false
            ),
            "JWK {member}"
        );
    }
    let mut b64 = header.clone();
    b64["b64"] = json!(true);
    b64["crit"] = json!(["b64"]);
    assert!(accepts(
        &key.sign_raw(&b64.to_string(), &claims().to_string()),
        false
    ));
}

#[test]
fn given_duplicate_members_at_each_depth_when_verifying_then_rejects_even_with_valid_signatures() {
    let key = ProofKey::from_seed(1);
    let header = json!({"typ":"dpop+jwt","alg":"ES256","jwk":key.jwk()}).to_string();
    for duplicate in [
        format!(
            "{{\"alg\":\"ES256\",\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":{}}}",
            key.jwk()
        ),
        header.replace("\"kty\":\"EC\"", "\"kty\":\"EC\",\"kty\":\"EC\""),
        header.replacen('{', "{\"extra\":{\"a\":1,\"a\":2},", 1),
    ] {
        assert!(!accepts(
            &key.sign_raw(&duplicate, &claims().to_string()),
            false
        ));
    }
    for payload in [
        format!("{{\"jti\":\"one\",\"jti\":\"two\",\"htm\":\"GET\",\"htu\":\"https://resource.example/a\",\"iat\":{NOW}}}"),
        claims().to_string().replacen('{',"{\"nested\":{\"a\":[{\"x\":1,\"x\":2}]},",1),
    ] { assert!(!accepts(&key.sign_raw(&header,&payload),false)); }
}

#[test]
fn given_exact_numeric_dates_when_checking_inclusive_bounds_then_fractional_and_exponent_values_compare_exactly()
 {
    let key = ProofKey::from_seed(1);
    let header = json!({"typ":"dpop+jwt","alg":"ES256","jwk":key.jwk()}).to_string();
    for (iat, expected) in [
        ("1799999940", true),
        ("1799999939.99999999999999999", false),
        ("1800000005", true),
        ("1800000005.00000000000000001", false),
        ("1.79999994e9", true),
        ("1.800000005e9", true),
        ("-1", false),
        ("\"1800000000\"", false),
        ("null", false),
        ("1e1000", false),
    ] {
        let payload = format!("{{\"jti\":\"date\",\"htm\":\"GET\",\"htu\":\"https://resource.example/a\",\"iat\":{iat}}}");
        assert_eq!(
            accepts(&key.sign_raw(&header, &payload), false),
            expected,
            "date {iat}"
        );
    }
    let mut stale = claims();
    stale["iat"] = json!(0);
    assert!(accepts(&key.sign(&stale), true));
    stale["iat"] = json!("0");
    assert!(!accepts(&key.sign(&stale), true));
}

#[test]
fn given_claim_limits_and_method_mismatch_when_validating_then_enforces_limits_and_case() {
    let key = ProofKey::from_seed(1);
    for (member, value, expected) in [
        ("jti", json!("j".repeat(256)), true),
        ("jti", json!("j".repeat(257)), false),
        ("jti", json!(""), false),
        ("htm", json!("get"), false),
        ("htm", json!("POST"), false),
        ("htu", json!("http://resource.example/a"), false),
        ("htu", json!("https://resource.example/b"), false),
        ("extension", json!("x".repeat(2048)), true),
        ("extension", json!("x".repeat(2049)), false),
    ] {
        let mut changed = claims();
        changed[member] = value;
        assert_eq!(
            accepts(&key.sign(&changed), false),
            expected,
            "member {member}"
        );
    }
    let mut proof = key.sign(&claims()).into_bytes();
    let last = proof.len() - 5;
    proof[last] ^= 1;
    assert!(!accepts(std::str::from_utf8(&proof).unwrap(), false));
    for malformed in ["", ".", "a.b.c.d", "a.b", " a.b.c", "a=.b.c"] {
        assert!(!accepts(malformed, false));
    }
}

#[test]
fn given_stateless_validator_when_same_proof_replays_inside_window_then_acceptance_is_explicit() {
    let proof = ProofKey::from_seed(1).sign(&claims());
    assert!(accepts(&proof, false));
    assert!(accepts(&proof, false));
    let target = DpopTargetUri::parse_base("https://resource.example/a").unwrap();
    assert!(
        DpopValidationInput {
            proof: &proof,
            method: "GET",
            target_uri: &target,
            now_seconds: NOW + 61,
            nonce_controls_freshness: false,
            algorithms: DpopAlgorithm::supported()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn given_public_key_metadata_permitting_verification_when_other_operations_are_declared_then_verifies_without_changing_thumbprint()
 {
    let key = ProofKey::from_seed(1);
    let mut jwk = key.jwk();
    jwk["key_ops"] = json!(["sign", "verify"]);
    jwk["alg"] = json!("ES256");
    jwk["use"] = json!("sig");
    let header = json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk});
    let compact = key.sign_raw(&header.to_string(), &claims().to_string());
    let target = DpopTargetUri::parse_base("https://resource.example/a").unwrap();
    let validated = DpopValidationInput {
        proof: &compact,
        method: "GET",
        target_uri: &target,
        now_seconds: NOW,
        nonce_controls_freshness: false,
        algorithms: DpopAlgorithm::supported(),
    }
    .validate()
    .unwrap();
    assert_eq!(validated.thumbprint(), &key.thumbprint());
    for operations in [
        json!(["verify", "verify"]),
        json!(["sign"]),
        json!(["verify", true]),
    ] {
        let mut changed = header.clone();
        changed["jwk"]["key_ops"] = operations;
        assert!(!accepts(
            &key.sign_raw(&changed.to_string(), &claims().to_string()),
            false
        ));
    }
}
