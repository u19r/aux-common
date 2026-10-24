use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jose_core::{BoundedJson, EmbeddedEs256Key, LosslessJws};
use serde_json::json;

use crate::{DpopAlgorithm, DpopTargetUri, DpopValidationInput, test_support::ProofKey};

#[test]
fn given_parser_byte_bounds_when_parsing_then_accepts_feasible_boundaries_and_rejects_limit_plus_one()
 {
    for length in [8192, 8193] {
        let document = format!("{{}}{}", " ".repeat(length - 2));
        assert_eq!(
            BoundedJson::parse(document.as_bytes()).is_ok(),
            length == 8192
        );
        let compact = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(&document),
            URL_SAFE_NO_PAD.encode("{}"),
            URL_SAFE_NO_PAD.encode([0; 64])
        );
        assert_eq!(LosslessJws::parse(&compact).is_ok(), length == 8192);
    }
    for length in [1024, 1025] {
        let compact = format!("e30.e30.{}", URL_SAFE_NO_PAD.encode(vec![0; length]));
        assert_eq!(LosslessJws::parse(&compact).is_ok(), length == 1024);
    }
    for length in [12 * 1024 + 1, 24 * 1024 + 1] {
        assert!(LosslessJws::parse(&format!("{}.e30.AA", "a".repeat(length))).is_err());
    }
}

#[test]
fn given_collection_depth_and_string_bounds_when_parsing_then_checks_each_limit_and_successor() {
    for count in [32, 33] {
        let object = (0..count)
            .map(|index| format!("\"k{index}\":null"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            BoundedJson::parse(format!("{{{object}}}").as_bytes()).is_ok(),
            count == 32
        );
        let array = vec!["null"; count].join(",");
        assert_eq!(
            BoundedJson::parse(format!("[{array}]").as_bytes()).is_ok(),
            count == 32
        );
    }
    for count in [8, 9] {
        let document = format!("{}0{}", "[".repeat(count), "]".repeat(count));
        assert_eq!(BoundedJson::parse(document.as_bytes()).is_ok(), count == 8);
    }
    for count in [2048, 2049] {
        assert_eq!(
            BoundedJson::parse(json!({"member":"a".repeat(count)}).to_string().as_bytes()).is_ok(),
            count == 2048
        );
    }
}

#[test]
fn given_embedded_key_wire_size_and_member_limits_when_verifying_then_enforces_raw_json_bounds_without_fetches()
 {
    let key = ProofKey::from_seed(1);
    let jwk = key.jwk().to_string();
    for length in [4096, 4097] {
        let padded = format!(
            "{{{}{}",
            " ".repeat(length - jwk.len()),
            jwk.strip_prefix('{').unwrap()
        );
        assert_eq!(
            EmbeddedEs256Key::parse_json(padded.as_bytes()).is_ok(),
            length == 4096
        );
        let header = format!("{{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{padded}}}");
        let target = DpopTargetUri::parse_base("https://resource.example/a").unwrap();
        let proof = key.sign_raw(
            &header,
            &json!({"jti":"size", "htm":"GET","htu":target.as_str(),"iat":1_800_000_000})
                .to_string(),
        );
        assert_eq!(
            DpopValidationInput {
                proof: &proof,
                method: "GET",
                target_uri: &target,
                now_seconds: 1_800_000_000,
                nonce_controls_freshness: false,
                algorithms: DpopAlgorithm::supported()
            }
            .validate()
            .is_ok(),
            length == 4096
        );
    }
    for count in [16, 17] {
        let mut jwk = key.jwk();
        for index in 4..count {
            jwk[format!("extension{index}")] = json!(null);
        }
        assert_eq!(EmbeddedEs256Key::try_from(&jwk).is_ok(), count == 16);
    }
}
