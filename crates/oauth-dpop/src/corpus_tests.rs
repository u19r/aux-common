use serde_json::Value;

use crate::{DpopTargetUri, JwkThumbprint, ResourceProofValidationInput};

#[test]
fn given_independent_openssl_signed_corpus_when_validating_then_agrees_with_expected_protocol_results()
 {
    let corpus: Value =
        serde_json::from_str(include_str!("../fixtures/independent-corpus.json")).unwrap();
    let target = DpopTargetUri::try_from(corpus["target_uri"].as_str().unwrap()).unwrap();
    let jkt = JwkThumbprint::try_from(corpus["expected_jkt"].as_str().unwrap().to_owned()).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 45);
    for case in cases {
        let accepted = ResourceProofValidationInput {
            access_token: corpus["access_token"].as_str().unwrap(),
            proof: case["proof"].as_str().unwrap(),
            method: case["request_method"].as_str().unwrap_or("GET"),
            target_uri: &target,
            expected_jkt: &jkt,
            now_seconds: corpus["now_seconds"].as_i64().unwrap(),
        }
        .validate()
        .is_ok();
        assert_eq!(
            accepted,
            case["accepted"].as_bool().unwrap(),
            "independent case {}",
            case["name"].as_str().unwrap()
        );
    }
}
