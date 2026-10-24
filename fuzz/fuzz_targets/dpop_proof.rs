#![no_main]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libfuzzer_sys::fuzz_target;
use oauth_dpop::{
    DpopAlgorithm, DpopTargetUri, DpopValidationInput, JwkThumbprint, ResourceProofValidationInput,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

fuzz_target!(|data: &[u8]| {
    let _ = jose_core::BoundedJson::parse(data);
    let _ = jose_core::EmbeddedEs256Key::parse_json(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = jose_core::LosslessJws::parse(text);
    let _ = DpopTargetUri::try_from(text);
    let _ = JwkThumbprint::try_from(text.to_owned());
    let target = DpopTargetUri::parse_base("https://resource.example/a").unwrap();
    let _ = DpopValidationInput {
        proof: text,
        method: "GET",
        target_uri: &target,
        now_seconds: 1_800_000_000,
        nonce_controls_freshness: false,
        algorithms: DpopAlgorithm::supported(),
    }
    .validate();
    let thumbprint = JwkThumbprint::try_from("A".repeat(43)).unwrap();
    let _ = ResourceProofValidationInput {
        access_token: "token",
        proof: text,
        method: "GET",
        target_uri: &target,
        expected_jkt: &thumbprint,
        now_seconds: 1_800_000_000,
    }
    .validate();
    if data.len() > 8192 {
        return;
    }
    // Authenticate mutated claims too, so fuzzing reaches protocol checks beyond
    // signature rejection.
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let header = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk": {
        "kty":"EC", "crv":"P-256", "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())
    }});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(data)
    );
    let signature: Signature = key.sign(input.as_bytes());
    let proof = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    let _ = DpopValidationInput {
        proof: &proof,
        method: "GET",
        target_uri: &target,
        now_seconds: 1_800_000_000,
        nonce_controls_freshness: false,
        algorithms: DpopAlgorithm::supported(),
    }
    .validate();
});
