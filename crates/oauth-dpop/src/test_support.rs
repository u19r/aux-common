//! Explicit signing fixtures, excluded from ordinary production builds.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::JwkThumbprint;

pub struct ProofKey {
    key: SigningKey,
}

impl ProofKey {
    pub fn from_seed(seed: u8) -> Self {
        Self {
            key: SigningKey::from_slice(&[seed; 32]).expect("valid explicit test key"),
        }
    }

    pub fn jwk(&self) -> Value {
        let point = self.key.verifying_key().to_sec1_point(false);
        json!({"kty":"EC", "crv":"P-256", "x":URL_SAFE_NO_PAD.encode(point.x().expect("x")), "y":URL_SAFE_NO_PAD.encode(point.y().expect("y"))})
    }

    pub fn thumbprint(&self) -> JwkThumbprint {
        let jwk = self.jwk();
        let projection = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap()
        );
        JwkThumbprint::try_from(URL_SAFE_NO_PAD.encode(Sha256::digest(projection.as_bytes())))
            .expect("SHA-256 thumbprint")
    }

    pub fn sign(&self, claims: &Value) -> String {
        self.sign_raw(
            &json!({"typ":"dpop+jwt","alg":"ES256","jwk":self.jwk()}).to_string(),
            &claims.to_string(),
        )
    }

    pub fn sign_raw(&self, header: &str, payload: &str) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature: Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }
}
