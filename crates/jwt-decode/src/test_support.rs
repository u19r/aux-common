use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use http_request::{
    HttpClientBuilder, HttpRequestError, HttpResponse, StatusCode, Transport, TransportFuture, Url,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AllowedAlgorithms, Clock, JwksCachePolicy, JwksSource, JwksUrl, JwtVerifier, RegisteredClaims,
    RemoteJwksSource, SignatureAlgorithm, TokenKind, VerificationPolicy,
};

pub(super) const HMAC_SECRET: &[u8] = b"local test hmac secret with enough entropy";

const PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCHCRKh2mfWe8dQ
ZCgeBxIySK7WWFt/Cb0lyhq3a3eoXCWtmvJnTVJk+UQ0snPqdqnzBNplYdOuffJO
+faRD8n8mn+4oVTuxaLyddOiDRJaNqr8UXwRI/TQ0ZPrVZDQ78TuzGOCOwmgfU5Z
5shtfSG6QDU3U9K4lalVsjdxpVnnue+tu0+TLtTTNfx09IazWQRqOgunW7FHGdF+
4JjuWXqmEjQz2CVcYhSmfjEWzERAjEeQcX43h5xkAAYizyZF3DWVhSxnTexad0Uu
GxDb7/qVqMgJGRqhAkJX15o4gAPor5pCSbCo/3WCLBFMmz2WYReq3LZOQXxVo39l
CGklk4ONAgMBAAECgf9ycujJmq6tF8oF1094Khqg4o4QxQt+sG0RtsHX78W9WtRo
Jo/YFEVloZMtaPX/AgK88A3k9aY+TgKPXyaIwslDGbv9h1DdR6gfsdcSbwtIDy0i
AwqWM8b8LAcDZTmOCMZr19Ket0thtI0VsfZHLpS/9Oedx1elrAoVeEL6o+tGltNt
sfnGW8M67HJMpRaGHMFkGdsp7sl+adlEpK/HgumyFJ/qnbjPWOXF9ia2zELQX4AJ
7dEn8hhvozi6G5EwtWOhe0u1qNrvOBcDSA17iMYmf/MlZAafHltWpgjh6sAKQrp8
QtNGHN2+5EGefyEwN+szzoXZblvTkp9SrXgb1+UCgYEAu9dpdWkc3Z1CEmWFB0cQ
XC//1Ch3Oda58gL3ho3GzzMpzM/HjU7In/JK9GijMC87y7UxEY7vZp0i06dyjwmn
TExtExfpcXUrTXoOa3dV7Hnmj+L8qGiBynZlsIT3vdjHowSnU9WaXrcdYeei4g5+
VTVYxwxLmMflXOSRvuMGsCcCgYEAuAiC+RoL5fvTSfZ+Eq1NxnwTVuiHEXBTxbLq
Emrim5M842kY7haBULbi6ApdrVMPjlmpATSuL1qwvMPgcjEHlRYL6712mp550n1s
2dyl5opE9qAyMctzEFgb6TwlnRZU40OplcKSPTJEeb3tAERTPn0QZlG7UhGtJT8s
ejIzyysCgYB9PDs1amUyY9xfQ4wTtA92RxI7stb6muzSK6Q382JvVl8yC/2xeqtL
6FCM7w6N24/0WtNiL3fxZCaKEoPQVdFSj0nRhwm++S1rtErU33VL+mH74IwvA640
/AcET0KVMmi3iSy+OhV3vII8eiEgsiUMTkroOoxUSkHjUwjQya/11QKBgCfQ151T
UE2yvRTceoxJ6HDP+VMtPcO9HLLCMbhIXbyxD1RYMaeZQOMYnmD7lSbhuJTguxri
reja4zAD5PRvvSc5PN0FAbsUHGE496ru/Qmy0pbVM+boEH3xwiAk/jJNWZJN2kvn
a8JHtN7uA2+yWJxFbJ3mgvOPlXlggJvzbpc/AoGBAI1Lbcaldcv3nPBs+yZmaDkE
cehIWwl6g06CksfAxjvUWlX+17q6HGQlweZ3Ea1aBbjsszyXmPVAbggMeVDq5q12
RIGLWeczWCcNQlr2KTZzzA/26CllsP9tNPJSRxy7Kgoo7ZB+K8zglm+v2M0/4Ajt
3eAqZLcnvqtR50UvTyQm
-----END PRIVATE KEY-----";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Claims {
    #[serde(flatten)]
    pub(super) registered: RegisteredClaims,
    pub(super) token_type: TokenKind,
    pub(super) client_id: String,
}

#[derive(Debug)]
pub(super) struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }
}

pub(super) fn build_verifier() -> JwtVerifier {
    JwtVerifier::builder()
        .jwks_source(JwksSource::json_string(jwks()).unwrap())
        .allowed_algorithms(AllowedAlgorithms::asymmetric([SignatureAlgorithm::RS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap()
}

pub(super) fn build_remote_verifier(transport: CountingTransport) -> JwtVerifier {
    build_remote_verifier_with_policy(transport, JwksCachePolicy::default())
}

pub(super) fn build_remote_verifier_with_policy(
    transport: CountingTransport,
    cache_policy: JwksCachePolicy,
) -> JwtVerifier {
    let http_client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .unwrap();
    let source = RemoteJwksSource::new(
        JwksUrl::parse_https("https://issuer.example/jwks.json").unwrap(),
        cache_policy,
        http_client,
    );
    JwtVerifier::builder()
        .jwks_source(JwksSource::Url(Box::new(source)))
        .allowed_algorithms(AllowedAlgorithms::asymmetric([SignatureAlgorithm::RS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap()
}

pub(super) fn build_hmac_verifier() -> JwtVerifier {
    JwtVerifier::builder()
        .jwks_source(JwksSource::local_symmetric_key("hmac-key", HMAC_SECRET).unwrap())
        .allowed_algorithms(AllowedAlgorithms::symmetric([SignatureAlgorithm::HS256]).unwrap())
        .clock(Arc::new(FixedClock))
        .build()
        .unwrap()
}

pub(super) fn policy() -> VerificationPolicy {
    VerificationPolicy::access_token()
        .issuer("https://issuer.example")
        .unwrap()
        .audience("aux-api")
        .unwrap()
        .client_id("client-123")
        .unwrap()
        .max_issued_age(Duration::from_secs(600))
        .build()
        .unwrap()
}

pub(super) fn registered_claims(exp: i64, iat: i64) -> RegisteredClaims {
    RegisteredClaims {
        iss: "https://issuer.example".to_owned(),
        sub: Some("subject".to_owned()),
        aud: Some(crate::Audience::Single("aux-api".to_owned())),
        exp,
        nbf: None,
        iat: Some(iat),
        jti: None,
    }
}

pub(super) fn token(claims: Claims) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    header.typ = Some("at+jwt".to_owned());
    signed_token(header, claims)
}

pub(super) fn hmac_token(claims: Claims) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("hmac-key".to_owned());
    header.typ = Some("at+jwt".to_owned());
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(HMAC_SECRET)).unwrap()
}

pub(super) fn signed_token(header: Header, claims: Claims) -> String {
    let key = EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap();
    jsonwebtoken::encode(&header, &claims, &key).unwrap()
}

pub(super) fn signed_value_token(header: Header, claims: Value) -> String {
    let key = EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap();
    jsonwebtoken::encode(&header, &claims, &key).unwrap()
}

pub(super) fn signed_raw_token(header_json: &[u8], claims_json: &[u8]) -> String {
    let key = EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap();
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json);
    let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_json);
    let message = format!("{header}.{claims}");
    let signature = jsonwebtoken::crypto::sign(message.as_bytes(), &key, Algorithm::RS256).unwrap();
    format!("{message}.{signature}")
}

pub(super) fn id_header() -> Header {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    header.typ = Some("JWT".to_owned());
    header
}

pub(super) fn token_without_iat() -> String {
    let key = EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_owned());
    header.typ = Some("at+jwt".to_owned());
    let claims = serde_json::json!({
        "iss": "https://issuer.example",
        "aud": "aux-api",
        "exp": 1_700_000_300_i64,
        "token_type": "access",
        "client_id": "client-123"
    });
    jsonwebtoken::encode(&header, &claims, &key).unwrap()
}

pub(super) fn jwks() -> String {
    let mut jwk = jwk();
    jwk.common.key_id = Some("test-key".to_owned());
    jwk.common.public_key_use = Some(jsonwebtoken::jwk::PublicKeyUse::Signature);
    serde_json::json!({ "keys": [jwk] }).to_string()
}

pub(super) fn jwks_without_test_key() -> String {
    let mut jwk = jwk();
    jwk.common.key_id = Some("old-key".to_owned());
    jwk.common.public_key_use = Some(jsonwebtoken::jwk::PublicKeyUse::Signature);
    serde_json::json!({ "keys": [jwk] }).to_string()
}

pub(super) fn jwk() -> jsonwebtoken::jwk::Jwk {
    let key = EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap();
    jsonwebtoken::jwk::Jwk::from_encoding_key(&key, Algorithm::RS256).unwrap()
}

pub(super) fn valid_claims() -> Claims {
    Claims {
        registered: registered_claims(1_700_000_300, 1_699_999_990),
        token_type: TokenKind::Access,
        client_id: "client-123".to_owned(),
    }
}

pub(super) struct CountingTransport {
    pub(super) attempts: Arc<AtomicUsize>,
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
}

impl CountingTransport {
    pub(super) fn from_bodies(bodies: Vec<String>) -> Self {
        Self::from_results(
            bodies
                .into_iter()
                .map(|body| Ok(mock_response(body)))
                .collect(),
        )
    }

    pub(super) fn from_results(responses: Vec<Result<HttpResponse, HttpRequestError>>) -> Self {
        Self {
            attempts: Arc::new(AtomicUsize::new(0)),
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }
}

impl std::fmt::Debug for CountingTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CountingTransport(..)")
    }
}

impl Transport for CountingTransport {
    fn send(&self, _request: http_request::reqwest::Request) -> TransportFuture {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let response = self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("mock response");
        Box::pin(async move { response })
    }
}

pub(super) fn mock_response(body: String) -> HttpResponse {
    HttpResponse::from_mock(
        StatusCode::OK,
        http_request::header::HeaderMap::new(),
        body.into_bytes(),
        Url::parse("https://issuer.example/jwks.json").unwrap(),
    )
}
