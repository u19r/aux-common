use std::{
    ffi::OsString,
    fs,
    sync::{LazyLock, Mutex, MutexGuard},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use http::{HeaderMap, HeaderValue, Uri, header::HOST};
use url::Url;

use crate::{
    AwsRequestSigner, AwsStaticCredentials, CredentialSource, SignableBody,
    resolve_default_chain_credentials, resolve_default_chain_credentials_with_expiry,
    signer::{
        half_life_refresh_after, resolve_ecs_authorization_token, resolve_ecs_task_credentials_uri,
        validate_ecs_full_uri,
    },
};

static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct EnvVarGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvVarGuard {
    fn set(vars: &[(&'static str, Option<&str>)]) -> Self {
        let mut saved = Vec::with_capacity(vars.len());
        for (name, value) in vars {
            saved.push((*name, std::env::var_os(name)));
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        Self { saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (name, value) in self.saved.iter().rev() {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn with_env_lock<T>(run: impl FnOnce() -> T) -> T {
    let _lock = env_lock();
    run()
}

fn with_env_var<T>(name: &str, value: Option<&str>, run: impl FnOnce() -> T) -> T {
    let previous = std::env::var_os(name);
    unsafe {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
    let result = run();
    unsafe {
        match previous {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
    result
}

fn temp_path(prefix: &str, suffix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}.{suffix}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ))
}

#[test]
fn half_life_refresh_after_uses_half_remaining_lifetime() {
    let now = UNIX_EPOCH + Duration::from_secs(100);
    let expires_after = now + Duration::from_secs(60);

    assert_eq!(
        half_life_refresh_after(now, Some(expires_after)),
        Some(now + Duration::from_secs(30))
    );
}

#[test]
fn half_life_refresh_after_returns_now_for_expired_credentials() {
    let now = UNIX_EPOCH + Duration::from_secs(100);
    let expires_after = now - Duration::from_secs(1);

    assert_eq!(half_life_refresh_after(now, Some(expires_after)), Some(now));
}

#[test]
fn half_life_refresh_after_returns_none_when_expiry_missing() {
    assert_eq!(half_life_refresh_after(UNIX_EPOCH, None), None);
}

#[test]
fn resolve_ecs_task_credentials_uri_normalizes_relative_paths() {
    with_env_lock(|| {
        with_env_var("AWS_CONTAINER_CREDENTIALS_FULL_URI", None, || {
            with_env_var(
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                Some("v2/credentials"),
                || {
                    let uri = resolve_ecs_task_credentials_uri()
                        .expect("uri")
                        .expect("relative credentials uri");
                    assert_eq!(uri.as_str(), "http://169.254.170.2/v2/credentials");
                },
            );
        });
    });
}

#[test]
fn validate_ecs_full_uri_rejects_public_http_hosts() {
    let err = validate_ecs_full_uri(&Url::parse("http://example.com/creds").expect("url"))
        .expect_err("public http ecs uri should fail");
    let source = std::error::Error::source(&err)
        .map(std::string::ToString::to_string)
        .unwrap_or_default();

    assert!(
        source.contains("must use HTTPS or a loopback/local ECS host"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn resolve_ecs_authorization_token_reads_and_trims_token_files() {
    let path = temp_path("aws-sigv4-signing-token", "txt");
    fs::write(&path, "  token-from-file \n").expect("write token file");

    with_env_lock(|| {
        with_env_var("AWS_CONTAINER_AUTHORIZATION_TOKEN", None, || {
            with_env_var(
                "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
                Some(path.to_str().expect("path string")),
                || {
                    let token = resolve_ecs_authorization_token()
                        .expect("token")
                        .expect("authorization token");
                    assert_eq!(token, "token-from-file");
                },
            );
        });
    });

    fs::remove_file(path).expect("remove token file");
}

#[test]
fn resolve_default_chain_credentials_uses_environment_credentials_and_trims_session_token() {
    let _lock = env_lock();
    let _guard = EnvVarGuard::set(&[
        ("AWS_ACCESS_KEY_ID", Some("AKIDEXAMPLE")),
        ("AWS_SECRET_ACCESS_KEY", Some("secret-access-key")),
        ("AWS_SESSION_TOKEN", Some(" session-token ")),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
    ]);

    let resolved =
        resolve_default_chain_credentials_with_expiry().expect("environment credentials");
    assert_eq!(resolved.credentials.access_key_id, "AKIDEXAMPLE");
    assert_eq!(resolved.credentials.secret_access_key, "secret-access-key");
    assert_eq!(
        resolved.credentials.session_token.as_deref(),
        Some("session-token")
    );
    assert_eq!(resolved.expires_after, None);
    assert_eq!(resolved.refresh_after, None);

    let static_view = resolve_default_chain_credentials().expect("static credentials view");
    assert_eq!(static_view.access_key_id, "AKIDEXAMPLE");
    assert_eq!(static_view.secret_access_key, "secret-access-key");
    assert_eq!(static_view.session_token.as_deref(), Some("session-token"));
}

#[test]
fn resolve_default_chain_credentials_rejects_partial_environment_configuration() {
    let _lock = env_lock();
    let home_dir = temp_path("aws-sigv4-signing-home", "dir");
    fs::create_dir_all(&home_dir).expect("create temp home dir");
    let _guard = EnvVarGuard::set(&[
        ("AWS_ACCESS_KEY_ID", Some("AKIDEXAMPLE")),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", Some(home_dir.to_str().expect("home dir string"))),
    ]);

    let error = resolve_default_chain_credentials()
        .expect_err("partial environment credentials should fail closed");
    let message = error.to_string();
    assert!(
        message.contains("not properly configured"),
        "unexpected error: {message}"
    );

    fs::remove_dir_all(home_dir).expect("remove temp home dir");
}

#[test]
fn resolve_default_chain_credentials_reports_when_all_providers_are_unavailable() {
    let _lock = env_lock();
    let home_dir = temp_path("aws-sigv4-signing-home", "dir");
    fs::create_dir_all(&home_dir).expect("create temp home dir");
    let _guard = EnvVarGuard::set(&[
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", Some(home_dir.to_str().expect("home dir string"))),
    ]);

    let error = resolve_default_chain_credentials()
        .expect_err("default chain should fail when every provider is disabled");
    assert!(
        error.to_string().contains("not enabled"),
        "unexpected error: {error}"
    );

    fs::remove_dir_all(home_dir).expect("remove temp home dir");
}

#[test]
fn resolve_ecs_task_credentials_uri_prefers_full_uri_over_relative_uri() {
    let _lock = env_lock();
    let _guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            Some("http://127.0.0.1:8080/full"),
        ),
        (
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            Some("/v2/credentials"),
        ),
    ]);

    let uri = resolve_ecs_task_credentials_uri()
        .expect("uri resolution")
        .expect("resolved uri");
    assert_eq!(uri.as_str(), "http://127.0.0.1:8080/full");
}

#[test]
fn resolve_ecs_task_credentials_uri_rejects_double_slash_relative_paths() {
    let _lock = env_lock();
    let _guard = EnvVarGuard::set(&[
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", Some("//bad-path")),
    ]);

    let error = resolve_ecs_task_credentials_uri()
        .expect_err("double-slash relative URI should be rejected");
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .unwrap_or_default();
    assert!(
        source.contains("must be a path"),
        "unexpected error: {error:?}"
    );
}

#[test]
fn validate_ecs_full_uri_accepts_https_and_loopback_http_only() {
    validate_ecs_full_uri(&Url::parse("https://credentials.example.test/path").expect("https url"))
        .expect("https ecs URI should be accepted");
    validate_ecs_full_uri(&Url::parse("http://localhost/creds").expect("localhost url"))
        .expect("loopback http URI should be accepted");

    let err = validate_ecs_full_uri(&Url::parse("ftp://localhost/creds").expect("ftp url"))
        .expect_err("non-http scheme should fail");
    let source = std::error::Error::source(&err)
        .map(std::string::ToString::to_string)
        .unwrap_or_default();
    assert!(
        source.contains("must use HTTP or HTTPS"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn resolve_ecs_authorization_token_prefers_file_and_rejects_empty_file() {
    let _lock = env_lock();
    let path = temp_path("aws-sigv4-signing-empty-token", "txt");
    fs::write(&path, "   ").expect("write empty token file");
    let _guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            Some(path.to_str().expect("path string")),
        ),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", Some("env-token")),
    ]);

    let error = resolve_ecs_authorization_token()
        .expect_err("empty token file should fail before env fallback");
    let message = std::error::Error::source(&error)
        .map_or_else(|| error.to_string(), std::string::ToString::to_string);
    assert!(message.contains("was empty"), "unexpected error: {message}");

    fs::remove_file(path).expect("remove token file");
}

#[test]
fn with_env_var_restores_original_value() {
    let original = OsString::from("original");
    unsafe {
        std::env::set_var("AWS_SIGV4_SIGNING_TEST_ENV", &original);
    }

    with_env_lock(|| {
        with_env_var("AWS_SIGV4_SIGNING_TEST_ENV", Some("temporary"), || {
            assert_eq!(
                std::env::var("AWS_SIGV4_SIGNING_TEST_ENV").as_deref(),
                Ok("temporary")
            );
        });
    });

    assert_eq!(
        std::env::var_os("AWS_SIGV4_SIGNING_TEST_ENV"),
        Some(original)
    );
    unsafe {
        std::env::remove_var("AWS_SIGV4_SIGNING_TEST_ENV");
    }
}

#[tokio::test]
async fn sign_wrapper_adds_authorization_headers_for_post_requests() {
    let signer = AwsRequestSigner::new(
        "eu-west-2",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "very-secret".to_string(),
            session_token: None,
        }),
        "execute-api",
    )
    .expect("signer");
    let uri: Uri = "https://api.example.com/customers".parse().expect("uri");

    let headers = signer
        .sign(&uri, &HeaderMap::new(), br#"{"hello":"world"}"#)
        .await
        .expect("signed request");

    assert_eq!(
        headers.get(HOST).and_then(|value| value.to_str().ok()),
        Some("api.example.com")
    );
    assert!(headers.contains_key("x-amz-date"));
    assert!(headers.contains_key("x-amz-content-sha256"));
    assert!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
    );
}

#[tokio::test]
async fn sign_request_adds_host_checksum_and_session_token_headers() {
    let signer = AwsRequestSigner::new(
        "eu-west-2",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "very-secret".to_string(),
            session_token: Some("session-token".to_string()),
        }),
        "execute-api",
    )
    .expect("signer");
    let uri: Uri = "https://api.example.com/customers".parse().expect("uri");

    let headers = signer
        .sign_request("GET", &uri, &HeaderMap::new(), SignableBody::Bytes(&[]))
        .await
        .expect("signed request");

    assert_eq!(
        headers.get(HOST).and_then(|value| value.to_str().ok()),
        Some("api.example.com")
    );
    assert_eq!(
        headers
            .get("x-amz-security-token")
            .and_then(|value| value.to_str().ok()),
        Some("session-token")
    );
    assert!(headers.contains_key("x-amz-date"));
    assert!(headers.contains_key("x-amz-content-sha256"));
    assert!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
    );
}

#[tokio::test]
async fn sign_request_preserves_explicit_host_header_and_presign_uses_query_params() {
    let signer = AwsRequestSigner::new(
        "us-east-1",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "very-secret".to_string(),
            session_token: Some("session-token".to_string()),
        }),
        "execute-api",
    )
    .expect("signer");
    let uri: Uri = "https://api.example.com/customers?existing=1"
        .parse()
        .expect("uri");
    let mut base_headers = HeaderMap::new();
    base_headers.insert(HOST, HeaderValue::from_static("override.example.com"));

    let signed_headers = signer
        .sign_request("POST", &uri, &base_headers, SignableBody::Bytes(b"{}"))
        .await
        .expect("signed headers");
    assert_eq!(
        signed_headers
            .get(HOST)
            .and_then(|value| value.to_str().ok()),
        Some("override.example.com")
    );

    let presigned = signer
        .presign_request(
            "GET",
            &uri,
            &base_headers,
            SignableBody::Bytes(&[]),
            Duration::from_secs(120),
        )
        .await
        .expect("presigned uri");
    let presigned_url = Url::parse(&presigned.to_string()).expect("presigned url");
    let query = presigned_url.query_pairs().collect::<Vec<_>>();

    assert!(
        query
            .iter()
            .any(|(key, value)| key == "existing" && value == "1")
    );
    assert!(
        query
            .iter()
            .any(|(key, value)| { key == "X-Amz-Algorithm" && value == "AWS4-HMAC-SHA256" })
    );
    assert!(
        query
            .iter()
            .any(|(key, value)| key == "X-Amz-Security-Token" && value == "session-token")
    );
    assert!(
        query
            .iter()
            .any(|(key, value)| key == "X-Amz-Expires" && value == "120")
    );
    assert!(
        query
            .iter()
            .any(|(key, value)| { key == "X-Amz-SignedHeaders" && value.contains("host") })
    );
    assert!(!query.iter().any(|(key, _)| key == "X-Amz-Content-Sha256"));
}
