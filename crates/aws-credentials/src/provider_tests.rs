#![expect(
    unsafe_code,
    reason = "Rust 2024 marks process environment mutation unsafe; these tests serialize and \
              restore state"
)]

use std::{
    ffi::OsString,
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::{
        Arc, LazyLock, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_credential_types::provider::ProvideCredentials;
use url::Url;

use crate::{
    AwsResolvedCredentials, AwsStaticCredentials, CredentialSource,
    DefaultChainCredentialsProvider, half_life_refresh_after,
    provider::{
        credential_cache_ttl, metadata_refresh_after, run_bounded_command,
        validate_aws_cli_output_size,
    },
    resolve_default_chain_credentials, resolve_default_chain_credentials_with_expiry,
    resolve_ecs_authorization_token, resolve_ecs_task_credentials_uri, validate_ecs_full_uri,
};

#[test]
fn credential_debug_output_redacts_secret_material() {
    let credentials = AwsStaticCredentials {
        access_key_id: "AKIDEXAMPLE".to_string(),
        secret_access_key: "sentinel-secret-access-key".to_string(),
        session_token: Some("sentinel-session-token".to_string()),
    };
    let resolved = AwsResolvedCredentials {
        credentials: credentials.clone(),
        expires_after: None,
        refresh_after: None,
    };

    for debug in [
        format!("{credentials:?}"),
        format!("{resolved:?}"),
        format!("{:?}", CredentialSource::Static(credentials)),
    ] {
        assert!(!debug.contains("sentinel-secret-access-key"), "{debug}");
        assert!(!debug.contains("sentinel-session-token"), "{debug}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
    }
}

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

fn spawn_http_response(
    listener: TcpListener,
    response: String,
    received: Option<std::sync::mpsc::Sender<()>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("configure test listener");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0_u8; 1024];
                    let _ = stream.read(&mut request);
                    stream
                        .write_all(response.as_bytes())
                        .expect("write test response");
                    if let Some(received) = received {
                        received.send(()).expect("signal received request");
                    }
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept test request: {error}"),
            }
        }
    })
}

fn spawn_counted_http_response(
    listener: TcpListener,
    response: String,
    requests: Arc<AtomicUsize>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("configure counted test listener");
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut idle_deadline = None;
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0_u8; 1024];
                    let _ = stream.read(&mut request);
                    stream
                        .write_all(response.as_bytes())
                        .expect("write counted test response");
                    requests.fetch_add(1, Ordering::SeqCst);
                    idle_deadline = Some(Instant::now() + Duration::from_millis(150));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline
                        || idle_deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept counted test request: {error}"),
            }
        }
    })
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
    let expires_after = now + Duration::from_mins(1);

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
    let path = temp_path("aws-credentials-token", "txt");
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
fn resolve_ecs_authorization_token_rejects_oversized_token_files() {
    let _lock = env_lock();
    let path = temp_path("aws-credentials-oversized-token", "txt");
    fs::write(
        &path,
        vec![b'x'; crate::constants::MAX_AUTHORIZATION_TOKEN_BYTES + 1],
    )
    .expect("write oversized token file");
    let _guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            Some(path.to_str().expect("path string")),
        ),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", Some("env-token")),
    ]);

    let error = resolve_ecs_authorization_token()
        .expect_err("oversized token file should be rejected before env fallback");
    let message = std::error::Error::source(&error)
        .map_or_else(|| error.to_string(), std::string::ToString::to_string);
    assert!(message.contains("exceeds configured limit"), "{message}");

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
    let home_dir = temp_path("aws-credentials-home", "dir");
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
    let home_dir = temp_path("aws-credentials-home", "dir");
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
fn ecs_credentials_reject_redirects_before_accepting_alternate_credentials() {
    let redirect_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind redirect listener");
    let target_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind target listener");
    let redirect_addr = redirect_listener.local_addr().expect("redirect address");
    let target_addr = target_listener.local_addr().expect("target address");
    let target_response_body =
        r#"{"AccessKeyId":"redirected-access-key","SecretAccessKey":"redirected-secret"}"#;
    let target_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: \
         close\r\n\r\n{}",
        target_response_body.len(),
        target_response_body
    );
    let redirect_response = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{target_addr}/credentials\r\nContent-Length: \
         0\r\nConnection: close\r\n\r\n"
    );
    let (target_received, target_requests) = std::sync::mpsc::channel();
    let redirect_thread = spawn_http_response(redirect_listener, redirect_response, None);
    let target_thread =
        spawn_http_response(target_listener, target_response, Some(target_received));

    let _lock = env_lock();
    let home_dir = temp_path("aws-credentials-redirect-home", "dir");
    fs::create_dir_all(&home_dir).expect("create temp home dir");
    let _guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            Some(&format!("http://{redirect_addr}/credentials")),
        ),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", Some(home_dir.to_str().expect("home dir string"))),
    ]);

    let error = resolve_default_chain_credentials()
        .expect_err("credential provider must not accept redirected credentials");
    assert!(
        std::error::Error::source(&error).is_some(),
        "unexpected error: {error}"
    );
    assert!(
        target_requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "provider followed redirect to alternate credential endpoint"
    );

    redirect_thread.join().expect("join redirect server");
    target_thread.join().expect("join target server");
    fs::remove_dir_all(home_dir).expect("remove temp home dir");
}

#[test]
fn async_ecs_credentials_reject_redirects_before_accepting_alternate_credentials() {
    let redirect_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind redirect listener");
    let target_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind target listener");
    let redirect_addr = redirect_listener.local_addr().expect("redirect address");
    let target_addr = target_listener.local_addr().expect("target address");
    let target_response_body =
        r#"{"AccessKeyId":"redirected-access-key","SecretAccessKey":"redirected-secret"}"#;
    let target_response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: \
         close\r\n\r\n{}",
        target_response_body.len(),
        target_response_body
    );
    let redirect_response = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{target_addr}/credentials\r\nContent-Length: \
         0\r\nConnection: close\r\n\r\n"
    );
    let (target_received, target_requests) = std::sync::mpsc::channel();
    let redirect_thread = spawn_http_response(redirect_listener, redirect_response, None);
    let target_thread =
        spawn_http_response(target_listener, target_response, Some(target_received));

    let _lock = env_lock();
    let home_dir = temp_path("aws-credentials-async-redirect-home", "dir");
    fs::create_dir_all(&home_dir).expect("create temp home dir");
    let _guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            Some(&format!("http://{redirect_addr}/credentials")),
        ),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", Some(home_dir.to_str().expect("home dir string"))),
    ]);

    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");
    let error = runtime
        .block_on(provider.provide_credentials())
        .expect_err("async provider must not accept redirected credentials");
    assert!(
        std::error::Error::source(&error).is_some(),
        "unexpected error: {error}"
    );
    assert!(
        target_requests
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "async provider followed redirect to alternate credential endpoint"
    );

    redirect_thread.join().expect("join redirect server");
    target_thread.join().expect("join target server");
    fs::remove_dir_all(home_dir).expect("remove temp home dir");
}

#[test]
fn metadata_response_body_limit_rejects_oversized_blocking_body() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind metadata listener");
    let address = listener.local_addr().expect("metadata address");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        crate::constants::MAX_METADATA_RESPONSE_BYTES + 1
    );
    let server = spawn_http_response(listener, response, None);
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(format!("http://{address}/credentials"))
        .send()
        .expect("metadata response");

    let error = crate::provider::bounded_blocking_response_body(response)
        .expect_err("oversized metadata response must be rejected");
    assert!(error.to_string().contains("exceeds configured limit"));
    server.join().expect("join metadata server");
}

#[test]
fn aws_cli_output_size_is_bounded_before_json_parsing() {
    let oversized = vec![b'x'; crate::constants::MAX_AWS_CLI_OUTPUT_BYTES + 1];
    let error = validate_aws_cli_output_size(&oversized, &[])
        .expect_err("oversized aws cli output must be rejected");
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .unwrap_or_default();
    assert!(source.contains("exceeds configured limit"), "{source}");
}

#[cfg(unix)]
#[test]
fn aws_cli_output_flood_is_terminated_while_pipes_are_capped() {
    let output = run_bounded_command({
        let mut command = Command::new("sh");
        command.args(["-c", "yes x"]);
        command
    })
    .expect("bounded command should return a terminated child");

    assert!(!output.timed_out);
    assert!(output.stdout.len() <= crate::constants::MAX_AWS_CLI_OUTPUT_BYTES + 1);
    assert!(output.stderr.len() <= crate::constants::MAX_AWS_CLI_OUTPUT_BYTES + 1);
    assert!(
        output.stdout.len() > crate::constants::MAX_AWS_CLI_OUTPUT_BYTES,
        "the flood must be observed at the cap boundary"
    );
}

#[cfg(unix)]
#[test]
fn async_profile_resolution_does_not_block_runtime_executor() {
    use std::os::unix::fs::PermissionsExt;

    let _lock = env_lock();
    let bin_dir = temp_path("aws-credentials-cli-bin", "dir");
    fs::create_dir_all(&bin_dir).expect("create cli directory");
    let aws_path = bin_dir.join("aws");
    fs::write(&aws_path, "#!/bin/sh\n/bin/sleep 0.2\n").expect("write aws test command");
    fs::set_permissions(&aws_path, fs::Permissions::from_mode(0o755))
        .expect("make aws test command executable");
    let home_dir = temp_path("aws-credentials-async-profile-home", "dir");
    fs::create_dir_all(&home_dir).expect("create temp home dir");
    let path = bin_dir.to_str().expect("cli directory string");
    let home = home_dir.to_str().expect("home directory string");
    let _guard = EnvVarGuard::set(&[
        ("PATH", Some(path)),
        ("HOME", Some(home)),
        ("AWS_PROFILE", Some("default")),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
    ]);

    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("create current-thread runtime");
    let marker = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let marker_for_task = Arc::clone(&marker);
    let (result, marker_seen) = runtime.block_on(async move {
        let marker_task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            marker_for_task.store(true, Ordering::SeqCst);
        });
        let result = provider.provide_credentials().await;
        marker_task.await.expect("marker task should complete");
        (result, marker.load(std::sync::atomic::Ordering::SeqCst))
    });

    assert!(
        result.is_err(),
        "empty test CLI output must not resolve credentials"
    );
    assert!(
        marker_seen,
        "the async provider blocked the executor while resolving the profile"
    );
    fs::remove_dir_all(bin_dir).expect("remove cli directory");
    fs::remove_dir_all(home_dir).expect("remove temp home dir");
}

#[test]
fn concurrent_provider_misses_share_one_metadata_resolution() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind metadata listener");
    let address = listener.local_addr().expect("metadata address");
    let response_body = r#"{"AccessKeyId":"AKIDEXAMPLE","SecretAccessKey":"secret-access-key"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: \
         close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    let requests = Arc::new(AtomicUsize::new(0));
    let server = spawn_counted_http_response(listener, response, Arc::clone(&requests));

    let _lock = env_lock();
    let home_dir = temp_path("aws-credentials-concurrent-home", "dir");
    fs::create_dir_all(&home_dir).expect("create temp home dir");
    let endpoint = format!("http://{address}/credentials");
    let _guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            Some(endpoint.as_str()),
        ),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", Some(home_dir.to_str().expect("home dir string"))),
    ]);

    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");
    runtime.block_on(async {
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let provider = provider.clone();
            let barrier = Arc::clone(&barrier);
            tasks.spawn(async move {
                barrier.wait().await;
                provider.provide_credentials().await
            });
        }
        while let Some(result) = tasks.join_next().await {
            let credentials = result
                .expect("provider task")
                .expect("metadata credentials");
            assert_eq!(credentials.access_key_id(), "AKIDEXAMPLE");
        }
    });

    server.join().expect("join metadata server");
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    fs::remove_dir_all(home_dir).expect("remove temp home dir");
}

#[test]
fn metadata_request_errors_redact_configured_endpoint_values() {
    let _lock = env_lock();
    let home_dir = temp_path("aws-credentials-error-redaction-home", "dir");
    fs::create_dir_all(&home_dir).expect("create temp home dir");
    let _guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            Some("http://127.0.0.1:9/credentials?secret=sentinel"),
        ),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", Some(home_dir.to_str().expect("home dir string"))),
    ]);

    let error =
        resolve_default_chain_credentials().expect_err("unreachable metadata endpoint should fail");
    assert!(!error.to_string().contains("secret=sentinel"));
    fs::remove_dir_all(home_dir).expect("remove temp home dir");
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
fn resolve_ecs_task_credentials_uri_rejects_backslash_authority_escape() {
    let _lock = env_lock();
    let _guard = EnvVarGuard::set(&[
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        (
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            Some("\\\\attacker/creds"),
        ),
    ]);

    let error = resolve_ecs_task_credentials_uri()
        .expect_err("backslash authority escape should be rejected");
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
    validate_ecs_full_uri(&Url::parse("http://127.0.0.1/creds").expect("loopback ipv4 url"))
        .expect("loopback IPv4 ecs URI should be accepted");
    validate_ecs_full_uri(&Url::parse("http://[::1]/creds").expect("loopback ipv6 url"))
        .expect("loopback IPv6 ecs URI should be accepted");

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
    let path = temp_path("aws-credentials-empty-token", "txt");
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
        std::env::set_var("AWS_CREDENTIALS_TEST_ENV", &original);
    }

    with_env_lock(|| {
        with_env_var("AWS_CREDENTIALS_TEST_ENV", Some("temporary"), || {
            assert_eq!(
                std::env::var("AWS_CREDENTIALS_TEST_ENV").as_deref(),
                Ok("temporary")
            );
        });
    });

    assert_eq!(std::env::var_os("AWS_CREDENTIALS_TEST_ENV"), Some(original));
    unsafe {
        std::env::remove_var("AWS_CREDENTIALS_TEST_ENV");
    }
}

#[test]
fn given_metadata_expiry_when_refresh_deadline_computed_then_skew_is_subtracted() {
    let now = UNIX_EPOCH + Duration::from_mins(5);
    let expires_after = now + Duration::from_mins(30);

    assert_eq!(
        metadata_refresh_after(now, Some(expires_after)),
        expires_after - Duration::from_mins(5)
    );
}

#[test]
fn given_missing_metadata_expiry_when_refresh_deadline_computed_then_fallback_is_used() {
    let now = UNIX_EPOCH + Duration::from_mins(5);

    assert_eq!(
        metadata_refresh_after(now, None),
        now + Duration::from_mins(10)
    );
}

#[test]
fn given_future_refresh_deadline_when_cache_ttl_computed_then_remaining_duration_is_used() {
    let now = UNIX_EPOCH + Duration::from_mins(5);
    let refresh_after = now + Duration::from_secs(45);

    assert_eq!(
        credential_cache_ttl(Some(refresh_after), now),
        Duration::from_secs(45)
    );
}

#[test]
fn given_elapsed_refresh_deadline_when_cache_ttl_computed_then_zero_is_used() {
    let now = UNIX_EPOCH + Duration::from_mins(5);
    let refresh_after = now - Duration::from_secs(1);

    assert_eq!(
        credential_cache_ttl(Some(refresh_after), now),
        Duration::ZERO
    );
}
