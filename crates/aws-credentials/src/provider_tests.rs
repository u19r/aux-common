#![expect(
    unsafe_code,
    reason = "Rust 2024 marks process environment mutation unsafe; these tests serialize and \
              restore state"
)]

use std::{
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    sync::{
        Arc, LazyLock, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use url::Url;

use crate::{
    AwsResolvedCredentials, AwsStaticCredentials, CredentialSource,
    DefaultChainCredentialsProvider, ProvideCredentials, half_life_refresh_after,
    provider::{
        credential_cache_ttl, metadata_refresh_after, run_bounded_command,
        validate_aws_cli_output_size,
    },
    resolve_default_chain_credentials, resolve_default_chain_credentials_with_expiry,
    resolve_ecs_authorization_token, resolve_ecs_task_credentials_uri, static_credentials,
    validate_ecs_full_uri,
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
                    let _request = read_http_request(&mut stream);
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

fn spawn_http_response_with_request(
    listener: TcpListener,
    response: String,
    received: std::sync::mpsc::Sender<String>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener
            .set_nonblocking(true)
            .expect("configure request test listener");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_http_request(&mut stream);
                    stream
                        .write_all(response.as_bytes())
                        .expect("write request test response");
                    received.send(request).expect("signal request details");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "accept request test: timed out waiting for ECS request"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept request test: {error}"),
            }
        }
    })
}

fn read_http_request(stream: &mut TcpStream) -> String {
    const MAX_REQUEST_BYTES: usize = 4096;

    stream
        .set_nonblocking(true)
        .expect("configure request test stream");
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut request = [0_u8; MAX_REQUEST_BYTES];
    let mut bytes_read = 0;

    loop {
        assert!(
            bytes_read != request.len(),
            "read test request: HTTP headers exceed 4096-byte limit"
        );

        match stream.read(&mut request[bytes_read..]) {
            Ok(0) => panic!("read test request: EOF before complete HTTP headers"),
            Ok(read) => {
                bytes_read += read;
                if request[..bytes_read]
                    .windows(4)
                    .any(|window| window == b"\r\n\r\n")
                {
                    return String::from_utf8_lossy(&request[..bytes_read]).into_owned();
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                panic!("read test request: timed out waiting for complete HTTP headers");
            }
            Err(error) => panic!("read test request: {error}"),
        }
    }
}

fn set_provider_environment(
    endpoint: Option<&str>,
    authorization_token: Option<&str>,
    home_dir: &Path,
) -> EnvVarGuard {
    EnvVarGuard::set(&[
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", endpoint),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", authorization_token),
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
        ("HOME", home_dir.to_str()),
    ])
}

const METADATA_PROXY_BYPASS_CHILD_ENV: &str = "AWS_CREDENTIALS_METADATA_PROXY_BYPASS_CHILD";
const METADATA_PROXY_BYPASS_ENDPOINT_ENV: &str = "AWS_CREDENTIALS_METADATA_PROXY_BYPASS_ENDPOINT";
const METADATA_PROXY_BYPASS_ASYNC_TEST: &str =
    "provider_tests::given_ambient_proxy_when_async_metadata_resolves_then_proxy_is_bypassed";
const METADATA_PROXY_BYPASS_BLOCKING_TEST: &str =
    "provider_tests::given_ambient_proxy_when_blocking_metadata_resolves_then_proxy_is_bypassed";

fn run_metadata_proxy_bypass_child(resolve: impl FnOnce()) {
    if std::env::var_os(METADATA_PROXY_BYPASS_CHILD_ENV).is_none() {
        return;
    }

    let endpoint =
        std::env::var(METADATA_PROXY_BYPASS_ENDPOINT_ENV).expect("metadata proxy bypass endpoint");
    let home_dir = temp_path("aws-credentials-metadata-proxy-home", "dir");
    fs::create_dir_all(&home_dir).expect("create metadata proxy home");
    let _guard = set_provider_environment(Some(&endpoint), Some("metadata-token"), &home_dir);
    resolve();
    fs::remove_dir_all(home_dir).expect("remove metadata proxy home");
}

fn assert_metadata_proxy_bypass_child_succeeds(test_name: &str) {
    let target_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind metadata target");
    let proxy_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind metadata proxy");
    let target_address = target_listener
        .local_addr()
        .expect("metadata target address");
    let proxy_address = proxy_listener.local_addr().expect("metadata proxy address");
    let endpoint = format!("http://{target_address}/credentials");
    let proxy_endpoint = format!("http://{proxy_address}/");
    let response_body = r#"{"AccessKeyId":"AKIDPROXY","SecretAccessKey":"proxy-secret"}"#;
    let (target_received, target_requests) = std::sync::mpsc::channel();
    let (proxy_received, proxy_requests) = std::sync::mpsc::channel();
    let target = spawn_http_response(
        target_listener,
        json_response("200 OK", response_body),
        Some(target_received),
    );
    let proxy = spawn_http_response(
        proxy_listener,
        json_response("502 Bad Gateway", "proxy used"),
        Some(proxy_received),
    );
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(METADATA_PROXY_BYPASS_CHILD_ENV, "1")
        .env(METADATA_PROXY_BYPASS_ENDPOINT_ENV, endpoint)
        .env("HTTP_PROXY", &proxy_endpoint)
        .env("HTTPS_PROXY", &proxy_endpoint)
        .env("ALL_PROXY", &proxy_endpoint)
        .env("http_proxy", &proxy_endpoint)
        .env("https_proxy", &proxy_endpoint)
        .env("all_proxy", &proxy_endpoint)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("run metadata proxy bypass child");
    let target_received = target_requests.recv_timeout(Duration::from_secs(1)).is_ok();
    let proxy_received = proxy_requests
        .recv_timeout(Duration::from_millis(100))
        .is_ok();
    target.join().expect("join metadata target");
    proxy.join().expect("join metadata proxy");
    assert!(
        output.status.success(),
        "metadata proxy bypass child failed (target_received={target_received}, \
         proxy_received={proxy_received})\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(target_received, "metadata target must receive the request");
    assert!(
        !proxy_received,
        "metadata request was sent through the ambient proxy"
    );
}

fn json_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: \
         close\r\n\r\n{body}",
        body.len()
    )
}

fn chunked_json_response(body: &str) -> String {
    let mut response = String::from(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: \
         chunked\r\nConnection: close\r\n\r\n",
    );
    for chunk in body.as_bytes().chunks(8192) {
        write!(&mut response, "{:X}\r\n", chunk.len()).expect("write chunk header");
        response.push_str(std::str::from_utf8(chunk).expect("credential fixture is UTF-8"));
        response.push_str("\r\n");
    }
    response.push_str("0\r\n\r\n");
    response
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

async fn wait_for_counter(path: &Path, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let observed = fs::read_to_string(path)
            .ok()
            .and_then(|contents| contents.trim().parse::<usize>().ok());
        if observed == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {} to become {expected}, observed {observed:?}",
            path.display()
        );
        tokio::task::yield_now().await;
    }
}

async fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        tokio::task::yield_now().await;
    }
}

#[cfg(unix)]
fn process_is_gone_within(pid: u32) -> bool {
    let pid = pid.to_string();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let alive = Command::new("/bin/kill")
            .args(["-0", pid.as_str()])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !alive {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn write_cancellation_cli(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(
        path,
        r#"#!/bin/sh
set -eu
state="$AWS_CREDENTIALS_TEST_STATE"
lock="$state/lock"
active_file="$state/active"
maximum_file="$state/maximum"
while ! /bin/mkdir "$lock" 2>/dev/null; do /bin/sleep 0.001; done
active=$(/bin/cat "$active_file")
active=$((active + 1))
printf '%s\n' "$active" > "$active_file"
maximum=$(/bin/cat "$maximum_file")
if [ "$active" -gt "$maximum" ]; then
    printf '%s\n' "$active" > "$maximum_file"
fi
: > "$state/started"
/bin/rmdir "$lock"
finish() {
    while ! /bin/mkdir "$lock" 2>/dev/null; do /bin/sleep 0.001; done
    active=$(/bin/cat "$active_file")
    active=$((active - 1))
    printf '%s\n' "$active" > "$active_file"
    /bin/rmdir "$lock"
}
trap finish EXIT
/bin/sleep 0.5
printf '%s\n' '{"AccessKeyId":"AKIDPROFILE","SecretAccessKey":"profile-secret"}'
"#,
    )
    .expect("write cancel CLI");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("make cancel CLI executable");
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
    assert_eq!(message, "authorization token file exceeds configured limit");

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
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("partial environment source");
    assert_eq!(
        source,
        "AWS credential environment variables are partially configured"
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
    let _lock = env_lock();
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
    let (redirect_received, redirect_requests) = std::sync::mpsc::channel();
    let (target_received, target_requests) = std::sync::mpsc::channel();
    let redirect_thread = spawn_http_response(
        redirect_listener,
        redirect_response,
        Some(redirect_received),
    );
    let target_thread =
        spawn_http_response(target_listener, target_response, Some(target_received));

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
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("credential chain failure source");
    assert_eq!(
        source,
        "failed to resolve credentials from default chain: ecs task metadata: provider request \
         failed"
    );
    redirect_requests
        .recv_timeout(Duration::from_secs(1))
        .expect("redirect listener must receive the initial request");
    redirect_thread.join().expect("join redirect server");
    target_thread.join().expect("join target server");
    assert!(
        target_requests.try_recv().is_err(),
        "provider followed redirect to alternate credential endpoint"
    );
    fs::remove_dir_all(home_dir).expect("remove temp home dir");
}

#[test]
fn async_ecs_credentials_reject_redirects_before_accepting_alternate_credentials() {
    let _lock = env_lock();
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
    let (redirect_received, redirect_requests) = std::sync::mpsc::channel();
    let (target_received, target_requests) = std::sync::mpsc::channel();
    let redirect_thread = spawn_http_response(
        redirect_listener,
        redirect_response,
        Some(redirect_received),
    );
    let target_thread =
        spawn_http_response(target_listener, target_response, Some(target_received));

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
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("credential chain failure source");
    assert_eq!(
        source,
        "credential providers failed: ecs task metadata: provider request failed"
    );
    redirect_requests
        .recv_timeout(Duration::from_secs(1))
        .expect("redirect listener must receive the initial request");
    redirect_thread.join().expect("join redirect server");
    target_thread.join().expect("join target server");
    assert!(
        target_requests.try_recv().is_err(),
        "async provider followed redirect to alternate credential endpoint"
    );
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
    assert_eq!(
        error.to_string(),
        "metadata response exceeds configured limit"
    );
    server.join().expect("join metadata server");
}

#[test]
fn aws_cli_output_size_is_bounded_before_json_parsing() {
    let oversized = vec![b'x'; crate::constants::MAX_AWS_CLI_OUTPUT_BYTES + 1];
    let error = validate_aws_cli_output_size(&oversized, &[])
        .expect_err("oversized aws cli output must be rejected");
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("CLI output size failure source");
    assert_eq!(source, "aws cli credential output exceeds configured limit");
}

#[cfg(unix)]
#[test]
fn aws_cli_output_flood_is_terminated_while_pipes_are_capped() {
    let output = run_bounded_command(
        {
            let mut command = Command::new("sh");
            command.args(["-c", "yes x"]);
            command
        },
        crate::constants::AWS_CLI_COMMAND_TIMEOUT,
    )
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
fn aws_cli_timeout_terminates_spawned_descendants() {
    let pid_path = temp_path("aws-credentials-descendant-pid", "txt");
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            "/bin/sleep 30 >/dev/null 2>&1 & child=$!; printf '%s\\n' \"$child\" > \
             \"$AWS_CREDENTIALS_DESCENDANT_PID\"; wait",
        ])
        .env("AWS_CREDENTIALS_DESCENDANT_PID", &pid_path);

    let output = run_bounded_command(command, Duration::from_millis(150))
        .expect("bounded command should return after timeout");
    assert!(output.timed_out);

    let child_pid = fs::read_to_string(&pid_path)
        .expect("descendant PID marker")
        .trim()
        .parse::<u32>()
        .expect("descendant PID");
    let descendant_gone = process_is_gone_within(child_pid);
    if !descendant_gone {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", child_pid.to_string().as_str()])
            .status();
    }
    assert!(descendant_gone, "timed-out command descendant survived");
    let _ = fs::remove_file(pid_path);
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

#[cfg(unix)]
#[test]
fn given_aborted_credential_waiters_when_profile_cli_is_running_then_only_one_cli_refresh_runs() {
    let _lock = env_lock();
    let bin_dir = temp_path("aws-credentials-cancel-cli-bin", "dir");
    let state_dir = temp_path("aws-credentials-cancel-state", "dir");
    let home_dir = temp_path("aws-credentials-cancel-home", "dir");
    fs::create_dir_all(&bin_dir).expect("create cancel CLI directory");
    fs::create_dir_all(&state_dir).expect("create cancel state directory");
    fs::create_dir_all(&home_dir).expect("create cancel home directory");
    let active_path = state_dir.join("active");
    let maximum_path = state_dir.join("maximum");
    let started_path = state_dir.join("started");
    fs::write(&active_path, "0\n").expect("initialize active counter");
    fs::write(&maximum_path, "0\n").expect("initialize maximum counter");
    let aws_path = bin_dir.join("aws");
    write_cancellation_cli(&aws_path);

    let path = bin_dir.to_str().expect("cancel CLI path");
    let home = home_dir.to_str().expect("cancel home path");
    let state = state_dir.to_str().expect("cancel state path");
    let _guard = EnvVarGuard::set(&[
        ("PATH", Some(path)),
        ("HOME", Some(home)),
        ("AWS_CREDENTIALS_TEST_STATE", Some(state)),
        ("AWS_PROFILE", Some("profile")),
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
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");
    runtime.block_on(async {
        let provider_for_first = provider.clone();
        let first = tokio::spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(25),
                provider_for_first.provide_credentials(),
            )
            .await
        });
        wait_for_path(&started_path).await;
        first
            .await
            .expect("first waiter task")
            .expect_err("first waiter must time out");

        let mut waiters = Vec::new();
        for _ in 0..8 {
            let provider_for_waiter = provider.clone();
            waiters.push(tokio::spawn(async move {
                provider_for_waiter.provide_credentials().await
            }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        for waiter in waiters {
            waiter.abort();
            waiter.await.expect_err("refresh waiter must be aborted");
        }

        wait_for_counter(&active_path, 0).await;
    });

    let maximum = fs::read_to_string(&maximum_path).expect("read maximum counter");
    assert_eq!(maximum.trim(), "1", "profile CLI refreshes overlapped");
    fs::remove_dir_all(bin_dir).expect("remove cancel CLI directory");
    fs::remove_dir_all(state_dir).expect("remove cancel state directory");
    fs::remove_dir_all(home_dir).expect("remove cancel home directory");
}

#[test]
fn concurrent_provider_misses_share_one_metadata_resolution() {
    let _lock = env_lock();
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
fn validate_ecs_full_uri_pins_metadata_host_and_url_shape_edges() {
    // Given the ECS metadata address and shape variations around the
    // transport policy.
    validate_ecs_full_uri(&Url::parse("http://169.254.170.2/v2/credentials/abc").expect("url"))
        .expect("ECS metadata host must stay reachable over HTTP");
    for url in [
        "http://169.254.170.2:80/creds",
        "HTTP://169.254.170.2/creds",
        "http://LOCALHOST/creds",
        "https://169.254.170.2/creds",
    ] {
        validate_ecs_full_uri(&Url::parse(url).expect("url"))
            .expect("equivalent edge shape must stay accepted: {url}");
    }

    // When attacker-shaped neighbors arrive over plain HTTP.
    for url in [
        "http://169.254.170.3/creds",
        "http://169.254.169.254/creds",
        "http://user:pass@169.254.170.2/creds",
        "http://169.254.170.2.evil.example.test/creds",
        "http://evil169.254.170.2/creds",
        "http:///creds",
    ] {
        assert!(
            validate_ecs_full_uri(
                &Url::parse(url)
                    .unwrap_or_else(|_| Url::parse("http://invalid.invalid/").expect("fallback"))
            )
            .is_err(),
            "neighbor shape must fail: {url}"
        );
    }
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
    assert_eq!(message, "authorization token file was empty");

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

#[test]
fn given_refresh_deadline_when_credentials_are_checked_then_refresh_state_is_explicit() {
    // Given credentials with a refresh deadline.
    let refresh_after = UNIX_EPOCH + Duration::from_secs(10);
    let credentials = AwsResolvedCredentials {
        credentials: AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "secret-access-key".to_string(),
            session_token: None,
        },
        expires_after: None,
        refresh_after: Some(refresh_after),
    };

    // When the clock is before and at that deadline.
    let before_deadline = credentials.needs_refresh_at(refresh_after - Duration::from_secs(1));
    let at_deadline = credentials.needs_refresh_at(refresh_after);

    // Then refresh begins exactly at the configured boundary.
    assert!(!before_deadline);
    assert!(at_deadline);
    assert!(credentials.needs_refresh());
}

#[test]
fn given_credential_views_when_debugged_or_converted_then_provider_metadata_is_safe() {
    // Given static credentials and a default-chain source marker.
    let credentials = AwsStaticCredentials {
        access_key_id: "AKIDEXAMPLE".to_string(),
        secret_access_key: "sentinel-secret".to_string(),
        session_token: Some("sentinel-token".to_string()),
    };
    let static_view = static_credentials(&credentials);

    // When the public views are converted and formatted.
    let source_debug = format!("{:?}", CredentialSource::DefaultChain);
    let provider_debug = format!(
        "{:?}",
        DefaultChainCredentialsProvider::new().expect("create credential provider")
    );

    // Then conversion preserves values while diagnostics disclose no secrets.
    assert_eq!(static_view.access_key_id(), "AKIDEXAMPLE");
    assert_eq!(static_view.secret_access_key(), "sentinel-secret");
    assert_eq!(static_view.session_token(), Some("sentinel-token"));
    assert_eq!(source_debug, "DefaultChain");
    assert!(
        provider_debug.contains("[SINGLEFLIGHT]"),
        "{provider_debug}"
    );
    assert!(!provider_debug.contains("sentinel-secret"));
}

#[test]
fn given_cached_environment_credentials_when_provided_twice_then_second_call_avoids_resolution() {
    // Given a provider that first resolves environment credentials.
    let _lock = env_lock();
    let home_dir = temp_path("aws-credentials-cache-home", "dir");
    fs::create_dir_all(&home_dir).expect("create cache home");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    let (provider, first) = {
        let _guard = EnvVarGuard::set(&[
            ("AWS_ACCESS_KEY_ID", Some("AKIDCACHED")),
            ("AWS_SECRET_ACCESS_KEY", Some("cached-secret")),
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
            ("HOME", home_dir.to_str()),
        ]);
        let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
        let first = runtime
            .block_on(provider.provide_credentials())
            .expect("first credentials");
        (provider, first)
    };

    // When the environment is changed before the same provider is asked again.
    let _guard = EnvVarGuard::set(&[
        ("AWS_ACCESS_KEY_ID", Some("AKIDCHANGED")),
        ("AWS_SECRET_ACCESS_KEY", Some("changed-secret")),
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
        ("HOME", home_dir.to_str()),
    ]);
    let second = runtime
        .block_on(provider.provide_credentials())
        .expect("cached credentials");

    // Then the cache returns the first credential material instead of resolving
    // the mutation.
    assert_eq!(first.access_key_id(), "AKIDCACHED");
    assert_eq!(second.access_key_id(), "AKIDCACHED");
    assert_eq!(second.secret_access_key(), "cached-secret");
    fs::remove_dir_all(home_dir).expect("remove cache home");
}

#[test]
fn given_ambient_proxy_when_async_metadata_resolves_then_proxy_is_bypassed() {
    if std::env::var_os(METADATA_PROXY_BYPASS_CHILD_ENV).is_some() {
        run_metadata_proxy_bypass_child(|| {
            let provider = DefaultChainCredentialsProvider::new()
                .expect("create metadata credential provider");
            let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");
            let credentials = runtime
                .block_on(provider.provide_credentials())
                .expect("async metadata credentials");
            assert_eq!(credentials.access_key_id(), "AKIDPROXY");
        });
        return;
    }

    assert_metadata_proxy_bypass_child_succeeds(METADATA_PROXY_BYPASS_ASYNC_TEST);
}

#[test]
fn given_ambient_proxy_when_blocking_metadata_resolves_then_proxy_is_bypassed() {
    if std::env::var_os(METADATA_PROXY_BYPASS_CHILD_ENV).is_some() {
        run_metadata_proxy_bypass_child(|| {
            let credentials = resolve_default_chain_credentials_with_expiry()
                .expect("blocking metadata credentials");
            assert_eq!(credentials.credentials.access_key_id, "AKIDPROXY");
        });
        return;
    }

    assert_metadata_proxy_bypass_child_succeeds(METADATA_PROXY_BYPASS_BLOCKING_TEST);
}

#[test]
fn given_local_ecs_endpoint_when_async_provider_resolves_then_credentials_and_token_are_forwarded()
{
    // Given a local ECS endpoint and an authorization token.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let response_body =
        r#"{"AccessKeyId":"AKIDASYNC","SecretAccessKey":"async-secret","Token":"async-session"}"#;
    let (request_received, requests) = std::sync::mpsc::channel();
    let server = spawn_http_response_with_request(
        listener,
        json_response("200 OK", response_body),
        request_received,
    );
    let home_dir = temp_path("aws-credentials-async-ecs-home", "dir");
    fs::create_dir_all(&home_dir).expect("create async ECS home");
    let endpoint = format!("http://{address}/credentials");
    let _guard = set_provider_environment(Some(&endpoint), Some("ecs-token"), &home_dir);
    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    // When the asynchronous provider resolves the default chain.
    let credentials = runtime
        .block_on(provider.provide_credentials())
        .expect("async ECS credentials");

    // Then it accepts only the local response and forwards the configured
    // token.
    assert_eq!(credentials.access_key_id(), "AKIDASYNC");
    assert_eq!(credentials.secret_access_key(), "async-secret");
    assert_eq!(credentials.session_token(), Some("async-session"));
    let request = requests
        .recv_timeout(Duration::from_secs(1))
        .expect("ECS request");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: ecs-token")
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove async ECS home");
}

#[test]
fn given_local_ecs_endpoint_when_async_response_is_forbidden_then_chain_fails_closed() {
    // Given a local ECS endpoint that rejects an otherwise valid credential
    // response.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let response_body = r#"{"AccessKeyId":"AKIDSTATUS","SecretAccessKey":"status-secret"}"#;
    let server = spawn_http_response(
        listener,
        json_response("403 Forbidden", response_body),
        None,
    );
    let home_dir = temp_path("aws-credentials-async-status-home", "dir");
    fs::create_dir_all(&home_dir).expect("create async status home");
    let endpoint = format!("http://{address}/credentials");
    let _guard = set_provider_environment(Some(&endpoint), None, &home_dir);
    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    // When the asynchronous provider receives the rejected response.
    let error = runtime
        .block_on(provider.provide_credentials())
        .expect_err("forbidden ECS response must fail");

    // Then the ECS failure is reported and alternate providers are not used.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("credential chain failure source");
    assert_eq!(
        source,
        "credential providers failed: ecs task metadata: provider request failed"
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove async status home");
}

#[test]
fn given_chunked_valid_oversized_metadata_when_async_body_is_bounded_then_limit_error_is_specific()
{
    // Given a valid credential response whose chunked body exceeds the metadata
    // limit.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let response_body = format!(
        r#"{{"AccessKeyId":"AKIDCHUNKED","SecretAccessKey":"chunked-secret","Token":"chunked-session","Padding":"{}"}}"#,
        "x".repeat(crate::constants::MAX_METADATA_RESPONSE_BYTES)
    );
    let server = spawn_http_response(listener, chunked_json_response(&response_body), None);
    let endpoint = format!("http://{address}/credentials");
    let home_dir = temp_path("aws-credentials-async-size-home", "dir");
    fs::create_dir_all(&home_dir).expect("create async size home");
    let _guard = set_provider_environment(Some(&endpoint), None, &home_dir);
    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    // When the asynchronous provider consumes the response stream.
    let error = runtime
        .block_on(provider.provide_credentials())
        .expect_err("oversized ECS response must fail");

    // Then the ECS provider reports the bounded-response failure.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("credential chain failure source");
    assert_eq!(
        source,
        "credential providers failed: ecs task metadata: provider request failed"
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove async size home");
}

#[test]
fn given_local_ecs_endpoint_when_async_json_is_invalid_then_chain_fails_closed() {
    // Given a local ECS endpoint with a non-JSON successful response.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let server = spawn_http_response(listener, json_response("200 OK", "not-json"), None);
    let home_dir = temp_path("aws-credentials-async-json-home", "dir");
    fs::create_dir_all(&home_dir).expect("create async JSON home");
    let endpoint = format!("http://{address}/credentials");
    let _guard = set_provider_environment(Some(&endpoint), None, &home_dir);
    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    // When the asynchronous provider parses the response.
    let error = runtime
        .block_on(provider.provide_credentials())
        .expect_err("invalid ECS JSON must fail");

    // Then malformed response data is reported by the ECS provider boundary.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("credential chain failure source");
    assert_eq!(
        source,
        "credential providers failed: ecs task metadata: provider request failed"
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove async JSON home");
}

#[test]
fn given_local_ecs_endpoint_when_credentials_are_incomplete_then_chain_fails_closed() {
    // Given a syntactically valid response missing the required secret
    // material.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let response_body = r#"{"AccessKeyId":"","SecretAccessKey":"secret"}"#;
    let server = spawn_http_response(listener, json_response("200 OK", response_body), None);
    let home_dir = temp_path("aws-credentials-incomplete-home", "dir");
    fs::create_dir_all(&home_dir).expect("create incomplete home");
    let endpoint = format!("http://{address}/credentials");
    let _guard = set_provider_environment(Some(&endpoint), None, &home_dir);
    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    // When the asynchronous provider validates the decoded credentials.
    let error = runtime
        .block_on(provider.provide_credentials())
        .expect_err("incomplete ECS credentials must fail");

    // Then an incomplete response is rejected rather than cached.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("credential chain failure source");
    assert_eq!(
        source,
        "credential providers failed: ecs task metadata: provider request failed"
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove incomplete home");
}

#[test]
fn given_local_ecs_endpoint_when_blocking_provider_resolves_then_credentials_and_token_are_forwarded()
 {
    // Given a local ECS endpoint and an authorization token.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let response_body = r#"{"AccessKeyId":"AKIDBLOCKING","SecretAccessKey":"blocking-secret","Token":"blocking-session"}"#;
    let (request_received, requests) = std::sync::mpsc::channel();
    let server = spawn_http_response_with_request(
        listener,
        json_response("200 OK", response_body),
        request_received,
    );
    let home_dir = temp_path("aws-credentials-blocking-ecs-home", "dir");
    fs::create_dir_all(&home_dir).expect("create blocking ECS home");
    let endpoint = format!("http://{address}/credentials");
    let _guard = set_provider_environment(Some(&endpoint), Some("blocking-token"), &home_dir);

    // When the blocking default chain resolves credentials.
    let resolved =
        resolve_default_chain_credentials_with_expiry().expect("blocking ECS credentials");

    // Then it accepts the local response and forwards the configured token.
    assert_eq!(resolved.credentials.access_key_id, "AKIDBLOCKING");
    assert_eq!(resolved.credentials.secret_access_key, "blocking-secret");
    assert_eq!(
        resolved.credentials.session_token.as_deref(),
        Some("blocking-session")
    );
    assert!(resolved.refresh_after.is_some());
    let request = requests
        .recv_timeout(Duration::from_secs(1))
        .expect("ECS request");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: blocking-token")
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove blocking ECS home");
}

#[cfg(unix)]
#[test]
fn given_profile_export_json_when_blocking_chain_resolves_then_expiry_is_preserved() {
    use std::os::unix::fs::PermissionsExt;

    // Given a local aws CLI shim returning process-format credentials.
    let _lock = env_lock();
    let bin_dir = temp_path("aws-credentials-profile-bin", "dir");
    let home_dir = temp_path("aws-credentials-profile-home", "dir");
    fs::create_dir_all(&bin_dir).expect("create profile bin");
    fs::create_dir_all(&home_dir).expect("create profile home");
    let aws_path = bin_dir.join("aws");
    fs::write(
        &aws_path,
        r#"#!/bin/sh
printf '%s\n' '{"AccessKeyId":"AKIDPROFILE","SecretAccessKey":"profile-secret","SessionToken":"profile-session","Expiration":"2035-01-01T00:00:00Z"}'
"#,
    )
    .expect("write profile CLI");
    fs::set_permissions(&aws_path, fs::Permissions::from_mode(0o755))
        .expect("make profile CLI executable");
    let path = bin_dir.to_str().expect("profile bin path");
    let _guard = EnvVarGuard::set(&[
        ("PATH", Some(path)),
        ("AWS_PROFILE", Some("profile")),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", home_dir.to_str()),
    ]);

    // When the blocking chain invokes the profile provider.
    let resolved = resolve_default_chain_credentials_with_expiry()
        .expect("profile credentials should resolve");

    // Then profile values and the parsed expiration reach the public result.
    assert_eq!(resolved.credentials.access_key_id, "AKIDPROFILE");
    assert_eq!(resolved.credentials.secret_access_key, "profile-secret");
    assert_eq!(
        resolved.credentials.session_token.as_deref(),
        Some("profile-session")
    );
    assert_eq!(
        resolved.expires_after,
        Some(UNIX_EPOCH + Duration::from_hours(569_784))
    );
    assert!(resolved.refresh_after.is_some());
    fs::remove_dir_all(bin_dir).expect("remove profile bin");
    fs::remove_dir_all(home_dir).expect("remove profile home");
}

#[test]
fn given_token_file_failures_when_authorization_is_resolved_then_each_failure_is_reported() {
    // Given a missing token file that must not fall back to the environment
    // token.
    let _lock = env_lock();
    let missing_path = temp_path("aws-credentials-missing-token", "txt");
    let missing_guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            missing_path.to_str(),
        ),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", Some("fallback-token")),
    ]);
    let missing_error = resolve_ecs_authorization_token()
        .expect_err("missing token file must fail closed before fallback");
    let missing_message = std::error::Error::source(&missing_error).map_or_else(
        || missing_error.to_string(),
        std::string::ToString::to_string,
    );
    assert!(
        missing_message.contains("could not be read"),
        "unexpected error: {missing_message}"
    );
    drop(missing_guard);

    // When the token file contains bytes that are not valid UTF-8.
    let invalid_path = temp_path("aws-credentials-invalid-token", "txt");
    fs::write(&invalid_path, [0xff, 0xfe]).expect("write invalid token file");
    let _invalid_guard = EnvVarGuard::set(&[
        (
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            invalid_path.to_str(),
        ),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", Some("fallback-token")),
    ]);
    let invalid_error = resolve_ecs_authorization_token()
        .expect_err("invalid token file must fail closed before fallback");

    // Then invalid file data is rejected without accepting fallback
    // credentials.
    let invalid_message = std::error::Error::source(&invalid_error).map_or_else(
        || invalid_error.to_string(),
        std::string::ToString::to_string,
    );
    assert!(
        invalid_message.contains("not valid UTF-8"),
        "unexpected error: {invalid_message}"
    );
    fs::remove_file(invalid_path).expect("remove invalid token file");
}

#[test]
fn given_whitespace_token_environment_when_authorization_is_resolved_then_no_token_is_returned() {
    // Given whitespace-only environment configuration and no token file.
    let _lock = env_lock();
    let _guard = EnvVarGuard::set(&[
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", Some("   ")),
    ]);

    // When the authorization token is resolved.
    let token = resolve_ecs_authorization_token().expect("token resolution");

    // Then whitespace is treated as absent rather than as a credential header.
    assert_eq!(token, None);
}

#[test]
fn given_invalid_ecs_full_uri_when_uri_is_resolved_then_configuration_is_rejected() {
    // Given a malformed full URI instead of a trusted ECS endpoint.
    let _lock = env_lock();
    let _guard = EnvVarGuard::set(&[
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", Some("not a uri")),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
    ]);

    // When the ECS endpoint is parsed.
    let error = resolve_ecs_task_credentials_uri().expect_err("malformed URI must fail");

    // Then parsing failure is reported as invalid configuration.
    let message = std::error::Error::source(&error)
        .map_or_else(|| error.to_string(), std::string::ToString::to_string);
    assert!(
        message.contains("ECS credentials URI was invalid"),
        "{message}"
    );
}

#[test]
fn given_leading_slash_ecs_relative_uri_when_uri_is_resolved_then_trusted_base_is_preserved() {
    // Given a relative URI already beginning with a slash.
    let _lock = env_lock();
    let _guard = EnvVarGuard::set(&[
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        (
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            Some("/v2/credentials"),
        ),
    ]);

    // When the relative endpoint is normalized.
    let uri = resolve_ecs_task_credentials_uri()
        .expect("URI resolution")
        .expect("relative ECS URI");

    // Then it remains on the fixed ECS metadata host.
    assert_eq!(uri.as_str(), "http://169.254.170.2/v2/credentials");
}

#[test]
fn given_expired_metadata_when_refresh_deadline_is_computed_then_skew_is_subtracted() {
    // Given an expiration before the current time.
    let now = UNIX_EPOCH + Duration::from_mins(5);
    let expires_after = UNIX_EPOCH + Duration::from_mins(1);

    // When the metadata refresh deadline is computed.
    let refresh_after = metadata_refresh_after(now, Some(expires_after));

    // Then subtraction remains deterministic even for expired metadata.
    assert_eq!(refresh_after, expires_after - Duration::from_mins(5));
}

#[test]
fn given_no_refresh_deadline_when_cache_ttl_is_computed_then_static_ttl_is_used() {
    // Given credentials without an expiry-derived refresh deadline.
    let now = UNIX_EPOCH + Duration::from_mins(5);

    // When the cache lifetime is selected.
    let ttl = credential_cache_ttl(None, now);

    // Then the bounded static cache lifetime is used.
    assert_eq!(ttl, crate::constants::CREDENTIAL_CACHE_STATIC_TTL);
}

#[cfg(unix)]
#[test]
fn given_profile_command_failure_when_blocking_chain_resolves_then_error_is_recoverable() {
    use std::os::unix::fs::PermissionsExt;

    // Given a profile CLI that rejects the requested export.
    let _lock = env_lock();
    let bin_dir = temp_path("aws-credentials-profile-failure-bin", "dir");
    let home_dir = temp_path("aws-credentials-profile-failure-home", "dir");
    fs::create_dir_all(&bin_dir).expect("create profile failure bin");
    fs::create_dir_all(&home_dir).expect("create profile failure home");
    let aws_path = bin_dir.join("aws");
    fs::write(
        &aws_path,
        r#"#!/bin/sh
printf '%s\n' '{"AccessKeyId":"AKIDPROFILEFAIL","SecretAccessKey":"profile-failure-secret"}'
exit 7
"#,
    )
    .expect("write failing profile CLI");
    fs::set_permissions(&aws_path, fs::Permissions::from_mode(0o755))
        .expect("make failing profile CLI executable");
    let path = bin_dir.to_str().expect("profile failure bin path");
    let _guard = EnvVarGuard::set(&[
        ("PATH", Some(path)),
        ("AWS_PROFILE", Some("profile")),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", home_dir.to_str()),
    ]);

    // When the blocking chain invokes the rejected profile provider.
    let error = resolve_default_chain_credentials_with_expiry()
        .expect_err("rejected profile export must fail");

    // Then the chain returns the profile-provider failure without contacting
    // metadata endpoints.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("credential chain failure source");
    assert_eq!(
        source,
        "failed to resolve credentials from default chain: aws cli profile: provider request \
         failed"
    );
    fs::remove_dir_all(bin_dir).expect("remove profile failure bin");
    fs::remove_dir_all(home_dir).expect("remove profile failure home");
}

#[cfg(unix)]
#[test]
fn given_invalid_profile_export_json_when_blocking_chain_resolves_then_credentials_are_not_created()
{
    use std::os::unix::fs::PermissionsExt;

    // Given a profile CLI that returns successful but malformed output.
    let _lock = env_lock();
    let bin_dir = temp_path("aws-credentials-profile-json-bin", "dir");
    let home_dir = temp_path("aws-credentials-profile-json-home", "dir");
    fs::create_dir_all(&bin_dir).expect("create profile JSON bin");
    fs::create_dir_all(&home_dir).expect("create profile JSON home");
    let aws_path = bin_dir.join("aws");
    fs::write(&aws_path, "#!/bin/sh\nprintf '%s\\n' not-json\n")
        .expect("write malformed profile CLI");
    fs::set_permissions(&aws_path, fs::Permissions::from_mode(0o755))
        .expect("make malformed profile CLI executable");
    let path = bin_dir.to_str().expect("profile JSON bin path");
    let _guard = EnvVarGuard::set(&[
        ("PATH", Some(path)),
        ("AWS_PROFILE", Some("profile")),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_CONTAINER_CREDENTIALS_FULL_URI", None),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
        ("HOME", home_dir.to_str()),
    ]);

    // When the blocking chain parses the malformed profile output.
    let error = resolve_default_chain_credentials_with_expiry()
        .expect_err("malformed profile output must fail");

    // Then malformed output remains an error instead of partial credentials.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("credential chain failure source");
    assert_eq!(
        source,
        "failed to resolve credentials from default chain: aws cli profile: provider request \
         failed"
    );
    fs::remove_dir_all(bin_dir).expect("remove profile JSON bin");
    fs::remove_dir_all(home_dir).expect("remove profile JSON home");
}

#[test]
fn given_no_provider_configuration_and_no_home_when_blocking_chain_resolves_then_source_is_explicit()
 {
    // Given no environment, profile files, ECS endpoint, or enabled IMDS
    // provider.
    let _lock = env_lock();
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
        ("HOME", None),
    ]);

    // When the blocking default chain is resolved.
    let error = resolve_default_chain_credentials_with_expiry()
        .expect_err("an empty default chain should not resolve credentials");

    // Then callers receive a stable, source-level explanation of the absence.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("no-provider source");
    assert_eq!(
        source,
        "no credentials found in environment variables, ECS task metadata, or IMDS"
    );
}

#[test]
fn given_no_provider_configuration_when_async_chain_resolves_then_source_is_explicit() {
    // Given no environment, profile files, ECS endpoint, or enabled IMDS
    // provider.
    let _lock = env_lock();
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
        ("HOME", None),
    ]);
    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    // When the asynchronous default chain is resolved.
    let error = runtime
        .block_on(provider.provide_credentials())
        .expect_err("an empty async chain should not resolve credentials");

    // Then the async provider reports the same absence as the blocking API.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("no-provider source");
    assert_eq!(
        source,
        "no credentials found in environment variables, ECS task metadata, or IMDS"
    );
}

#[test]
fn given_profile_file_and_ecs_failure_when_blocking_chain_resolves_then_all_provider_failures_are_reported()
 {
    // Given an AWS credentials file that enables profile lookup and an ECS
    // endpoint that rejects the request.
    let _lock = env_lock();
    let home_dir = temp_path("aws-credentials-profile-file-home", "dir");
    let bin_dir = temp_path("aws-credentials-profile-file-bin", "dir");
    fs::create_dir_all(home_dir.join(".aws")).expect("create profile directory");
    fs::create_dir_all(&bin_dir).expect("create empty PATH directory");
    fs::write(home_dir.join(".aws/credentials"), "[default]\n").expect("write profile marker");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let server = spawn_http_response(
        listener,
        json_response("503 Service Unavailable", "{}"),
        None,
    );
    let endpoint = format!("http://{address}/credentials");
    let _guard = EnvVarGuard::set(&[
        ("PATH", bin_dir.to_str()),
        ("HOME", home_dir.to_str()),
        ("AWS_ACCESS_KEY_ID", None),
        ("AWS_SECRET_ACCESS_KEY", None),
        ("AWS_ACCESS_KEY", None),
        ("AWS_SECRET_KEY", None),
        ("AWS_SESSION_TOKEN", None),
        ("AWS_PROFILE", None),
        ("AWS_DEFAULT_PROFILE", None),
        ("AWS_CONFIG_FILE", None),
        ("AWS_SHARED_CREDENTIALS_FILE", None),
        (
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            Some(endpoint.as_str()),
        ),
        ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN", None),
        ("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", None),
        ("AWS_EC2_METADATA_DISABLED", Some("true")),
    ]);

    // When the chain tries each configured source.
    let error = resolve_default_chain_credentials_with_expiry()
        .expect_err("profile and ECS failures must not resolve credentials");

    // Then each failure is named without leaking endpoint or command details.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("chain failure source");
    assert_eq!(
        source,
        "failed to resolve credentials from default chain: aws cli profile: provider request \
         failed; ecs task metadata: provider request failed"
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(bin_dir).expect("remove empty PATH directory");
    fs::remove_dir_all(home_dir).expect("remove profile home");
}

#[test]
fn given_local_ecs_endpoint_when_blocking_json_is_invalid_then_chain_fails_closed() {
    // Given a local ECS endpoint that returns a successful but malformed body.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let server = spawn_http_response(listener, json_response("200 OK", "not-json"), None);
    let home_dir = temp_path("aws-credentials-blocking-json-home", "dir");
    fs::create_dir_all(&home_dir).expect("create blocking JSON home");
    let endpoint = format!("http://{address}/credentials");
    let _guard = set_provider_environment(Some(&endpoint), None, &home_dir);

    // When the blocking provider parses the response.
    let error = resolve_default_chain_credentials_with_expiry()
        .expect_err("malformed blocking ECS JSON must fail");

    // Then malformed response data is not converted into credentials.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("blocking chain failure source");
    assert_eq!(
        source,
        "failed to resolve credentials from default chain: ecs task metadata: provider request \
         failed"
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove blocking JSON home");
}

#[test]
fn given_declared_oversized_ecs_body_when_blocking_provider_resolves_then_body_is_rejected() {
    // Given a local ECS response whose declared body exceeds the hard limit.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        crate::constants::MAX_METADATA_RESPONSE_BYTES + 1
    );
    let server = spawn_http_response(listener, response, None);
    let home_dir = temp_path("aws-credentials-blocking-size-home", "dir");
    fs::create_dir_all(&home_dir).expect("create blocking size home");
    let endpoint = format!("http://{address}/credentials");
    let _guard = set_provider_environment(Some(&endpoint), None, &home_dir);

    // When the blocking provider receives the response.
    let error = resolve_default_chain_credentials_with_expiry()
        .expect_err("oversized blocking ECS body must fail");

    // Then the bounded-body guard prevents parsing or caching the response.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("blocking size failure source");
    assert_eq!(
        source,
        "failed to resolve credentials from default chain: ecs task metadata: provider request \
         failed"
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove blocking size home");
}

#[test]
fn given_declared_oversized_ecs_body_when_async_provider_resolves_then_body_is_rejected() {
    // Given a local ECS response whose declared body exceeds the hard limit.
    let _lock = env_lock();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ECS listener");
    let address = listener.local_addr().expect("ECS address");
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        crate::constants::MAX_METADATA_RESPONSE_BYTES + 1
    );
    let server = spawn_http_response(listener, response, None);
    let home_dir = temp_path("aws-credentials-async-size-home", "dir");
    fs::create_dir_all(&home_dir).expect("create async size home");
    let endpoint = format!("http://{address}/credentials");
    let _guard = set_provider_environment(Some(&endpoint), None, &home_dir);
    let provider = DefaultChainCredentialsProvider::new().expect("create credential provider");
    let runtime = tokio::runtime::Runtime::new().expect("create tokio runtime");

    // When the asynchronous provider consumes the response metadata.
    let error = runtime
        .block_on(provider.provide_credentials())
        .expect_err("oversized async ECS body must fail");

    // Then the bounded-body guard prevents parsing or caching the response.
    let source = std::error::Error::source(&error)
        .map(std::string::ToString::to_string)
        .expect("async size failure source");
    assert_eq!(
        source,
        "credential providers failed: ecs task metadata: provider request failed"
    );
    server.join().expect("join ECS server");
    fs::remove_dir_all(home_dir).expect("remove async size home");
}

#[test]
fn given_chunked_oversized_metadata_when_blocking_body_is_bounded_then_limit_error_is_specific() {
    // Given a chunked blocking response that exceeds the metadata limit.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind metadata listener");
    let address = listener.local_addr().expect("metadata address");
    let body = "x".repeat(crate::constants::MAX_METADATA_RESPONSE_BYTES + 1);
    let server = spawn_http_response(listener, chunked_json_response(&body), None);
    let client = reqwest::blocking::Client::new();
    let response = client
        .get(format!("http://{address}/credentials"))
        .send()
        .expect("metadata response");

    // When the bounded blocking reader consumes the chunks.
    let error = crate::provider::bounded_blocking_response_body(response)
        .expect_err("chunked oversized response must fail");

    // Then the overflow remains a deterministic size error.
    assert_eq!(
        error.to_string(),
        "metadata response exceeds configured limit"
    );
    server.join().expect("join metadata server");
}
