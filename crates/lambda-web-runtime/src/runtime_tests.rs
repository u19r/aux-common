use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    process::Command,
    thread::JoinHandle,
};

use super::{LambdaWebEnvironment, LambdaWebRuntimeError};

const PROXY_CHILD_ENV: &str = "LAMBDA_WEB_RUNTIME_PROXY_CHILD";
const PROXY_TEST_NAME: &str =
    "runtime_tests::given_ambient_proxy_when_notifying_ready_then_runtime_is_reached_directly";

/// Serve one readiness acknowledgement with `status`.
fn spawn_ready_endpoint(status: u16) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut header = vec![];
        let mut byte = [0];
        while !header.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        assert!(header.starts_with(b"POST /2025-09-01/ready HTTP/1.1\r\n"));
        assert!(
            !String::from_utf8(header)
                .unwrap()
                .to_lowercase()
                .contains("authorization:")
        );
        stream.read_exact(&mut [0; 2]).unwrap();
        write!(
            stream,
            "HTTP/1.1 {status} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    });
    (address, server)
}

#[tokio::test]
async fn given_runtime_readiness_responses_when_notified_then_only_success_marks_ready() {
    for status in [204, 503] {
        let (address, server) = spawn_ready_endpoint(status);
        let env = LambdaWebEnvironment::parse(Some("127.0.0.1:9000"), Some(&address.to_string()))
            .unwrap()
            .unwrap();
        let result = env.notify_ready().await;
        if status == 204 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(LambdaWebRuntimeError::ReadyRejected(status)));
        }
        server.join().unwrap();
    }
}

#[tokio::test]
async fn given_ambient_proxy_when_notifying_ready_then_runtime_is_reached_directly() {
    if std::env::var_os(PROXY_CHILD_ENV).is_some() {
        let (address, server) = spawn_ready_endpoint(204);
        let env = LambdaWebEnvironment::parse(Some("127.0.0.1:9000"), Some(&address.to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(env.notify_ready().await, Ok(()));
        server.join().unwrap();
        return;
    }

    // Given proxy variables that name a proxy which accepts but never answers.
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());

    // When readiness is acknowledged in a child process with that environment.
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            PROXY_TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROXY_CHILD_ENV, "1")
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("all_proxy", &proxy_url)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();

    // Then the loopback runtime API is reached directly and acknowledges.
    assert!(
        output.status.success(),
        "proxy child failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    drop(proxy);
}

#[tokio::test]
async fn given_active_requests_when_shutdown_begins_then_drain_is_bounded_and_cancelled() {
    let env = LambdaWebEnvironment::parse(Some("127.0.0.1:9000"), Some("127.0.0.1:9001"))
        .unwrap()
        .unwrap();
    let started = std::time::Instant::now();
    let active_request = std::future::pending::<()>();
    let result = env
        .run_until_shutdown(active_request, std::future::ready(()))
        .await;
    assert!(result.is_none());
    assert!(started.elapsed() >= env.shutdown_grace());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    let result = env
        .run_until_shutdown(std::future::ready(42), std::future::pending())
        .await;
    assert_eq!(result, Some(42));
}
