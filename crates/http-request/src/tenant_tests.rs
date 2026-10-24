use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use bytes::Bytes;
use futures_util::stream;
use reqwest::{
    Client, Method, Url,
    dns::{Addrs, Name, Resolve, Resolving},
    header::HeaderValue,
};

use crate::{
    HttpRequestDispatchStatus, HttpRequestError, HttpRequestErrorKind, RetryConfig,
    constants::{
        REDIRECT_BLOCKED_HOST_MISMATCH, REDIRECT_BLOCKED_METHOD_CHANGE,
        REDIRECT_BLOCKED_SCHEME_CHANGE, REDIRECT_BLOCKED_TOO_MANY, SSRF_BLOCKED_DNS_EMPTY,
        SSRF_BLOCKED_DNS_FAILURE, SSRF_BLOCKED_DNS_TIMEOUT, SSRF_BLOCKED_DOMAIN_NOT_ALLOWLISTED,
        SSRF_BLOCKED_FRAGMENT, SSRF_BLOCKED_HOST_HEADER, SSRF_BLOCKED_IP_LITERAL,
        SSRF_BLOCKED_MISSING_HOST, SSRF_BLOCKED_PORT, SSRF_BLOCKED_RESERVED_IP,
        SSRF_BLOCKED_SCHEME, SSRF_BLOCKED_USERINFO,
    },
    tenant::{
        AllowedDomain, SsrfProtectionConfig, SsrfProtector, TenantHttpClient, is_blocked_ip,
        match_allowlisted_domain, request_body_len, same_origin,
    },
};

struct SequenceDnsResolver {
    responses: Mutex<VecDeque<Vec<SocketAddr>>>,
}

impl Resolve for SequenceDnsResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let addrs = self
            .responses
            .lock()
            .expect("DNS response lock")
            .pop_front()
            .expect("DNS response");
        Box::pin(async move { Ok(Box::new(addrs.into_iter()) as Addrs) })
    }
}

struct CountingDnsResolver {
    yielded: Arc<AtomicUsize>,
}

impl Resolve for CountingDnsResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let yielded = Arc::clone(&self.yielded);
        Box::pin(async move {
            let addrs = std::iter::from_fn(move || {
                let index = yielded.fetch_add(1, Ordering::Relaxed);
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, (index + 1) as u8)),
                    443,
                ))
            });
            Ok(Box::new(addrs) as Addrs)
        })
    }
}

#[tokio::test]
async fn ssrf_owner_validates_every_connector_resolution() {
    let resolver = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 8,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([
                vec!["93.184.216.34:443".parse().expect("public address")],
                vec!["10.0.0.7:443".parse().expect("private address")],
            ])),
        }),
    );
    let name: Name = "example.com".parse().expect("DNS name");

    let first = resolver
        .resolve(name)
        .await
        .expect("public connector resolution");
    assert_eq!(first.collect::<Vec<_>>().len(), 1);

    let name: Name = "example.com".parse().expect("DNS name");
    let error = match resolver.resolve(name).await {
        Ok(_) => panic!("rebound private address must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("reserved_ip"), "{error}");
}

#[tokio::test]
async fn ssrf_preflight_dns_resolution_honors_configured_timeout() {
    let protector = SsrfProtector::new(SsrfProtectionConfig {
        allowed_schemes: vec!["https".to_string()],
        allowed_ports: vec![443],
        max_dns_addresses: 8,
        allow_loopback_ips: true,
        dns_timeout: Duration::ZERO,
    });
    let url = Url::parse("https://localhost/credentials").expect("URL");

    let error = protector
        .resolve_and_validate(&url)
        .await
        .expect_err("zero DNS budget must fail closed");
    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_DNS_TIMEOUT
        }
    ));
}

#[tokio::test]
async fn given_shared_ssrf_owner_when_preflight_and_connector_resolve_then_policy_stays_in_sync() {
    let owner = Arc::new(SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 8,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([
                vec!["93.184.216.34:443".parse().expect("public address")],
                vec!["10.0.0.7:443".parse().expect("private address")],
            ])),
        }),
    ));
    let url = Url::parse("https://approved.example.com/credentials").expect("approved URL");

    owner
        .resolve_and_validate(&url)
        .await
        .expect("preflight should accept the public first answer");

    let name: Name = "approved.example.com".parse().expect("DNS name");
    let error = match owner.resolve(name).await {
        Ok(_) => panic!("connector must independently reject the rebound private answer"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("reserved_ip"), "{error}");
}

#[tokio::test]
async fn given_site_local_ipv6_destination_when_preflighting_then_blocks_reserved_ip() {
    // Given an approved hostname whose DNS lookup yields the deprecated
    // site-local IPv6 range.
    let protector = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 8,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([vec![SocketAddr::new(
                "fec0::1".parse().expect("site-local IPv6 address"),
                443,
            )]])),
        }),
    );
    let url = Url::parse("https://approved.example.com/credentials").expect("approved URL");

    // When the SSRF preflight validates its DNS answer.
    let error = protector
        .resolve_and_validate(&url)
        .await
        .expect_err("site-local IPv6 DNS answer must be rejected");

    // Then the preflight fails closed at the shared reserved-IP boundary.
    assert!(
        matches!(
            error,
            HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_RESERVED_IP
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn given_local_use_nat64_destination_when_preflighting_then_blocks_reserved_ip() {
    // Given an approved hostname whose DNS lookup yields RFC 8215 local-use
    // NAT64 space.
    let protector = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 8,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([vec![SocketAddr::new(
                "64:ff9b:1::1"
                    .parse()
                    .expect("local-use NAT64 IPv6 address"),
                443,
            )]])),
        }),
    );
    let url = Url::parse("https://approved.example.com/credentials").expect("approved URL");

    // When the SSRF preflight validates its DNS answer.
    let error = protector
        .resolve_and_validate(&url)
        .await
        .expect_err("local-use NAT64 IPv6 DNS answer must be rejected");

    // Then the preflight fails closed at the shared reserved-IP boundary.
    assert!(
        matches!(
            error,
            HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_RESERVED_IP
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn given_many_dns_answers_when_resolving_then_applies_cap_before_collecting() {
    // Given a resolver that can produce an unbounded stream of public
    // addresses.
    let yielded = Arc::new(AtomicUsize::new(0));
    let resolver = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 2,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(CountingDnsResolver {
            yielded: Arc::clone(&yielded),
        }),
    );
    let name: Name = "approved.example.com".parse().expect("DNS name");

    // When the connector resolver validates the answer.
    let addrs = resolver.resolve(name).await.expect("capped DNS answer");

    // Then the cap bounds both iteration and the materialized result.
    assert_eq!(addrs.collect::<Vec<_>>().len(), 2);
    assert_eq!(yielded.load(Ordering::Relaxed), 2);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedRequest {
    authority: String,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct TestResponse {
    status_line: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl TestResponse {
    fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status_line: "HTTP/1.1 200 OK",
            headers: Vec::new(),
            body: body.into(),
        }
    }

    fn redirect(status_line: &'static str, location: Option<String>) -> Self {
        let mut headers = Vec::new();
        if let Some(location) = location {
            headers.push(("Location".to_string(), location));
        }
        Self {
            status_line,
            headers,
            body: Vec::new(),
        }
    }
}

struct TestServer {
    address: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn spawn<F>(max_requests: usize, handler: F) -> Self
    where F: Fn(usize, &RecordedRequest) -> TestResponse + Send + Sync + 'static {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        listener
            .set_nonblocking(true)
            .expect("configure test listener");
        let address = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded_requests = Arc::clone(&requests);
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let handler = Arc::new(handler);

        let handle = thread::spawn(move || {
            for request_index in 0..max_requests {
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if server_shutdown.load(Ordering::Acquire) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept test connection: {error}"),
                    }
                };
                stream
                    .set_nonblocking(false)
                    .expect("configure accepted test stream");
                let request = read_request(&mut stream);
                recorded_requests
                    .lock()
                    .expect("recorded requests lock")
                    .push(request.clone());
                let response = handler(request_index, &request);
                write_response(&mut stream, response);
            }
        });

        Self {
            address,
            requests,
            shutdown,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.address)
    }

    fn port(&self) -> u16 {
        self.address
            .rsplit(':')
            .next()
            .expect("server port segment")
            .parse()
            .expect("server port")
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.requests
            .lock()
            .expect("recorded requests lock")
            .clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("test server join");
        }
    }
}

fn read_request(stream: &mut TcpStream) -> RecordedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");

    let mut buffer = Vec::new();
    let mut chunk = [0; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).expect("read request");
        assert!(read > 0, "request ended before headers were complete");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_bytes(&buffer, b"\r\n\r\n") {
            break index;
        }
    };

    let header_block = String::from_utf8(buffer[..header_end].to_vec()).expect("utf8 headers");
    let content_length = header_block
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let read = stream.read(&mut chunk).expect("read request body");
        assert!(read > 0, "request ended before body was complete");
        buffer.extend_from_slice(&chunk[..read]);
    }

    let request_line = header_block.lines().next().expect("request line");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().expect("request method").to_string();
    let path = request_parts.next().expect("request path").to_string();
    let headers = header_block
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.trim().to_ascii_lowercase();
            matches!(name.as_str(), "authorization" | "content-type" | "x-test")
                .then(|| (name, value.trim().to_string()))
        })
        .collect();

    let authority = header_block
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().to_string())
        })
        .expect("HTTP authority");

    RecordedRequest {
        authority,
        method,
        path,
        headers,
        body: buffer[body_start..body_start + content_length].to_vec(),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_response(stream: &mut TcpStream, response: TestResponse) {
    let mut raw = format!(
        "{}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status_line,
        response.body.len()
    )
    .into_bytes();

    for (name, value) in response.headers {
        raw.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&response.body);

    stream.write_all(&raw).expect("write response");
    stream.flush().expect("flush response");
}

fn tenant_client_with_ports(
    allowed_domains: Vec<AllowedDomain>,
    allowed_ports: Vec<u16>,
) -> TenantHttpClient {
    TenantHttpClient::builder("tenant")
        .allowlist(allowed_domains)
        .allowed_schemes(vec!["http".to_string(), "https".to_string()])
        .allowed_ports(allowed_ports)
        .allow_loopback_ips(true)
        .build()
        .expect("build tenant client")
}

fn tenant_client_for_server(server: &TestServer) -> TenantHttpClient {
    tenant_client_with_ports(vec![AllowedDomain::exact("127.0.0.1")], vec![server.port()])
}

const PROXY_BYPASS_CHILD_ENV: &str = "HTTP_REQUEST_PROXY_BYPASS_CHILD";
const PROXY_BYPASS_TARGET_ENV: &str = "HTTP_REQUEST_PROXY_BYPASS_TARGET";
const PROXY_BYPASS_TEST_NAME: &str =
    "tenant_tests::given_ambient_proxy_when_restricted_client_sends_then_bypasses_proxy";

#[tokio::test]
async fn given_ambient_proxy_when_restricted_client_sends_then_bypasses_proxy() {
    if std::env::var_os(PROXY_BYPASS_CHILD_ENV).is_some() {
        run_proxy_bypass_child().await;
        return;
    }

    let target = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("direct"));
    let proxy = TestServer::spawn(1, |_request_index, _request| TestResponse {
        status_line: "HTTP/1.1 502 Bad Gateway",
        headers: Vec::new(),
        body: b"proxy used".to_vec(),
    });
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            PROXY_BYPASS_TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROXY_BYPASS_CHILD_ENV, "1")
        .env(PROXY_BYPASS_TARGET_ENV, target.url("/proxy-bypass"))
        .env("HTTP_PROXY", proxy.url("/"))
        .env("HTTPS_PROXY", proxy.url("/"))
        .env("ALL_PROXY", proxy.url("/"))
        .env("http_proxy", proxy.url("/"))
        .env("https_proxy", proxy.url("/"))
        .env("all_proxy", proxy.url("/"))
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("run proxy bypass child");

    assert!(
        output.status.success(),
        "proxy bypass child failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(target.requests().len(), 1);
    assert!(proxy.requests().is_empty());
}

async fn run_proxy_bypass_child() {
    let target = std::env::var(PROXY_BYPASS_TARGET_ENV).expect("proxy bypass target");
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("127.0.0.1")])
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![
            Url::parse(&target)
                .expect("proxy bypass target URL")
                .port()
                .expect("proxy bypass target port"),
        ])
        .allow_loopback_ips(true)
        .build()
        .expect("tenant client");

    let response = client
        .get(target)
        .send()
        .await
        .expect("direct request should bypass proxy");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

fn expect_http_error<T>(result: Result<T, HttpRequestError>, message: &str) -> HttpRequestError {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
}

#[test]
fn match_allowlisted_domain_prefers_most_specific_rule() {
    let domains = vec![
        AllowedDomain::with_subdomains("example.com"),
        AllowedDomain::with_subdomains("api.example.com"),
        AllowedDomain::exact("tenant.example.com"),
    ];

    let matched = match_allowlisted_domain("tenant.api.example.com", &domains)
        .expect("matching allowlist entry");

    assert_eq!(matched.host, "api.example.com");
    assert!(matched.allow_subdomains);
}

#[test]
fn given_equivalent_default_ports_when_comparing_origins_then_matches() {
    let https_default = Url::parse("https://example.com/path").expect("url");
    let https_explicit = Url::parse("https://example.com:443/other").expect("url");
    let different_port = Url::parse("https://example.com:8443/other").expect("url");

    assert!(same_origin(&https_default, &https_explicit));
    assert!(!same_origin(&https_default, &different_port));
}

#[test]
fn given_scheme_change_when_comparing_redirect_origins_then_rejects() {
    let https = Url::parse("https://example.com:443/path").expect("https URL");
    let http = Url::parse("http://example.com:443/path").expect("http URL");

    assert!(!same_origin(&https, &http));
}

#[test]
fn request_body_len_reads_inline_body_bytes() {
    let request = Client::new()
        .request(Method::POST, "https://example.com")
        .body("hello world")
        .build()
        .expect("request");

    assert_eq!(request_body_len(&request), Some(11));
}

#[test]
fn is_blocked_ip_allows_loopback_only_when_explicitly_enabled() {
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));

    assert!(is_blocked_ip(loopback, false));
    assert!(!is_blocked_ip(loopback, true));
    assert!(is_blocked_ip(private, true));
}

#[test]
fn is_blocked_ip_rejects_ipv4_mapped_reserved_addresses() {
    let metadata = "::ffff:169.254.169.254"
        .parse::<IpAddr>()
        .expect("mapped metadata address");
    let private = "::ffff:10.0.0.7"
        .parse::<IpAddr>()
        .expect("mapped private address");

    assert!(is_blocked_ip(metadata, false));
    assert!(is_blocked_ip(private, false));
}

#[test]
fn is_blocked_ip_rejects_ipv4_compatible_reserved_addresses() {
    let private = "::10.0.0.7"
        .parse::<IpAddr>()
        .expect("IPv4-compatible private address");
    let public = "::8.8.8.8"
        .parse::<IpAddr>()
        .expect("IPv4-compatible public address");

    assert!(is_blocked_ip(private, false));
    assert!(!is_blocked_ip(public, false));
}

#[test]
fn is_blocked_ip_rejects_isatap_reserved_addresses() {
    let private = "2001:4860:1234:5678:0:5efe:a00:1"
        .parse::<IpAddr>()
        .expect("ISATAP private address");
    let public = "2001:4860:1234:5678:0:5efe:808:808"
        .parse::<IpAddr>()
        .expect("ISATAP public address");

    assert!(is_blocked_ip(private, false));
    assert!(!is_blocked_ip(public, false));
}

#[test]
fn is_blocked_ip_rejects_reserved_addresses_through_well_known_nat64_prefix() {
    let metadata = "64:ff9b::a9fe:a9fe"
        .parse::<IpAddr>()
        .expect("NAT64 metadata address");
    let public = "64:ff9b::0808:0808"
        .parse::<IpAddr>()
        .expect("NAT64 public address");

    assert!(is_blocked_ip(metadata, false));
    assert!(!is_blocked_ip(public, false));
}

#[test]
fn given_cloud_metadata_addresses_when_checking_then_block_including_ecs_and_peers() {
    // Given the link-local metadata endpoints across clouds, which DNS
    // rebinding converges on regardless of the validated hostname.
    for address in [
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "192.0.0.192",
        "fd00:ec2::254",
    ] {
        let ip = address.parse::<IpAddr>().expect("metadata address");

        // When the resolved address reaches the blocking predicate.
        // Then every metadata form is blocked with or without loopback
        // opt-in, since none of them is loopback.
        assert!(is_blocked_ip(ip, false), "metadata leaked: {address}");
        assert!(is_blocked_ip(ip, true), "metadata leaked: {address}");
    }
}

#[test]
fn given_transition_and_unspecified_addresses_when_checking_then_block() {
    // Given 6to4-embedded, unspecified, and carrier-grade addresses that
    // alternate IP encodings smuggle past naive filters.
    for address in [
        "2002:0a00:0001::1",
        "2002:0808:0808::1",
        "::",
        "0.0.0.0",
        "100.64.0.1",
        "224.0.0.251",
    ] {
        let ip = address.parse::<IpAddr>().expect("transition address");

        // When the resolved address reaches the blocking predicate.
        // Then the shared reserved-range policy blocks each form, including
        // the whole deprecated 6to4 range regardless of the embedded address.
        assert!(
            is_blocked_ip(ip, false),
            "transition address leaked: {address}"
        );
    }

    // Public controls on either side of the transition mechanisms stay
    // reachable so the table does not over-block.
    for address in ["8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"] {
        let ip = address.parse::<IpAddr>().expect("public address");
        assert!(!is_blocked_ip(ip, false), "public blocked: {address}");
    }
}

#[tokio::test]
async fn given_flipping_dns_between_preflights_when_simulating_rebinding_then_second_answer_rejected()
 {
    // Given an attacker DNS table that answers public first and link-local
    // on re-resolution, modeling the rebinding timeline against the real
    // preflight predicate.
    let protector = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 8,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([
                vec!["93.184.216.34:443".parse().expect("public address")],
                vec!["169.254.169.254:443".parse().expect("metadata address")],
            ])),
        }),
    );
    let url = Url::parse("https://rebind.attacker.invalid/").expect("URL");

    // When validation runs against the first answer.
    protector
        .resolve_and_validate(&url)
        .await
        .expect("public answer validates");

    // Then re-resolution after the TTL flip is rejected, so only pinning the
    // validated set (or re-validating, as the connector resolver does on
    // every resolution) closes the window.
    let error = protector
        .resolve_and_validate(&url)
        .await
        .expect_err("rebound metadata must fail closed");
    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_RESERVED_IP
        }
    ));
}

#[test]
fn given_teredo_ipv6_address_when_classifying_ssrf_destination_then_blocks_it() {
    let teredo = "2001:0000:4136:e378:8000:63bf:3fff:fdd2"
        .parse::<IpAddr>()
        .expect("Teredo IPv6 address");

    assert!(is_blocked_ip(teredo, false));
}

#[test]
fn given_six_to_four_ipv6_address_when_classifying_ssrf_destination_then_blocks_it() {
    let six_to_four = "2002:c000:0204::1"
        .parse::<IpAddr>()
        .expect("6to4 IPv6 address");

    assert!(is_blocked_ip(six_to_four, false));
}

#[test]
fn given_global_ipv6_address_when_classifying_ssrf_destination_then_allows_it() {
    let global = "2001:4860:4860::8888"
        .parse::<IpAddr>()
        .expect("global IPv6 address");

    assert!(!is_blocked_ip(global, false));
}

#[test]
fn is_blocked_ip_rejects_local_use_nat64_addresses() {
    let local_use = "64:ff9b:1::1"
        .parse::<IpAddr>()
        .expect("local-use NAT64 address");
    let global = "64:ff9b:2::1"
        .parse::<IpAddr>()
        .expect("outside local-use NAT64 range");

    assert!(is_blocked_ip(local_use, false));
    assert!(!is_blocked_ip(global, false));
}

#[test]
fn tenant_http_client_builder_requires_non_empty_allowlist() {
    let err = TenantHttpClient::builder("tenant")
        .build()
        .err()
        .expect("tenant client without allowlist should fail");

    assert!(
        err.to_string().contains("domain_not_allowlisted"),
        "unexpected error: {err}"
    );
}

#[test]
fn tenant_http_client_when_constructed_then_exposes_tenant_id() {
    let tenant_id = "tenant";
    let client = TenantHttpClient::new(tenant_id, vec![AllowedDomain::exact("example.com")])
        .expect("tenant client");

    assert_eq!(client.tenant_id(), tenant_id);
}

#[tokio::test]
async fn tenant_http_client_when_request_helpers_used_then_send_expected_http_methods() {
    let server = TestServer::spawn(6, |_request_index, _request| TestResponse::ok("ok"));
    let client = tenant_client_for_server(&server);

    client
        .get(server.url("/get"))
        .send()
        .await
        .expect("GET response");
    client
        .post(server.url("/post"))
        .body("created")
        .send()
        .await
        .expect("POST response");
    client
        .put(server.url("/put"))
        .send()
        .await
        .expect("PUT response");
    client
        .patch(server.url("/patch"))
        .send()
        .await
        .expect("PATCH response");
    client
        .delete(server.url("/delete"))
        .send()
        .await
        .expect("DELETE response");
    client
        .request(Method::HEAD, server.url("/head"))
        .send()
        .await
        .expect("HEAD response");

    let requests = server.requests();
    assert_eq!(
        requests
            .into_iter()
            .map(|request| (request.method, request.path))
            .collect::<Vec<_>>(),
        vec![
            ("GET".to_string(), "/get".to_string()),
            ("POST".to_string(), "/post".to_string()),
            ("PUT".to_string(), "/put".to_string()),
            ("PATCH".to_string(), "/patch".to_string()),
            ("DELETE".to_string(), "/delete".to_string()),
            ("HEAD".to_string(), "/head".to_string()),
        ]
    );
}

#[tokio::test]
async fn given_retry_policy_when_get_receives_transient_failure_then_retries_at_tenant_boundary() {
    // Given a tenant endpoint that recovers on the second request.
    let server = TestServer::spawn(2, |request_index, _request| {
        if request_index == 0 {
            TestResponse {
                status_line: "HTTP/1.1 503 Service Unavailable",
                headers: Vec::new(),
                body: Vec::new(),
            }
        } else {
            TestResponse::ok("recovered")
        }
    });
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("127.0.0.1")])
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![server.port()])
        .allow_loopback_ips(true)
        .retry(RetryConfig {
            max_retries: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            retry_non_idempotent: false,
        })
        .build()
        .expect("tenant client");

    // When an idempotent GET is sent through the tenant client.
    let response = client
        .get(server.url("/retry"))
        .send()
        .await
        .expect("retried response");

    // Then the tenant retry policy allows recovery without changing the
    // boundary.
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn tenant_http_client_when_same_origin_temporary_redirect_then_replays_request() {
    let server = TestServer::spawn(2, |request_index, _request| match request_index {
        0 => TestResponse::redirect(
            "HTTP/1.1 307 Temporary Redirect",
            Some("/final".to_string()),
        ),
        1 => TestResponse::ok("redirected"),
        _ => unreachable!("unexpected request index"),
    });
    let client = tenant_client_for_server(&server);

    let response = client
        .post(server.url("/start"))
        .body("payload")
        .send()
        .await
        .expect("redirected response");

    assert_eq!(response.text().await.expect("response body"), "redirected");
    assert_eq!(
        server.requests(),
        vec![
            RecordedRequest {
                authority: format!("127.0.0.1:{}", server.port()),
                method: "POST".to_string(),
                path: "/start".to_string(),
                headers: Vec::new(),
                body: b"payload".to_vec(),
            },
            RecordedRequest {
                authority: format!("127.0.0.1:{}", server.port()),
                method: "POST".to_string(),
                path: "/final".to_string(),
                headers: Vec::new(),
                body: b"payload".to_vec(),
            },
        ]
    );
}

#[tokio::test]
async fn tenant_http_client_when_redirect_limit_is_zero_then_blocks_first_redirect() {
    let server = TestServer::spawn(1, |_request_index, _request| {
        TestResponse::redirect("HTTP/1.1 307 Temporary Redirect", Some("/next".to_string()))
    });
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("127.0.0.1")])
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![server.port()])
        .allow_loopback_ips(true)
        .max_redirects(0)
        .build()
        .expect("build tenant client");

    let error = expect_http_error(
        client.get(server.url("/start")).send().await,
        "redirect limit should block first redirect",
    );

    assert!(
        matches!(
            error,
            HttpRequestError::RedirectBlocked {
                reason: REDIRECT_BLOCKED_TOO_MANY
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn tenant_http_client_when_redirect_changes_method_then_blocks_redirect() {
    let server = TestServer::spawn(1, |_request_index, _request| {
        TestResponse::redirect("HTTP/1.1 302 Found", Some("/next".to_string()))
    });
    let client = tenant_client_for_server(&server);

    let error = expect_http_error(
        client.get(server.url("/start")).send().await,
        "302 redirect should be blocked",
    );

    assert!(
        matches!(
            error,
            HttpRequestError::RedirectBlocked {
                reason: REDIRECT_BLOCKED_METHOD_CHANGE
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn tenant_http_client_when_redirect_omits_location_then_blocks_redirect() {
    let server = TestServer::spawn(1, |_request_index, _request| {
        TestResponse::redirect("HTTP/1.1 307 Temporary Redirect", None)
    });
    let client = tenant_client_for_server(&server);

    let error = expect_http_error(
        client.get(server.url("/start")).send().await,
        "redirect without location should be blocked",
    );

    assert!(
        matches!(
            error,
            HttpRequestError::RedirectBlocked {
                reason: REDIRECT_BLOCKED_METHOD_CHANGE
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn tenant_http_client_when_redirect_changes_host_then_blocks_redirect() {
    let server = TestServer::spawn(1, |_request_index, _request| {
        TestResponse::redirect(
            "HTTP/1.1 307 Temporary Redirect",
            Some("http://localhost/next".to_string()),
        )
    });
    let client = tenant_client_for_server(&server);

    let error = expect_http_error(
        client.get(server.url("/start")).send().await,
        "host-mismatched redirect should be blocked",
    );

    assert!(
        matches!(
            error,
            HttpRequestError::RedirectBlocked {
                reason: REDIRECT_BLOCKED_HOST_MISMATCH
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn tenant_http_client_when_stream_body_declares_small_content_length_then_rejects() {
    let body = reqwest::Body::wrap_stream(stream::once(async {
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"hello"))
    }));

    let error = expect_http_error(
        TenantHttpClient::builder("tenant")
            .allowlist(vec![AllowedDomain::exact("example.com")])
            .max_content_length(4)
            .build()
            .expect("build tenant client")
            .post("https://example.com")
            .header(reqwest::header::CONTENT_LENGTH, "1")
            .body(body)
            .send()
            .await,
        "streaming body with a forged small content length should be rejected",
    );

    assert!(
        matches!(error, HttpRequestError::RequestSizeUnknown { max: 4 }),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn tenant_http_client_when_body_exceeds_limit_then_rejects_request() {
    let error = expect_http_error(
        TenantHttpClient::builder("tenant")
            .allowlist(vec![AllowedDomain::exact("example.com")])
            .max_content_length(4)
            .build()
            .expect("build tenant client")
            .post("https://example.com")
            .body("hello")
            .send()
            .await,
        "oversized request should be rejected",
    );

    assert!(matches!(
        error,
        HttpRequestError::RequestTooLarge { size: 5, max: 4 }
    ));
}

#[tokio::test]
async fn tenant_http_client_when_body_size_is_unknown_then_rejects_request() {
    let body = reqwest::Body::wrap_stream(stream::once(async {
        Ok::<Bytes, std::io::Error>(Bytes::from_static(b"hello"))
    }));
    let error = expect_http_error(
        TenantHttpClient::builder("tenant")
            .allowlist(vec![AllowedDomain::exact("example.com")])
            .build()
            .expect("build tenant client")
            .post("https://example.com")
            .body(body)
            .send()
            .await,
        "streaming request without content length should be rejected",
    );

    assert!(matches!(error, HttpRequestError::RequestSizeUnknown { .. }));
}

#[tokio::test]
async fn tenant_http_client_when_domain_is_not_allowlisted_then_blocks_request() {
    let error = expect_http_error(
        TenantHttpClient::builder("tenant")
            .allowlist(vec![AllowedDomain::exact("example.com")])
            .build()
            .expect("build tenant client")
            .get("https://api.example.com")
            .send()
            .await,
        "non-allowlisted domain should be blocked",
    );

    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_DOMAIN_NOT_ALLOWLISTED
        }
    ));
}

#[tokio::test]
async fn tenant_http_client_when_scheme_is_not_allowed_then_blocks_request() {
    let error = expect_http_error(
        TenantHttpClient::builder("tenant")
            .allowlist(vec![AllowedDomain::exact("example.com")])
            .build()
            .expect("build tenant client")
            .get("http://example.com")
            .send()
            .await,
        "http scheme should be blocked by default",
    );

    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_SCHEME
        }
    ));
}

#[tokio::test]
async fn tenant_http_client_when_url_contains_userinfo_then_blocks_request() {
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("example.com")])
        .build()
        .expect("build tenant client");
    let request = reqwest::Request::new(
        Method::GET,
        Url::parse("https://user@example.com/path").expect("userinfo url"),
    );
    let error = expect_http_error(client.execute(request).await, "userinfo should be blocked");

    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_USERINFO
        }
    ));
}

#[tokio::test]
async fn tenant_http_client_when_url_contains_fragment_then_blocks_request() {
    let error = expect_http_error(
        TenantHttpClient::builder("tenant")
            .allowlist(vec![AllowedDomain::exact("example.com")])
            .build()
            .expect("build tenant client")
            .get("https://example.com/path#fragment")
            .send()
            .await,
        "fragment should be blocked",
    );

    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_FRAGMENT
        }
    ));
}

#[tokio::test]
async fn tenant_http_client_when_port_is_not_allowlisted_then_blocks_request() {
    let error = expect_http_error(
        TenantHttpClient::builder("tenant")
            .allowlist(vec![AllowedDomain::exact("example.com")])
            .build()
            .expect("build tenant client")
            .get("https://example.com:444/path")
            .send()
            .await,
        "non-allowlisted port should be blocked",
    );

    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_PORT
        }
    ));
}

#[tokio::test]
async fn tenant_http_client_when_host_is_ip_literal_without_loopback_override_then_blocks_request()
{
    let error = expect_http_error(
        TenantHttpClient::builder("tenant")
            .allowlist(vec![AllowedDomain::exact("127.0.0.1")])
            .allowed_schemes(vec!["http".to_string()])
            .allowed_ports(vec![80])
            .build()
            .expect("build tenant client")
            .get("http://127.0.0.1")
            .send()
            .await,
        "ip literal should be blocked",
    );

    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_IP_LITERAL
        }
    ));
}

#[tokio::test]
async fn tenant_http_client_rejects_host_header_overrides() {
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("example.com")])
        .build()
        .expect("build tenant client");
    let mut request = reqwest::Request::new(
        Method::GET,
        Url::parse("https://example.com/endpoint").expect("request url"),
    );
    request.headers_mut().insert(
        reqwest::header::HOST,
        HeaderValue::from_static("privileged.example.com"),
    );

    let error = expect_http_error(
        client.execute(request).await,
        "Host override should be blocked",
    );
    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_HOST_HEADER
        }
    ));
}

#[test]
fn given_str_domain_when_converting_to_allowed_domain_then_creates_exact_rule() {
    // Given a domain supplied through the ergonomic string conversion.
    let domain: AllowedDomain = "Example.COM".into();

    // When the converted rule is inspected.
    // Then it is an exact rule and preserves the caller's host spelling.
    assert_eq!(domain.host, "Example.COM");
    assert!(!domain.allow_subdomains);
}

#[test]
fn allowed_domain_debug_redacts_host() {
    let domain = AllowedDomain::exact("private.customer.example");
    let rendered = format!("{domain:?}");
    assert!(rendered.contains("host_present: true"));
    assert!(!rendered.contains("private.customer.example"));
}

#[tokio::test]
async fn given_builder_options_when_building_tenant_client_then_applies_response_limit() {
    // Given a local endpoint and the response limit needed by this test.
    let server = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("long"));
    let client = TenantHttpClient::builder("tenant")
        .add_domain(AllowedDomain::exact("127.0.0.1"))
        .max_response_length(2)
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![server.port()])
        .allow_loopback_ips(true)
        .build()
        .expect("tenant client");

    // When a response exceeds the configured tenant response budget.
    let response = client
        .get(server.url("/bounded"))
        .send()
        .await
        .expect("response headers");
    let error = expect_http_error(
        response.text().await,
        "response body should honor the configured tenant limit",
    );

    // Then the builder's response limit is enforced at the response boundary.
    assert!(matches!(
        error,
        HttpRequestError::ResponseTooLarge { size: 4, max: 2 }
    ));
}

#[tokio::test]
async fn given_client_timeout_when_server_is_slow_then_times_out_at_tenant_boundary() {
    // Given a local endpoint that responds after the tenant client deadline.
    let server = TestServer::spawn(1, |_request_index, _request| {
        thread::sleep(Duration::from_millis(200));
        TestResponse::ok("late")
    });
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("127.0.0.1")])
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![server.port()])
        .allow_loopback_ips(true)
        .retry(RetryConfig {
            max_retries: 0,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            retry_non_idempotent: false,
        })
        .timeout(Duration::from_millis(100))
        .connect_timeout(Duration::from_secs(1))
        .build()
        .expect("tenant client");

    // When the request uses the client-level deadline.
    let error = expect_http_error(
        client.get(server.url("/slow-client")).send().await,
        "client timeout should abort a slow response",
    );

    // Then the configured tenant deadline is surfaced as a transport timeout.
    assert!(
        matches!(
            &error,
            HttpRequestError::Transport {
                kind: HttpRequestErrorKind::Timeout
            }
        ),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        error.dispatch_status(),
        HttpRequestDispatchStatus::PossiblyDispatched
    );
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn given_zero_dns_address_budget_when_executing_then_blocks_empty_dns_answer() {
    // Given an allowlisted hostname whose resolver budget is explicitly zero.
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("localhost")])
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![80])
        .max_dns_addresses(0)
        .allow_loopback_ips(true)
        .build()
        .expect("tenant client");

    // When the preflight truncates the local resolver result to that budget.
    let error = expect_http_error(
        client.get("http://localhost/path").send().await,
        "zero DNS address budget should fail closed",
    );

    // Then the tenant boundary reports an empty DNS answer instead of
    // dispatching.
    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_DNS_EMPTY
        }
    ));
}

#[tokio::test]
async fn given_allowlisted_local_hostname_without_loopback_override_when_executing_then_blocks_reserved_ip()
 {
    // Given an allowlisted hostname that resolves only to local loopback
    // addresses.
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("localhost")])
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![80])
        .build()
        .expect("tenant client");

    // When the tenant boundary performs its reserved-address preflight.
    let error = expect_http_error(
        client.get("http://localhost/path").send().await,
        "loopback DNS result should be rejected without an override",
    );

    // Then hostname indirection cannot bypass the reserved-IP policy.
    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_RESERVED_IP
        }
    ));
}

#[tokio::test]
async fn given_allowlisted_local_hostname_when_sending_then_uses_custom_dns_resolver() {
    // Given a local HTTP endpoint and a hostname that the default resolver
    // cannot resolve.
    let server = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("resolved"));
    let resolver = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["http".to_string()],
            allowed_ports: vec![server.port()],
            max_dns_addresses: 8,
            allow_loopback_ips: true,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([vec![SocketAddr::from((
                [127, 0, 0, 1],
                server.port(),
            ))]])),
        }),
    );
    let client = Client::builder()
        .no_proxy()
        .dns_resolver(resolver)
        .build()
        .expect("resolver-backed client");

    // When reqwest sends a request to the deterministic, otherwise
    // unresolvable hostname.
    let response = client
        .get(format!(
            "http://tenant-http-request-test.invalid:{}/resolved",
            server.port()
        ))
        .send()
        .await
        .expect("resolved response");

    // Then the injected resolver, rather than the default resolver, reaches
    // the local endpoint.
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(server.requests()[0].path, "/resolved");
}

#[tokio::test]
async fn given_tenant_client_when_local_hostname_sends_then_uses_default_dns_resolver() {
    // Given a local HTTP endpoint addressed through the tenant client's
    // production resolver wiring.
    let server = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("resolved"));
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("localhost")])
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![server.port()])
        .allow_loopback_ips(true)
        .build()
        .expect("tenant client");

    // When the tenant boundary resolves and sends to the local hostname.
    let response = client
        .get(format!("http://localhost:{}/resolved", server.port()))
        .send()
        .await
        .expect("resolved response");

    // Then the production SSRF resolver reaches the local endpoint.
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(server.requests()[0].path, "/resolved");
}

#[tokio::test]
async fn given_request_builder_headers_and_query_when_sending_then_forwards_both() {
    // Given a local endpoint with a custom header and query parameter.
    let server = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("ok"));
    let client = tenant_client_for_server(&server);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-test", HeaderValue::from_static("present"));

    // When the request builder applies both forwarding helpers.
    let response = client
        .post(server.url("/builder"))
        .headers(headers)
        .query(&[("page", "1")])
        .send()
        .await
        .expect("request response");

    // Then the path and custom header arrive at the local server.
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let request = &server.requests()[0];
    assert_eq!(request.path, "/builder?page=1");
    assert_eq!(
        request.headers,
        vec![("x-test".to_string(), "present".to_string())]
    );
}

#[tokio::test]
async fn given_request_builder_json_when_sending_then_encodes_json_payload() {
    // Given a local endpoint and a JSON value.
    let server = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("ok"));
    let client = tenant_client_for_server(&server);

    // When the JSON forwarding helper sends the request.
    client
        .post(server.url("/json"))
        .json(&serde_json::json!({"json": true}))
        .send()
        .await
        .expect("JSON response");

    // Then JSON content type and the JSON payload are both preserved.
    let request = &server.requests()[0];
    assert_eq!(
        request.headers,
        vec![("content-type".to_string(), "application/json".to_string())]
    );
    assert_eq!(request.body, br#"{"json":true}"#);
}

#[tokio::test]
async fn given_request_builder_form_when_sending_then_encodes_form_payload() {
    // Given a local endpoint and a form value.
    let server = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("ok"));
    let client = tenant_client_for_server(&server);

    // When the form forwarding helper sends the request.
    client
        .post(server.url("/form"))
        .form(&[("form", "value")])
        .send()
        .await
        .expect("form response");

    // Then form content type and the encoded form payload are preserved.
    let request = &server.requests()[0];
    assert_eq!(
        request.headers,
        vec![(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string()
        )]
    );
    assert_eq!(request.body, b"form=value");
}

#[tokio::test]
async fn given_request_builder_bearer_auth_when_sending_then_sets_authorization() {
    // Given a local endpoint and a bearer token.
    let server = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("ok"));
    let client = tenant_client_for_server(&server);

    // When bearer authentication is forwarded.
    client
        .get(server.url("/bearer"))
        .bearer_auth("bearer-token")
        .send()
        .await
        .expect("bearer response");

    // Then the server receives the bearer authorization header.
    assert_eq!(
        server.requests()[0].headers,
        vec![(
            "authorization".to_string(),
            "Bearer bearer-token".to_string()
        )]
    );
}

#[tokio::test]
async fn given_request_builder_basic_auth_when_sending_then_sets_authorization() {
    // Given a local endpoint and basic credentials.
    let server = TestServer::spawn(1, |_request_index, _request| TestResponse::ok("ok"));
    let client = tenant_client_for_server(&server);

    // When basic authentication is forwarded.
    client
        .get(server.url("/basic"))
        .basic_auth("user", Some("password"))
        .send()
        .await
        .expect("basic response");

    // Then the server receives the encoded basic authorization header.
    assert_eq!(
        server.requests()[0].headers,
        vec![(
            "authorization".to_string(),
            "Basic dXNlcjpwYXNzd29yZA==".to_string()
        )]
    );
}

#[tokio::test]
async fn given_request_builder_timeout_when_server_is_slow_then_times_out() {
    // Given a local endpoint that waits longer than the request deadline.
    let server = TestServer::spawn(1, |_request_index, _request| {
        thread::sleep(Duration::from_millis(50));
        TestResponse::ok("late")
    });
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("127.0.0.1")])
        .allowed_schemes(vec!["http".to_string()])
        .allowed_ports(vec![server.port()])
        .allow_loopback_ips(true)
        .retry(RetryConfig {
            max_retries: 0,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            retry_non_idempotent: false,
        })
        .build()
        .expect("tenant client");

    // When the request builder applies a deadline shorter than the response.
    let error = expect_http_error(
        client
            .get(server.url("/slow"))
            .timeout(Duration::from_millis(20))
            .send()
            .await,
        "request deadline should abort the slow response",
    );

    // Then the timeout is surfaced as a transport timeout.
    assert!(matches!(
        error,
        HttpRequestError::Transport {
            kind: HttpRequestErrorKind::Timeout
        }
    ));
}

#[tokio::test]
async fn given_same_origin_redirect_with_changed_scheme_when_sending_then_blocks_scheme_change() {
    // Given an HTTP endpoint that redirects to HTTPS on the same host and port.
    let redirect_port = Arc::new(Mutex::new(None));
    let handler_port = Arc::clone(&redirect_port);
    let server = TestServer::spawn(1, move |_request_index, _request| {
        let port = handler_port
            .lock()
            .expect("redirect port lock")
            .expect("redirect port");
        TestResponse::redirect(
            "HTTP/1.1 307 Temporary Redirect",
            Some(format!("https://127.0.0.1:{port}/next")),
        )
    });
    *redirect_port.lock().expect("redirect port lock") = Some(server.port());
    let client = tenant_client_for_server(&server);

    // When the redirect is followed by the tenant client.
    let error = expect_http_error(
        client.get(server.url("/start")).send().await,
        "scheme-changing redirect should be blocked",
    );

    // Then the origin policy rejects the scheme change before a second request.
    assert!(matches!(
        error,
        HttpRequestError::RedirectBlocked {
            reason: REDIRECT_BLOCKED_SCHEME_CHANGE
        }
    ));
}

#[tokio::test]
async fn given_ipv6_loopback_literal_with_userinfo_when_validating_then_blocks_userinfo() {
    // Given an explicitly allowed IPv6 loopback host with forbidden userinfo.
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact("[::1]")])
        .allowed_schemes(vec!["https".to_string()])
        .allowed_ports(vec![443])
        .allow_loopback_ips(true)
        .build()
        .expect("tenant client");
    let request = reqwest::Request::new(
        Method::GET,
        Url::parse("https://user@[::1]/path").expect("IPv6 URL"),
    );

    // When the request is validated without contacting the endpoint.
    let error = expect_http_error(
        client.execute(request).await,
        "IPv6 userinfo should be blocked",
    );

    // Then the IPv6 literal is accepted only long enough to enforce the
    // userinfo rule.
    assert!(
        matches!(
            error,
            HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_USERINFO
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn given_url_without_host_when_executing_then_blocks_missing_host() {
    // Given a URL scheme that has no host component.
    let client = TenantHttpClient::new("tenant", vec![AllowedDomain::exact("example.com")])
        .expect("tenant client");
    let request = reqwest::Request::new(
        Method::GET,
        Url::parse("data:text/plain,hello").expect("hostless URL"),
    );

    // When the tenant boundary validates the request URL.
    let error = expect_http_error(
        client.execute(request).await,
        "hostless URL should be blocked",
    );

    // Then no DNS or transport work is attempted.
    assert!(
        matches!(
            error,
            HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_MISSING_HOST
            }
        ),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn given_allowlisted_unresolvable_host_when_executing_then_blocks_dns_failure() {
    // Given an allowlisted hostname from the reserved, non-resolvable .invalid
    // namespace.
    let client = TenantHttpClient::builder("tenant")
        .allowlist(vec![AllowedDomain::exact(
            "tenant-http-request-test.invalid",
        )])
        .build()
        .expect("tenant client");

    // When the tenant boundary performs its DNS preflight.
    let error = expect_http_error(
        client
            .get("https://tenant-http-request-test.invalid/path")
            .send()
            .await,
        "an unresolvable allowlisted host should be rejected",
    );

    // Then DNS failure is surfaced as a fail-closed SSRF decision.
    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_DNS_FAILURE
        }
    ));
}

#[tokio::test]
async fn given_empty_dns_answer_when_resolving_then_blocks_empty_result() {
    // Given a deterministic resolver that returns no connector addresses.
    let resolver = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 8,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([Vec::new()])),
        }),
    );
    let name: Name = "example.com".parse().expect("DNS name");

    // When the custom resolver validates that empty answer.
    let error = match resolver.resolve(name).await {
        Ok(_) => panic!("empty DNS answer must be rejected"),
        Err(error) => error,
    };

    // Then the resolver exposes the fail-closed empty-answer reason.
    assert!(
        error.to_string().contains(SSRF_BLOCKED_DNS_EMPTY),
        "{error}"
    );
}

#[tokio::test]
async fn given_site_local_ipv6_dns_answer_when_resolving_then_blocks_reserved_ip() {
    // Given an approved hostname whose connector DNS answer is site-local IPv6.
    let resolver = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 8,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([vec![SocketAddr::new(
                "fec0::1".parse().expect("site-local IPv6 address"),
                443,
            )]])),
        }),
    );
    let name: Name = "approved.example.com".parse().expect("DNS name");

    // When the connector resolver validates the answer.
    let error = match resolver.resolve(name).await {
        Ok(_) => panic!("site-local IPv6 DNS answer must be rejected"),
        Err(error) => error,
    };

    // Then connector resolution fails closed with the existing reason.
    assert!(
        error.to_string().contains(SSRF_BLOCKED_RESERVED_IP),
        "{error}"
    );
}

#[tokio::test]
async fn given_local_use_nat64_dns_answer_when_resolving_then_blocks_reserved_ip() {
    // Given an approved hostname whose connector DNS answer is RFC 8215
    // local-use NAT64.
    let resolver = SsrfProtector::with_resolver(
        SsrfProtectionConfig {
            allowed_schemes: vec!["https".to_string()],
            allowed_ports: vec![443],
            max_dns_addresses: 8,
            allow_loopback_ips: false,
            dns_timeout: Duration::from_secs(1),
        },
        Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from([vec![SocketAddr::new(
                "64:ff9b:1::1"
                    .parse()
                    .expect("local-use NAT64 IPv6 address"),
                443,
            )]])),
        }),
    );
    let name: Name = "approved.example.com".parse().expect("DNS name");

    // When the connector resolver validates the answer.
    let error = match resolver.resolve(name).await {
        Ok(_) => panic!("local-use NAT64 IPv6 DNS answer must be rejected"),
        Err(error) => error,
    };

    // Then connector resolution fails closed with the existing reason.
    assert!(
        error.to_string().contains(SSRF_BLOCKED_RESERVED_IP),
        "{error}"
    );
}

#[test]
fn given_equal_length_allowlist_rules_when_matching_then_keeps_first_rule() {
    // Given two matching rules with equal specificity and equal host length.
    let domains = vec![
        AllowedDomain::exact("example.com"),
        AllowedDomain::with_subdomains("example.com"),
    ];

    // When the host is matched against both rules.
    let matched = match_allowlisted_domain("example.com", &domains).expect("matching rule");

    // Then declaration order remains deterministic for a specificity tie.
    assert!(!matched.allow_subdomains);
}

#[tokio::test]
async fn given_fixture_dns_when_tenant_requests_public_authority_then_connection_uses_fixture_and_host_stays_public()
 {
    let server = TestServer::spawn(1, |_, _| TestResponse::ok("fixture"));
    let address = SocketAddr::from(([127, 0, 0, 1], server.port()));
    let client = TenantHttpClient::builder("fixture")
        .allowlist(vec![AllowedDomain::exact("issuer.example.test")])
        .allowed_schemes(vec!["http".into()])
        .allowed_ports(vec![80])
        .allow_loopback_ips(true)
        .test_dns_resolver(Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from(vec![vec![address]; 4])),
        }))
        .build()
        .expect("fixture client");
    let response = client
        .get("http://issuer.example.test/discovery")
        .send()
        .await
        .expect("fixture response");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/discovery");
    assert_eq!(requests[0].authority, "issuer.example.test");
}

#[tokio::test]
async fn given_fixture_dns_without_loopback_permission_when_tenant_requests_then_ssrf_still_blocks_dispatch()
 {
    let server = TestServer::spawn(1, |_, _| TestResponse::ok("must not dispatch"));
    let address = SocketAddr::from(([127, 0, 0, 1], server.port()));
    let client = TenantHttpClient::builder("fixture")
        .allowlist(vec![AllowedDomain::exact("issuer.example.test")])
        .allowed_schemes(vec!["http".into()])
        .allowed_ports(vec![80])
        .test_dns_resolver(Arc::new(SequenceDnsResolver {
            responses: Mutex::new(VecDeque::from(vec![vec![address]; 4])),
        }))
        .build()
        .expect("fixture client");
    let error = client
        .get("http://issuer.example.test/discovery")
        .send()
        .await
        .err()
        .expect("SSRF rejection");
    assert!(matches!(
        error,
        HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_RESERVED_IP
        }
    ));
    assert!(server.requests().is_empty());
}
