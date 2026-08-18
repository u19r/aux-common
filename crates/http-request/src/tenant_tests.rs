use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
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
    HttpRequestError,
    constants::{
        REDIRECT_BLOCKED_HOST_MISMATCH, REDIRECT_BLOCKED_METHOD_CHANGE, REDIRECT_BLOCKED_TOO_MANY,
        SSRF_BLOCKED_DNS_TIMEOUT, SSRF_BLOCKED_DOMAIN_NOT_ALLOWLISTED, SSRF_BLOCKED_FRAGMENT,
        SSRF_BLOCKED_HOST_HEADER, SSRF_BLOCKED_IP_LITERAL, SSRF_BLOCKED_PORT, SSRF_BLOCKED_SCHEME,
        SSRF_BLOCKED_USERINFO,
    },
    tenant::{
        AllowedDomain, SsrfDnsResolver, SsrfProtectionConfig, SsrfProtector, TenantHttpClient,
        is_blocked_ip, match_allowlisted_domain, request_body_len, same_origin,
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

#[tokio::test]
async fn ssrf_dns_resolver_validates_every_connector_resolution() {
    let resolver = SsrfDnsResolver::with_resolver(
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedRequest {
    method: String,
    path: String,
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
    handle: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn spawn<F>(max_requests: usize, handler: F) -> Self
    where F: Fn(usize, &RecordedRequest) -> TestResponse + Send + Sync + 'static {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        listener
            .set_nonblocking(false)
            .expect("configure test listener");
        let address = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded_requests = Arc::clone(&requests);
        let handler = Arc::new(handler);

        let handle = thread::spawn(move || {
            for request_index in 0..max_requests {
                let (mut stream, _) = listener.accept().expect("accept test connection");
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

    RecordedRequest {
        method,
        path,
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
                method: "POST".to_string(),
                path: "/start".to_string(),
                body: b"payload".to_vec(),
            },
            RecordedRequest {
                method: "POST".to_string(),
                path: "/final".to_string(),
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
