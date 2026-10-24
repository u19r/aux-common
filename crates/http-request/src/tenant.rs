use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, OnceLock},
    time::Duration,
};

use http::HeaderMap;
use ipnet::IpNet;
use reqwest::{
    Method, Request, RequestBuilder, StatusCode, Url,
    dns::{Addrs, Name, Resolve, Resolving},
};
use tokio::net::lookup_host;

use crate::{
    client::HttpClient,
    constants::{
        DEFAULT_ALLOWED_PORTS, DEFAULT_ALLOWED_SCHEMES, DEFAULT_HTTPS_PORT,
        DEFAULT_MAX_CONTENT_LENGTH_BYTES, DEFAULT_MAX_DNS_ADDRESSES, DEFAULT_MAX_REDIRECTS,
        DEFAULT_MAX_RESPONSE_LENGTH_BYTES, DEFAULT_TENANT_CONNECT_TIMEOUT,
        DEFAULT_TENANT_REQUEST_TIMEOUT, REDIRECT_BLOCKED_HOST_MISMATCH,
        REDIRECT_BLOCKED_METHOD_CHANGE, REDIRECT_BLOCKED_SCHEME_CHANGE, REDIRECT_BLOCKED_TOO_MANY,
        RESERVED_IP_RANGES, SSRF_BLOCKED_DNS_EMPTY, SSRF_BLOCKED_DNS_FAILURE,
        SSRF_BLOCKED_DNS_TIMEOUT, SSRF_BLOCKED_DOMAIN_NOT_ALLOWLISTED, SSRF_BLOCKED_FRAGMENT,
        SSRF_BLOCKED_HOST_HEADER, SSRF_BLOCKED_IP_LITERAL, SSRF_BLOCKED_MISSING_HOST,
        SSRF_BLOCKED_PORT, SSRF_BLOCKED_RESERVED_IP, SSRF_BLOCKED_SCHEME, SSRF_BLOCKED_USERINFO,
    },
    error::{HttpRequestError, Result},
    observer::HttpRequestObserver,
    response::HttpResponse,
    retry::RetryConfig,
};

#[derive(Clone)]
pub struct AllowedDomain {
    pub host: String,
    pub allow_subdomains: bool,
}

impl std::fmt::Debug for AllowedDomain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AllowedDomain")
            .field("host_present", &true)
            .field("allow_subdomains", &self.allow_subdomains)
            .finish()
    }
}

impl AllowedDomain {
    pub fn exact(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            allow_subdomains: false,
        }
    }

    pub fn with_subdomains(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            allow_subdomains: true,
        }
    }
}

impl From<&str> for AllowedDomain {
    fn from(value: &str) -> Self {
        Self::exact(value)
    }
}

#[derive(Debug, Clone)]
pub struct TenantHttpRequestConfig {
    pub allowed_domains: Vec<AllowedDomain>,
    pub max_content_length: usize,
    pub max_response_length: usize,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub max_redirects: usize,
    pub allowed_schemes: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub max_dns_addresses: usize,
    pub allow_loopback_ips: bool,
}

impl Default for TenantHttpRequestConfig {
    fn default() -> Self {
        Self {
            allowed_domains: Vec::new(),
            max_content_length: DEFAULT_MAX_CONTENT_LENGTH_BYTES,
            max_response_length: DEFAULT_MAX_RESPONSE_LENGTH_BYTES,
            timeout: DEFAULT_TENANT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_TENANT_CONNECT_TIMEOUT,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            allowed_schemes: DEFAULT_ALLOWED_SCHEMES
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            allowed_ports: DEFAULT_ALLOWED_PORTS.to_vec(),
            max_dns_addresses: DEFAULT_MAX_DNS_ADDRESSES,
            allow_loopback_ips: false,
        }
    }
}

#[derive(Clone)]
pub struct TenantHttpClient {
    tenant_id: String,
    config: TenantHttpRequestConfig,
    http: HttpClient,
    ssrf: Arc<SsrfProtector>,
}

pub struct TenantHttpClientBuilder {
    tenant_id: String,
    config: TenantHttpRequestConfig,
    retry: RetryConfig,
    resolver: Arc<dyn Resolve>,
    observer: Option<Arc<dyn HttpRequestObserver>>,
    #[cfg(any(test, feature = "test-support"))]
    test_certificates: Vec<reqwest::Certificate>,
}

impl TenantHttpClientBuilder {
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            config: TenantHttpRequestConfig::default(),
            retry: RetryConfig::default(),
            resolver: Arc::new(TokioDnsResolver),
            observer: None,
            #[cfg(any(test, feature = "test-support"))]
            test_certificates: Vec::new(),
        }
    }

    #[must_use]
    pub fn allowlist(mut self, domains: Vec<AllowedDomain>) -> Self {
        self.config.allowed_domains = domains;
        self
    }

    #[must_use]
    pub fn add_domain(mut self, domain: AllowedDomain) -> Self {
        self.config.allowed_domains.push(domain);
        self
    }

    #[must_use]
    pub fn max_content_length(mut self, bytes: usize) -> Self {
        self.config.max_content_length = bytes;
        self
    }

    #[must_use]
    pub fn max_response_length(mut self, bytes: usize) -> Self {
        self.config.max_response_length = bytes;
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    #[must_use]
    pub fn max_redirects(mut self, max_redirects: usize) -> Self {
        self.config.max_redirects = max_redirects;
        self
    }

    #[must_use]
    pub fn allowed_schemes(mut self, schemes: Vec<String>) -> Self {
        self.config.allowed_schemes = schemes;
        self
    }

    #[must_use]
    pub fn allowed_ports(mut self, ports: Vec<u16>) -> Self {
        self.config.allowed_ports = ports;
        self
    }

    #[must_use]
    pub fn max_dns_addresses(mut self, max: usize) -> Self {
        self.config.max_dns_addresses = max;
        self
    }

    #[must_use]
    pub fn allow_loopback_ips(mut self, allow: bool) -> Self {
        self.config.allow_loopback_ips = allow;
        self
    }

    #[must_use]
    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.retry = retry;
        self
    }

    #[must_use]
    pub fn with_observer<O>(mut self, observer: O) -> Self
    where O: HttpRequestObserver {
        self.observer = Some(Arc::new(observer));
        self
    }

    #[must_use]
    pub fn with_shared_observer(mut self, observer: Arc<dyn HttpRequestObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Supply deterministic test DNS while retaining destination and address
    /// validation.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn test_dns_resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Trust a fixture CA without disabling certificate or hostname
    /// verification.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn test_root_certificate(mut self, certificate: reqwest::Certificate) -> Self {
        self.test_certificates.push(certificate);
        self
    }

    pub fn build(self) -> Result<TenantHttpClient> {
        if self.config.allowed_domains.is_empty() {
            return Err(HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_DOMAIN_NOT_ALLOWLISTED,
            });
        }

        let ssrf_config = SsrfProtectionConfig {
            allowed_schemes: self.config.allowed_schemes.clone(),
            allowed_ports: self.config.allowed_ports.clone(),
            max_dns_addresses: self.config.max_dns_addresses,
            allow_loopback_ips: self.config.allow_loopback_ips,
            dns_timeout: self.config.timeout,
        };
        let ssrf = Arc::new(SsrfProtector::with_resolver(ssrf_config, self.resolver));
        let client = reqwest::Client::builder()
            .timeout(self.config.timeout)
            .connect_timeout(self.config.connect_timeout)
            // Keep proxy resolution outside the tenant SSRF trust boundary.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .dns_resolver(Arc::clone(&ssrf));
        #[cfg(any(test, feature = "test-support"))]
        let client = self
            .test_certificates
            .into_iter()
            .fold(client, |builder, certificate| {
                builder.add_root_certificate(certificate)
            });
        let client = client.build().map_err(|_| HttpRequestError::Build)?;

        let http = HttpClient::with_client_and_observer(client, self.retry, self.observer);

        Ok(TenantHttpClient {
            tenant_id: self.tenant_id,
            config: self.config,
            http,
            ssrf,
        })
    }
}

impl TenantHttpClient {
    pub fn builder(tenant_id: impl Into<String>) -> TenantHttpClientBuilder {
        TenantHttpClientBuilder::new(tenant_id)
    }

    pub fn new(tenant_id: impl Into<String>, allowed_domains: Vec<AllowedDomain>) -> Result<Self> {
        TenantHttpClientBuilder::new(tenant_id)
            .allowlist(allowed_domains)
            .build()
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn request<U: reqwest::IntoUrl>(&self, method: Method, url: U) -> TenantRequestBuilder {
        TenantRequestBuilder::new(self.clone(), self.http.inner().request(method, url))
    }

    pub fn get<U: reqwest::IntoUrl>(&self, url: U) -> TenantRequestBuilder {
        TenantRequestBuilder::new(self.clone(), self.http.inner().get(url))
    }

    pub fn post<U: reqwest::IntoUrl>(&self, url: U) -> TenantRequestBuilder {
        TenantRequestBuilder::new(self.clone(), self.http.inner().post(url))
    }

    pub fn put<U: reqwest::IntoUrl>(&self, url: U) -> TenantRequestBuilder {
        TenantRequestBuilder::new(self.clone(), self.http.inner().put(url))
    }

    pub fn patch<U: reqwest::IntoUrl>(&self, url: U) -> TenantRequestBuilder {
        TenantRequestBuilder::new(self.clone(), self.http.inner().patch(url))
    }

    pub fn delete<U: reqwest::IntoUrl>(&self, url: U) -> TenantRequestBuilder {
        TenantRequestBuilder::new(self.clone(), self.http.inner().delete(url))
    }

    pub async fn execute_request(&self, builder: RequestBuilder) -> Result<HttpResponse> {
        let request = builder.build().map_err(|_| HttpRequestError::Build)?;
        self.execute(request).await
    }

    pub async fn execute(&self, request: Request) -> Result<HttpResponse> {
        if request.headers().contains_key(reqwest::header::HOST) {
            return Err(HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_HOST_HEADER,
            });
        }
        validate_request_size(&request, self.config.max_content_length)?;
        let mut current = request;
        let mut redirects = 0usize;

        loop {
            let url = current.url().clone();
            self.validate_url(&url).await?;

            let current_clone = current.try_clone();
            if current_clone.is_none() {
                let response = self.http.execute(current).await?;
                if response.status().is_redirection() {
                    return Err(HttpRequestError::RequestNotCloneable);
                }
                return Ok(response.with_max_body_size(Some(self.config.max_response_length)));
            }

            let response = self
                .http
                .execute(current_clone.ok_or(HttpRequestError::RequestNotCloneable)?)
                .await?;
            if !response.status().is_redirection() {
                return Ok(response.with_max_body_size(Some(self.config.max_response_length)));
            }

            if redirects >= self.config.max_redirects {
                return Err(HttpRequestError::RedirectBlocked {
                    reason: REDIRECT_BLOCKED_TOO_MANY,
                });
            }

            let status = response.status();
            if status != StatusCode::TEMPORARY_REDIRECT && status != StatusCode::PERMANENT_REDIRECT
            {
                return Err(HttpRequestError::RedirectBlocked {
                    reason: REDIRECT_BLOCKED_METHOD_CHANGE,
                });
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(HttpRequestError::RedirectBlocked {
                    reason: REDIRECT_BLOCKED_METHOD_CHANGE,
                })?;

            let next_url = url
                .join(location)
                .map_err(|_| HttpRequestError::InvalidUrl)?;

            let mut next_request = current
                .try_clone()
                .ok_or(HttpRequestError::RequestNotCloneable)?;
            *next_request.url_mut() = next_url.clone();

            if !same_origin(&url, &next_url) {
                let reason = if !same_host_and_port(&url, &next_url) {
                    REDIRECT_BLOCKED_HOST_MISMATCH
                } else {
                    REDIRECT_BLOCKED_SCHEME_CHANGE
                };
                return Err(HttpRequestError::RedirectBlocked { reason });
            }

            current = next_request;
            redirects += 1;
        }
    }

    async fn validate_url(&self, url: &Url) -> Result<()> {
        let host = url.host_str().ok_or(HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_MISSING_HOST,
        })?;

        if let Some(host_value) = url.host() {
            let ip_literal = match host_value {
                url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
                url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
                url::Host::Domain(_) => None,
            };
            if let Some(ip) = ip_literal
                && !(self.config.allow_loopback_ips && ip.is_loopback())
            {
                return Err(HttpRequestError::SsrfBlocked {
                    reason: SSRF_BLOCKED_IP_LITERAL,
                });
            }
        }

        if match_allowlisted_domain(host, &self.config.allowed_domains).is_none() {
            return Err(HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_DOMAIN_NOT_ALLOWLISTED,
            });
        }

        self.ssrf.resolve_and_validate(url).await?;
        Ok(())
    }
}

pub struct TenantRequestBuilder {
    client: TenantHttpClient,
    inner: RequestBuilder,
}

impl TenantRequestBuilder {
    fn new(client: TenantHttpClient, inner: RequestBuilder) -> Self {
        Self { client, inner }
    }

    #[must_use]
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        reqwest::header::HeaderName: TryFrom<K>,
        <reqwest::header::HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        reqwest::header::HeaderValue: TryFrom<V>,
        <reqwest::header::HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.inner = self.inner.header(key, value);
        self
    }

    #[must_use]
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.inner = self.inner.headers(headers);
        self
    }

    #[must_use]
    pub fn query<T: serde::Serialize + ?Sized>(mut self, query: &T) -> Self {
        self.inner = self.inner.query(query);
        self
    }

    #[must_use]
    pub fn json<T: serde::Serialize + ?Sized>(mut self, json: &T) -> Self {
        self.inner = self.inner.json(json);
        self
    }

    #[must_use]
    pub fn form<T: serde::Serialize + ?Sized>(mut self, form: &T) -> Self {
        self.inner = self.inner.form(form);
        self
    }

    #[must_use]
    pub fn body<B: Into<reqwest::Body>>(mut self, body: B) -> Self {
        self.inner = self.inner.body(body);
        self
    }

    #[must_use]
    pub fn bearer_auth<T: std::fmt::Display>(mut self, token: T) -> Self {
        self.inner = self.inner.bearer_auth(token);
        self
    }

    #[must_use]
    pub fn basic_auth<U, P>(mut self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display,
    {
        self.inner = self.inner.basic_auth(username, password);
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub async fn send(self) -> Result<HttpResponse> {
        self.client.execute_request(self.inner).await
    }
}

#[derive(Clone)]
pub(crate) struct SsrfProtectionConfig {
    pub(crate) allowed_schemes: Vec<String>,
    pub(crate) allowed_ports: Vec<u16>,
    pub(crate) max_dns_addresses: usize,
    pub(crate) allow_loopback_ips: bool,
    pub(crate) dns_timeout: Duration,
}

#[derive(Clone, Copy)]
struct TokioDnsResolver;

impl Resolve for TokioDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // Keep Tokio's DNS iterator lazy so callers apply their address
            // cap before materializing a result vector.
            let addrs = lookup_host((host, 0)).await?;
            Ok(Box::new(addrs) as Addrs)
        })
    }
}

#[derive(Clone)]
pub(crate) struct SsrfProtector {
    config: SsrfProtectionConfig,
    resolver: Arc<dyn Resolve>,
}

impl SsrfProtector {
    #[cfg(test)]
    pub(crate) fn new(config: SsrfProtectionConfig) -> Self {
        Self::with_resolver(config, Arc::new(TokioDnsResolver))
    }

    pub(crate) fn with_resolver(config: SsrfProtectionConfig, resolver: Arc<dyn Resolve>) -> Self {
        Self { config, resolver }
    }

    fn resolve_capped(&self, name: Name) -> Resolving {
        let resolving = self.resolver.resolve(name);
        let max_dns_addresses = self.config.max_dns_addresses;
        let allow_loopback_ips = self.config.allow_loopback_ips;
        Box::pin(async move {
            let mut addrs = resolving.await?.take(max_dns_addresses).collect::<Vec<_>>();
            validate_resolved_addresses(&mut addrs, allow_loopback_ips)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }

    fn validate_url_syntax(&self, url: &Url) -> Result<()> {
        if !self
            .config
            .allowed_schemes
            .iter()
            .any(|scheme| scheme.eq_ignore_ascii_case(url.scheme()))
        {
            return Err(HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_SCHEME,
            });
        }

        if url.username() != "" || url.password().is_some() {
            return Err(HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_USERINFO,
            });
        }

        if url.fragment().is_some() {
            return Err(HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_FRAGMENT,
            });
        }

        let port = url.port_or_known_default().unwrap_or(DEFAULT_HTTPS_PORT);
        if !self.config.allowed_ports.contains(&port) {
            return Err(HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_PORT,
            });
        }

        Ok(())
    }

    pub(crate) async fn resolve_and_validate(&self, url: &Url) -> Result<()> {
        self.validate_url_syntax(url)?;
        let host = url.host_str().ok_or(HttpRequestError::SsrfBlocked {
            reason: SSRF_BLOCKED_MISSING_HOST,
        })?;

        // Tokio's zero-duration timeout is allowed to poll an immediately
        // ready future once before observing the deadline.  Treat a zero DNS
        // budget as an explicit fail-closed configuration so a local cache or
        // resolver cannot bypass the caller's safety boundary.
        if self.config.dns_timeout.is_zero() {
            return Err(HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_DNS_TIMEOUT,
            });
        }

        let name = host
            .parse::<Name>()
            .map_err(|_| HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_DNS_FAILURE,
            })?;
        // `resolve_capped` materializes only the bounded, validated result;
        // preflight only needs to consume that proof, not copy it again.
        let _ = tokio::time::timeout(self.config.dns_timeout, self.resolve_capped(name))
            .await
            .map_err(|_| HttpRequestError::SsrfBlocked {
                reason: SSRF_BLOCKED_DNS_TIMEOUT,
            })?
            .map_err(|error| HttpRequestError::SsrfBlocked {
                reason: error
                    .downcast_ref::<SsrfResolutionError>()
                    .map_or(SSRF_BLOCKED_DNS_FAILURE, |error| error.reason()),
            })?;
        Ok(())
    }
}

impl Resolve for SsrfProtector {
    fn resolve(&self, name: Name) -> Resolving {
        self.resolve_capped(name)
    }
}

#[derive(Clone, Copy, Debug)]
enum SsrfResolutionError {
    Empty,
    Reserved,
}

impl SsrfResolutionError {
    const fn reason(self) -> &'static str {
        match self {
            Self::Empty => SSRF_BLOCKED_DNS_EMPTY,
            Self::Reserved => SSRF_BLOCKED_RESERVED_IP,
        }
    }
}

impl std::fmt::Display for SsrfResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason())
    }
}

impl std::error::Error for SsrfResolutionError {}

fn validate_resolved_addresses(
    addrs: &mut Vec<SocketAddr>,
    allow_loopback_ips: bool,
) -> std::result::Result<(), SsrfResolutionError> {
    if addrs.is_empty() {
        return Err(SsrfResolutionError::Empty);
    }

    addrs.sort_by_key(SocketAddr::ip);
    addrs.dedup();
    if addrs
        .iter()
        .any(|addr| is_blocked_ip(addr.ip(), allow_loopback_ips))
    {
        return Err(SsrfResolutionError::Reserved);
    }
    Ok(())
}

fn validate_request_size(request: &Request, max: usize) -> Result<()> {
    let size = request_body_len(request);
    match size {
        Some(size) if size > max => Err(HttpRequestError::RequestTooLarge { size, max }),
        Some(_) => Ok(()),
        None => Err(HttpRequestError::RequestSizeUnknown { max }),
    }
}

pub(crate) fn request_body_len(request: &Request) -> Option<usize> {
    if request.body().is_none() {
        return Some(0);
    }
    if let Some(body) = request.body()
        && let Some(bytes) = body.as_bytes()
    {
        return Some(bytes.len());
    }

    // A streaming body has no inspectable byte length at this boundary.  Do
    // not trust a caller-supplied Content-Length: reqwest/hyper will enforce
    // framing only after this preflight has already decided whether dispatch
    // is allowed, so a forged smaller header would otherwise bypass the
    // tenant's configured request budget.
    None
}

pub(crate) fn is_blocked_ip(ip: IpAddr, allow_loopback_ips: bool) -> bool {
    if allow_loopback_ips && ip.is_loopback() {
        return false;
    }
    if let IpAddr::V6(ipv6) = ip {
        // Normalize IPv4-compatible and mapped forms before applying the
        // shared IPv4 reserved-range policy.
        if let Some(ipv4) = ipv6.to_ipv4().or_else(|| isatap_ipv4(ipv6)) {
            return is_blocked_ip(IpAddr::V4(ipv4), allow_loopback_ips);
        }
        if let Some(ipv4) = well_known_nat64_ipv4(ipv6) {
            return is_blocked_ip(IpAddr::V4(ipv4), allow_loopback_ips);
        }
    }
    reserved_ip_ranges().iter().any(|range| range.contains(&ip))
}

fn isatap_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    // ISATAP uses a modified EUI-64 identifier: 00-00-5e-fe followed by IPv4.
    let segments = ip.segments();
    (segments[5] == 0x5efe && (segments[4] & 0xfcff) == 0).then(|| {
        let octets = ip.octets();
        Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15])
    })
}

fn well_known_nat64_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    (segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0]).then(|| {
        let octets = ip.octets();
        Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15])
    })
}

pub(crate) fn match_allowlisted_domain<'a>(
    host: &str,
    domains: &'a [AllowedDomain],
) -> Option<&'a AllowedDomain> {
    let host = host.to_ascii_lowercase();
    let mut best: Option<&AllowedDomain> = None;

    for domain in domains {
        let candidate = domain.host.to_ascii_lowercase();
        let matches = if domain.allow_subdomains {
            host == candidate || host.ends_with(&format!(".{candidate}"))
        } else {
            host == candidate
        };
        if !matches {
            continue;
        }
        best = match best {
            None => Some(domain),
            Some(current) => {
                if domain.host.len() > current.host.len() {
                    Some(domain)
                } else {
                    Some(current)
                }
            }
        };
    }

    best
}

fn same_host_and_port(left: &Url, right: &Url) -> bool {
    left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

pub(crate) fn same_origin(left: &Url, right: &Url) -> bool {
    same_host_and_port(left, right) && left.scheme() == right.scheme()
}

fn reserved_ip_ranges() -> &'static [IpNet] {
    static RANGES: OnceLock<Vec<IpNet>> = OnceLock::new();
    RANGES.get_or_init(|| {
        RESERVED_IP_RANGES
            .iter()
            .filter_map(|range| range.parse::<IpNet>().ok())
            .collect()
    })
}
