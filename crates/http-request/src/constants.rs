use std::time::Duration;

pub(crate) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) const DEFAULT_MAX_RETRIES: u32 = 3;
pub(crate) const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_millis(200);
pub(crate) const DEFAULT_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
pub(crate) const MAX_RETRY_EXPONENT: u32 = 10;

pub(crate) const DEFAULT_TENANT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const DEFAULT_TENANT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const DEFAULT_MAX_CONTENT_LENGTH_BYTES: usize = 256 * 1024;
pub(crate) const DEFAULT_MAX_RESPONSE_LENGTH_BYTES: usize = 256 * 1024;
pub(crate) const DEFAULT_MAX_ERROR_BODY_LENGTH_BYTES: usize = 256 * 1024;

pub(crate) const DEFAULT_MAX_REDIRECTS: usize = 5;
pub(crate) const DEFAULT_MAX_DNS_ADDRESSES: usize = 8;
pub(crate) const DEFAULT_ALLOWED_SCHEMES: &[&str] = &["https"];
pub(crate) const DEFAULT_ALLOWED_PORTS: &[u16] = &[443];
pub(crate) const DEFAULT_HTTPS_PORT: u16 = 443;

pub(crate) const LABEL_METHOD: &str = "method";
pub(crate) const LABEL_STATUS_CLASS: &str = "status_class";
pub(crate) const LABEL_OUTCOME: &str = "outcome";

pub(crate) const OUTCOME_SUCCESS: &str = "success";
pub(crate) const OUTCOME_ERROR: &str = "error";
pub(crate) const OUTCOME_RETRY: &str = "retry";

pub(crate) const STATUS_CLASS_2XX: &str = "2xx";
pub(crate) const STATUS_CLASS_3XX: &str = "3xx";
pub(crate) const STATUS_CLASS_4XX: &str = "4xx";
pub(crate) const STATUS_CLASS_5XX: &str = "5xx";
pub(crate) const STATUS_CLASS_ERROR: &str = "error";

pub(crate) const REDIRECT_BLOCKED_METHOD_CHANGE: &str = "redirect_method_change";
pub(crate) const REDIRECT_BLOCKED_HOST_MISMATCH: &str = "redirect_host_mismatch";
pub(crate) const REDIRECT_BLOCKED_SCHEME_CHANGE: &str = "redirect_scheme_change";
pub(crate) const REDIRECT_BLOCKED_TOO_MANY: &str = "redirect_limit_exceeded";

pub(crate) const SSRF_BLOCKED_DOMAIN_NOT_ALLOWLISTED: &str = "domain_not_allowlisted";
pub(crate) const SSRF_BLOCKED_RESERVED_IP: &str = "reserved_ip";
pub(crate) const SSRF_BLOCKED_IP_LITERAL: &str = "ip_literal_host";
pub(crate) const SSRF_BLOCKED_MISSING_HOST: &str = "missing_host";
pub(crate) const SSRF_BLOCKED_DNS_FAILURE: &str = "dns_resolution_failed";
pub(crate) const SSRF_BLOCKED_DNS_EMPTY: &str = "dns_resolution_empty";
pub(crate) const SSRF_BLOCKED_DNS_TIMEOUT: &str = "dns_resolution_timeout";
pub(crate) const SSRF_BLOCKED_SCHEME: &str = "disallowed_scheme";
pub(crate) const SSRF_BLOCKED_USERINFO: &str = "user_info_not_allowed";
pub(crate) const SSRF_BLOCKED_FRAGMENT: &str = "fragment_not_allowed";
pub(crate) const SSRF_BLOCKED_PORT: &str = "disallowed_port";
pub(crate) const SSRF_BLOCKED_HOST_HEADER: &str = "host_header_override";
