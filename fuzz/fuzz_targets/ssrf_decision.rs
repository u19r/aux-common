#![no_main]

use bg_jobs_http::ApprovedEndpoint;
use http_request::{AllowedDomain, TenantHttpClient};
use libfuzzer_sys::fuzz_target;
use url::Url;

// Structured decision oracle for SSRF destination policy.
//
// Registration-owned endpoints (`ApprovedEndpoint`) and tenant allowlists
// are the trust roots; job payloads and request URLs are attacker input.
// The oracle pins the structural contract of `matches`: an approval may
// only name the exact host or a dot-bounded subdomain on the exact port,
// userinfo and case and trailing dots must never change a verdict, and an
// explicit port must never match a differently-ported endpoint. Builder
// construction itself must never panic and must reject empty allowlists.
// DNS resolution timing (rebinding between validation and connect) is
// covered by the in-crate flipping-resolver simulation; the per-resolution
// IP table is pinned by the reserved-address corpus tests.
fn split_input(data: &[u8]) -> (String, String) {
    let text = String::from_utf8_lossy(data);
    let middle = text.len() / 2;
    let boundary = text.floor_char_boundary(middle);
    (text[..boundary].to_string(), text[boundary..].to_string())
}

fn with_userinfo(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    Some(format!("{scheme}://user:pass@{rest}"))
}

fn with_port(url: &str, port: u16) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let scheme = &url[..url.len() - rest.len() - 3];
    let suffix_start = rest
        .find(['/', '?', '#'])
        .map(|index| index + scheme.len() + 3);
    let (authority, suffix) = match suffix_start {
        Some(index) => (url[..index].to_string(), url[index..].to_string()),
        None => (url.to_string(), String::new()),
    };
    Some(format!("{authority}:{port}{suffix}"))
}

fn toggle_trailing_dot(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    if !host.is_ascii() {
        return None;
    }
    let scheme_end = url.find("://")? + 3;
    let host_end = scheme_end
        + url[scheme_end..]
            .find(['/', '?', '#', '@', ':'])
            .unwrap_or(url[scheme_end..].len());
    if host_end <= scheme_end {
        return None;
    }
    let mut toggled = url.to_string();
    if host.ends_with('.') {
        toggled.remove(host_end - 1);
    } else {
        toggled.insert(host_end, '.');
    }
    Some(toggled)
}

fn uppercased_host(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    Some(url.replacen(host, &host.to_ascii_uppercase(), 1))
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let (host_text, url_text) = split_input(data);
    let host_text = host_text.trim();
    if host_text.is_empty() || host_text.len() > 253 {
        return;
    }

    // Pin the builder boundary: empty allowlists always fail, construction
    // never panics.
    assert!(
        TenantHttpClient::new("tenant", Vec::new()).is_err(),
        "empty allowlist must fail closed"
    );
    let _ = TenantHttpClient::new("tenant", vec![AllowedDomain::exact(host_text)]);

    let endpoint = if data[0].is_multiple_of(2) {
        match ApprovedEndpoint::exact(host_text) {
            Ok(endpoint) => endpoint,
            Err(_) => return,
        }
    } else {
        match ApprovedEndpoint::with_subdomains(host_text) {
            Ok(endpoint) => endpoint,
            Err(_) => return,
        }
    };
    let url = match Url::parse(url_text.trim()) {
        Ok(url) => url,
        Err(_) => return,
    };
    let verdict = endpoint.matches(&url);

    // Port confusion: an explicit foreign port matches only a same-ported
    // endpoint.
    if let Some(ported) = with_port(url_text.trim(), 8443)
        && let Ok(ported_url) = Url::parse(&ported)
    {
        assert_eq!(
            endpoint.matches(&ported_url),
            endpoint.port() == 8443,
            "port verdict diverged for {ported}"
        );
    }

    if !verdict {
        return;
    }

    // An approval structurally binds the exact host or a dot-bounded
    // subdomain on the exact port. Byte-wise suffix checks require ASCII.
    let host = url.host_str().expect("matched URL has a host");
    assert!(
        !host.contains('@'),
        "userinfo leaked into matched host: {host}"
    );
    if host.is_ascii() && endpoint.host().is_ascii() {
        let expected = host.eq_ignore_ascii_case(endpoint.host())
            || (endpoint.allows_subdomains()
                && host.len() > endpoint.host().len() + 1
                && host[..host.len() - endpoint.host().len()].ends_with('.')
                && host[host.len() - endpoint.host().len()..]
                    .eq_ignore_ascii_case(endpoint.host()));
        assert!(expected, "approval escaped host binding: {host}");
    }
    assert_eq!(
        url.port_or_known_default(),
        Some(endpoint.port()),
        "approval escaped port binding"
    );

    // Normalization differentials: userinfo, case, and trailing dots must
    // never change an approval verdict.
    if let Some(userinfo_url) = with_userinfo(url_text.trim())
        && let Ok(parsed) = Url::parse(&userinfo_url)
    {
        assert_eq!(
            endpoint.matches(&parsed),
            verdict,
            "userinfo changed verdict for {userinfo_url}"
        );
    }
    if let Some(upper) = uppercased_host(url_text.trim())
        && let Ok(parsed) = Url::parse(&upper)
    {
        assert_eq!(
            endpoint.matches(&parsed),
            verdict,
            "case changed verdict for {upper}"
        );
    }
    let dotted = toggle_trailing_dot(url_text.trim());
    if let Some(dotted) = dotted
        && let Ok(parsed) = Url::parse(&dotted)
    {
        assert_eq!(
            endpoint.matches(&parsed),
            verdict,
            "trailing dot changed verdict for {dotted}"
        );
    }
});
