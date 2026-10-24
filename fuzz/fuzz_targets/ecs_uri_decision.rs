#![no_main]

use aws_credentials::validate_ecs_full_uri;
use libfuzzer_sys::fuzz_target;
use url::Url;

// Structured decision oracle for ECS credential-endpoint validation.
//
// The full URI comes from the environment, so its shape decides where
// container credentials are fetched from. The oracle pins the exact policy:
// plain HTTP is confined to the ECS metadata address, loopback, and
// localhost, while HTTPS may address any host. Any accepted HTTP
// destination outside that set would send credential requests to an
// attacker-influenced endpoint.
fn http_host_allowed(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => {
            address == std::net::Ipv4Addr::new(169, 254, 170, 2) || address.is_loopback()
        }
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(url) = Url::parse(text.trim()) else {
        return;
    };
    if validate_ecs_full_uri(&url).is_ok() {
        assert!(
            url.scheme() == "https" || (url.scheme() == "http" && http_host_allowed(&url)),
            "credential endpoint escaped transport policy: {text:?}"
        );
    }
});
