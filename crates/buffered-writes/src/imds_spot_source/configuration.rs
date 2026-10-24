use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::LifecycleError;

pub(super) fn parse_endpoint(endpoint: &str) -> Result<String, LifecycleError> {
    let endpoint = Url::parse(endpoint).map_err(|_| LifecycleError::InvalidConfiguration {
        reason: "IMDS endpoint is invalid",
    })?;
    if !has_metadata_origin(&endpoint)
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
    {
        return Err(LifecycleError::InvalidConfiguration {
            reason: "IMDS endpoint must be a metadata or loopback IP with no credentials, path, \
                     query or fragment",
        });
    }
    Ok(endpoint.as_str().trim_end_matches('/').to_owned())
}

fn has_metadata_origin(endpoint: &Url) -> bool {
    endpoint.scheme() == "http"
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
        && has_allowed_address(endpoint)
}

fn has_allowed_address(endpoint: &Url) -> bool {
    match endpoint.host() {
        Some(Host::Ipv4(address)) => {
            address.is_loopback() || address == Ipv4Addr::new(169, 254, 169, 254)
        }
        Some(Host::Ipv6(address)) => {
            address.is_loopback() || address == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)
        }
        Some(Host::Domain(_)) | None => false,
    }
}
