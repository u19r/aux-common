use std::fmt::Write as _;

use http::{HeaderMap, HeaderValue, Uri, header::HOST};

use super::encoding::canonical_path;
use crate::SigningError;

pub(super) struct CanonicalHeaders {
    pub(super) names: String,
    values: String,
}

impl TryFrom<&HeaderMap> for CanonicalHeaders {
    type Error = SigningError;

    fn try_from(headers: &HeaderMap) -> Result<Self, Self::Error> {
        let mut names: Vec<_> = headers
            .keys()
            .map(http::HeaderName::as_str)
            .filter(|name| {
                ![
                    "authorization",
                    "user-agent",
                    "x-amzn-trace-id",
                    "transfer-encoding",
                ]
                .contains(name)
            })
            .collect();
        names.sort_unstable();
        let mut values = String::new();
        for name in &names {
            let joined = headers
                .get_all(*name)
                .iter()
                .map(|value| {
                    let value = value
                        .to_str()
                        .map_err(|_| SigningError::InvalidHeaderValue)?;
                    Ok(value
                        .split(' ')
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        .join(" "))
                })
                .collect::<Result<Vec<_>, SigningError>>()?
                .join(",");
            let _ = writeln!(values, "{name}:{joined}");
        }
        Ok(Self {
            names: names.join(";"),
            values,
        })
    }
}

impl CanonicalHeaders {
    pub(super) fn request(&self, request: CanonicalRequest<'_>) -> String {
        let path = canonical_path(request.uri.path(), request.is_s3);
        format!(
            "{}\n{path}\n{}\n{}\n{}\n{}",
            request.method, request.query, self.values, self.names, request.payload_hash
        )
    }
}

#[derive(Clone, Copy)]
pub(super) struct CanonicalRequest<'a> {
    pub(super) method: &'a str,
    pub(super) uri: &'a Uri,
    pub(super) query: &'a str,
    pub(super) payload_hash: &'a str,
    pub(super) is_s3: bool,
}

pub(super) fn prepare_headers(uri: &Uri, base: &HeaderMap) -> Result<HeaderMap, SigningError> {
    if uri.scheme_str() != Some("https") {
        return Err(SigningError::InsecureTransport);
    }
    let authority = uri.authority().ok_or(SigningError::InvalidUri)?;
    if authority.as_str().contains('@') {
        return Err(SigningError::InvalidUri);
    }
    let mut headers = base.clone();
    if !headers.contains_key(HOST) {
        let authority = authority.as_str();
        let host = authority.strip_suffix(":443").unwrap_or(authority);
        let value = HeaderValue::from_str(host).map_err(|_| SigningError::InvalidHeaderValue)?;
        headers.insert(HOST, value);
    }
    Ok(headers)
}
