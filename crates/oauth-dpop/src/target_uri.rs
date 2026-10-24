use http::Uri;

use crate::{DpopError, constants::MAX_URI_BYTES};

/// Validated ASCII HTTPS target with RFC 3986 path normalization and no
/// query/fragment.
#[derive(Clone, PartialEq, Eq)]
pub struct DpopTargetUri {
    encoded: String,
    authority: String,
}

impl TryFrom<&str> for DpopTargetUri {
    type Error = DpopError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > MAX_URI_BYTES
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte <= 32 || byte == 127 || byte == b'\\')
        {
            return Err(DpopError::InvalidTarget);
        }
        let without_fragment = value.split('#').next().ok_or(DpopError::InvalidTarget)?;
        let uri: Uri = without_fragment
            .parse()
            .map_err(|_| DpopError::InvalidTarget)?;
        if !uri
            .scheme_str()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
        {
            return Err(DpopError::InvalidTarget);
        }
        let authority = normalize_authority(uri.authority().ok_or(DpopError::InvalidTarget)?)?;
        let path = normalize_path(uri.path())?;
        Ok(Self {
            encoded: format!("https://{authority}{path}"),
            authority,
        })
    }
}

impl DpopTargetUri {
    /// Configuration cannot embed request query parameters or a fragment.
    pub fn parse_base(value: &str) -> Result<Self, DpopError> {
        if value.contains(['?', '#']) {
            return Err(DpopError::InvalidTarget);
        }
        Self::try_from(value)
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Resolve a listener request beneath its explicit public base.
    /// Absolute-form requests must already be within that base and retain
    /// their original normalized path.
    pub fn resolve_request_uri(&self, uri: &http::Uri) -> Result<Self, DpopError> {
        if uri.scheme().is_none() {
            return self.join_path(uri.path());
        }
        let target = Self::try_from(uri.to_string().as_str())?;
        let prefix = self.encoded.strip_suffix('/').unwrap_or(&self.encoded);
        if target.authority != self.authority
            || !(target.as_str() == prefix || target.as_str().starts_with(&format!("{prefix}/")))
        {
            return Err(DpopError::InvalidTarget);
        }
        Ok(target)
    }

    pub fn join_path(&self, path: &str) -> Result<Self, DpopError> {
        if !path.starts_with('/') {
            return Err(DpopError::InvalidTarget);
        }
        Self::try_from(
            format!(
                "{}/{}",
                self.encoded.strip_suffix('/').unwrap_or(&self.encoded),
                path.strip_prefix('/').ok_or(DpopError::InvalidTarget)?
            )
            .as_str(),
        )
    }
}

impl std::fmt::Debug for DpopTargetUri {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DpopTargetUri([REDACTED])")
    }
}

fn normalize_path(path: &str) -> Result<String, DpopError> {
    let decoded = normalize_percent(path)?;
    let mut segments = Vec::new();
    let mut parts = decoded.split('/').peekable();
    while let Some(segment) = parts.next() {
        match segment {
            "." => {
                if parts.peek().is_none() {
                    segments.push("");
                }
            }
            ".." => {
                if segments.len() > 1 {
                    segments.pop();
                }
                if parts.peek().is_none() {
                    segments.push("");
                }
            }
            _ => segments.push(segment),
        }
    }
    let normalized = segments.join("/");
    Ok(if normalized.is_empty() {
        "/".to_owned()
    } else {
        normalized
    })
}

fn normalize_percent(path: &str) -> Result<String, DpopError> {
    let mut result = String::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            result.push(char::from(byte));
            continue;
        }
        let high = bytes
            .next()
            .and_then(parse_hex_value)
            .ok_or(DpopError::InvalidTarget)?;
        let low = bytes
            .next()
            .and_then(parse_hex_value)
            .ok_or(DpopError::InvalidTarget)?;
        let decoded = high * 16 + low;
        if decoded.is_ascii_alphanumeric() || b"-._~".contains(&decoded) {
            result.push(char::from(decoded));
        } else {
            result.push('%');
            result.push(char::from(b"0123456789ABCDEF"[usize::from(high)]));
            result.push(char::from(b"0123456789ABCDEF"[usize::from(low)]));
        }
    }
    Ok(result)
}

fn parse_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn normalize_authority(authority: &http::uri::Authority) -> Result<String, DpopError> {
    if authority.as_str().contains('@') || authority.host().is_empty() {
        return Err(DpopError::InvalidTarget);
    }
    let host = authority.host().to_ascii_lowercase();
    if host.starts_with('[') {
        let address = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .ok_or(DpopError::InvalidTarget)?;
        address
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| DpopError::InvalidTarget)?;
    } else if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
    {
        return Err(DpopError::InvalidTarget);
    }
    let suffix = authority
        .as_str()
        .strip_prefix(authority.host())
        .ok_or(DpopError::InvalidTarget)?;
    let port = parse_port(suffix)?;
    Ok(match port {
        None | Some(443) => host,
        Some(port) => format!("{host}:{port}"),
    })
}

fn parse_port(suffix: &str) -> Result<Option<u16>, DpopError> {
    if suffix.is_empty() {
        return Ok(None);
    }
    let digits = suffix
        .strip_prefix(':')
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(DpopError::InvalidTarget)?;
    digits
        .parse::<u16>()
        .map(Some)
        .map_err(|_| DpopError::InvalidTarget)
}
