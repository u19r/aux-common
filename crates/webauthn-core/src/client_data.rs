use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::de::{self, MapAccess, Visitor};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{WebAuthnError, types::RpPolicy};

const MAX_CLIENT_DATA_BYTES: usize = 16 * 1024;

#[derive(Debug)]
struct ClientDataFields {
    ceremony_type: String,
    challenge: String,
    origin: String,
    cross_origin: bool,
    top_origin: Option<String>,
}

impl<'de> serde::Deserialize<'de> for ClientDataFields {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        struct FieldsVisitor;

        impl<'de> Visitor<'de> for FieldsVisitor {
            type Value = ClientDataFields;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a WebAuthn client-data JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where A: MapAccess<'de> {
                let mut seen = std::collections::HashSet::new();
                let mut ceremony_type = None;
                let mut challenge = None;
                let mut origin = None;
                let mut cross_origin = None;
                let mut top_origin = None;
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate client-data member"));
                    }
                    match key.as_str() {
                        "type" => ceremony_type = Some(map.next_value()?),
                        "challenge" => challenge = Some(map.next_value()?),
                        "origin" => origin = Some(map.next_value()?),
                        "crossOrigin" => cross_origin = Some(map.next_value()?),
                        "topOrigin" => top_origin = Some(map.next_value()?),
                        _ => {
                            let _: de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(ClientDataFields {
                    ceremony_type: ceremony_type.ok_or_else(|| de::Error::missing_field("type"))?,
                    challenge: challenge.ok_or_else(|| de::Error::missing_field("challenge"))?,
                    origin: origin.ok_or_else(|| de::Error::missing_field("origin"))?,
                    cross_origin: cross_origin
                        .ok_or_else(|| de::Error::missing_field("crossOrigin"))?,
                    top_origin,
                })
            }
        }

        deserializer.deserialize_map(FieldsVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientData {
    pub ceremony_type: String,
    pub challenge: String,
    pub origin: String,
    pub cross_origin: bool,
    pub top_origin: Option<String>,
}

pub fn parse_client_data(
    bytes: &[u8],
    expected_type: &str,
    policy: &RpPolicy,
) -> Result<ClientData, WebAuthnError> {
    if bytes.is_empty() || bytes.len() > MAX_CLIENT_DATA_BYTES {
        return Err(WebAuthnError::ClientData);
    }
    let fields: ClientDataFields =
        serde_json::from_slice(bytes).map_err(|_| WebAuthnError::ClientData)?;
    if fields.ceremony_type != expected_type {
        return Err(WebAuthnError::ClientData);
    }
    let expected_challenge = URL_SAFE_NO_PAD
        .decode(policy.expected_challenge_b64().as_bytes())
        .map_err(|_| WebAuthnError::ClientData)?;
    let actual_challenge = URL_SAFE_NO_PAD
        .decode(fields.challenge.as_bytes())
        .map_err(|_| WebAuthnError::ClientData)?;
    if expected_challenge.len() != actual_challenge.len()
        || expected_challenge.ct_eq(&actual_challenge).unwrap_u8() != 1
        || URL_SAFE_NO_PAD.encode(&actual_challenge) != fields.challenge
    {
        return Err(WebAuthnError::ChallengeMismatch);
    }
    let actual_origin = normalize_origin(&fields.origin).ok_or(WebAuthnError::OriginMismatch)?;
    let expected_origin =
        normalize_origin(policy.expected_origin()).ok_or(WebAuthnError::OriginMismatch)?;
    if actual_origin != expected_origin {
        return Err(WebAuthnError::OriginMismatch);
    }
    if fields.cross_origin && fields.top_origin.is_none() {
        return Err(WebAuthnError::OriginMismatch);
    }
    if !fields.cross_origin && fields.top_origin.is_some() {
        return Err(WebAuthnError::OriginMismatch);
    }
    let top_origin = match fields.top_origin.as_deref() {
        Some(origin) => Some(normalize_origin(origin).ok_or(WebAuthnError::OriginMismatch)?),
        None => None,
    };
    if fields.cross_origin {
        let Some(top_origin) = top_origin.as_deref() else {
            return Err(WebAuthnError::OriginMismatch);
        };
        if top_origin == actual_origin.as_str() {
            return Err(WebAuthnError::OriginMismatch);
        }
        let allowed = match policy.cross_origin_policy() {
            crate::types::CrossOriginPolicy::Disallowed => false,
            crate::types::CrossOriginPolicy::AllowedOrigins(origins) => {
                origins.iter().any(|origin| origin == top_origin)
            }
        };
        if !allowed {
            return Err(WebAuthnError::OriginMismatch);
        }
    }
    Ok(ClientData {
        ceremony_type: fields.ceremony_type,
        challenge: fields.challenge,
        origin: actual_origin,
        cross_origin: fields.cross_origin,
        top_origin,
    })
}

pub(crate) fn is_valid_origin(value: &str) -> bool {
    normalize_origin(value).is_some()
}

pub(crate) fn normalize_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.path() != "/" && !url.path().is_empty())
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    // WebAuthn requires secure contexts. Keep cleartext usable only for an
    // explicit local-development loopback origin; private or public hosts are
    // never trusted over HTTP.
    if url.scheme() == "http" && !is_loopback_host(&host) {
        return None;
    }
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Some(format!(
        "{}://{host}{port}",
        url.scheme().to_ascii_lowercase()
    ))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host)
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}
