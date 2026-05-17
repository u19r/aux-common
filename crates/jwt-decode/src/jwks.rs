use std::{
    hash::{Hash, Hasher},
    sync::Arc,
    time::Duration,
};

use http_request::{HttpClient, Url};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use lru_ttl_cache::{CacheConfig, FetchingLruTtlCache, arc_fetch_fn};

use crate::{JwtDecodeError, JwtDecodeErrorKind, Result, json::JsonDocument};

#[derive(Debug, Clone)]
pub struct JwksDocument {
    keys: Arc<JwkSet>,
}

impl JwksDocument {
    pub fn from_json_str(json: &str) -> Result<Self> {
        JsonDocument::reject_duplicate_members(json.as_bytes())
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksParse))?;
        let keys = serde_json::from_str::<JwkSet>(json)
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksParse))?;
        Self::prevalidate(&keys)?;
        Ok(Self {
            keys: Arc::new(keys),
        })
    }

    pub(crate) fn find_unique_key(&self, kid: &str) -> Result<&Jwk> {
        let mut matches = self
            .keys
            .keys
            .iter()
            .filter(|key| key.common.key_id.as_deref() == Some(kid));

        let Some(first) = matches.next() else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::KeyNotFound));
        };

        if matches.next().is_some() {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::AmbiguousKeyId));
        }

        Ok(first)
    }

    fn prevalidate(jwks: &JwkSet) -> Result<()> {
        if jwks.keys.is_empty() {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::JwksParse));
        }

        for key in &jwks.keys {
            if matches!(key.algorithm, AlgorithmParameters::OctetKey(_)) {
                return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
            }
            if key.common.key_id.as_deref().is_some_and(str::is_empty) {
                return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum JwksSource {
    Jwks(JwksDocument),
    LocalSymmetric(LocalSymmetricKey),
    Url(Box<RemoteJwksSource>),
}

impl JwksSource {
    pub fn json_string(json: impl AsRef<str>) -> Result<Self> {
        Ok(Self::Jwks(JwksDocument::from_json_str(json.as_ref())?))
    }

    pub fn url(url: impl AsRef<str>) -> Result<Self> {
        Ok(Self::Url(Box::new(RemoteJwksSource::new(
            JwksUrl::parse_https(url.as_ref())?,
            JwksCachePolicy::default(),
            HttpClient::new().map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?,
        ))))
    }

    pub fn insecure_test_url(url: impl AsRef<str>) -> Result<Self> {
        Ok(Self::Url(Box::new(RemoteJwksSource::new(
            JwksUrl::parse_for_tests(url.as_ref())?,
            JwksCachePolicy::default(),
            HttpClient::new().map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?,
        ))))
    }

    pub fn local_symmetric_key(kid: impl Into<String>, secret: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self::LocalSymmetric(LocalSymmetricKey::new(
            kid.into(),
            secret.into(),
        )?))
    }

    pub(crate) async fn document_for_issuer(&self, issuer: &str) -> Result<Arc<JwksDocument>> {
        match self {
            Self::Jwks(document) => Ok(Arc::new(document.clone())),
            Self::LocalSymmetric(_) => Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
            Self::Url(source) => source.document_for_issuer(issuer).await,
        }
    }

    pub(crate) async fn refresh_document_for_issuer(
        &self,
        issuer: &str,
    ) -> Result<Arc<JwksDocument>> {
        match self {
            Self::Jwks(document) => Ok(Arc::new(document.clone())),
            Self::LocalSymmetric(_) => Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
            Self::Url(source) => source.refresh_document_for_issuer(issuer).await,
        }
    }

    pub(crate) fn local_symmetric_key_for(&self, kid: &str) -> Result<&LocalSymmetricKey> {
        let Self::LocalSymmetric(key) = self else {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        };
        if key.key_id() != kid {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::KeyNotFound));
        }
        Ok(key)
    }

    pub fn invalidate_issuer(&self, issuer: &str) {
        if let Self::Url(source) = self {
            source.invalidate_issuer(issuer);
        }
    }
}

#[derive(Clone)]
pub struct LocalSymmetricKey {
    key_id: String,
    secret: Arc<[u8]>,
}

impl LocalSymmetricKey {
    fn new(key_id: String, secret: Vec<u8>) -> Result<Self> {
        if key_id.is_empty() || secret.is_empty() {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        Ok(Self {
            key_id,
            secret: Arc::from(secret),
        })
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

impl std::fmt::Debug for LocalSymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSymmetricKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct JwksUrl {
    url: Url,
}

impl JwksUrl {
    pub fn parse_https(value: &str) -> Result<Self> {
        let url =
            Url::parse(value).map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?;
        if url.scheme() == "https" {
            return Ok(Self { url });
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))
    }

    pub fn parse_for_tests(value: &str) -> Result<Self> {
        let url =
            Url::parse(value).map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?;
        Ok(Self { url })
    }

    fn as_str(&self) -> &str {
        self.url.as_str()
    }
}

#[derive(Debug, Clone)]
pub struct JwksCachePolicy {
    pub capacity: usize,
    pub fallback_ttl: Duration,
    pub refresh_ttl: Duration,
    pub stale_ttl: Duration,
    pub max_body_size: usize,
    pub stale_on_fetch_error: bool,
}

impl Default for JwksCachePolicy {
    fn default() -> Self {
        Self {
            capacity: 128,
            fallback_ttl: Duration::from_secs(300),
            refresh_ttl: Duration::from_secs(240),
            stale_ttl: Duration::from_secs(60),
            max_body_size: 1024 * 1024,
            stale_on_fetch_error: true,
        }
    }
}

#[derive(Clone)]
pub struct RemoteJwksSource {
    url: JwksUrl,
    cache: FetchingLruTtlCache<JwksCacheKey, Arc<JwksDocument>, JwtDecodeError>,
    policy: JwksCachePolicy,
}

impl std::fmt::Debug for RemoteJwksSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteJwksSource")
            .field("url", &self.url)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl RemoteJwksSource {
    pub fn new(url: JwksUrl, policy: JwksCachePolicy, http_client: HttpClient) -> Self {
        let fetch_url = url.clone();
        let fetch_policy = policy.clone();
        let fetch = arc_fetch_fn(move |key: JwksCacheKey| {
            let client = http_client.clone();
            let url = fetch_url.clone();
            let policy = fetch_policy.clone();
            async move {
                let document = fetch_remote_jwks(&client, &url, &policy).await?;
                Ok(Some(Arc::new(document.with_expected_issuer(key.issuer))))
            }
        });
        let cache = FetchingLruTtlCache::new(
            CacheConfig::<JwksCacheKey, Arc<JwksDocument>>::new()
                .with_capacity(policy.capacity)
                .with_ttl(policy.fallback_ttl)
                .with_fetch(fetch)
                .with_refresh_ttl(policy.refresh_ttl),
        );
        Self { url, cache, policy }
    }

    async fn document_for_issuer(&self, issuer: &str) -> Result<Arc<JwksDocument>> {
        let key = self.cache_key(issuer);
        let value = if self.policy.stale_on_fetch_error {
            self.cache
                .get_or_fetch_stale_on_error(&key, self.policy.stale_ttl)
                .await?
        } else {
            self.cache.get_or_fetch(&key).await?
        };
        value.ok_or_else(|| JwtDecodeError::new(JwtDecodeErrorKind::JwksCache))
    }

    async fn refresh_document_for_issuer(&self, issuer: &str) -> Result<Arc<JwksDocument>> {
        let key = self.cache_key(issuer);
        self.cache.remove(&key);
        self.cache
            .get_or_fetch(&key)
            .await?
            .ok_or_else(|| JwtDecodeError::new(JwtDecodeErrorKind::JwksCache))
    }

    pub fn invalidate_issuer(&self, issuer: &str) {
        self.cache.remove(&self.cache_key(issuer));
    }

    fn cache_key(&self, issuer: &str) -> JwksCacheKey {
        JwksCacheKey {
            url: self.url.as_str().to_owned(),
            issuer: issuer.to_owned(),
        }
    }
}

#[derive(Clone, Eq)]
struct JwksCacheKey {
    url: String,
    issuer: String,
}

impl PartialEq for JwksCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url && self.issuer == other.issuer
    }
}

impl Hash for JwksCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
        self.issuer.hash(state);
    }
}

async fn fetch_remote_jwks(
    client: &HttpClient,
    url: &JwksUrl,
    policy: &JwksCachePolicy,
) -> Result<JwksDocument> {
    let response = client
        .get(url.as_str())
        .send()
        .await
        .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?
        .with_max_body_size(Some(policy.max_body_size))
        .error_for_status_with_body()
        .await
        .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?;
    let value = response
        .text()
        .await
        .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?;
    JwksDocument::from_json_str(&value)
}

impl JwksDocument {
    fn with_expected_issuer(self, _issuer: String) -> Self {
        self
    }
}
