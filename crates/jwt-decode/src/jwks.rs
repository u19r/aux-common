#[cfg(not(target_arch = "wasm32"))]
use std::hash::{Hash, Hasher};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};
#[cfg(not(target_arch = "wasm32"))]
use std::{sync::Mutex, time::Instant};

#[cfg(not(target_arch = "wasm32"))]
use http_request::{HttpClient, Url};
use jsonwebtoken::{
    DecodingKey,
    jwk::{Jwk, JwkSet},
};
#[cfg(not(target_arch = "wasm32"))]
use lru_ttl_cache::{CacheConfig, FetchingLruTtlCache, arc_fetch_fn};

use crate::{
    JwtDecodeError, JwtDecodeErrorKind, Result, SignatureAlgorithm,
    json::JsonDocument,
    key_policy::{KeyPolicy, MIN_HMAC_KEY_BYTES},
};

pub(crate) const MAX_JWKS_DOCUMENT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_JWKS_KEYS: usize = 1024;

#[derive(Clone)]
pub struct JwksDocument {
    keys: Arc<JwkSet>,
    decoding_keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
}

impl std::fmt::Debug for JwksDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksDocument")
            .field("key_count", &self.keys.keys.len())
            .finish_non_exhaustive()
    }
}

impl JwksDocument {
    pub fn from_json_str(json: &str) -> Result<Self> {
        if json.len() > MAX_JWKS_DOCUMENT_BYTES {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::JwksParse));
        }
        JsonDocument::reject_duplicate_members(json.as_bytes())
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksParse))?;
        let keys = serde_json::from_str::<JwkSet>(json)
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksParse))?;
        Self::prevalidate(&keys)?;
        Ok(Self {
            keys: Arc::new(keys),
            decoding_keys: Arc::new(RwLock::new(HashMap::new())),
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

    pub(crate) fn decoding_key_for(
        &self,
        kid: &str,
        algorithm: SignatureAlgorithm,
        allow_symmetric: bool,
    ) -> Result<DecodingKey> {
        let jwk = self.find_unique_key(kid)?;
        KeyPolicy::new(jwk, algorithm, allow_symmetric).validate()?;
        if let Some(key) = self.cached_decoding_key(kid)? {
            return Ok(key);
        }

        let key = DecodingKey::from_jwk(jwk)
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey))?;
        self.store_decoding_key(kid, key.clone())?;
        Ok(key)
    }

    fn cached_decoding_key(&self, kid: &str) -> Result<Option<DecodingKey>> {
        let guard = self
            .decoding_keys
            .read()
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey))?;
        Ok(guard.get(kid).cloned())
    }

    fn store_decoding_key(&self, kid: &str, key: DecodingKey) -> Result<()> {
        let mut guard = self
            .decoding_keys
            .write()
            .map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey))?;
        guard.insert(kid.to_owned(), key);
        Ok(())
    }

    fn prevalidate(jwks: &JwkSet) -> Result<()> {
        if jwks.keys.is_empty() {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::JwksParse));
        }
        if jwks.keys.len() > MAX_JWKS_KEYS {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::JwksParse));
        }

        for key in &jwks.keys {
            if key.common.key_id.as_deref().is_some_and(str::is_empty) {
                return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
pub enum JwksSource {
    Jwks(Arc<JwksDocument>),
    LocalSymmetric(LocalSymmetricKey),
    #[cfg(not(target_arch = "wasm32"))]
    Url(Box<RemoteJwksSource>),
}

impl std::fmt::Debug for JwksSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Jwks(_) => "static_jwks",
            Self::LocalSymmetric(_) => "local_symmetric",
            #[cfg(not(target_arch = "wasm32"))]
            Self::Url(_) => "remote_url",
        };
        f.debug_struct("JwksSource")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl JwksSource {
    pub fn json_string(json: impl AsRef<str>) -> Result<Self> {
        Ok(Self::Jwks(Arc::new(JwksDocument::from_json_str(
            json.as_ref(),
        )?)))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn url(url: impl AsRef<str>) -> Result<Self> {
        Ok(Self::Url(Box::new(RemoteJwksSource::new(
            JwksUrl::parse_https(url.as_ref())?,
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
        #[cfg(target_arch = "wasm32")]
        let _ = issuer;
        match self {
            Self::Jwks(document) => Ok(Arc::clone(document)),
            Self::LocalSymmetric(_) => Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Url(source) => source.document_for_issuer(issuer).await,
        }
    }

    pub(crate) fn static_document_for_issuer(&self, _issuer: &str) -> Result<Arc<JwksDocument>> {
        match self {
            Self::Jwks(document) => Ok(Arc::clone(document)),
            Self::LocalSymmetric(_) => Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Url(_) => Err(JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch)),
        }
    }

    pub(crate) async fn refresh_document_for_issuer(
        &self,
        issuer: &str,
    ) -> Result<Arc<JwksDocument>> {
        #[cfg(target_arch = "wasm32")]
        let _ = issuer;
        match self {
            Self::Jwks(document) => Ok(Arc::clone(document)),
            Self::LocalSymmetric(_) => Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
            #[cfg(not(target_arch = "wasm32"))]
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

    pub(crate) fn allows_symmetric_jwks(&self) -> bool {
        match self {
            Self::Jwks(_) | Self::LocalSymmetric(_) => true,
            #[cfg(not(target_arch = "wasm32"))]
            Self::Url(_) => false,
        }
    }

    pub fn invalidate_issuer(&self, issuer: &str) {
        #[cfg(not(target_arch = "wasm32"))]
        if let Self::Url(source) = self {
            source.invalidate_issuer(issuer);
        }
        #[cfg(target_arch = "wasm32")]
        let _ = issuer;
    }
}

#[derive(Clone)]
pub struct LocalSymmetricKey {
    key_id: String,
    decoding_key: DecodingKey,
    secret_len: usize,
}

impl LocalSymmetricKey {
    fn new(key_id: String, secret: Vec<u8>) -> Result<Self> {
        if key_id.is_empty() || secret.len() < MIN_HMAC_KEY_BYTES {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        let decoding_key = DecodingKey::from_secret(&secret);
        Ok(Self {
            key_id,
            decoding_key,
            secret_len: secret.len(),
        })
    }

    pub(crate) fn validate_for_algorithm(&self, algorithm: SignatureAlgorithm) -> Result<()> {
        let minimum = match algorithm {
            SignatureAlgorithm::HS256 => MIN_HMAC_KEY_BYTES,
            SignatureAlgorithm::HS384 => 48,
            SignatureAlgorithm::HS512 => 64,
            _ => return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey)),
        };
        if self.secret_len < minimum {
            return Err(JwtDecodeError::new(JwtDecodeErrorKind::InvalidKey));
        }
        Ok(())
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn decoding_key(&self) -> DecodingKey {
        self.decoding_key.clone()
    }
}

impl std::fmt::Debug for LocalSymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSymmetricKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
#[cfg(not(target_arch = "wasm32"))]
pub struct JwksUrl {
    url: Url,
}

#[cfg(not(target_arch = "wasm32"))]
impl JwksUrl {
    pub fn parse_https(value: &str) -> Result<Self> {
        let url =
            Url::parse(value).map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?;
        if url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
        {
            return Ok(Self { url });
        }
        Err(JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))
    }

    #[cfg(test)]
    pub(crate) fn parse_for_tests(value: &str) -> Result<Self> {
        let url =
            Url::parse(value).map_err(|_| JwtDecodeError::new(JwtDecodeErrorKind::JwksFetch))?;
        Ok(Self { url })
    }

    fn as_str(&self) -> &str {
        self.url.as_str()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Debug for JwksUrl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JwksUrl")
            .field("url", &"[REDACTED]")
            .finish()
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
            // Fail closed when the issuer cannot be refreshed. Callers that
            // have an explicit bounded availability policy must opt in to
            // stale-on-error and set a finite stale_ttl.
            stale_on_fetch_error: false,
        }
    }
}

#[derive(Clone)]
#[cfg(not(target_arch = "wasm32"))]
pub struct RemoteJwksSource {
    url: JwksUrl,
    cache: FetchingLruTtlCache<JwksCacheKey, Arc<JwksDocument>, JwtDecodeError>,
    policy: JwksCachePolicy,
    unknown_kid_refreshes: Arc<Mutex<HashMap<String, Instant>>>,
    invalidation_generations: Arc<Mutex<InvalidationGenerations>>,
}

#[cfg(not(target_arch = "wasm32"))]
const UNKNOWN_KID_REFRESH_COOLDOWN: Duration = Duration::from_secs(1);
#[cfg(not(target_arch = "wasm32"))]
const MAX_UNKNOWN_KID_REFRESH_COOLDOWNS: usize = 256;
#[cfg(not(target_arch = "wasm32"))]
const MAX_INVALIDATION_GENERATIONS: usize = 256;

#[derive(Default)]
#[cfg(not(target_arch = "wasm32"))]
struct InvalidationGenerations {
    per_issuer: HashMap<String, u64>,
    default_generation: u64,
    next_generation: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Debug for RemoteJwksSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteJwksSource")
            .field("url", &self.url)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[cfg(not(target_arch = "wasm32"))]
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
        Self {
            url,
            cache,
            policy,
            unknown_kid_refreshes: Arc::new(Mutex::new(HashMap::new())),
            invalidation_generations: Arc::new(Mutex::new(InvalidationGenerations::default())),
        }
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
        if !self.allow_unknown_kid_refresh(issuer) {
            return self.document_for_issuer(issuer).await;
        }
        let key = self.cache_key(issuer);
        self.cache.remove(&key);
        self.cache
            .get_or_fetch(&key)
            .await?
            .ok_or_else(|| JwtDecodeError::new(JwtDecodeErrorKind::JwksCache))
    }

    pub fn invalidate_issuer(&self, issuer: &str) {
        let previous_key = self.cache_key(issuer);
        if let Ok(mut generations) = self.invalidation_generations.lock() {
            generations.next_generation = generations.next_generation.saturating_add(1);
            let generation = generations.next_generation;
            if generations.per_issuer.len() >= MAX_INVALIDATION_GENERATIONS
                && !generations.per_issuer.contains_key(issuer)
            {
                generations.per_issuer.clear();
                generations.default_generation = generation;
            }
            generations.per_issuer.insert(issuer.to_owned(), generation);
        }
        self.cache.remove(&previous_key);
        if let Ok(mut refreshes) = self.unknown_kid_refreshes.lock() {
            refreshes.remove(issuer);
        }
    }

    fn allow_unknown_kid_refresh(&self, issuer: &str) -> bool {
        let Ok(mut refreshes) = self.unknown_kid_refreshes.lock() else {
            return false;
        };
        let now = Instant::now();
        if refreshes.get(issuer).is_some_and(|until| *until > now) {
            return false;
        }
        if refreshes.len() >= MAX_UNKNOWN_KID_REFRESH_COOLDOWNS {
            refreshes.clear();
        }
        let refresh_until = now.checked_add(UNKNOWN_KID_REFRESH_COOLDOWN).unwrap_or(now);
        refreshes.insert(issuer.to_owned(), refresh_until);
        true
    }

    fn cache_key(&self, issuer: &str) -> JwksCacheKey {
        let generation = self
            .invalidation_generations
            .lock()
            .ok()
            .map(|generations| {
                generations
                    .per_issuer
                    .get(issuer)
                    .copied()
                    .unwrap_or(generations.default_generation)
            })
            .unwrap_or_default();
        JwksCacheKey {
            url: self.url.as_str().to_owned(),
            issuer: issuer.to_owned(),
            generation,
        }
    }
}

#[derive(Clone, Eq)]
#[cfg(not(target_arch = "wasm32"))]
struct JwksCacheKey {
    url: String,
    issuer: String,
    generation: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl PartialEq for JwksCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url && self.issuer == other.issuer && self.generation == other.generation
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Hash for JwksCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
        self.issuer.hash(state);
        self.generation.hash(state);
    }
}

#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
impl JwksDocument {
    fn with_expected_issuer(self, _issuer: String) -> Self {
        self
    }
}
