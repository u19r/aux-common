use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{HttpClient, Result};

#[derive(Clone, Eq, PartialEq)]
pub struct OAuthTokenEndpoint {
    url: String,
    headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthUserinfoEndpoint {
    url: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OAuthRevocationEndpoint {
    url: String,
    headers: Vec<(String, String)>,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct OAuthAuthorizationCodeRequest {
    grant_type: &'static str,
    client_id: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct OAuthRefreshTokenRequest {
    grant_type: &'static str,
    client_id: String,
    refresh_token: String,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct OAuthRevocationRequest {
    token: String,
    token_type_hint: String,
    client_id: String,
}

#[derive(Clone, Eq, PartialEq, Deserialize)]
pub struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

impl fmt::Debug for OAuthTokenEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokenEndpoint")
            .field("url", &self.url)
            .field("header_names", &header_names(&self.headers))
            .finish()
    }
}

impl fmt::Debug for OAuthRevocationEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthRevocationEndpoint")
            .field("url", &self.url)
            .field("header_names", &header_names(&self.headers))
            .finish()
    }
}

impl fmt::Debug for OAuthAuthorizationCodeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthAuthorizationCodeRequest")
            .field("grant_type", &self.grant_type)
            .field("client_id", &self.client_id)
            .field("code", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for OAuthRefreshTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthRefreshTokenRequest")
            .field("grant_type", &self.grant_type)
            .field("client_id", &self.client_id)
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for OAuthRevocationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthRevocationRequest")
            .field("token", &"[REDACTED]")
            .field("token_type_hint", &self.token_type_hint)
            .field("client_id", &self.client_id)
            .finish()
    }
}

impl fmt::Debug for OAuthTokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

fn header_names(headers: &[(String, String)]) -> Vec<&str> {
    headers.iter().map(|(name, _)| name.as_str()).collect()
}

impl OAuthTokenEndpoint {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: Vec::new(),
        }
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

impl OAuthUserinfoEndpoint {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl OAuthRevocationEndpoint {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: Vec::new(),
        }
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

impl OAuthAuthorizationCodeRequest {
    #[must_use]
    pub fn public_client(
        client_id: impl Into<String>,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
        code_verifier: impl Into<String>,
    ) -> Self {
        Self {
            grant_type: "authorization_code",
            client_id: client_id.into(),
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            code_verifier: code_verifier.into(),
        }
    }
}

impl OAuthRefreshTokenRequest {
    #[must_use]
    pub fn public_client(client_id: impl Into<String>, refresh_token: impl Into<String>) -> Self {
        Self {
            grant_type: "refresh_token",
            client_id: client_id.into(),
            refresh_token: refresh_token.into(),
        }
    }
}

impl OAuthRevocationRequest {
    #[must_use]
    pub fn public_client(
        client_id: impl Into<String>,
        token: impl Into<String>,
        token_type_hint: impl Into<String>,
    ) -> Self {
        Self {
            token: token.into(),
            token_type_hint: token_type_hint.into(),
            client_id: client_id.into(),
        }
    }
}

impl OAuthTokenResponse {
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    #[must_use]
    pub fn token_type(&self) -> Option<&str> {
        self.token_type.as_deref()
    }

    #[must_use]
    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }

    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

impl HttpClient {
    pub async fn oauth_authorization_code_public_client(
        &self,
        endpoint: &OAuthTokenEndpoint,
        request: &OAuthAuthorizationCodeRequest,
    ) -> Result<OAuthTokenResponse> {
        self.post_oauth_form(endpoint, request).await
    }

    pub async fn oauth_refresh_token_public_client(
        &self,
        endpoint: &OAuthTokenEndpoint,
        request: &OAuthRefreshTokenRequest,
    ) -> Result<OAuthTokenResponse> {
        self.post_oauth_form(endpoint, request).await
    }

    pub async fn oauth_userinfo<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &OAuthUserinfoEndpoint,
        access_token: &str,
    ) -> Result<T> {
        self.get_json_with_bearer(endpoint.url(), access_token)
            .await
    }

    pub async fn oauth_revoke_public_client(
        &self,
        endpoint: &OAuthRevocationEndpoint,
        request: &OAuthRevocationRequest,
    ) -> Result<()> {
        let mut builder = self.post(endpoint.url()).form(request);
        for (name, value) in &endpoint.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let response = builder.send().await?;
        response.error_for_status_with_body().await?;
        Ok(())
    }

    async fn post_oauth_form<T: serde::de::DeserializeOwned, F: serde::Serialize + ?Sized>(
        &self,
        endpoint: &OAuthTokenEndpoint,
        form: &F,
    ) -> Result<T> {
        let mut request = self.post(endpoint.url()).form(form);
        for (name, value) in &endpoint.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        let response = request.send().await?;
        let response = response.error_for_status_with_body().await?;
        response.json().await
    }
}
