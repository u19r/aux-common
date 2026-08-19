use std::{fmt, str::FromStr};

use http::{HeaderMap, HeaderValue, Method, Uri, header::CONTENT_TYPE};
use http_request::{HttpClient, HttpResponse, StatusCode};
use url::Url;

use crate::{AwsRequestSigner, CredentialSource, SignableBody, SigningError};

#[derive(Clone)]
pub struct AwsSigv4TextResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
    url: String,
}

impl fmt::Debug for AwsSigv4TextResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names = self
            .headers
            .keys()
            .map(http::HeaderName::as_str)
            .collect::<Vec<_>>();
        formatter
            .debug_struct("AwsSigv4TextResponse")
            .field("status", &self.status)
            .field("header_names", &header_names)
            .field("body_len", &self.body.len())
            .field("url", &"[REDACTED]")
            .finish()
    }
}

impl AwsSigv4TextResponse {
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.headers
            .get("etag")
            .and_then(|value| value.to_str().ok())
    }
}

#[derive(Clone)]
pub struct AwsSigv4HttpClient {
    client: HttpClient,
    endpoint: String,
    signer: AwsRequestSigner,
}

impl AwsSigv4HttpClient {
    pub fn new(
        client: HttpClient,
        endpoint: &str,
        region: &str,
        credentials: CredentialSource,
        service_name: &str,
    ) -> Result<Self, SigningError> {
        if !client.redirects_disabled() {
            return Err(SigningError::RedirectPolicyRequired);
        }
        let endpoint = endpoint.trim_end_matches('/');
        let endpoint_url = Url::parse(endpoint).map_err(|_| SigningError::InvalidUrl)?;
        if endpoint_url.scheme() != "https" {
            return Err(SigningError::InsecureTransport);
        }
        if endpoint_url.username() != ""
            || endpoint_url.password().is_some()
            || endpoint_url.query().is_some()
            || endpoint_url.fragment().is_some()
        {
            return Err(SigningError::InvalidUrl);
        }
        let signer = AwsRequestSigner::new(region, credentials, service_name)?;
        Ok(Self {
            client,
            endpoint: endpoint.to_string(),
            signer,
        })
    }

    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<String>,
        mut extra_headers: HeaderMap,
        default_content_type: Option<&'static str>,
    ) -> Result<HttpResponse, SigningError> {
        if extra_headers.contains_key(http::header::HOST) {
            return Err(SigningError::HostHeaderOverride);
        }
        if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') {
            return Err(SigningError::InvalidUrl);
        }
        let url = format!("{}{}", self.endpoint, path);
        let endpoint_url = Url::parse(&self.endpoint).map_err(|_| SigningError::InvalidUrl)?;
        let request_url = Url::parse(&url).map_err(|_| SigningError::InvalidUrl)?;
        if request_url.scheme() != endpoint_url.scheme()
            || request_url.host() != endpoint_url.host()
            || request_url.port() != endpoint_url.port()
        {
            return Err(SigningError::InvalidUrl);
        }
        let uri = Uri::from_str(url.as_str()).map_err(|_| SigningError::InvalidUri)?;
        if let Some(content_type) = default_content_type
            && body.is_some()
            && !extra_headers.contains_key(CONTENT_TYPE)
        {
            extra_headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        let signed_headers = self
            .signer
            .sign_request(
                method.as_str(),
                &uri,
                &extra_headers,
                SignableBody::Bytes(body.as_deref().unwrap_or("").as_bytes()),
            )
            .await?;

        let mut request = self.client.request(method, url);
        for (name, value) in &signed_headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        request
            .send()
            .await
            .map_err(|err| SigningError::HttpRequest(err.kind()))
    }

    pub async fn send_text(
        &self,
        method: Method,
        path: &str,
        body: Option<String>,
        extra_headers: HeaderMap,
        default_content_type: Option<&'static str>,
    ) -> Result<AwsSigv4TextResponse, SigningError> {
        let response = self
            .send(method, path, body, extra_headers, default_content_type)
            .await?;
        signed_text_response(response).await
    }

    pub async fn send_xml(
        &self,
        method: Method,
        path: &str,
        body: Option<String>,
        extra_headers: HeaderMap,
    ) -> Result<AwsSigv4TextResponse, SigningError> {
        self.send_text(method, path, body, extra_headers, Some("application/xml"))
            .await
    }
}

async fn signed_text_response(
    response: HttpResponse,
) -> Result<AwsSigv4TextResponse, SigningError> {
    let status = response.status();
    let headers = response.headers().clone();
    let url = response.url().to_string();
    let body = response
        .text()
        .await
        .map_err(|err| SigningError::HttpRequest(err.kind()))?;

    Ok(AwsSigv4TextResponse {
        status,
        headers,
        body,
        url,
    })
}
