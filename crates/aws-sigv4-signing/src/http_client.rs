use std::str::FromStr;

use http::{HeaderMap, HeaderValue, Method, Uri, header::CONTENT_TYPE};
use http_request::{HttpClient, HttpResponse, StatusCode};

use crate::{AwsRequestSigner, CredentialSource, SignableBody, SigningError};

#[derive(Debug, Clone)]
pub struct AwsSigv4TextResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
    url: String,
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
        let signer = AwsRequestSigner::new(region, credentials, service_name)?;
        Ok(Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_string(),
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
        let url = format!("{}{}", self.endpoint, path);
        let uri =
            Uri::from_str(url.as_str()).map_err(|err| SigningError::InvalidUri(err.to_string()))?;
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
            .map_err(|err| SigningError::HttpRequest(err.to_string()))
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
        .map_err(|err| SigningError::HttpRequest(err.to_string()))?;

    Ok(AwsSigv4TextResponse {
        status,
        headers,
        body,
        url,
    })
}
