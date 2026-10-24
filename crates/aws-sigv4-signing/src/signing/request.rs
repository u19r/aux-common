use std::time::Duration;

use http::{HeaderMap, HeaderValue, Uri, header::AUTHORIZATION};

use super::{
    canonical::{CanonicalHeaders, CanonicalRequest, prepare_headers},
    context::SigningContext,
    encoding::canonical_query,
};
use crate::{SignableBody, SigningError};

pub(crate) struct SigningRequest<'a> {
    pub(crate) method: &'a str,
    pub(crate) uri: &'a Uri,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) body: SignableBody<'a>,
}

impl SigningContext<'_> {
    pub(crate) fn sign_headers(
        &self,
        request: &SigningRequest<'_>,
    ) -> Result<HeaderMap, SigningError> {
        let mut headers = prepare_headers(request.uri, request.headers)?;
        let hash = request.body.payload_hash()?;
        insert_header(&mut headers, "x-amz-date", &self.datetime)?;
        insert_header(&mut headers, "x-amz-content-sha256", &hash)?;
        if let Some(token) = self.credentials.session_token() {
            insert_header(&mut headers, "x-amz-security-token", token)?;
        }
        let canonical_headers = CanonicalHeaders::try_from(&headers)?;
        let query = canonical_query(request.uri.query(), &[]);
        let canonical = canonical_headers.request(CanonicalRequest {
            method: request.method,
            uri: request.uri,
            query: &query,
            payload_hash: &hash,
            is_s3: self.is_s3(),
        });
        let signature = self.signature(&canonical)?;
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}, SignedHeaders={}, Signature={signature}",
            self.credential(),
            canonical_headers.names
        );
        let mut authorization =
            HeaderValue::from_str(&authorization).map_err(|_| SigningError::InvalidHeaderValue)?;
        authorization.set_sensitive(true);
        headers.insert(AUTHORIZATION, authorization);
        Ok(headers)
    }

    pub(crate) fn presign(
        &self,
        request: &SigningRequest<'_>,
        expiry: Duration,
    ) -> Result<Uri, SigningError> {
        let headers = prepare_headers(request.uri, request.headers)?;
        let canonical_headers = CanonicalHeaders::try_from(&headers)?;
        let mut params = self.presign_parameters(&canonical_headers.names, expiry);
        let hash = request.body.payload_hash()?;
        let query = canonical_query(request.uri.query(), &params);
        let canonical = canonical_headers.request(CanonicalRequest {
            method: request.method,
            uri: request.uri,
            query: &query,
            payload_hash: &hash,
            is_s3: self.is_s3(),
        });
        params.push(("X-Amz-Signature".to_owned(), self.signature(&canonical)?));
        let query = canonical_query(None, &params);
        let original = request
            .uri
            .path_and_query()
            .map_or("/", |part| part.as_str());
        let separator = if request.uri.query().is_some() {
            '&'
        } else {
            '?'
        };
        let mut parts = request.uri.clone().into_parts();
        parts.path_and_query = Some(
            format!("{original}{separator}{query}")
                .parse()
                .map_err(|_| SigningError::InvalidUri)?,
        );
        Uri::from_parts(parts).map_err(|_| SigningError::InvalidUri)
    }
    fn presign_parameters(&self, names: &str, expiry: Duration) -> Vec<(String, String)> {
        let mut params = vec![
            ("X-Amz-Algorithm".to_owned(), "AWS4-HMAC-SHA256".to_owned()),
            ("X-Amz-Credential".to_owned(), self.credential()),
            ("X-Amz-Date".to_owned(), self.datetime.clone()),
            ("X-Amz-Expires".to_owned(), expiry.as_secs().to_string()),
            ("X-Amz-SignedHeaders".to_owned(), names.to_owned()),
        ];
        if let Some(token) = self.credentials.session_token() {
            params.push(("X-Amz-Security-Token".to_owned(), token.to_owned()));
        }
        params
    }
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &str,
) -> Result<(), SigningError> {
    let mut value = HeaderValue::from_str(value).map_err(|_| SigningError::InvalidHeaderValue)?;
    if name == "x-amz-security-token" {
        value.set_sensitive(true);
    }
    headers.insert(name, value);
    Ok(())
}
