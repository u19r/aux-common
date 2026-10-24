use std::pin::Pin;

use bytes::Bytes;
use futures_util::{Stream, StreamExt, stream};
use http::HeaderMap;
use reqwest::{Response, StatusCode, Url};
use serde::de::DeserializeOwned;

use crate::{
    constants::{DEFAULT_MAX_ERROR_BODY_LENGTH_BYTES, DEFAULT_MAX_RESPONSE_LENGTH_BYTES},
    error::{HttpRequestError, HttpRequestErrorKind, Result},
};

pub struct HttpResponse {
    inner: HttpResponseInner,
    max_body_size: Option<usize>,
}

enum HttpResponseInner {
    Reqwest(Response),
    Mock(MockResponse),
}

struct MockResponse {
    status: StatusCode,
    headers: HeaderMap,
    url: Url,
    body: Bytes,
}

impl HttpResponse {
    #[must_use]
    pub fn new(inner: Response, max_body_size: Option<usize>) -> Self {
        Self::from_reqwest(inner).with_max_body_size(max_body_size)
    }

    #[must_use]
    pub fn from_reqwest(inner: Response) -> Self {
        Self {
            inner: HttpResponseInner::Reqwest(inner),
            max_body_size: Some(DEFAULT_MAX_RESPONSE_LENGTH_BYTES),
        }
    }

    #[must_use]
    pub fn from_mock(status: StatusCode, headers: HeaderMap, body: Vec<u8>, url: Url) -> Self {
        Self {
            inner: HttpResponseInner::Mock(MockResponse {
                status,
                headers,
                url,
                body: Bytes::from(body),
            }),
            max_body_size: Some(DEFAULT_MAX_RESPONSE_LENGTH_BYTES),
        }
    }

    #[must_use]
    pub fn with_max_body_size(mut self, max_body_size: Option<usize>) -> Self {
        self.max_body_size = max_body_size;
        self
    }

    pub fn status(&self) -> StatusCode {
        match &self.inner {
            HttpResponseInner::Reqwest(inner) => inner.status(),
            HttpResponseInner::Mock(inner) => inner.status,
        }
    }

    pub fn headers(&self) -> &HeaderMap {
        match &self.inner {
            HttpResponseInner::Reqwest(inner) => inner.headers(),
            HttpResponseInner::Mock(inner) => &inner.headers,
        }
    }

    pub fn url(&self) -> &Url {
        match &self.inner {
            HttpResponseInner::Reqwest(inner) => inner.url(),
            HttpResponseInner::Mock(inner) => &inner.url,
        }
    }

    pub fn error_for_status(self) -> Result<Self> {
        if self.status().is_success() {
            Ok(self)
        } else {
            Err(HttpRequestError::HttpStatus {
                status: self.status(),
                body: None,
            })
        }
    }

    pub fn error_for_status_ref(&self) -> Result<&Self> {
        if self.status().is_success() {
            Ok(self)
        } else {
            Err(HttpRequestError::HttpStatus {
                status: self.status(),
                body: None,
            })
        }
    }

    pub async fn error_for_status_with_body(mut self) -> Result<Self> {
        if self.status().is_success() {
            return Ok(self);
        }
        let status = self.status();
        if self.max_body_size.is_none() {
            self.max_body_size = Some(DEFAULT_MAX_ERROR_BODY_LENGTH_BYTES);
        }
        let body = match self.text().await {
            Ok(body) => Some(body),
            Err(err) => return Err(err),
        };
        Err(HttpRequestError::HttpStatus { status, body })
    }

    /// Extract the underlying response only when no buffered-body limit is set.
    ///
    /// A capped response cannot be converted without discarding its safety
    /// invariant, so callers must stay on `bytes_stream`, `bytes`, `text`, or
    /// `json` (or explicitly opt out with `with_max_body_size(None)`).
    pub fn into_reqwest(self) -> Option<Response> {
        if self.max_body_size.is_some() {
            return None;
        }
        match self.inner {
            HttpResponseInner::Reqwest(inner) => Some(inner),
            HttpResponseInner::Mock(_) => None,
        }
    }

    /// Stream response chunks while enforcing the configured cumulative byte
    /// limit. An error terminates the stream. Explicitly disable the limit
    /// for a large download whose consumer owns bounded buffering.
    pub fn bytes_stream(self) -> Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>> {
        let raw: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>> = match self.inner {
            HttpResponseInner::Reqwest(inner) => Box::pin(
                inner
                    .bytes_stream()
                    .map(|chunk| chunk.map_err(response_body_error)),
            ),
            HttpResponseInner::Mock(inner) => Box::pin(stream::once(async move { Ok(inner.body) })),
        };
        let limit = self.max_body_size;
        Box::pin(stream::unfold(
            (Some(raw), 0usize),
            move |(raw, mut size)| async move {
                let mut raw = raw?;
                let chunk = raw.next().await?;
                let result = chunk.and_then(|chunk| {
                    size = size.saturating_add(chunk.len());
                    if let Some(max) = limit
                        && size > max
                    {
                        return Err(HttpRequestError::ResponseTooLarge { size, max });
                    }
                    Ok(chunk)
                });
                let next = if result.is_ok() { Some(raw) } else { None };
                Some((result, (next, size)))
            },
        ))
    }

    pub async fn bytes(self) -> Result<Bytes> {
        let mut stream = self.bytes_stream();
        let Some(first) = stream.next().await else {
            return Ok(Bytes::new());
        };
        let first = first?;
        let Some(second) = stream.next().await else {
            return Ok(first);
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(&second?);
        while let Some(chunk) = stream.next().await {
            bytes.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(bytes))
    }

    pub async fn text(self) -> Result<String> {
        let bytes = self.bytes().await?;
        String::from_utf8(bytes.to_vec()).map_err(|_| HttpRequestError::Decode)
    }

    pub async fn json<T: DeserializeOwned>(self) -> Result<T> {
        let bytes = self.bytes().await?;
        serde_json::from_slice(&bytes).map_err(|_| HttpRequestError::Decode)
    }
}

fn response_body_error(error: reqwest::Error) -> HttpRequestError {
    if error.is_timeout() {
        HttpRequestError::Transport {
            kind: HttpRequestErrorKind::Timeout,
        }
    } else {
        HttpRequestError::ResponseBody
    }
}
