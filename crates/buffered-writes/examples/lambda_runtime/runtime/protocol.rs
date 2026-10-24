use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use http_request::{HttpClient, RetryConfig, StatusCode};

use super::invocation::{Invocation, InvocationOutcome};
use crate::constants::{
    API_MAX_BODY_BYTES, API_OPERATION_TIMEOUT, ATTEMPT_ID_HEADER, NEXT_INVOCATION_PATH,
};

pub(super) struct RuntimeApi {
    origin: String,
    client: HttpClient,
}

impl RuntimeApi {
    pub(super) fn try_new(endpoint: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let address: SocketAddr = endpoint
            .parse()
            .map_err(|_| "invalid Runtime API address")?;
        let local = match address.ip() {
            IpAddr::V4(address) => address.is_loopback() || address.is_link_local(),
            IpAddr::V6(address) => address.is_loopback() || address.is_unicast_link_local(),
        };
        if !local {
            return Err("Runtime API must be local".into());
        }
        let client = HttpClient::builder()
            .with_reqwest_builder(|_| {
                http_request::reqwest::Client::builder()
                    .no_proxy()
                    .connect_timeout(API_OPERATION_TIMEOUT)
            })
            .retry(RetryConfig {
                max_retries: 0,
                base_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
                retry_non_idempotent: false,
            })
            .build()?;
        Ok(Self {
            origin: format!("http://{address}"),
            client,
        })
    }

    pub(super) async fn next(&self) -> Result<Invocation, Box<dyn std::error::Error>> {
        let response = self
            .client
            .get(format!("{}{NEXT_INVOCATION_PATH}", self.origin))
            .send()
            .await
            .map_err(|_| "Runtime API Next failed")?;
        if response.status() != StatusCode::OK {
            return Err("Runtime API Next was rejected".into());
        }
        Invocation::read_response(response).await
    }

    pub(super) async fn complete(
        &self,
        invocation: &Invocation,
        outcome: &InvocationOutcome,
    ) -> Result<&'static str, Box<dyn std::error::Error>> {
        tokio::time::timeout(
            API_OPERATION_TIMEOUT,
            self.post_completion(invocation, outcome),
        )
        .await
        .map_err(|_| "Runtime API response timed out")?
    }

    async fn post_completion(
        &self,
        invocation: &Invocation,
        outcome: &InvocationOutcome,
    ) -> Result<&'static str, Box<dyn std::error::Error>> {
        let (path, content_type, body) = outcome.response();
        let request = self
            .client
            .post(format!(
                "{}/2018-06-01/runtime/invocation/{}/{path}",
                self.origin, invocation.request_id
            ))
            .header("content-type", content_type)
            .header(ATTEMPT_ID_HEADER, &invocation.attempt_id)
            .body(body.to_string());
        let response = request
            .send()
            .await
            .map_err(|_| "Runtime API response failed")?;
        if response.status() != StatusCode::ACCEPTED {
            return Err("Runtime API response was rejected".into());
        }
        response
            .with_max_body_size(Some(API_MAX_BODY_BYTES))
            .bytes()
            .await
            .map_err(|_| "Runtime API response body failed")?;
        Ok(path)
    }
}
