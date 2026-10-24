use std::time::SystemTime;

use aws_credentials::Credentials;
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::SigningError;

pub(crate) struct SigningContext<'a> {
    pub(super) credentials: Credentials,
    pub(super) datetime: String,
    pub(super) scope: String,
    region: &'a str,
    service: &'a str,
}

impl<'a> SigningContext<'a> {
    pub(crate) fn try_new(
        region: &'a str,
        service: &'a str,
        credentials: Credentials,
        time: SystemTime,
    ) -> Result<Self, SigningError> {
        if !is_scope_component(region) || !is_scope_component(service) {
            return Err(SigningError::PrepareRequest);
        }
        let time: DateTime<Utc> = time.into();
        let datetime = time.format("%Y%m%dT%H%M%SZ").to_string();
        let scope = format!("{}/{region}/{service}/aws4_request", time.format("%Y%m%d"));
        Ok(Self {
            credentials,
            datetime,
            scope,
            region,
            service,
        })
    }

    pub(super) fn is_s3(&self) -> bool {
        self.service == "s3"
    }

    pub(super) fn credential(&self) -> String {
        format!("{}/{}", self.credentials.access_key_id(), self.scope)
    }

    pub(super) fn signature(&self, canonical_request: &str) -> Result<String, SigningError> {
        let digest = data_encoding::HEXLOWER.encode(&Sha256::digest(canonical_request.as_bytes()));
        let text = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{digest}",
            self.datetime, self.scope
        );
        let secret = Zeroizing::new(format!("AWS4{}", self.credentials.secret_access_key()));
        let date_key = Zeroizing::new(hmac_sha256(secret.as_bytes(), &self.datetime[..8])?);
        let region_key = Zeroizing::new(hmac_sha256(date_key.as_ref(), self.region)?);
        let service_key = Zeroizing::new(hmac_sha256(region_key.as_ref(), self.service)?);
        let signing_key = Zeroizing::new(hmac_sha256(service_key.as_ref(), "aws4_request")?);
        let signature = hmac_sha256(signing_key.as_ref(), &text)?;
        Ok(data_encoding::HEXLOWER.encode(&signature))
    }
}

fn hmac_sha256(key: &[u8], text: &str) -> Result<[u8; 32], SigningError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| SigningError::Signing)?;
    mac.update(text.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn is_scope_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
