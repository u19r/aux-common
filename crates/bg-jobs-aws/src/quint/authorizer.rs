use std::{future::Future, pin::Pin};

use aws_credentials::{
    Credentials, CredentialsError, ProvideCredentials, SharedCredentialsProvider,
};
use aws_sigv4_signing::AwsRequestSigner;
use bg_jobs_http::{
    AuthorizationFuture, AuthorizationRequest, HttpRequestDiagnostic, RequestAuthorizer,
};
use http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use quint_connect::Result;
use quint_http_connector::{AuthResult, ConnectorConfig};

use super::constants::{CONNECTOR_SECRET, CONNECTOR_SESSION};
use crate::{CredentialSource, SigV4Authorizer};

fn connector_authorizer() -> Result<SigV4Authorizer> {
    connector_authorizer_with_source(CredentialSource::Static(
        aws_credentials::AwsStaticCredentials {
            access_key_id: "AKIAEXAMPLE".to_owned(),
            secret_access_key: CONNECTOR_SECRET.to_owned(),
            session_token: Some(CONNECTOR_SESSION.to_owned()),
        },
    ))
}

fn connector_authorizer_with_source(source: CredentialSource) -> Result<SigV4Authorizer> {
    Ok(SigV4Authorizer::try_new(
        "eu-west-1",
        "execute-api",
        source,
    )?)
}

fn missing_secret_authorizer() -> Result<SigV4Authorizer> {
    #[derive(Debug)]
    struct UnavailableCredentials;

    impl ProvideCredentials for UnavailableCredentials {
        fn provide_credentials(
            &self,
        ) -> Pin<
            Box<
                dyn Future<Output = std::result::Result<Credentials, CredentialsError>> + Send + '_,
            >,
        > {
            Box::pin(std::future::ready(Err(
                CredentialsError::not_loaded_no_source(),
            )))
        }
    }

    Ok(SigV4Authorizer::from_signer(
        AwsRequestSigner::new_with_provider(
            "eu-west-1",
            SharedCredentialsProvider::new(UnavailableCredentials),
            "execute-api",
        ),
    ))
}

pub(super) enum AwsConnectorAuthorizer {
    SigV4(SigV4Authorizer),
    SigningFailure(SigV4Authorizer),
}

impl RequestAuthorizer for AwsConnectorAuthorizer {
    fn authorize<'a>(&'a self, mut request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        match self {
            Self::SigV4(authorizer) => authorizer.authorize(request),
            Self::SigningFailure(authorizer) => {
                // HeaderValue accepts opaque bytes, while the production
                // signer requires UTF-8 header values. This makes the signer
                // itself return SigningFailed after the request crosses it.
                let invalid_utf8 = HeaderValue::from_bytes(&[0xff])
                    .expect("opaque header byte must be representable");
                request
                    .headers_mut()
                    .insert("x-quint-signing-fixture", invalid_utf8);
                authorizer.authorize(request)
            }
        }
    }
}

pub(super) struct SigV4Connector;

impl ConnectorConfig for SigV4Connector {
    type Authorizer = AwsConnectorAuthorizer;

    fn policy_id() -> &'static str {
        "quint-sigv4"
    }

    fn supports_auth_result(auth: AuthResult) -> bool {
        auth != AuthResult::Denied
    }

    fn new_authorizer_for(auth: AuthResult) -> Result<Self::Authorizer> {
        match auth {
            AuthResult::Authorised => Ok(AwsConnectorAuthorizer::SigV4(connector_authorizer()?)),
            AuthResult::Denied => {
                Err(std::io::Error::other("AWS connector does not own policy denial").into())
            }
            AuthResult::MissingSecret => {
                Ok(AwsConnectorAuthorizer::SigV4(missing_secret_authorizer()?))
            }
            AuthResult::SignFailure => Ok(AwsConnectorAuthorizer::SigningFailure(
                connector_authorizer()?,
            )),
        }
    }

    fn assert_authorized(_original: &HeaderMap, authorized: &HeaderMap) -> Result {
        if !authorized.contains_key(AUTHORIZATION) {
            return Err(std::io::Error::other("SigV4 authorization header missing").into());
        }
        let contains_secret_key = authorized.values().any(|value| {
            let bytes = value.as_bytes();
            bytes
                .windows(CONNECTOR_SECRET.len())
                .any(|window| window == CONNECTOR_SECRET.as_bytes())
        });
        let rendered = format!("{authorized:?}");
        if contains_secret_key
            || rendered.contains(CONNECTOR_SECRET)
            || rendered.contains(CONNECTOR_SESSION)
        {
            return Err(std::io::Error::other("SigV4 credential escaped connector proof").into());
        }
        Ok(())
    }

    fn assert_request_projection(
        projection: &HttpRequestDiagnostic,
        _contains_secret: bool,
    ) -> Result {
        let rendered = format!("{projection:?}");
        if rendered.contains("api.example.com")
            || rendered.contains(CONNECTOR_SECRET)
            || rendered.contains(CONNECTOR_SESSION)
        {
            return Err(std::io::Error::other(
                "HTTP request diagnostic projection exposed AWS credentials",
            )
            .into());
        }
        Ok(())
    }

    fn label() -> &'static str {
        "AWS"
    }
}
