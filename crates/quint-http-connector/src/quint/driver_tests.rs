//! Full-state connector for the settled HTTP MBT boundary.

use std::collections::BTreeSet;

use bg_jobs_http::{
    AuthorizationErrorKind, AuthorizationFuture, AuthorizationRequest, HttpRequestDiagnostic,
    RequestAuthorizer,
};
use http::HeaderMap;
use quint_connect::Result;

use super::{
    driver::{ConnectorConfig, ConnectorDriver},
    model,
};

struct HttpConnector;

enum HttpConnectorAuthorizer {
    Authorised,
    Rejected(AuthorizationErrorKind),
}

impl RequestAuthorizer for HttpConnectorAuthorizer {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        match self {
            Self::Authorised => Box::pin(async move { Ok(request.into_headers()) }),
            Self::Rejected(error) => {
                let error = *error;
                Box::pin(async move { Err(error) })
            }
        }
    }
}

impl ConnectorConfig for HttpConnector {
    type Authorizer = HttpConnectorAuthorizer;

    fn policy_id() -> &'static str {
        "quint-http"
    }

    fn new_authorizer_for(auth: model::AuthResult) -> Result<Self::Authorizer> {
        Ok(match auth {
            model::AuthResult::Authorised => HttpConnectorAuthorizer::Authorised,
            model::AuthResult::Denied => {
                HttpConnectorAuthorizer::Rejected(AuthorizationErrorKind::InvalidRequest)
            }
            model::AuthResult::MissingSecret => {
                HttpConnectorAuthorizer::Rejected(AuthorizationErrorKind::CredentialUnavailable)
            }
            model::AuthResult::SignFailure => {
                HttpConnectorAuthorizer::Rejected(AuthorizationErrorKind::SigningFailed)
            }
        })
    }

    fn assert_authorized(original: &HeaderMap, authorized: &HeaderMap) -> Result {
        if original
            .iter()
            .all(|(name, value)| authorized.get(name) == Some(value))
        {
            return Ok(());
        }
        Err(std::io::Error::other("HTTP authorizer changed caller headers").into())
    }

    fn assert_request_projection(
        projection: &HttpRequestDiagnostic,
        _contains_secret: bool,
    ) -> Result {
        let rendered = format!("{projection:?}");
        if rendered.contains("api.example.com") || rendered.contains("connector-secret") {
            return Err(std::io::Error::other(
                "HTTP request diagnostic projection exposed restricted data",
            )
            .into());
        }
        Ok(())
    }

    fn label() -> &'static str {
        "HTTP"
    }
}

#[::quint_connect_guard::quint_run(
    spec = "../../quint/http-job-mbt.qnt",
    main = "http_job_mbt",
    init = "mbtInit",
    step = "mbtNondetStep",
    max_samples = 8,
    max_steps = 20,
    seed = "0x17"
)]
fn quint_http_full_state_matches_production() -> impl quint_connect::Driver {
    ConnectorDriver::<HttpConnector>::default()
}

#[test]
fn given_each_authorization_class_when_executed_then_it_crosses_the_production_executor_boundary() {
    for auth in [
        model::AuthResult::Authorised,
        model::AuthResult::Denied,
        model::AuthResult::MissingSecret,
        model::AuthResult::SignFailure,
    ] {
        let mut driver = ConnectorDriver::<HttpConnector>::default();
        assert!(
            driver
                .apply_command_for_test(model::Command::HttpPrepare {
                    members: BTreeSet::from([model::JobId::JobA]),
                })
                .is_ok()
        );
        assert!(
            driver
                .apply_command_for_test(model::Command::HttpInput {
                    job: model::JobId::JobA,
                    secret: true,
                    body_bytes: b"connector-secret".len() as i64,
                    destination_valid: true,
                })
                .is_ok()
        );
        assert!(
            driver
                .apply_command_for_test(model::Command::HttpAuthorize {
                    job: model::JobId::JobA,
                    auth,
                })
                .is_ok()
        );
        assert_eq!(driver.authorization_calls_for_test(), 1, "{auth:?}");
    }
}

#[test]
fn given_secret_input_when_each_projection_mode_is_requested_then_the_production_request_boundary_is_checked()
 {
    for include_secret in [false, true] {
        let mut driver = ConnectorDriver::<HttpConnector>::default();
        assert!(
            driver
                .apply_command_for_test(model::Command::HttpPrepare {
                    members: BTreeSet::from([model::JobId::JobA]),
                })
                .is_ok()
        );
        assert!(
            driver
                .apply_command_for_test(model::Command::HttpInput {
                    job: model::JobId::JobA,
                    secret: true,
                    body_bytes: b"connector-secret".len() as i64,
                    destination_valid: true,
                })
                .is_ok()
        );
        assert!(
            driver
                .apply_command_for_test(model::Command::HttpAuthorize {
                    job: model::JobId::JobA,
                    auth: model::AuthResult::Authorised,
                })
                .is_ok()
        );
        assert!(
            driver
                .apply_command_for_test(model::Command::HttpProject {
                    job: model::JobId::JobA,
                    include_secret,
                })
                .is_ok()
        );
        assert_eq!(driver.projection_checks_for_test(), 1);
        assert_eq!(
            driver.projection_for_test().meta.last_outcome,
            if include_secret {
                model::HttpOutcome::ProjectionRejected
            } else {
                model::HttpOutcome::Initialised
            }
        );
    }
}
