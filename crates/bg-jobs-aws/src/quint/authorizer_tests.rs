use std::collections::BTreeSet;

use quint_http_connector as model;
use quint_http_connector::ConnectorDriver;

use super::authorizer::SigV4Connector;

#[::quint_connect_guard::quint_run(
    spec = "../../quint/http-job-mbt.qnt",
    main = "http_job_mbt",
    init = "mbtInit",
    step = "mbtNondetStep",
    max_samples = 8,
    max_steps = 20,
    seed = "0x19"
)]
fn quint_authorizer_full_state_matches_production() -> impl quint_connect::Driver {
    ConnectorDriver::<SigV4Connector>::default()
}

#[test]
fn given_secret_input_when_each_projection_mode_is_requested_then_the_production_request_boundary_is_checked()
 {
    for include_secret in [false, true] {
        let mut driver = ConnectorDriver::<SigV4Connector>::default();
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

#[test]
fn given_each_aws_authorization_class_when_executed_then_it_crosses_the_production_executor_boundary()
 {
    for auth in [
        model::AuthResult::Authorised,
        model::AuthResult::MissingSecret,
        model::AuthResult::SignFailure,
    ] {
        let mut driver = ConnectorDriver::<SigV4Connector>::default();
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
