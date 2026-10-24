use std::{net::TcpListener, thread, time::Duration};

use crate::{HttpRequestDispatchStatus, HttpRequestError, HttpRequestErrorKind};

#[tokio::test]
async fn given_a_tls_setup_timeout_when_classifying_it_then_request_is_not_dispatched() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS timeout listener");
    let address = listener.local_addr().expect("read TLS timeout address");
    let server = thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("accept TLS timeout connection");
        thread::sleep(Duration::from_millis(200));
    });
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(20))
        .timeout(Duration::from_millis(100))
        .build()
        .expect("build timeout client");

    let error = client
        .get(format!("https://{address}/commit"))
        .send()
        .await
        .expect_err("TLS setup must time out before HTTP dispatch");

    assert!(error.is_timeout());
    assert!(error.is_connect());
    let error = HttpRequestError::from(error);
    assert_eq!(error.kind(), HttpRequestErrorKind::Connect);
    assert_eq!(
        error.dispatch_status(),
        HttpRequestDispatchStatus::NotDispatched
    );
    server.join().expect("join TLS timeout server");
}

#[test]
fn given_failure_boundaries_when_classifying_dispatch_then_only_proven_setup_failures_are_safe() {
    let not_dispatched = [
        HttpRequestError::Build,
        HttpRequestError::InvalidUrl,
        HttpRequestError::SsrfBlocked { reason: "policy" },
        HttpRequestError::Transport {
            kind: HttpRequestErrorKind::Connect,
        },
    ];
    let possibly_dispatched = [
        HttpRequestError::Transport {
            kind: HttpRequestErrorKind::Timeout,
        },
        HttpRequestError::ResponseBody,
        HttpRequestError::HttpStatus {
            status: reqwest::StatusCode::REQUEST_TIMEOUT,
            body: None,
        },
    ];

    assert!(
        not_dispatched
            .iter()
            .all(|error| error.dispatch_status() == HttpRequestDispatchStatus::NotDispatched)
    );
    assert!(
        possibly_dispatched
            .iter()
            .all(|error| error.dispatch_status() == HttpRequestDispatchStatus::PossiblyDispatched)
    );
}
