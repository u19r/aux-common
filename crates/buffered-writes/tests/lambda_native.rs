#![cfg(feature = "lambda")]

mod lambda_live;

use std::{collections::BTreeSet, time::Duration};

use lambda_live::{InvokeExpectation, TestFunction};
use serde_json::json;

#[test]
#[ignore = "creates disposable Lambda/IAM/log resources; requires explicit profile, ZIP and \
            receipt directory"]
fn given_deployed_extension_when_invocations_complete_then_reuse_warm_buffer_and_drain_on_runtime_exit()
 {
    let mut function = TestFunction::prepare();
    function.create();
    function.invoke(&json!({"value":1}), "young", InvokeExpectation::Success);
    let initial = function.wait_events(|events| {
        events
            .iter()
            .any(|event| event["event"] == "marker_acknowledged")
    });
    assert!(
        !initial.iter().any(|event| event["event"] == "applied"),
        "young admission must remain buffered"
    );
    std::thread::sleep(Duration::from_millis(1600));
    function.invoke(&json!({"value":2}), "aged", InvokeExpectation::Success);
    let aged = function.wait_events(|events| {
        events.iter().any(|event| event["event"] == "applied")
            && events
                .iter()
                .filter(|event| event["event"] == "response_acknowledged")
                .count()
                >= 2
            && events
                .iter()
                .filter(|event| event["event"] == "marker_acknowledged")
                .count()
                >= 2
    });
    let applied = aged
        .iter()
        .find(|event| event["event"] == "applied")
        .unwrap();
    assert_eq!(
        applied["items"], 2,
        "same warm process must retain the first item"
    );
    assert_eq!(applied["maximum"], 2);
    let streams: BTreeSet<_> = aged
        .iter()
        .filter(|event| event["event"] == "ready")
        .map(|event| event["stream"].clone().to_string())
        .collect();
    assert_eq!(
        streams.len(),
        1,
        "warm reuse evidence requires one environment"
    );
    function.invoke(
        &json!({"value":"invalid"}),
        "invalid",
        InvokeExpectation::FunctionError,
    );
    function.wait_events(|events| {
        events
            .iter()
            .any(|event| event["event"] == "error_acknowledged")
    });
    function.invoke(
        &json!({"value":3, "exit_after_response":true}),
        "exit",
        InvokeExpectation::Success,
    );
    let events =
        function.wait_events(|events| events.iter().any(|event| event["event"] == "drained"));
    let drained = events
        .iter()
        .find(|event| event["event"] == "drained")
        .unwrap();
    assert_eq!(drained["clean"], true);
    assert_eq!(drained["maximum"], 3);
    assert_eq!(drained["items_settled"], 1);
    function.cleanup();
}

#[test]
#[ignore = "creates disposable Lambda/IAM/log resources; requires explicit profile, ZIPs and \
            receipt directory"]
fn given_runtime_times_out_before_response_when_environment_resets_then_drain_and_reinitialize() {
    let mut function = TestFunction::prepare();
    function.create();
    function.invoke(
        &json!({"value":7, "hang_before_response":true}),
        "timeout",
        InvokeExpectation::Timeout,
    );
    let timed_out = function.wait_events(|events| {
        events.iter().any(|event| event["event"] == "drained")
            && events.iter().any(|event| {
                let message = event["message"].as_str().unwrap_or("").to_ascii_lowercase();
                message.contains("status: timeout") || message.contains("task timed out after")
            })
    });
    assert!(
        !timed_out
            .iter()
            .any(|event| event["event"] == "response_acknowledged"
                || event["event"] == "marker_acknowledged"),
        "an incomplete handler must not grant post-response permission"
    );
    let drained = timed_out
        .iter()
        .find(|event| event["event"] == "drained")
        .unwrap();
    assert_eq!(drained["clean"], true);
    assert_eq!(drained["maximum"], 7);
    assert_eq!(drained["items_settled"], 1);
    function.invoke(
        &json!({"value":8, "exit_after_response":true}),
        "after-reset",
        InvokeExpectation::Success,
    );
    let recovered = function.wait_events(|events| {
        events
            .iter()
            .filter(|event| event["event"] == "ready")
            .count()
            >= 2
            && events
                .iter()
                .any(|event| event["event"] == "drained" && event["maximum"] == 8)
    });
    assert!(
        recovered
            .iter()
            .any(|event| event["event"] == "marker_acknowledged" && event["items_settled"] == 0)
    );
    function.cleanup();
}
