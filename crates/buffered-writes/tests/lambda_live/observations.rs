use std::time::{Duration, Instant};

use serde_json::Value;

use super::resources::TestFunction;

pub(crate) enum InvokeExpectation {
    Success,
    FunctionError,
    Timeout,
}

impl TestFunction {
    pub(crate) fn invoke(&self, input: &Value, suffix: &str, expected: InvokeExpectation) {
        let reply = self.receipt_dir.join(format!("{suffix}-response.json"));
        let payload = input.to_string();
        let metadata = self.client.aws(&[
            "lambda",
            "invoke",
            "--function-name",
            &self.name,
            "--cli-binary-format",
            "raw-in-base64-out",
            "--payload",
            &payload,
            reply.to_str().unwrap(),
        ]);
        assert_eq!(metadata["StatusCode"], 200);
        let body: Value = serde_json::from_slice(&std::fs::read(reply).unwrap()).unwrap();
        match expected {
            InvokeExpectation::Success => {
                assert!(metadata.get("FunctionError").is_none());
                assert_eq!(body["value"], input["value"]);
            }
            InvokeExpectation::FunctionError => {
                assert!(metadata.get("FunctionError").is_some());
                assert_eq!(body["errorType"], "BufferedWritesInvocationError");
            }
            InvokeExpectation::Timeout => {
                assert!(metadata.get("FunctionError").is_some());
                assert!(
                    body["errorMessage"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty())
                );
            }
        }
    }

    fn events(&self) -> Vec<Value> {
        let start = self.started_ms.to_string();
        let response = self.client.aws(&[
            "logs",
            "filter-log-events",
            "--log-group-name",
            &format!("/aws/lambda/{}", self.name),
            "--start-time",
            &start,
        ]);
        response["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|event| {
                let message = event["message"].as_str()?;
                let mut value = serde_json::from_str::<Value>(message)
                    .ok()
                    .filter(Value::is_object)
                    .unwrap_or_else(
                        || serde_json::json!({"event":"platform_log", "message":message}),
                    );
                value["stream"] = event["logStreamName"].clone();
                value["timestamp"] = event["timestamp"].clone();
                Some(value)
            })
            .collect()
    }

    pub(crate) fn wait_events(&self, condition: impl Fn(&[Value]) -> bool) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let group = format!("/aws/lambda/{}", self.name);
            let exists =
                self.client
                    .command(&["logs", "describe-log-streams", "--log-group-name", &group]);
            if exists.status.success() {
                let events = self.events();
                std::fs::write(
                    self.receipt_dir.join("events.json"),
                    serde_json::to_vec_pretty(&events).unwrap(),
                )
                .unwrap();
                if condition(&events) {
                    return events;
                }
            }
            assert!(
                Instant::now() < deadline,
                "deployed lifecycle evidence incomplete; inspect events receipt"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}
