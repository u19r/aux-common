#![cfg(all(feature = "lambda", unix))]

use std::{
    io::{BufRead, BufReader},
    os::unix::process::ExitStatusExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{UnboundedReceiver, unbounded_channel},
};

struct ExampleProcess {
    child: Child,
    events: UnboundedReceiver<Value>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl ExampleProcess {
    fn start(mut command: Command) -> Self {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, events) = unbounded_channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let event = serde_json::from_str(&line.unwrap()).unwrap();
                if sender.send(event).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            events,
            reader: Some(reader),
        }
    }
    async fn event(&mut self, name: &str) -> Value {
        let event = tokio::time::timeout(Duration::from_secs(5), self.events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event["event"], name);
        event
    }
    async fn assert_quiet(&mut self, duration: Duration) {
        assert!(
            tokio::time::timeout(duration, self.events.recv())
                .await
                .is_err(),
            "unexpected process event"
        );
    }
    async fn exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "example did not exit within its bounded lifecycle"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}
impl Drop for ExampleProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}

struct LambdaFixture {
    extension: ExampleProcess,
    runtime: ExampleProcess,
    extensions_api: TcpListener,
    runtime_api: TcpListener,
}
impl LambdaFixture {
    async fn start(age_ms: u64, destination_delay_ms: u64) -> Self {
        let extensions_api = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let runtime_api = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut command = example_command("EXTENSION", &extensions_api, "127.0.0.1:0");
        command
            .env("BUFFERED_WRITES_FLUSH_AGE_MS", age_ms.to_string())
            .env(
                "BUFFERED_WRITES_DESTINATION_DELAY_MS",
                destination_delay_ms.to_string(),
            );
        let mut extension = ExampleProcess::start(command);
        let ready = extension.event("ready").await;
        let address = ready["ipc_address"].as_str().unwrap();
        let (mut stream, request) = accept_request(&extensions_api).await;
        assert!(request.starts_with("post /2020-01-01/extension/register "));
        assert!(request.contains("lambda-extension-name: lambda-extension"));
        assert!(request.contains("invoke") && request.contains("shutdown"));
        reply(
            &mut stream,
            200,
            "Lambda-Extension-Identifier: process-fixture\r\n",
            "{}",
        )
        .await;
        let runtime = ExampleProcess::start(example_command("RUNTIME", &runtime_api, address));
        Self {
            extension,
            runtime,
            extensions_api,
            runtime_api,
        }
    }
    async fn invoke(&mut self, input: Value, budget: Duration, outcome: &str) -> TcpStream {
        let attempt = self.start_invocation(input, budget).await;
        let (stream, request) = accept_request(&self.runtime_api).await;
        assert!(request.starts_with(&format!(
            "post /2018-06-01/runtime/invocation/same-request/{outcome} "
        )));
        assert!(request.contains(&format!("lambda-runtime-invocation-id: {attempt}")));
        if outcome == "error" {
            assert!(request.contains("content-type: application/vnd.aws.lambda.error+json"));
            assert!(request.contains("\"errortype\":\"bufferedwritesinvocationerror\""));
        }
        stream
    }
    async fn start_invocation(&mut self, input: Value, budget: Duration) -> uuid::Uuid {
        let (mut stream, request) = accept_request(&self.extensions_api).await;
        assert!(request.starts_with("get /2020-01-01/extension/event/next "));
        let headers = format!(
            "Lambda-Extension-Event-Identifier: {}\r\n",
            uuid::Uuid::now_v7()
        );
        let event = json!({"eventType":"INVOKE", "requestId":"same-request", "deadlineMs":deadline_ms(budget)});
        reply(&mut stream, 200, &headers, &event.to_string()).await;
        let (mut stream, request) = accept_request(&self.runtime_api).await;
        assert!(request.starts_with("get /2018-06-01/runtime/invocation/next "));
        let attempt = uuid::Uuid::now_v7();
        let headers = format!(
            "Lambda-Runtime-Aws-Request-Id: same-request\r\nLambda-Runtime-Invocation-Id: \
             {attempt}\r\n"
        );
        reply(&mut stream, 200, &headers, &input.to_string()).await;
        attempt
    }

    async fn acknowledge(&mut self, mut response: TcpStream, settled: Option<u64>) {
        reply(&mut response, 202, "", "").await;
        self.runtime.event("response_acknowledged").await;
        if let Some(settled) = settled {
            assert_eq!(
                self.runtime.event("marker_acknowledged").await["items_settled"],
                settled
            );
        }
    }
    async fn shutdown(&mut self, reason: &str, budget: Duration) {
        let (mut stream, request) = accept_request(&self.extensions_api).await;
        assert!(request.starts_with("get /2020-01-01/extension/event/next "));
        let headers = format!(
            "Lambda-Extension-Event-Identifier: {}\r\n",
            uuid::Uuid::now_v7()
        );
        let event = json!({"eventType":"SHUTDOWN", "shutdownReason":reason, "deadlineMs":deadline_ms(budget)});
        reply(&mut stream, 200, &headers, &event.to_string()).await;
    }
}

fn example_command(kind: &str, listener: &TcpListener, address: &str) -> Command {
    let binary = std::env::var(format!("BUFFERED_WRITES_LAMBDA_{kind}_EXAMPLE"))
        .expect("build and explicitly select both Lambda example binaries");
    let mut command = Command::new(binary);
    command
        .env(
            "AWS_LAMBDA_RUNTIME_API",
            listener.local_addr().unwrap().to_string(),
        )
        .env("BUFFERED_WRITES_IPC_ADDR", address)
        .env("BUFFERED_WRITES_IPC_TOKEN", "native-process-fixture");
    command
}

async fn accept_request(listener: &TcpListener) -> (TcpStream, String) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let header_end = loop {
            assert!(bytes.len() < 8192, "bounded fixture request");
            bytes.push(stream.read_u8().await.unwrap());
            if bytes.ends_with(b"\r\n\r\n") {
                break bytes.len();
            }
        };
        let headers = String::from_utf8(bytes.clone())
            .unwrap()
            .to_ascii_lowercase();
        let length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or(0);
        assert!(length <= 65536);
        bytes.resize(header_end + length, 0);
        stream.read_exact(&mut bytes[header_end..]).await.unwrap();
        (
            stream,
            String::from_utf8(bytes).unwrap().to_ascii_lowercase(),
        )
    })
    .await
    .unwrap()
}
async fn reply(stream: &mut TcpStream, status: u16, headers: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}
fn deadline_ms(budget: Duration) -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap()
        + u64::try_from(budget.as_millis()).unwrap()
}

#[tokio::test]
#[ignore = "requires explicitly selected native lambda-extension and lambda-runtime binaries"]
async fn given_separate_processes_when_responses_are_acknowledged_then_flush_warm_buffer_and_drain_before_exit()
 {
    let mut fixture = LambdaFixture::start(1000, 0).await;
    let response = fixture
        .invoke(json!({"value":1}), Duration::from_secs(5), "response")
        .await;
    fixture
        .extension
        .assert_quiet(Duration::from_millis(20))
        .await;
    fixture
        .runtime
        .assert_quiet(Duration::from_millis(20))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.extensions_api.accept())
            .await
            .is_err(),
        "extension Next must not precede response acknowledgement"
    );
    fixture.acknowledge(response, Some(0)).await;
    fixture
        .extension
        .assert_quiet(Duration::from_millis(20))
        .await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let response = fixture
        .invoke(json!({"value":2}), Duration::from_secs(5), "response")
        .await;
    fixture
        .extension
        .assert_quiet(Duration::from_millis(20))
        .await;
    fixture.acknowledge(response, Some(2)).await;
    let applied = fixture.extension.event("applied").await;
    assert_eq!(applied["items"], 2);
    assert_eq!(applied["maximum"], 2);
    let response = fixture
        .invoke(
            json!({"value":3, "exit_after_response":true}),
            Duration::from_secs(5),
            "response",
        )
        .await;
    fixture.acknowledge(response, Some(0)).await;
    assert!(fixture.runtime.exit().await.success());
    fixture.shutdown("SPINDOWN", Duration::from_secs(2)).await;
    assert_eq!(fixture.extension.event("applied").await["maximum"], 3);
    let drained = fixture.extension.event("drained").await;
    assert_eq!(drained["clean"], true);
    assert_eq!(drained["items_settled"], 1);
    assert!(fixture.extension.exit().await.success());
}

#[tokio::test]
#[ignore = "requires explicitly selected native lambda-extension and lambda-runtime binaries"]
async fn given_runtime_exits_without_marker_when_provider_deadline_expires_then_drain_retained_writes_on_shutdown()
 {
    let mut fixture = LambdaFixture::start(1000, 0).await;
    let response = fixture
        .invoke(
            json!({"value":7, "skip_marker":true, "exit_after_response":true}),
            Duration::from_millis(400),
            "response",
        )
        .await;
    fixture.acknowledge(response, None).await;
    assert!(fixture.runtime.exit().await.success());
    fixture
        .extension
        .assert_quiet(Duration::from_millis(30))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.extensions_api.accept())
            .await
            .is_err(),
        "missing marker cannot grant completion permission"
    );
    fixture.shutdown("TIMEOUT", Duration::from_secs(2)).await;
    assert_eq!(fixture.extension.event("applied").await["maximum"], 7);
    assert_eq!(fixture.extension.event("drained").await["clean"], true);
    assert!(fixture.extension.exit().await.success());
}

#[tokio::test]
#[ignore = "requires explicitly selected native lambda-extension and lambda-runtime binaries"]
async fn given_destination_hangs_when_shutdown_budget_ends_then_process_reports_unresolved_and_exits_failure()
 {
    let mut fixture = LambdaFixture::start(1000, 5000).await;
    let response = fixture
        .invoke(
            json!({"value":8, "exit_after_response":true}),
            Duration::from_secs(3),
            "response",
        )
        .await;
    fixture.acknowledge(response, Some(0)).await;
    assert!(fixture.runtime.exit().await.success());
    let start = Instant::now();
    fixture
        .shutdown("SPINDOWN", Duration::from_millis(450))
        .await;
    let drained = fixture.extension.event("drained").await;
    assert_eq!(drained["clean"], false);
    assert_eq!(drained["unresolved_items"], 1);
    assert_eq!(drained["maximum"], 0);
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "drain must use remaining provider budget"
    );
    assert!(!fixture.extension.exit().await.success());
}

#[tokio::test]
#[ignore = "requires explicitly selected native lambda-extension and lambda-runtime binaries"]
async fn given_extension_is_killed_when_young_write_is_buffered_then_no_shutdown_callback_or_clean_report()
 {
    let mut fixture = LambdaFixture::start(1000, 0).await;
    let response = fixture
        .invoke(
            json!({"value":9, "exit_after_response":true}),
            Duration::from_secs(3),
            "response",
        )
        .await;
    fixture.acknowledge(response, Some(0)).await;
    assert!(fixture.runtime.exit().await.success());
    fixture.extension.child.kill().unwrap();
    assert_eq!(fixture.extension.exit().await.signal(), Some(9));
    assert!(
        fixture.extension.events.recv().await.is_none(),
        "volatile writes cannot produce a drain receipt after forced kill"
    );
}

#[tokio::test]
#[ignore = "requires explicitly selected native lambda-extension and lambda-runtime binaries"]
async fn given_invalid_input_when_error_response_is_acknowledged_then_mark_completion_and_continue()
{
    let mut fixture = LambdaFixture::start(1000, 0).await;
    let mut response = fixture
        .invoke(json!({"value":"invalid"}), Duration::from_secs(5), "error")
        .await;
    fixture
        .extension
        .assert_quiet(Duration::from_millis(20))
        .await;
    fixture
        .runtime
        .assert_quiet(Duration::from_millis(20))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.extensions_api.accept())
            .await
            .is_err()
    );
    reply(&mut response, 202, "", "").await;
    fixture.runtime.event("error_acknowledged").await;
    assert_eq!(
        fixture.runtime.event("marker_acknowledged").await["items_settled"],
        0
    );
    let response = fixture
        .invoke(
            json!({"value":4, "exit_after_response":true}),
            Duration::from_secs(5),
            "response",
        )
        .await;
    fixture.acknowledge(response, Some(0)).await;
    assert!(fixture.runtime.exit().await.success());
    fixture.shutdown("SPINDOWN", Duration::from_secs(2)).await;
    let applied = fixture.extension.event("applied").await;
    assert_eq!(applied["maximum"], 4);
    assert_eq!(applied["items"], 1, "invalid input cannot admit a write");
    assert_eq!(fixture.extension.event("drained").await["clean"], true);
    assert!(fixture.extension.exit().await.success());
}

#[tokio::test]
#[ignore = "requires explicitly selected native lambda-extension and lambda-runtime binaries"]
async fn given_handler_hangs_before_response_when_runtime_is_killed_at_timeout_then_only_shutdown_drains()
 {
    let mut fixture = LambdaFixture::start(1000, 0).await;
    fixture
        .start_invocation(
            json!({"value":7, "hang_before_response":true}),
            Duration::from_millis(300),
        )
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), fixture.runtime_api.accept())
            .await
            .is_err(),
        "hung handler must not POST success or error before timeout"
    );
    fixture
        .runtime
        .assert_quiet(Duration::from_millis(20))
        .await;
    fixture
        .extension
        .assert_quiet(Duration::from_millis(20))
        .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    fixture.runtime.child.kill().unwrap();
    assert_eq!(fixture.runtime.exit().await.signal(), Some(9));
    fixture.shutdown("TIMEOUT", Duration::from_secs(2)).await;
    let applied = fixture.extension.event("applied").await;
    assert_eq!(applied["maximum"], 7);
    let report = fixture.extension.event("drained").await;
    assert_eq!(report["clean"], true);
    assert_eq!(report["items_settled"], 1);
    assert!(fixture.extension.exit().await.success());
}
