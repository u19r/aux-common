#![cfg(feature = "sqs")]

use std::{
    collections::BTreeSet,
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_credentials::{AwsStaticCredentials, CredentialSource};
use buffered_writes::{
    AtomicSink, BufferedWrites, Deadline, QueueConfig, ReplayQueue, ReplayWorker, SealedBatch,
    SinkError, SinkLimits, SqsQueue, WriteAttempt, WriteQueue,
};
use http_request::HttpClient;
use serde_json::{Value, json};

// CLI/SSO support is test infrastructure only. Credential JSON never enters
// logs or files.
struct TestQueues {
    profile: String,
    region: String,
    names: Vec<String>,
}

impl TestQueues {
    fn aws(&self, arguments: &[&str]) -> Value {
        let output = Command::new("aws")
            .args(arguments)
            .args([
                "--profile",
                &self.profile,
                "--region",
                &self.region,
                "--cli-connect-timeout",
                "5",
                "--cli-read-timeout",
                "15",
                "--output",
                "json",
            ])
            .output()
            .expect("AWS CLI must be installed for native queue tests");
        assert!(
            output.status.success(),
            "native AWS operation failed; verify test profile/session"
        );
        if output.stdout.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&output.stdout).expect("AWS CLI JSON response")
        }
    }

    fn create_queue(&mut self, suffix: &str) -> String {
        let name = format!("buffered-writes-test-{}-{suffix}", uuid::Uuid::now_v7());
        let attributes = json!({"MaximumMessageSize":"1048576", "MessageRetentionPeriod":"60",
            "VisibilityTimeout":"30", "SqsManagedSseEnabled":"true"})
        .to_string();
        self.names.push(name.clone());
        let response = self.aws(&[
            "sqs",
            "create-queue",
            "--queue-name",
            &name,
            "--attributes",
            &attributes,
        ]);
        response["QueueUrl"].as_str().expect("queue URL").to_owned()
    }

    fn queue(&self, source: &str, quarantine: &str) -> SqsQueue {
        let credentials = self.aws(&["configure", "export-credentials", "--format", "process"]);
        SqsQueue::try_new_with_client(
            QueueConfig::sqs(source)
                .with_region(&self.region)
                .with_quarantine_url(quarantine),
            CredentialSource::Static(AwsStaticCredentials {
                access_key_id: credentials["AccessKeyId"]
                    .as_str()
                    .expect("access key")
                    .into(),
                secret_access_key: credentials["SecretAccessKey"]
                    .as_str()
                    .expect("secret key")
                    .into(),
                session_token: credentials["SessionToken"].as_str().map(str::to_owned),
            }),
            HttpClient::builder().build().unwrap(),
        )
        .unwrap()
    }
}

impl Drop for TestQueues {
    fn drop(&mut self) {
        for name in &self.names {
            let discovered = Command::new("aws")
                .args([
                    "sqs",
                    "get-queue-url",
                    "--queue-name",
                    name,
                    "--profile",
                    &self.profile,
                    "--region",
                    &self.region,
                    "--cli-connect-timeout",
                    "5",
                    "--cli-read-timeout",
                    "15",
                    "--output",
                    "json",
                ])
                .output();
            let url = discovered
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| serde_json::from_slice::<Value>(&output.stdout).ok())
                .and_then(|value| value["QueueUrl"].as_str().map(str::to_owned));
            let Some(url) = url else {
                eprintln!("native SQS cleanup could not resolve disposable queue: {name}");
                continue;
            };
            let result = Command::new("aws")
                .args([
                    "sqs",
                    "delete-queue",
                    "--queue-url",
                    &url,
                    "--profile",
                    &self.profile,
                    "--region",
                    &self.region,
                    "--cli-connect-timeout",
                    "5",
                    "--cli-read-timeout",
                    "15",
                ])
                .output();
            if !matches!(result, Ok(output) if output.status.success()) {
                eprintln!("native SQS cleanup failed for disposable queue: {url}");
            }
        }
    }
}

async fn sealed_batch() -> SealedBatch {
    let captured = Arc::new(Mutex::new(None));
    let observed = captured.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        *observed.lock().unwrap() = Some(attempt.sealed_batch().clone());
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let writer = BufferedWrites::builder("native-sqs/v1", sink)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.flush_writes().await;
    captured.lock().unwrap().take().unwrap()
}

#[tokio::test]
#[ignore = "creates disposable AWS queues; requires BUFFERED_WRITES_SQS_PROFILE and a valid session"]
async fn given_real_sqs_when_duplicate_batches_replay_then_effect_once_and_poison_moves_before_delete()
 {
    let mut resources = TestQueues {
        profile: std::env::var("BUFFERED_WRITES_SQS_PROFILE").expect("explicit test AWS profile"),
        region: std::env::var("BUFFERED_WRITES_SQS_REGION")
            .unwrap_or_else(|_| "eu-central-1".into()),
        names: Vec::new(),
    };
    let source = resources.create_queue("source");
    let quarantine = resources.create_queue("quarantine");
    let queue = resources.queue(&source, &quarantine);
    let batch = sealed_batch().await;
    let deadline = Deadline::after(Duration::from_secs(45));
    queue.publish(batch.clone(), deadline).await.unwrap();
    queue.publish(batch, deadline).await.unwrap();
    let effects = Arc::new(Mutex::new(BTreeSet::new()));
    let observed = effects.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        observed
            .lock()
            .unwrap()
            .insert(attempt.sealed_batch().batch_id().to_string());
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let worker = ReplayWorker::builder("native-sqs/v1", queue.clone(), sink)
        .build()
        .unwrap();
    let mut delivered = 0;
    while delivered < 2 && !deadline.is_expired_at(std::time::Instant::now()) {
        delivered += worker
            .replay_once(10, deadline)
            .await
            .unwrap()
            .batches_delivered;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        delivered >= 2,
        "both explicit publications must reach replay"
    );
    assert_eq!(
        effects.lock().unwrap().len(),
        1,
        "test sink deduplicates stable batch identity"
    );
    resources.aws(&[
        "sqs",
        "send-message",
        "--queue-url",
        &source,
        "--message-body",
        "invalid-envelope",
    ]);
    let mut poisoned = 0;
    while poisoned == 0 && !deadline.is_expired_at(std::time::Instant::now()) {
        poisoned += worker
            .replay_once(10, deadline)
            .await
            .unwrap()
            .batches_quarantined;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(poisoned, 1);
    let quarantine_queue = resources.queue(&quarantine, &source);
    let mut received = Vec::new();
    while received.is_empty() && !deadline.is_expired_at(std::time::Instant::now()) {
        received = quarantine_queue.receive(1, deadline).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(received.len(), 1);
    let record: Value = serde_json::from_slice(&received[0].envelope_bytes).unwrap();
    assert_eq!(record["version"], 1);
    quarantine_queue
        .renew_visibility(
            &received[0].receipt_handle,
            Duration::from_secs(5),
            deadline,
        )
        .await
        .unwrap();
    quarantine_queue
        .acknowledge(&received[0].receipt_handle, deadline)
        .await
        .unwrap();
    assert_eq!(
        effects.lock().unwrap().len(),
        1,
        "poison must not reach sink"
    );
}
