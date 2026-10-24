#![cfg(feature = "valkey")]

mod support;

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use buffered_writes::{
    AtomicSink, BufferCapacity, BufferClaimRequest, BufferSealAction, BufferSealRequest,
    BufferStats, BufferedWrites, ClaimedWork, Deadline, Namespace, OperationId, SinkError,
    SinkLimits, ValkeyBuffer, ValkeyCredentials, WriteAttempt, WriteBuffer, WriteError,
    WriteOptions,
};

struct Server {
    child: Option<Child>,
    directory: PathBuf,
    port: u16,
    tls: bool,
}
impl Server {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let directory =
            std::env::temp_dir().join(format!("buffered-writes-valkey-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&directory).unwrap();
        let mut server = Self {
            child: None,
            directory,
            port,
            tls: false,
        };
        server.restart().await;
        server
    }
    async fn restart(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        let mut command = Command::new(
            std::env::var("BUFFERED_WRITES_VALKEY_SERVER")
                .unwrap_or_else(|_| "redis-server".to_owned()),
        );
        command
            .args([
                "--bind",
                "127.0.0.1",
                "--port",
                &if self.tls { 0 } else { self.port }.to_string(),
                "--appendonly",
                "yes",
                "--appendfsync",
                "always",
                "--save",
                "",
                "--requirepass",
                "buffered-writes-test",
                "--maxmemory-policy",
                "noeviction",
                "--dir",
            ])
            .arg(&self.directory);
        if self.tls {
            command
                .args([
                    "--tls-port",
                    &self.port.to_string(),
                    "--tls-auth-clients",
                    "no",
                    "--tls-cert-file",
                ])
                .arg(self.directory.join("server.crt"))
                .arg("--tls-key-file")
                .arg(self.directory.join("server.key"))
                .arg("--tls-ca-cert-file")
                .arg(self.directory.join("ca.crt"));
        }
        self.child = Some(
            command
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("native provider tests require redis-server on PATH"),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while std::net::TcpStream::connect(("127.0.0.1", self.port)).is_err() {
            assert!(Instant::now() < deadline, "test server did not start");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn plaintext_connection(&self) -> redis::aio::MultiplexedConnection {
        assert!(!self.tls);
        redis::Client::open(format!(
            "redis://:buffered-writes-test@127.0.0.1:{}/",
            self.port
        ))
        .unwrap()
        .get_multiplexed_async_connection_with_config(
            &redis::AsyncConnectionConfig::new()
                .set_response_timeout(Some(Duration::from_secs(12))),
        )
        .await
        .unwrap()
    }
    async fn replicate_from(&self, primary: &Server) {
        let mut master = primary.plaintext_connection().await;
        let _: () = redis::cmd("CONFIG")
            .arg("SET")
            .arg("repl-diskless-sync-delay")
            .arg(0)
            .query_async(&mut master)
            .await
            .unwrap();
        let mut replica = self.plaintext_connection().await;
        let _: () = redis::cmd("CONFIG")
            .arg("SET")
            .arg("masterauth")
            .arg("buffered-writes-test")
            .query_async(&mut replica)
            .await
            .unwrap();
        let _: () = redis::cmd("REPLICAOF")
            .arg("127.0.0.1")
            .arg(primary.port)
            .query_async(&mut replica)
            .await
            .unwrap();
        self.wait_for_primary_pair(primary).await;
        primary.wait_for_replica_fsync().await;
    }
    async fn wait_for_replica_fsync(&self) {
        let mut connection = self.plaintext_connection().await;
        let key = format!("buffered-test-fsync:{}", uuid::Uuid::now_v7());
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg("checkpoint")
            .query_async(&mut connection)
            .await
            .unwrap();
        let (_, replicas): (usize, usize) = redis::cmd("WAITAOF")
            .arg(0)
            .arg(1)
            .arg(10_000)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(
            replicas >= 1,
            "fixture requires a durable initial replica before testing later loss"
        );
    }
    async fn wait_for_primary_pair(&self, primary: &Server) {
        let mut master = primary.plaintext_connection().await;
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("aux-buffered-writes:*")
            .query_async(&mut master)
            .await
            .unwrap();
        assert_eq!(keys.len(), 2);
        let expected: Vec<Option<Vec<u8>>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(&mut master)
            .await
            .unwrap();
        let mut replica = self.plaintext_connection().await;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(pair) = redis::cmd("MGET")
                .arg(&keys)
                .query_async::<Vec<Option<Vec<u8>>>>(&mut replica)
                .await
                && pair == expected
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "replica did not receive the exact state/metadata pair"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }
    fn endpoint(&self) -> String {
        if self.tls {
            format!("rediss://localhost:{}/", self.port)
        } else {
            format!("redis://127.0.0.1:{}/", self.port)
        }
    }
    fn credentials(&self) -> ValkeyCredentials {
        let credentials = ValkeyCredentials::new("buffered-writes-test");
        if self.tls {
            credentials.with_tls_ca_pem(std::fs::read(self.directory.join("ca.crt")).unwrap())
        } else {
            credentials.with_tls_required(false)
        }
    }
    fn provider(&self, namespace: &str) -> ValkeyBuffer {
        ValkeyBuffer::try_new(
            Namespace::try_new(namespace).unwrap(),
            self.endpoint(),
            self.credentials(),
        )
        .unwrap()
    }
    async fn start_tls() -> Self {
        let mut server = Self::start().await;
        server.generate_tls_certificates();
        server.tls = true;
        server.restart().await;
        server
    }
    fn generate_tls_certificates(&self) {
        std::fs::write(
            self.directory.join("server.ext"),
            concat!(
                "basicConstraints=critical,CA:FALSE\n",
                "keyUsage=digitalSignature,keyEncipherment\n",
                "extendedKeyUsage=serverAuth\n",
                "subjectAltName=DNS:localhost\n"
            ),
        )
        .unwrap();
        let commands = [
            vec![
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=BufferedWritesTestRoot",
                "-keyout",
                "ca.key",
                "-out",
                "ca.crt",
            ],
            vec![
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
            ],
            vec![
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "server.crt",
                "-days",
                "1",
                "-sha256",
                "-extfile",
                "server.ext",
            ],
        ];
        for arguments in commands {
            let output = Command::new("openssl")
                .args(&arguments)
                .current_dir(&self.directory)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "certificate fixture {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn sink(captured: Arc<Mutex<Vec<u32>>>) -> AtomicSink<u32> {
    AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let captured = captured.clone();
        async move {
            captured.lock().unwrap().extend_from_slice(attempt.items());
            Ok::<(), SinkError>(())
        }
    })
    .unwrap()
}

fn reserved_writer(buffer: ValkeyBuffer) -> BufferedWrites<u32> {
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 1000).unwrap(),
        |_: WriteAttempt<u32>| async { Err::<(), _>(SinkError::unknown_outcome("unknown commit")) },
    )
    .unwrap();
    BufferedWrites::builder("reserved-remote/v1", sink)
        .with_buffer_provider(buffer)
        .buffer_capacity(BufferCapacity::default().max_bytes(1800))
        .delivery_policy(buffered_writes::DeliveryPolicy {
            max_attempts_per_turn: 1,
            ..Default::default()
        })
        .flush_policy(|_: &BufferStats| false)
        .prepare_with("packed/v1", |batch| {
            buffered_writes::PreparedWrites::packed(&batch, &"x".repeat(400))
        })
        .build()
        .unwrap()
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_reserved_open_write_when_remote_restarts_then_keep_budget_and_seal_within_capacity()
{
    use buffered_writes::BufferInspectRequest;
    let mut server = Server::start().await;
    let id = OperationId::generate_v7();
    let inspect = || BufferInspectRequest {
        operation_id: Some(id.clone()),
        now_utc_ms: 0,
        now_instant: Instant::now(),
        deadline: Deadline::after(Duration::from_secs(2)),
    };
    let reserved;
    let receipt;
    {
        let buffer = server.provider("reserved-remote/v1");
        let writer = reserved_writer(buffer.clone());
        writer
            .add_write_item_with_options(1, WriteOptions::new().with_operation_id(id.clone()))
            .await
            .unwrap();
        assert!(matches!(
            writer.add_write_item(2).await,
            Err(WriteError::Full)
        ));
        let snapshot = buffer.inspect(inspect()).await.unwrap();
        reserved = snapshot.stats.bytes();
        receipt = snapshot.admission.unwrap();
        assert_eq!(receipt.status, buffered_writes::AdmissionStatus::Buffered);
        assert!(reserved <= 1800);
    }
    server.restart().await;
    let buffer = server.provider("reserved-remote/v1");
    assert_eq!(
        buffer.inspect(inspect()).await.unwrap().stats.bytes(),
        reserved
    );
    assert_eq!(
        buffer.inspect(inspect()).await.unwrap().admission,
        Some(receipt)
    );
    let writer = reserved_writer(buffer.clone());
    let report = writer.flush_writes().await;
    assert_eq!(report.batches_failed, 1);
    assert_eq!(report.quarantined_items, 0);
    let snapshot = buffer.inspect(inspect()).await.unwrap();
    assert_eq!(snapshot.admission, Some(receipt));
    assert_eq!(snapshot.unsettled_items, 1);
    assert_eq!(snapshot.unresolved_batch_ids.len(), 1);
    assert!(snapshot.stats.bytes() <= reserved);
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_unsupported_remote_format_when_read_then_reject_without_replacing_retained_data() {
    let server = Server::start().await;
    let buffer = server.provider("format/v1");
    let writer = BufferedWrites::builder("format/v1", sink(Arc::new(Mutex::new(Vec::new()))))
        .with_buffer_provider(buffer.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let client = redis::Client::open(format!(
        "redis://:buffered-writes-test@127.0.0.1:{}/",
        server.port
    ))
    .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("aux-buffered-writes:*")
        .query_async(&mut connection)
        .await
        .unwrap();
    let state_key = keys.iter().find(|key| key.ends_with(":state")).unwrap();
    let metadata_key = keys.iter().find(|key| key.ends_with(":metadata")).unwrap();
    let bytes: Vec<u8> = redis::cmd("GET")
        .arg(state_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    let state: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut previous = state.clone();
    previous["version"] = serde_json::json!(1);
    let mut foreign = state.clone();
    foreign["namespace"] = serde_json::json!("other/v1");
    let mut previous_v2 = state.clone();
    previous_v2["version"] = serde_json::json!(2);
    let mut previous_v3 = state.clone();
    previous_v3["version"] = serde_json::json!(3);
    let mut previous_v5 = state.clone();
    previous_v5["version"] = serde_json::json!(5);
    let mut previous_v4 = state.clone();
    previous_v4["version"] = serde_json::json!(4);
    for old in [
        serde_json::to_vec(&state["state"]).unwrap(),
        serde_json::to_vec(&previous).unwrap(),
        serde_json::to_vec(&previous_v2).unwrap(),
        serde_json::to_vec(&previous_v3).unwrap(),
        serde_json::to_vec(&previous_v4).unwrap(),
        serde_json::to_vec(&previous_v5).unwrap(),
        serde_json::to_vec(&foreign).unwrap(),
    ] {
        let _: () = redis::cmd("SET")
            .arg(state_key)
            .arg(&old)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(writer.flush_writes().await.buffer_error.is_some());
        let unchanged: Vec<u8> = redis::cmd("GET")
            .arg(state_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(unchanged, old);
    }
    let bytes: Vec<u8> = redis::cmd("GET")
        .arg(metadata_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    let mut metadata: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for (version, foreign) in [
        (1, false),
        (2, false),
        (3, false),
        (4, false),
        (999, false),
        (5, true),
    ] {
        metadata["version"] = serde_json::json!(version);
        if foreign {
            metadata["namespace"] = serde_json::json!("other/v1");
        }
        let _: () = redis::cmd("SET")
            .arg(metadata_key)
            .arg(serde_json::to_vec(&metadata).unwrap())
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(matches!(
            buffer
                .inspect(buffered_writes::BufferInspectRequest {
                    operation_id: None,
                    now_utc_ms: 0,
                    now_instant: Instant::now(),
                    deadline: Deadline::after(Duration::from_secs(1)),
                })
                .await,
            Err(buffered_writes::BufferError::CorruptStorage { .. })
        ));
    }
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_remote_admission_when_server_restarts_then_independent_client_recovers() {
    let mut server = Server::start().await;
    let captured = Arc::new(Mutex::new(Vec::new()));
    {
        let writer = BufferedWrites::builder("restart/v1", sink(captured.clone()))
            .with_buffer_provider(server.provider("restart/v1"))
            .build()
            .unwrap();
        writer.add_write_item(42).await.unwrap();
    }
    server.restart().await;
    let writer = BufferedWrites::builder("restart/v1", sink(captured.clone()))
        .with_buffer_provider(server.provider("restart/v1"))
        .build()
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(*captured.lock().unwrap(), vec![42]);
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_independent_clients_when_concurrent_admission_reaches_capacity_then_accept_exactly_25()
 {
    let server = Server::start().await;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut writers = Vec::new();
    for _ in 0..2 {
        writers.push(
            BufferedWrites::builder("capacity/v1", sink(captured.clone()))
                .with_buffer_provider(server.provider("capacity/v1"))
                .flush_policy(|_: &BufferStats| false)
                .buffer_capacity(BufferCapacity::default())
                .build()
                .unwrap(),
        );
    }
    let mut tasks = Vec::new();
    for item in 0..32 {
        let writer = writers[item as usize % 2].clone();
        tasks.push(tokio::spawn(
            async move { writer.add_write_item(item).await },
        ));
    }
    let mut accepted = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => accepted += 1,
            Err(WriteError::Full) => {}
            other => panic!("unexpected admission result: {other:?}"),
        }
    }
    assert_eq!(accepted, 25);
    assert_eq!(writers[0].flush_writes().await.items_settled, 25);
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_shared_namespace_when_duplicate_admission_uses_new_client_then_keep_one_item() {
    let server = Server::start().await;
    let captured = Arc::new(Mutex::new(Vec::new()));
    let options = WriteOptions::new().with_operation_id(OperationId::try_new("request-1").unwrap());
    for _ in 0..2 {
        let writer = BufferedWrites::builder("dedup/v1", sink(captured.clone()))
            .with_buffer_provider(server.provider("dedup/v1"))
            .build()
            .unwrap();
        writer
            .add_write_item_with_options(7, options.clone())
            .await
            .unwrap();
    }
    let provider = server.provider("dedup/v1");
    assert_eq!(
        provider
            .list_scopes(0, 10, Deadline::after(Duration::from_secs(2)))
            .await
            .unwrap()
            .1
            .len(),
        1
    );
    let writer = BufferedWrites::builder("dedup/v1", sink(captured.clone()))
        .with_buffer_provider(provider)
        .build()
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(*captured.lock().unwrap(), vec![7]);
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_expired_claim_when_another_client_claims_then_reject_stale_fence() {
    let server = Server::start().await;
    let first = server.provider("fence/v1");
    let second = server.provider("fence/v1");
    let writer = BufferedWrites::builder("fence/v1", sink(Arc::new(Mutex::new(Vec::new()))))
        .with_buffer_provider(first.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let request = BufferClaimRequest {
        max_watermark: None,
        allow_open_claim: true,
        force_all_ages: true,
        max_items: 25,
        max_bytes: 64 * 1024,
        lease_duration: Duration::from_millis(20),
        now_utc_ms: 0,
        now_instant: Instant::now(),
        deadline: Deadline::after(Duration::from_secs(2)),
    };
    let ClaimedWork::OpenCandidate(claim) = first.claim(request).await.unwrap() else {
        panic!("expected first claim")
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    let ClaimedWork::OpenCandidate(next) = second.claim(request).await.unwrap() else {
        panic!("expected takeover")
    };
    assert_ne!(claim.fencing_token, next.fencing_token);
    assert!(matches!(
        first
            .seal(BufferSealRequest {
                fencing_token: claim.fencing_token,
                action: BufferSealAction::ReleaseCandidate,
                capacity: buffered_writes::BufferCapacity::default(),
                lease_duration: Duration::from_millis(20),
                now_utc_ms: 0,
                deadline: Deadline::after(Duration::from_secs(1)),
            })
            .await,
        Err(buffered_writes::BufferError::StaleFence { .. })
    ));
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_server_clock_claims_when_expired_or_released_then_reject_old_authority_and_preserve_writes()
 {
    let server = Server::start().await;
    support::verify_temporal_leases(server.provider("lease-contract/v1"), |ttl| async move {
        tokio::time::sleep(ttl + Duration::from_millis(30)).await;
    })
    .await;
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_invalid_persisted_batch_ownership_when_remote_claims_then_reject_without_rewriting()
{
    let server = Server::start().await;
    let buffer = server.provider("reserved-remote/v1");
    let writer = reserved_writer(buffer.clone());
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 0);
    let client = redis::Client::open(format!(
        "redis://:buffered-writes-test@127.0.0.1:{}/",
        server.port
    ))
    .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("aux-buffered-writes:*:state")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(keys.len(), 1);
    let bytes: Vec<u8> = redis::cmd("GET")
        .arg(&keys[0])
        .query_async(&mut connection)
        .await
        .unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for case in 0..4 {
        let mut corrupt = original.clone();
        let state = &mut corrupt["state"];
        let entries = state["sealed_batches"].as_object_mut().unwrap();
        let key = entries.keys().next().unwrap().clone();
        let mut entry = entries.remove(&key).unwrap();
        let key = if case < 2 {
            entry["completed_operations"] = serde_json::json!([OperationId::generate_v7()]);
            key
        } else {
            buffered_writes::BatchId::generate_v7().to_string()
        };
        entries.insert(key, entry);
        if case % 2 == 1 {
            state["quarantined_batches"] = state["sealed_batches"].take();
            state["sealed_batches"] = serde_json::json!({});
        }
        let corrupt = serde_json::to_vec(&corrupt).unwrap();
        let _: () = redis::cmd("SET")
            .arg(&keys[0])
            .arg(&corrupt)
            .query_async(&mut connection)
            .await
            .unwrap();
        let result = buffer
            .claim(BufferClaimRequest {
                max_watermark: None,
                allow_open_claim: true,
                force_all_ages: true,
                max_items: 25,
                max_bytes: 64 * 1024,
                lease_duration: Duration::from_secs(5),
                now_utc_ms: 0,
                now_instant: Instant::now(),
                deadline: Deadline::after(Duration::from_secs(2)),
            })
            .await;
        assert!(
            matches!(
                result,
                Err(buffered_writes::BufferError::CorruptStorage { .. })
            ),
            "{result:?}"
        );
        let unchanged: Vec<u8> = redis::cmd("GET")
            .arg(&keys[0])
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(unchanged, corrupt);
    }
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_inconsistent_remote_metadata_when_mutating_then_preserve_both_keys() {
    let server = Server::start().await;
    let buffer = server.provider("metadata-owner/v1");
    let writer =
        BufferedWrites::builder("metadata-owner/v1", sink(Arc::new(Mutex::new(Vec::new()))))
            .with_buffer_provider(buffer.clone())
            .build()
            .unwrap();
    writer.add_write_item(7).await.unwrap();
    let client = redis::Client::open(format!(
        "redis://:buffered-writes-test@127.0.0.1:{}/",
        server.port
    ))
    .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("aux-buffered-writes:*")
        .query_async(&mut connection)
        .await
        .unwrap();
    let state_key = keys.iter().find(|key| key.ends_with(":state")).unwrap();
    let metadata_key = keys.iter().find(|key| key.ends_with(":metadata")).unwrap();
    let original: (Option<Vec<u8>>, Option<Vec<u8>>) = redis::cmd("MGET")
        .arg(state_key)
        .arg(metadata_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    for case in 0..5 {
        let mut expected = original.clone();
        if case < 3 {
            let mut metadata: serde_json::Value =
                serde_json::from_slice(expected.1.as_ref().unwrap()).unwrap();
            if case < 2 {
                metadata["version"] = serde_json::json!(case + 1);
            } else {
                metadata["namespace"] = serde_json::json!("other/v1");
            }
            expected.1 = Some(serde_json::to_vec(&metadata).unwrap());
        } else if case == 3 {
            expected.1 = None;
        } else {
            expected.0 = None;
        }
        let _: () = redis::cmd("DEL")
            .arg(state_key)
            .arg(metadata_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        for (key, value) in [(state_key, &expected.0), (metadata_key, &expected.1)] {
            if let Some(bytes) = value {
                let _: () = redis::cmd("SET")
                    .arg(key)
                    .arg(bytes)
                    .query_async(&mut connection)
                    .await
                    .unwrap();
            }
        }
        let result = buffer
            .claim(BufferClaimRequest {
                max_watermark: None,
                allow_open_claim: true,
                force_all_ages: true,
                max_items: 25,
                max_bytes: 64 * 1024,
                lease_duration: Duration::from_secs(5),
                now_utc_ms: 0,
                now_instant: Instant::now(),
                deadline: Deadline::after(Duration::from_secs(2)),
            })
            .await;
        assert!(
            matches!(
                result,
                Err(buffered_writes::BufferError::CorruptStorage { .. })
            ),
            "case={case}: {result:?}"
        );
        let after: (Option<Vec<u8>>, Option<Vec<u8>>) = redis::cmd("MGET")
            .arg(state_key)
            .arg(metadata_key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(after, expected);
        let snapshot = buffer
            .inspect(buffered_writes::BufferInspectRequest {
                operation_id: None,
                now_utc_ms: 0,
                now_instant: Instant::now(),
                deadline: Deadline::after(Duration::from_secs(2)),
            })
            .await;
        assert!(
            matches!(
                snapshot,
                Err(buffered_writes::BufferError::CorruptStorage { .. })
            ),
            "case={case}: {snapshot:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_persisted_credits_above_new_capacity_when_remote_restarts_then_preserve_recoverable_writes()
 {
    let mut server = Server::start().await;
    let buffer = server.provider("capacity-recovery/v1");
    let recovery_host = &mut server;
    support::verify_lower_capacity(
        buffer,
        move |buffer| async move {
            drop(buffer);
            recovery_host.restart().await;
            recovery_host.provider("capacity-recovery/v1")
        },
        BufferCapacity::default().max_bytes(1200),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_larger_preparation_than_persisted_credits_when_remote_restarts_then_preserve_recoverable_writes()
 {
    let mut server = Server::start().await;
    let buffer = server.provider("preparation-recovery/v1");
    let recovery_host = &mut server;
    support::verify_changed_preparation(buffer, move |buffer| async move {
        drop(buffer);
        recovery_host.restart().await;
        recovery_host.provider("preparation-recovery/v1")
    })
    .await;
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_future_retained_timestamp_when_remote_retries_then_metadata_matches_claim_without_bypassing_lease()
 {
    let server = Server::start().await;
    let buffer = server.provider("reserved-remote/v1");
    let writer = reserved_writer(buffer.clone());
    writer.add_write_item(1).await.unwrap();
    writer.flush_writes().await;
    let client = redis::Client::open(format!(
        "redis://:buffered-writes-test@127.0.0.1:{}/",
        server.port
    ))
    .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("aux-buffered-writes:*")
        .query_async(&mut connection)
        .await
        .unwrap();
    let state_key = keys.iter().find(|key| key.ends_with(":state")).unwrap();
    let metadata_key = keys.iter().find(|key| key.ends_with(":metadata")).unwrap();
    let state_bytes: Vec<u8> = redis::cmd("GET")
        .arg(state_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    let metadata_bytes: Vec<u8> = redis::cmd("GET")
        .arg(metadata_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    let mut state: serde_json::Value = serde_json::from_slice(&state_bytes).unwrap();
    let mut metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes).unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let future = now + 3_600_000;
    // Simulate rollback after a later retry schedule while the original batch
    // remains older than current provider time. Keep its immutable digest
    // intact.
    let entry = state["state"]["sealed_batches"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    let batch: buffered_writes::SealedBatch =
        serde_json::from_value(entry["batch"].clone()).unwrap();
    assert!(batch.first_item_time_ms() <= now);
    entry["next_retry_at_ms"] = serde_json::json!(future + 100);
    entry["retry_scheduled_at_ms"] = serde_json::json!(future);
    metadata["sealed_leases"][0]["retry_scheduled_at"] = serde_json::json!(future);
    metadata["sealed_leases"][0]["retry_at"] = serde_json::json!(future + 100);
    let deadline = Deadline::after(Duration::from_secs(5));
    let claim = BufferClaimRequest {
        max_watermark: None,
        allow_open_claim: false,
        force_all_ages: false,
        max_items: 25,
        max_bytes: 65536,
        lease_duration: Duration::from_secs(10),
        now_utc_ms: now,
        now_instant: Instant::now(),
        deadline,
    };
    for active in [true, false] {
        let expiry = if active {
            serde_json::json!(now + 10_000)
        } else {
            serde_json::Value::Null
        };
        state["state"]["sealed_batches"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap()["lease_expires_at_ms"] = expiry.clone();
        metadata["sealed_leases"][0]["expires"] = expiry;
        let _: () = redis::cmd("MSET")
            .arg(state_key)
            .arg(serde_json::to_vec(&state).unwrap())
            .arg(metadata_key)
            .arg(serde_json::to_vec(&metadata).unwrap())
            .query_async(&mut connection)
            .await
            .unwrap();
        let snapshot = buffer
            .inspect(buffered_writes::BufferInspectRequest {
                operation_id: None,
                now_utc_ms: now,
                now_instant: Instant::now(),
                deadline,
            })
            .await
            .unwrap();
        assert_eq!(snapshot.claimable_sealed_batches, usize::from(!active));
        assert_eq!(snapshot.in_flight_batches, usize::from(active));
        match buffer.claim(claim).await.unwrap() {
            ClaimedWork::None => assert!(active),
            ClaimedWork::ExistingSealed(leased) => {
                assert!(!active);
                assert_eq!(leased.batch, batch);
            }
            ClaimedWork::OpenCandidate(_) => panic!("unexpected open work"),
        }
    }
}

#[tokio::test]
#[ignore = "requires local redis-server; run the provider acceptance recipe"]
async fn given_client_clock_ahead_of_provider_when_retry_backoff_expires_then_normal_response_retries_on_provider_time()
 {
    let server = Server::start().await;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::ready(Err::<(), _>(SinkError::retryable("outage")))
    })
    .unwrap();
    let clock = buffered_writes::TestClock::with_utc_millis(
        chrono::Utc::now().timestamp_millis() + 3_600_000,
    );
    clock.set_auto_advance_on_sleep(false);
    let writer = BufferedWrites::builder("clock-skew/v1", sink)
        .with_buffer_provider(server.provider("clock-skew/v1"))
        .with_clock(clock)
        .delivery_policy(buffered_writes::DeliveryPolicy {
            max_attempts_per_turn: 1,
            fallback_age: Duration::from_secs(86_400),
            retry_base_delay: Duration::from_millis(20),
            ..Default::default()
        })
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.batches_failed, 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(writer.after_response().await.batches_failed, 1);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; starts a disposable local service"]
async fn given_connected_provider_when_eviction_policy_changes_then_reject_further_admission() {
    let server = Server::start().await;
    let provider = server.provider("policy-change/v1");
    let writer = BufferedWrites::builder("policy-change/v1", sink(Arc::default()))
        .with_buffer_provider(provider)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let client = redis::Client::open(format!(
        "redis://:buffered-writes-test@127.0.0.1:{}/",
        server.port
    ))
    .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory-policy")
        .arg("allkeys-lru")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(
        writer.add_write_item(2).await.is_err(),
        "cached connection must not accept an eviction policy"
    );
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; starts a disposable local service"]
async fn given_same_namespace_when_old_metadata_is_mixed_with_new_state_then_reject_inspection() {
    let server = Server::start().await;
    let provider = server.provider("mixed-revision/v1");
    let writer = BufferedWrites::builder("mixed-revision/v1", sink(Arc::default()))
        .with_buffer_provider(provider.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let client = redis::Client::open(format!(
        "redis://:buffered-writes-test@127.0.0.1:{}/",
        server.port
    ))
    .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("aux-buffered-writes:*:metadata")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(keys.len(), 1);
    let old: Vec<u8> = redis::cmd("GET")
        .arg(&keys[0])
        .query_async(&mut connection)
        .await
        .unwrap();
    writer.add_write_item(2).await.unwrap();
    let _: () = redis::cmd("SET")
        .arg(&keys[0])
        .arg(old)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(
        provider
            .inspect(buffered_writes::BufferInspectRequest {
                operation_id: None,
                now_utc_ms: chrono::Utc::now().timestamp_millis(),
                now_instant: Instant::now(),
                deadline: Deadline::after(Duration::from_secs(1))
            })
            .await
            .is_err(),
        "separately valid metadata must match the retained state revision"
    );
}

#[tokio::test]
#[ignore = "requires redis-server with TLS and openssl; starts a disposable local service"]
async fn given_authenticated_tls_when_service_restarts_then_discover_and_drain_with_independent_client()
 {
    let mut server = Server::start_tls().await;
    let writer = BufferedWrites::builder("tls-recovery/v1", sink(Arc::default()))
        .with_buffer_provider(server.provider("tls-recovery/v1"))
        .build()
        .unwrap();
    writer
        .add_write_item_with_options(
            7,
            WriteOptions::new()
                .with_scope(buffered_writes::TenantScope::try_from("trusted-scope").unwrap()),
        )
        .await
        .unwrap();
    drop(writer);
    server.restart().await;
    let provider = server.provider("tls-recovery/v1");
    let (cursor, scopes) = provider
        .list_scopes(0, 25, Deadline::after(Duration::from_secs(2)))
        .await
        .unwrap();
    assert_eq!(cursor, 0);
    assert_eq!(
        scopes,
        vec![buffered_writes::TenantScope::try_from("trusted-scope").unwrap()]
    );
    let values: Arc<Mutex<Vec<u32>>> = Arc::default();
    let writer = BufferedWrites::builder("tls-recovery/v1", sink(values.clone()))
        .with_buffer_provider(provider)
        .build()
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(*values.lock().unwrap(), vec![7]);
}

#[tokio::test]
#[ignore = "requires redis-server with TLS and openssl; starts a disposable local service"]
async fn given_tls_peer_when_ca_hostname_or_password_is_wrong_then_reject_without_admission() {
    let server = Server::start_tls().await;
    let untrusted = ValkeyBuffer::try_new(
        Namespace::try_from("tls-negative/v1").unwrap(),
        server.endpoint(),
        ValkeyCredentials::new("buffered-writes-test"),
    )
    .unwrap();
    let wrong_host = ValkeyBuffer::try_new(
        Namespace::try_from("tls-negative/v1").unwrap(),
        format!("rediss://127.0.0.1:{}/", server.port),
        server.credentials(),
    )
    .unwrap();
    let wrong_password = ValkeyBuffer::try_new(
        Namespace::try_from("tls-negative/v1").unwrap(),
        server.endpoint(),
        ValkeyCredentials::new("wrong-password")
            .with_tls_ca_pem(std::fs::read(server.directory.join("ca.crt")).unwrap()),
    )
    .unwrap();
    for provider in [untrusted, wrong_host, wrong_password] {
        assert!(
            provider
                .inspect(buffered_writes::BufferInspectRequest {
                    operation_id: None,
                    now_utc_ms: chrono::Utc::now().timestamp_millis(),
                    now_instant: Instant::now(),
                    deadline: Deadline::after(Duration::from_millis(300))
                })
                .await
                .is_err()
        );
    }
    let provider = server.provider("tls-negative/v1");
    assert_eq!(
        provider
            .list_scopes(0, 25, Deadline::after(Duration::from_secs(2)))
            .await
            .unwrap(),
        (0, vec![])
    );
}

#[test]
fn given_tls_endpoint_with_insecure_fragment_or_embedded_secrets_when_configured_then_reject() {
    for endpoint in [
        "rediss://localhost/#insecure",
        "rediss://user:password@localhost/",
        "redis://localhost/",
    ] {
        assert!(
            ValkeyBuffer::try_new(
                Namespace::try_from("tls-validation/v1").unwrap(),
                endpoint,
                ValkeyCredentials::new("secret")
            )
            .is_err()
        );
    }
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; starts a disposable local service"]
async fn given_expiring_or_lost_retention_when_live_provider_inspects_then_reject_without_reinitializing()
 {
    let server = Server::start().await;
    let provider = server.provider("retention-loss/v1");
    let writer = BufferedWrites::builder("retention-loss/v1", sink(Arc::default()))
        .with_buffer_provider(provider.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let client = redis::Client::open(format!(
        "redis://:buffered-writes-test@127.0.0.1:{}/",
        server.port
    ))
    .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("aux-buffered-writes:*")
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: () = redis::cmd("PEXPIRE")
        .arg(&keys[0])
        .arg(60_000)
        .query_async(&mut connection)
        .await
        .unwrap();
    let inspect = || buffered_writes::BufferInspectRequest {
        operation_id: None,
        now_utc_ms: chrono::Utc::now().timestamp_millis(),
        now_instant: Instant::now(),
        deadline: Deadline::after(Duration::from_secs(2)),
    };
    assert!(provider.inspect(inspect()).await.is_err());
    let _: () = redis::cmd("DEL")
        .arg(&keys)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(
        provider.inspect(inspect()).await.is_err(),
        "live ownership cannot turn known retention into an empty namespace"
    );
    assert!(writer.add_write_item(2).await.is_err());
    let remaining: usize = redis::cmd("DBSIZE")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "do not silently replace lost retention");
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; starts a disposable local service"]
async fn given_noeviction_memory_exhaustion_when_admission_retries_after_recovery_then_preserve_one_identity()
 {
    let server = Server::start().await;
    let provider = server.provider("server-capacity/v1");
    let values: Arc<Mutex<Vec<u32>>> = Arc::default();
    let writer = BufferedWrites::builder("server-capacity/v1", sink(values.clone()))
        .with_buffer_provider(provider)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let client = redis::Client::open(format!(
        "redis://:buffered-writes-test@127.0.0.1:{}/",
        server.port
    ))
    .unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("aux-buffered-writes:*")
        .query_async(&mut connection)
        .await
        .unwrap();
    let before: Vec<Vec<u8>> = redis::cmd("MGET")
        .arg(&keys)
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory")
        .arg(1)
        .query_async(&mut connection)
        .await
        .unwrap();
    let options =
        WriteOptions::new().with_operation_id(OperationId::try_from("capacity-retry").unwrap());
    assert!(
        writer
            .add_write_item_with_options(2, options.clone())
            .await
            .is_err()
    );
    let after: Vec<Vec<u8>> = redis::cmd("MGET")
        .arg(&keys)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(after, before);
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory")
        .arg(0)
        .query_async(&mut connection)
        .await
        .unwrap();
    writer
        .add_write_item_with_options(2, options)
        .await
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 2);
    assert_eq!(*values.lock().unwrap(), vec![1, 2]);
}

enum ProxyMode {
    DropCommitReply,
    DelayCommit,
    HoldReply,
}
struct ProxyControl {
    drop_reply: std::sync::atomic::AtomicBool,
    dropped: std::sync::atomic::AtomicBool,
    delay_next: std::sync::atomic::AtomicBool,
    delayed: std::sync::atomic::AtomicBool,
    hold_next: std::sync::atomic::AtomicBool,
    held: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
struct FaultProxy {
    port: u16,
    control: Arc<ProxyControl>,
    task: tokio::task::JoinHandle<()>,
}
impl FaultProxy {
    async fn start(upstream: u16, mode: ProxyMode) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let control = Arc::new(ProxyControl {
            drop_reply: std::sync::atomic::AtomicBool::new(matches!(
                mode,
                ProxyMode::DropCommitReply
            )),
            dropped: std::sync::atomic::AtomicBool::new(false),
            delay_next: std::sync::atomic::AtomicBool::new(false),
            delayed: std::sync::atomic::AtomicBool::new(false),
            hold_next: std::sync::atomic::AtomicBool::new(false),
            held: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let observed = control.clone();
        let task = tokio::spawn(async move {
            loop {
                let (client, _) = listener.accept().await.unwrap();
                let observed = observed.clone();
                tokio::spawn(async move {
                    Self::forward(client, upstream, observed).await;
                });
            }
        });
        Self {
            port,
            control,
            task,
        }
    }
    async fn forward(client: tokio::net::TcpStream, port: u16, control: Arc<ProxyControl>) {
        use std::sync::atomic::Ordering;

        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let Ok(server) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
            return;
        };
        let (client_read, mut client_write) = client.into_split();
        let (server_read, mut server_write) = server.into_split();
        let client_control = control.clone();
        let sender = tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(client_read);
            loop {
                let mut line = Vec::new();
                if !matches!(reader.read_until(b'\n', &mut line).await, Ok(length) if length > 0) {
                    break;
                }
                if line == b"commit\r\n" && client_control.delay_next.swap(false, Ordering::SeqCst)
                {
                    client_control.delayed.store(true, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                if server_write.write_all(&line).await.is_err() {
                    break;
                }
            }
        });
        let mut reader = tokio::io::BufReader::new(server_read);
        loop {
            let mut line = Vec::new();
            if !matches!(reader.read_until(b'\n', &mut line).await, Ok(length) if length > 0) {
                break;
            }
            // In this fresh RESP2 namespace the first integer-one response is
            // the CAS commit, after authentication/empty inspection/TIME.
            if line == b":1\r\n" && control.hold_next.swap(false, Ordering::SeqCst) {
                control.held.notify_one();
                control.release.notified().await;
            }
            if line == b":1\r\n" && control.drop_reply.swap(false, Ordering::SeqCst) {
                control.dropped.store(true, Ordering::SeqCst);
                break;
            }
            if client_write.write_all(&line).await.is_err() {
                break;
            }
        }
        sender.abort();
    }
}
impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; starts a disposable service and TCP fault proxy"]
async fn given_committed_append_when_network_drops_its_reply_then_retry_reconciles_one_write() {
    let server = Server::start().await;
    let proxy = FaultProxy::start(server.port, ProxyMode::DropCommitReply).await;
    let provider = ValkeyBuffer::try_new(
        Namespace::try_from("ack-loss/v1").unwrap(),
        format!("redis://127.0.0.1:{}/?protocol=resp2", proxy.port),
        server.credentials(),
    )
    .unwrap();
    let values: Arc<Mutex<Vec<u32>>> = Arc::default();
    let writer = BufferedWrites::builder("ack-loss/v1", sink(values.clone()))
        .with_buffer_provider(provider.clone())
        .build()
        .unwrap();
    let options =
        WriteOptions::new().with_operation_id(OperationId::try_from("stable-admission").unwrap());
    assert!(matches!(
        writer.add_write_item_with_options(7, options.clone()).await,
        Err(WriteError::Ambiguous { .. })
    ));
    assert!(
        proxy
            .control
            .dropped
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    writer
        .add_write_item_with_options(7, options)
        .await
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(*values.lock().unwrap(), vec![7]);
}

#[tokio::test]
#[ignore = "requires redis-server on PATH; starts a disposable service and TCP fault proxy"]
async fn given_active_lease_when_network_delay_crosses_expiry_before_cas_then_renew_cannot_resurrect_authority()
 {
    use std::sync::atomic::Ordering;
    let server = Server::start().await;
    let proxy = FaultProxy::start(server.port, ProxyMode::DelayCommit).await;
    let provider = ValkeyBuffer::try_new(
        Namespace::try_from("delayed-lease/v1").unwrap(),
        format!("redis://127.0.0.1:{}/?protocol=resp2", proxy.port),
        server.credentials(),
    )
    .unwrap();
    let unknown = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Err::<(), _>(SinkError::unknown_outcome(
            "test commit acknowledgement unavailable",
        ))
    })
    .unwrap();
    let writer = BufferedWrites::builder("delayed-lease/v1", unknown)
        .with_buffer_provider(provider.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.batches_failed, 1);
    tokio::time::sleep(Duration::from_millis(60)).await;
    let request = BufferClaimRequest {
        max_watermark: None,
        allow_open_claim: true,
        force_all_ages: true,
        max_items: 25,
        max_bytes: 64 * 1024,
        lease_duration: Duration::from_millis(100),
        now_utc_ms: chrono::Utc::now().timestamp_millis(),
        now_instant: Instant::now(),
        deadline: Deadline::after(Duration::from_secs(2)),
    };
    let ClaimedWork::ExistingSealed(leased) = provider.claim(request).await.unwrap() else {
        panic!("expected sealed batch");
    };
    proxy.control.delay_next.store(true, Ordering::SeqCst);
    assert!(matches!(
        provider
            .renew(buffered_writes::BufferRenewRequest {
                batch_id: leased.batch.batch_id(),
                fencing_token: leased.fencing_token,
                lease_duration: Duration::from_secs(1),
                now_utc_ms: request.now_utc_ms,
                deadline: request.deadline
            })
            .await,
        Err(buffered_writes::BufferError::StaleFence { .. })
    ));
    assert!(proxy.control.delayed.load(Ordering::SeqCst));
    let independent = server.provider("delayed-lease/v1");
    let ClaimedWork::ExistingSealed(next) = independent.claim(request).await.unwrap() else {
        panic!("expected expired lease takeover");
    };
    assert_eq!(next.batch.batch_id(), leased.batch.batch_id());
    assert_ne!(next.fencing_token, leased.fencing_token);
}

#[tokio::test]
#[ignore = "requires a Valkey/Redis-compatible server; starts disposable primary and replica"]
async fn given_replicated_claim_when_primary_fails_and_replica_is_promoted_then_preserve_batch_and_fencing()
 {
    let mut primary = Server::start().await;
    let replica = Server::start().await;
    let provider = primary.provider("promotion/v1");
    let unknown = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Err::<(), _>(SinkError::unknown_outcome(
            "test acknowledgement unavailable",
        ))
    })
    .unwrap();
    let writer = BufferedWrites::builder("promotion/v1", unknown)
        .with_buffer_provider(provider.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    assert_eq!(writer.flush_writes().await.batches_failed, 1);
    replica.replicate_from(&primary).await;
    let request = BufferClaimRequest {
        max_watermark: None,
        allow_open_claim: true,
        force_all_ages: true,
        max_items: 25,
        max_bytes: 64 * 1024,
        lease_duration: Duration::from_secs(10),
        now_utc_ms: chrono::Utc::now().timestamp_millis(),
        now_instant: Instant::now(),
        deadline: Deadline::after(Duration::from_secs(10)),
    };
    let ClaimedWork::ExistingSealed(first) = provider.claim(request).await.unwrap() else {
        panic!("expected sealed batch");
    };
    replica.wait_for_primary_pair(&primary).await;
    primary.stop();
    let mut connection = replica.plaintext_connection().await;
    let _: () = redis::cmd("REPLICAOF")
        .arg("NO")
        .arg("ONE")
        .query_async(&mut connection)
        .await
        .unwrap();
    let promoted = replica.provider("promotion/v1");
    assert!(matches!(
        promoted.claim(request).await.unwrap(),
        ClaimedWork::None
    ));
    promoted
        .settle(buffered_writes::BufferSettleRequest {
            batch_id: first.batch.batch_id(),
            fencing_token: first.fencing_token,
            disposition: buffered_writes::SettleDisposition::ReleaseForRetry {
                retry_delay: Duration::ZERO,
            },
            now_utc_ms: request.now_utc_ms,
            deadline: request.deadline,
        })
        .await
        .unwrap();
    let ClaimedWork::ExistingSealed(second) = promoted.claim(request).await.unwrap() else {
        panic!("expected released batch");
    };
    assert_eq!(second.batch.batch_id(), first.batch.batch_id());
    assert_eq!(second.batch.digest(), first.batch.digest());
    assert_ne!(second.fencing_token, first.fencing_token);
    assert!(matches!(
        promoted
            .renew(buffered_writes::BufferRenewRequest {
                batch_id: first.batch.batch_id(),
                fencing_token: first.fencing_token,
                lease_duration: Duration::from_secs(10),
                now_utc_ms: request.now_utc_ms,
                deadline: request.deadline
            })
            .await,
        Err(buffered_writes::BufferError::StaleFence { .. })
    ));
}

#[tokio::test]
#[ignore = "requires a Valkey/Redis-compatible server; demonstrates asynchronous-replication loss"]
async fn given_offline_replica_when_primary_acknowledges_then_fails_then_promoting_old_copy_can_lose_the_write()
 {
    let mut primary = Server::start().await;
    let mut replica = Server::start().await;
    let writer = BufferedWrites::builder("failover-loss/v1", sink(Arc::default()))
        .with_buffer_provider(primary.provider("failover-loss/v1"))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    replica.replicate_from(&primary).await;
    replica.stop();
    let receipt = writer.add_write_item(2).await.unwrap();
    assert_eq!(
        receipt.durability(),
        buffered_writes::DurabilityClass::RemoteValkey
    );
    primary.stop();
    replica.restart().await;
    let recovered: Arc<Mutex<Vec<u32>>> = Arc::default();
    let writer = BufferedWrites::builder("failover-loss/v1", sink(recovered.clone()))
        .with_buffer_provider(replica.provider("failover-loss/v1"))
        .build()
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    assert_eq!(
        *recovered.lock().unwrap(),
        vec![1],
        "the second acknowledged write never reached the promoted copy"
    );
}

#[derive(Clone, Copy, Debug)]
enum NativeCancellation {
    Append,
    Claim,
    Seal,
    Renew,
    Settle,
    Inspect,
}
fn cancellation_append(id: &str, value: u32) -> buffered_writes::BufferAppendRequest {
    buffered_writes::BufferAppendRequest {
        record: buffered_writes::AdmittedRecord {
            operation_id: OperationId::try_from(id).unwrap(),
            scope: buffered_writes::TenantScope::try_from("cancel-scope").unwrap(),
            codec_version: "serde-json/v1".to_owned(),
            admitted_at_utc_ms: chrono::Utc::now().timestamp_millis(),
            admitted_at_mono: Instant::now(),
            payload: bytes::Bytes::from(serde_json::to_vec(&value).unwrap()),
        },
        reserved_bytes: 4096,
        capacity: BufferCapacity::default(),
        deadline: Deadline::after(Duration::from_secs(5)),
    }
}
fn cancellation_claim() -> BufferClaimRequest {
    BufferClaimRequest {
        max_watermark: None,
        allow_open_claim: true,
        force_all_ages: true,
        max_items: 25,
        max_bytes: 64 * 1024,
        lease_duration: Duration::from_millis(500),
        now_utc_ms: chrono::Utc::now().timestamp_millis(),
        now_instant: Instant::now(),
        deadline: Deadline::after(Duration::from_secs(5)),
    }
}
fn cancellation_seal(
    namespace: &Namespace,
    candidate: buffered_writes::OpenBatchCandidate,
) -> BufferSealRequest {
    let batch = buffered_writes::SealedBatch::try_new(buffered_writes::SealedBatchInput {
        batch_id: buffered_writes::BatchId::generate_v7(),
        namespace: namespace.clone(),
        scope: candidate.records[0].scope.clone(),
        codec_version: "serde-json/v1".to_owned(),
        strategy_version: "default-items/v1".to_owned(),
        first_item_time_ms: candidate.records[0].admitted_at_utc_ms,
        records: candidate
            .records
            .iter()
            .map(|record| buffered_writes::PersistedRecord {
                operation_id: record.operation_id.clone(),
                admitted_at_utc_ms: record.admitted_at_utc_ms,
                payload: record.payload.clone(),
            })
            .collect::<Vec<_>>()
            .into(),
        prepared: buffered_writes::PreparedPayload::SharedRecords,
        operation_ids: candidate
            .records
            .iter()
            .map(|record| record.operation_id.clone())
            .collect::<Vec<_>>()
            .into(),
    })
    .unwrap();
    BufferSealRequest {
        fencing_token: candidate.fencing_token,
        action: BufferSealAction::InstallBatch(batch),
        capacity: BufferCapacity::default(),
        lease_duration: Duration::from_millis(500),
        now_utc_ms: chrono::Utc::now().timestamp_millis(),
        deadline: Deadline::after(Duration::from_secs(5)),
    }
}

#[tokio::test]
#[ignore = "requires a Valkey/Redis-compatible server; starts disposable services and fault proxies"]
async fn given_each_provider_operation_when_caller_cancels_after_server_commit_then_independent_recovery_preserves_ownership()
 {
    use std::sync::atomic::Ordering;

    use buffered_writes::{
        BufferInspectRequest, BufferRenewRequest, BufferSettleRequest, SettleDisposition,
    };
    for operation in [
        NativeCancellation::Append,
        NativeCancellation::Claim,
        NativeCancellation::Seal,
        NativeCancellation::Renew,
        NativeCancellation::Settle,
        NativeCancellation::Inspect,
    ] {
        let server = Server::start().await;
        let proxy = FaultProxy::start(server.port, ProxyMode::HoldReply).await;
        let namespace = Namespace::try_from("native-cancel/v1").unwrap();
        let provider = ValkeyBuffer::try_new(
            namespace.clone(),
            format!("redis://127.0.0.1:{}/?protocol=resp2", proxy.port),
            server.credentials(),
        )
        .unwrap();
        let original = cancellation_append("cancel-one", 1);
        provider.append(original.clone()).await.unwrap();
        let mut seal = None;
        let mut leased = None;
        if matches!(
            operation,
            NativeCancellation::Seal | NativeCancellation::Renew | NativeCancellation::Settle
        ) {
            let ClaimedWork::OpenCandidate(candidate) =
                provider.claim(cancellation_claim()).await.unwrap()
            else {
                panic!("expected open candidate");
            };
            let request = cancellation_seal(&namespace, candidate);
            if matches!(operation, NativeCancellation::Seal) {
                seal = Some(request);
            } else {
                leased = provider.seal(request).await.unwrap();
            }
        }
        let inspect = || BufferInspectRequest {
            operation_id: Some(original.record.operation_id.clone()),
            now_utc_ms: chrono::Utc::now().timestamp_millis(),
            now_instant: Instant::now(),
            deadline: Deadline::after(Duration::from_secs(5)),
        };
        let target = provider.clone();
        proxy.control.hold_next.store(true, Ordering::SeqCst);
        let pending: futures_util::future::BoxFuture<'static, ()> = match operation {
            NativeCancellation::Append => Box::pin(async move {
                let _ = target.append(cancellation_append("cancel-two", 2)).await;
            }),
            NativeCancellation::Claim => Box::pin(async move {
                let _ = target.claim(cancellation_claim()).await;
            }),
            NativeCancellation::Seal => {
                let request = seal.unwrap();
                Box::pin(async move {
                    let _ = target.seal(request).await;
                })
            }
            NativeCancellation::Renew => {
                let work = leased.clone().unwrap();
                Box::pin(async move {
                    let _ = target
                        .renew(BufferRenewRequest {
                            batch_id: work.batch.batch_id(),
                            fencing_token: work.fencing_token,
                            lease_duration: Duration::from_secs(2),
                            now_utc_ms: chrono::Utc::now().timestamp_millis(),
                            deadline: Deadline::after(Duration::from_secs(5)),
                        })
                        .await;
                })
            }
            NativeCancellation::Settle => {
                let work = leased.clone().unwrap();
                Box::pin(async move {
                    let _ = target
                        .settle(BufferSettleRequest {
                            batch_id: work.batch.batch_id(),
                            fencing_token: work.fencing_token,
                            disposition: SettleDisposition::Delivered,
                            now_utc_ms: chrono::Utc::now().timestamp_millis(),
                            deadline: Deadline::after(Duration::from_secs(5)),
                        })
                        .await;
                })
            }
            NativeCancellation::Inspect => {
                let request = inspect();
                Box::pin(async move {
                    let _ = target.inspect(request).await;
                })
            }
        };
        let task = tokio::spawn(pending);
        tokio::time::timeout(Duration::from_secs(5), proxy.control.held.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled(), "{operation:?}");
        proxy.control.release.notify_one();
        let independent = server.provider("native-cancel/v1");
        let after = independent.inspect(inspect()).await.unwrap();
        let expected = match operation {
            NativeCancellation::Append => 2,
            NativeCancellation::Settle => 0,
            _ => 1,
        };
        assert_eq!(after.unsettled_items, expected, "{operation:?}");
        if matches!(operation, NativeCancellation::Settle) {
            assert_eq!(
                after.admission.unwrap().status,
                buffered_writes::AdmissionStatus::Written
            );
            assert!(independent.append(original).await.unwrap().duplicate);
        }
        if matches!(
            operation,
            NativeCancellation::Claim | NativeCancellation::Seal | NativeCancellation::Renew
        ) {
            assert!(
                matches!(
                    independent.claim(cancellation_claim()).await.unwrap(),
                    ClaimedWork::None
                ),
                "{operation:?}"
            );
            tokio::time::sleep(Duration::from_millis(550)).await;
        }
        if matches!(operation, NativeCancellation::Renew) {
            assert!(
                matches!(
                    independent.claim(cancellation_claim()).await.unwrap(),
                    ClaimedWork::None
                ),
                "renewal must survive beyond the old lease deadline"
            );
            let work = leased.unwrap();
            independent
                .settle(BufferSettleRequest {
                    batch_id: work.batch.batch_id(),
                    fencing_token: work.fencing_token,
                    disposition: SettleDisposition::ReleaseForRetry {
                        retry_delay: Duration::ZERO,
                    },
                    now_utc_ms: chrono::Utc::now().timestamp_millis(),
                    deadline: Deadline::after(Duration::from_secs(5)),
                })
                .await
                .unwrap();
        }
        let values: Arc<Mutex<Vec<u32>>> = Arc::default();
        let writer = BufferedWrites::builder("native-cancel/v1", sink(values.clone()))
            .with_buffer_provider(independent)
            .build()
            .unwrap();
        assert_eq!(
            writer.flush_writes().await.items_settled,
            expected,
            "{operation:?}"
        );
        assert_eq!(
            *values.lock().unwrap(),
            if expected == 2 {
                vec![1, 2]
            } else if expected == 1 {
                vec![1]
            } else {
                vec![]
            },
            "{operation:?}"
        );
    }
}
