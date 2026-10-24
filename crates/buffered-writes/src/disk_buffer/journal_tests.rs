use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{
    AtomicSink, BufferInspectRequest, BufferedWrites, Deadline, DiskBuffer, Namespace, OperationId,
    SinkError, SinkLimits, WriteAttempt, WriteBuffer, WriteOptions,
};

pub(super) fn crash_boundary(boundary: &str) {
    if std::env::var("BUFFERED_DISK_CRASH_POINT").ok().as_deref() != Some(boundary) {
        return;
    }
    static MATCHED_BOUNDARIES: AtomicUsize = AtomicUsize::new(0);
    let skip = std::env::var("BUFFERED_DISK_CRASH_SKIP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if MATCHED_BOUNDARIES.fetch_add(1, Ordering::SeqCst) < skip {
        return;
    }
    let directory = PathBuf::from(std::env::var_os("BUFFERED_DISK_CRASH_DIR").unwrap());
    fs::write(directory.join("boundary.tmp"), boundary).unwrap();
    fs::rename(directory.join("boundary.tmp"), directory.join("boundary")).unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

type CommitPause = (
    PathBuf,
    usize,
    Arc<std::sync::Barrier>,
    Arc<std::sync::Barrier>,
);
static COMMIT_PAUSES: Mutex<Vec<CommitPause>> = Mutex::new(Vec::new());
pub(super) fn pause_before_sync(directory: &Path) {
    let pause = {
        let mut pauses = COMMIT_PAUSES.lock().unwrap();
        match pauses.iter().position(|pause| pause.0 == directory) {
            Some(index) if pauses[index].1 > 0 => {
                pauses[index].1 -= 1;
                None
            }
            Some(index) => Some(pauses.remove(index)),
            None => None,
        }
    };
    if let Some((_, _, entered, release)) = pause {
        entered.wait();
        release.wait();
    }
}

struct CrashDirectory(PathBuf);
impl CrashDirectory {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("buffered-disk-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}
impl Drop for CrashDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct CrashChild(Child);
impl Drop for CrashChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn open(directory: &Path) -> DiskBuffer {
    DiskBuffer::open(Namespace::try_from("disk-crash/v1").unwrap(), directory)
        .unwrap_or_else(|error| panic!("open failed for {}: {error:?}", directory.display()))
}
fn writer(buffer: DiskBuffer) -> BufferedWrites<u32> {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Err::<(), _>(SinkError::unknown_outcome(
            "test acknowledgement unavailable",
        ))
    })
    .unwrap();
    BufferedWrites::builder("disk-crash/v1", sink)
        .with_buffer_provider(buffer)
        .build()
        .unwrap()
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn inspect(buffer: &DiskBuffer) -> crate::BufferSnapshot {
    runtime()
        .block_on(buffer.inspect(BufferInspectRequest {
            operation_id: Some(OperationId::try_from("seed-operation").unwrap()),
            now_utc_ms: chrono::Utc::now().timestamp_millis(),
            now_instant: Instant::now(),
            deadline: Deadline::after(Duration::from_secs(2)),
        }))
        .unwrap()
}
fn seed(directory: &Path, sealed: bool) -> crate::BufferSnapshot {
    let buffer = open(directory);
    let writer = writer(buffer.clone());
    runtime().block_on(async {
        writer
            .add_write_item_with_options(
                1,
                WriteOptions::new()
                    .with_operation_id(OperationId::try_from("seed-operation").unwrap()),
            )
            .await
            .unwrap();
        if sealed {
            assert_eq!(writer.flush_writes().await.batches_failed, 1);
        }
    });
    inspect(&buffer)
}
fn kill_at(directory: &Path, boundary: &str, operation: &str) {
    kill_after(directory, boundary, operation, 0);
}
fn kill_after(directory: &Path, boundary: &str, operation: &str, skip: usize) {
    let mut child = CrashChild(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "disk_buffer::journal_tests::given_crash_child_when_boundary_is_reached_then_wait_for_kill", "--ignored"])
        .env("BUFFERED_DISK_CRASH_DIR", directory)
        .env("BUFFERED_DISK_CRASH_POINT", boundary)
        .env("BUFFERED_DISK_CRASH_OPERATION", operation)
        .env("BUFFERED_DISK_CRASH_SKIP", skip.to_string())
        .stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    while !directory.join("boundary").exists() && Instant::now() < deadline {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("child exited before {boundary}: {status}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        fs::read_to_string(directory.join("boundary")).unwrap(),
        boundary
    );
    assert!(
        DiskBuffer::open(Namespace::try_from("disk-crash/v1").unwrap(), directory).is_err(),
        "another process must not bypass the writer lock"
    );
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
    }
}

#[test]
fn given_synced_item_when_killed_at_append_boundaries_then_recover_only_whole_snapshots() {
    for boundary in [
        "append-before-frame",
        "frame-after-header",
        "frame-after-payload",
        "append-after-sync",
    ] {
        let directory = CrashDirectory::new();
        let before = seed(&directory.0, false);
        kill_at(&directory.0, boundary, "append");
        let buffer = open(&directory.0);
        let after = inspect(&buffer);
        assert_eq!(after.admission, before.admission, "{boundary}");
        assert!(!buffer.has_interior_corruption(), "{boundary}");
        let expected = if matches!(boundary, "append-before-frame" | "frame-after-header") {
            1
        } else {
            2
        };
        assert_eq!(after.unsettled_items, expected, "{boundary}");
    }
}

#[test]
fn given_unknown_batch_when_killed_at_compaction_boundaries_then_preserve_identity_and_receipts() {
    for boundary in [
        "compact-after-header",
        "frame-after-header",
        "frame-after-payload",
        "compact-after-sync",
        "compact-after-replace",
        "compact-after-directory-sync",
    ] {
        let directory = CrashDirectory::new();
        let before = seed(&directory.0, true);
        assert_eq!(before.unresolved_batch_ids.len(), 1);
        kill_at(&directory.0, boundary, "compact");
        let buffer = open(&directory.0);
        let after = inspect(&buffer);
        assert_eq!(after.admission, before.admission, "{boundary}");
        assert_eq!(
            after.unresolved_batch_ids, before.unresolved_batch_ids,
            "{boundary}"
        );
        assert_eq!(after.unsettled_items, 1, "{boundary}");
        assert!(!buffer.has_interior_corruption());
    }
}

#[test]
#[ignore = "child fixture executed and SIGKILLed by journal crash matrix parents"]
fn given_crash_child_when_boundary_is_reached_then_wait_for_kill() {
    let directory = PathBuf::from(std::env::var_os("BUFFERED_DISK_CRASH_DIR").unwrap());
    let buffer = open(&directory);
    match std::env::var("BUFFERED_DISK_CRASH_OPERATION")
        .unwrap()
        .as_str()
    {
        "compact" => buffer.compact_now().unwrap(),
        "flush" => {
            let observed = directory.join("observed-batch");
            let sink =
                AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
                    fs::write(
                        &observed,
                        format!("{:?}:{:?}", attempt.batch_id(), attempt.digest()),
                    )
                    .unwrap();
                    async {
                        Err::<(), _>(SinkError::unknown_outcome(
                            "test acknowledgement unavailable",
                        ))
                    }
                })
                .unwrap();
            let writer = BufferedWrites::builder("disk-crash/v1", sink)
                .with_buffer_provider(buffer)
                .delivery_policy(crate::DeliveryPolicy {
                    max_attempts_per_turn: 1,
                    ..Default::default()
                })
                .build()
                .unwrap();
            runtime().block_on(writer.flush_writes());
        }
        mode @ ("partial" | "complete") => {
            let complete = mode == "complete";
            let observed = directory.join("observed-batch");
            let sink = crate::PartialSink::try_new(
                SinkLimits::default(),
                move |attempt: WriteAttempt<u32>| {
                    fs::write(
                        &observed,
                        format!("{:?}:{:?}", attempt.batch_id(), attempt.digest()),
                    )
                    .unwrap();
                    let outcome = if complete {
                        crate::WriteOutcome::Complete
                    } else {
                        crate::WriteOutcome::Partial(
                            attempt
                                .pending_operation_ids()
                                .iter()
                                .enumerate()
                                .map(|(index, id)| {
                                    (
                                        id.clone(),
                                        if index == 0 {
                                            crate::OperationStatus::Completed
                                        } else {
                                            crate::OperationStatus::Unknown
                                        },
                                    )
                                })
                                .collect(),
                        )
                    };
                    std::future::ready(Ok::<_, SinkError>(outcome))
                },
            )
            .unwrap();
            let writer = BufferedWrites::builder("disk-crash/v1", sink)
                .with_buffer_provider(buffer)
                .delivery_policy(crate::DeliveryPolicy {
                    max_attempts_per_turn: 1,
                    ..Default::default()
                })
                .build()
                .unwrap();
            runtime().block_on(writer.flush_writes());
        }
        "append" => runtime().block_on(async {
            writer(buffer).add_write_item(2).await.unwrap();
        }),
        _ => panic!("unsupported crash fixture"),
    }
    panic!("crash boundary was not reached");
}

#[test]
fn given_synced_frame_when_length_is_corrupt_then_preserve_bytes_and_block_compaction() {
    let directory = CrashDirectory::new();
    seed(&directory.0, false);
    let path = directory.0.join("journal.bin");
    let mut bytes = fs::read(&path).unwrap();
    bytes[13] ^= 0x40;
    fs::write(&path, &bytes).unwrap();
    let buffer = open(&directory.0);
    assert!(
        buffer.has_interior_corruption(),
        "corrupt length must not become an incomplete tail"
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(buffer.compact_now().is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn given_missing_directory_when_sync_is_required_then_report_storage_failure() {
    let directory = CrashDirectory::new();
    assert!(matches!(
        super::journal::sync_directory(&directory.0.join("missing")),
        Err(crate::BufferError::StorageUnavailable { .. })
    ));
}

#[test]
fn given_finite_journal_when_snapshot_does_not_fit_then_preserve_admission_absence() {
    let directory = CrashDirectory::new();
    let buffer = DiskBuffer::open_with_max_bytes(
        Namespace::try_from("disk-crash/v1").unwrap(),
        &directory.0,
        128,
    )
    .unwrap();
    let writer = writer(buffer.clone());
    assert!(
        runtime()
            .block_on(
                writer.add_write_item_with_options(
                    1,
                    WriteOptions::new()
                        .with_operation_id(OperationId::try_from("seed-operation").unwrap())
                )
            )
            .is_err()
    );
    assert_eq!(inspect(&buffer).unsettled_items, 0);
    assert!(inspect(&buffer).admission.is_none());
    assert!(fs::metadata(directory.0.join("journal.bin")).unwrap().len() <= 128);
    assert!(
        DiskBuffer::open_with_max_bytes(
            Namespace::try_from("disk-crash/v1").unwrap(),
            directory.0.join("tiny"),
            9
        )
        .is_err()
    );
}

#[test]
fn given_open_write_when_killed_after_claim_seal_or_settlement_then_replay_preserves_identity() {
    for skip in 0..3 {
        let directory = CrashDirectory::new();
        let before = seed(&directory.0, false);
        kill_after(&directory.0, "append-after-sync", "flush", skip);
        let buffer = open(&directory.0);
        let snapshot = inspect(&buffer);
        assert_eq!(snapshot.admission, before.admission);
        assert_eq!(snapshot.unsettled_items, 1);
        if skip > 0 {
            assert_eq!(snapshot.unresolved_batch_ids.len(), 1);
        }
        let observed = Arc::new(Mutex::new(Vec::new()));
        let copies = observed.clone();
        let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
            copies.lock().unwrap().push((
                attempt.batch_id(),
                format!("{:?}:{:?}", attempt.batch_id(), attempt.digest()),
            ));
            async { Ok::<(), SinkError>(()) }
        })
        .unwrap();
        let clock =
            crate::TestClock::with_utc_millis(chrono::Utc::now().timestamp_millis() + 60_000);
        clock.set_auto_advance_on_sleep(false);
        let writer = BufferedWrites::builder("disk-crash/v1", sink)
            .with_clock(clock)
            .with_buffer_provider(buffer.clone())
            .build()
            .unwrap();
        assert_eq!(
            runtime().block_on(writer.flush_writes()).items_settled,
            1,
            "crash boundary {skip}"
        );
        assert_eq!(inspect(&buffer).unsettled_items, 0);
        let observed = observed.lock().unwrap();
        assert_eq!(observed.len(), 1);
        if skip > 0 {
            assert_eq!(snapshot.unresolved_batch_ids, vec![observed[0].0]);
        }
        if skip == 2 {
            assert_eq!(
                fs::read_to_string(directory.0.join("observed-batch")).unwrap(),
                observed[0].1
            );
        }
    }
}

#[test]
#[ignore = "requires a marked disposable small volume via BUFFERED_WRITES_DISK_FULL_VOLUME"]
fn given_real_enospc_when_admission_is_unconfirmed_then_reopen_and_retry_keeps_one_write() {
    use std::io::Write;
    let volume = PathBuf::from(std::env::var_os("BUFFERED_WRITES_DISK_FULL_VOLUME").unwrap());
    assert_eq!(
        fs::read_to_string(volume.join("buffered-writes-disposable-volume")).unwrap(),
        "buffered-writes-disk-full-test-v1"
    );
    let directory =
        CrashDirectory(volume.join(format!("buffered-disk-full-{}", uuid::Uuid::now_v7())));
    fs::create_dir(&directory.0).unwrap();
    let buffer = open(&directory.0);
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<Vec<u8>>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("disk-crash/v1", sink.clone())
        .with_buffer_provider(buffer.clone())
        .build()
        .unwrap();
    let filler = directory.0.join("filler");
    let mut file = fs::File::create(&filler).unwrap();
    let mut full = false;
    for _ in 0..1024 {
        if let Err(error) = file.write_all(&[1; 64 * 1024]) {
            assert_eq!(
                error.raw_os_error(),
                Some(28),
                "must reproduce native ENOSPC"
            );
            full = true;
            break;
        }
    }
    assert!(
        full,
        "fixture must be a disposable volume smaller than 64 MiB"
    );
    let id = OperationId::try_from("seed-operation").unwrap();
    assert!(matches!(
        runtime().block_on(writer.add_write_item_with_options(
            vec![7; 8 * 1024],
            WriteOptions::new().with_operation_id(id.clone())
        )),
        Err(crate::WriteError::Ambiguous { .. })
    ));
    assert!(buffer.compact_now().is_err());
    drop(file);
    fs::remove_file(&filler).unwrap();
    drop(writer);
    drop(buffer);
    let buffer = open(&directory.0);
    assert!(!buffer.has_interior_corruption());
    let writer = BufferedWrites::builder("disk-crash/v1", sink)
        .with_buffer_provider(buffer.clone())
        .build()
        .unwrap();
    runtime()
        .block_on(writer.add_write_item_with_options(
            vec![7; 8 * 1024],
            WriteOptions::new().with_operation_id(id),
        ))
        .unwrap();
    assert_eq!(inspect(&buffer).unsettled_items, 1);
    assert_eq!(runtime().block_on(writer.flush_writes()).items_settled, 1);
    assert_eq!(inspect(&buffer).unsettled_items, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_dispatched_append_when_caller_cancels_before_sync_then_retry_preserves_one_write() {
    let directory = CrashDirectory::new();
    let buffer = open(&directory.0);
    let writer = writer(buffer.clone());
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    COMMIT_PAUSES
        .lock()
        .unwrap()
        .push((directory.0.clone(), 0, entered.clone(), release.clone()));
    let pending = writer.clone();
    let task = tokio::spawn(async move {
        pending
            .add_write_item_with_options(
                1,
                WriteOptions::new()
                    .with_operation_id(OperationId::try_from("seed-operation").unwrap()),
            )
            .await
    });
    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .unwrap();
    writer
        .add_write_item_with_options(
            1,
            WriteOptions::new().with_operation_id(OperationId::try_from("seed-operation").unwrap()),
        )
        .await
        .unwrap();
    let snapshot = buffer
        .inspect(BufferInspectRequest {
            operation_id: Some(OperationId::try_from("seed-operation").unwrap()),
            now_utc_ms: chrono::Utc::now().timestamp_millis(),
            now_instant: Instant::now(),
            deadline: Deadline::after(Duration::from_secs(2)),
        })
        .await
        .unwrap();
    assert_eq!(snapshot.unsettled_items, 1);
    assert!(snapshot.admission.is_some());
}

#[test]
fn given_sparse_oversized_journal_when_opened_then_reject_without_reading_or_rewriting() {
    let directory = CrashDirectory::new();
    seed(&directory.0, false);
    let path = directory.0.join("journal.bin");
    let before = fs::read(&path).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(8 * 1024 * 1024 * 1024)
        .unwrap();
    assert!(
        DiskBuffer::open_with_max_bytes(
            Namespace::try_from("disk-crash/v1").unwrap(),
            &directory.0,
            4096
        )
        .is_err()
    );
    assert_eq!(fs::metadata(&path).unwrap().len(), 8 * 1024 * 1024 * 1024);
    use std::io::Read;
    let mut prefix = vec![0; before.len()];
    fs::File::open(&path)
        .unwrap()
        .read_exact(&mut prefix)
        .unwrap();
    assert_eq!(prefix, before);
}

#[test]
fn given_corrupt_journal_when_reopened_repeatedly_then_quarantine_remains_bounded_and_exact() {
    let directory = CrashDirectory::new();
    seed(&directory.0, false);
    let path = directory.0.join("journal.bin");
    let mut before = fs::read(&path).unwrap();
    before[16] ^= 1;
    fs::write(&path, &before).unwrap();
    for _ in 0..20 {
        let buffer = open(&directory.0);
        assert!(buffer.has_interior_corruption());
        assert!(buffer.compact_now().is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!directory.0.join("journal.quarantine.bin").exists());
        drop(buffer);
    }
}

#[test]
fn given_sink_progress_when_killed_during_settlement_then_recovery_preserves_known_completion() {
    for mode in ["partial", "complete"] {
        for boundary in [
            "frame-after-header",
            "frame-after-payload",
            "append-after-sync",
        ] {
            let directory = CrashDirectory::new();
            seed(&directory.0, false);
            {
                let buffer = open(&directory.0);
                runtime()
                    .block_on(writer(buffer).add_write_item(2))
                    .unwrap();
            }
            kill_after(&directory.0, boundary, mode, 2);
            let buffer = open(&directory.0);
            let known = boundary != "frame-after-header";
            let after = inspect(&buffer);
            let complete = known && mode == "complete";
            assert_eq!(after.unsettled_items, if complete { 0 } else { 2 });
            if complete {
                assert_eq!(
                    after.admission.unwrap().status,
                    crate::AdmissionStatus::Written
                );
            }
            let observed = Arc::new(Mutex::new(Vec::new()));
            let copied = observed.clone();
            let sink = crate::PartialSink::try_new(
                SinkLimits::default(),
                move |attempt: WriteAttempt<u32>| {
                    copied.lock().unwrap().push((
                        format!("{:?}:{:?}", attempt.batch_id(), attempt.digest()),
                        attempt.pending_operation_ids().len(),
                    ));
                    std::future::ready(Ok::<_, SinkError>(crate::WriteOutcome::Complete))
                },
            )
            .unwrap();
            let clock =
                crate::TestClock::with_utc_millis(chrono::Utc::now().timestamp_millis() + 60_000);
            clock.set_auto_advance_on_sleep(false);
            let writer = BufferedWrites::builder("disk-crash/v1", sink)
                .with_clock(clock)
                .with_buffer_provider(buffer.clone())
                .build()
                .unwrap();
            runtime().block_on(writer.flush_writes());
            assert_eq!(inspect(&buffer).unsettled_items, 0);
            let observed = observed.lock().unwrap();
            if complete {
                assert!(
                    observed.is_empty(),
                    "durable receipt prevents repeat dispatch"
                );
            } else {
                assert_eq!(observed.len(), 1);
                assert_eq!(
                    observed[0].0,
                    fs::read_to_string(directory.0.join("observed-batch")).unwrap()
                );
                assert_eq!(
                    observed[0].1,
                    if known && mode == "partial" { 1 } else { 2 }
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_disk_delivery_when_cancelled_during_claim_seal_or_settle_then_recovery_keeps_ownership()
 {
    for skip in 0..3 {
        let directory = CrashDirectory::new();
        let buffer = open(&directory.0);
        let effects = Arc::new(Mutex::new(Vec::new()));
        let copied = effects.clone();
        let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
            copied.lock().unwrap().push(attempt.batch_id());
            async { Ok::<(), SinkError>(()) }
        })
        .unwrap();
        let writer = BufferedWrites::builder("disk-crash/v1", sink.clone())
            .with_buffer_provider(buffer.clone())
            .build()
            .unwrap();
        writer.add_write_item(1).await.unwrap();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        COMMIT_PAUSES.lock().unwrap().push((
            directory.0.clone(),
            skip,
            entered.clone(),
            release.clone(),
        ));
        let pending = writer.clone();
        let task = tokio::spawn(async move { pending.flush_writes().await });
        tokio::task::spawn_blocking(move || entered.wait())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();
        let snapshot = buffer
            .inspect(BufferInspectRequest {
                operation_id: None,
                now_utc_ms: chrono::Utc::now().timestamp_millis(),
                now_instant: Instant::now(),
                deadline: Deadline::after(Duration::from_secs(2)),
            })
            .await
            .unwrap();
        assert_eq!(snapshot.unsettled_items, if skip == 2 { 0 } else { 1 });
        drop(writer);
        drop(buffer);
        let buffer = open(&directory.0);
        let clock =
            crate::TestClock::with_utc_millis(chrono::Utc::now().timestamp_millis() + 60_000);
        clock.set_auto_advance_on_sleep(false);
        let writer = BufferedWrites::builder("disk-crash/v1", sink)
            .with_clock(clock)
            .with_buffer_provider(buffer.clone())
            .build()
            .unwrap();
        let report = writer.flush_writes().await;
        assert_eq!(report.items_settled, if skip == 2 { 0 } else { 1 });
        assert_eq!(effects.lock().unwrap().len(), 1);
        assert_eq!(
            buffer
                .inspect(BufferInspectRequest {
                    operation_id: None,
                    now_utc_ms: chrono::Utc::now().timestamp_millis(),
                    now_instant: Instant::now(),
                    deadline: Deadline::after(Duration::from_secs(2))
                })
                .await
                .unwrap()
                .unsettled_items,
            0
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn given_disk_renewal_when_caller_cancels_before_sync_then_recovered_lease_preserves_fencing()
{
    let directory = CrashDirectory::new();
    let initial_directory = directory.0.clone();
    tokio::task::spawn_blocking(move || seed(&initial_directory, true))
        .await
        .unwrap();
    let buffer = open(&directory.0);
    let now = chrono::Utc::now().timestamp_millis() + 60_000;
    let request = crate::BufferClaimRequest {
        max_watermark: None,
        allow_open_claim: true,
        force_all_ages: true,
        max_items: 25,
        max_bytes: 64 * 1024,
        lease_duration: Duration::from_secs(1),
        now_utc_ms: now,
        now_instant: Instant::now(),
        deadline: Deadline::after(Duration::from_secs(2)),
    };
    let crate::ClaimedWork::ExistingSealed(leased) = buffer.claim(request).await.unwrap() else {
        panic!("expected sealed batch");
    };
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    COMMIT_PAUSES
        .lock()
        .unwrap()
        .push((directory.0.clone(), 0, entered.clone(), release.clone()));
    let pending = buffer.renew(crate::BufferRenewRequest {
        batch_id: leased.batch.batch_id(),
        fencing_token: leased.fencing_token,
        lease_duration: Duration::from_secs(10),
        now_utc_ms: now + 500,
        deadline: request.deadline,
    });
    let task = tokio::spawn(pending);
    tokio::task::spawn_blocking(move || entered.wait())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::task::spawn_blocking(move || release.wait())
        .await
        .unwrap();
    buffer
        .inspect(BufferInspectRequest {
            operation_id: None,
            now_utc_ms: now,
            now_instant: Instant::now(),
            deadline: request.deadline,
        })
        .await
        .unwrap();
    drop(buffer);
    let buffer = open(&directory.0);
    assert!(matches!(
        buffer
            .claim(crate::BufferClaimRequest {
                now_utc_ms: now + 1500,
                ..request
            })
            .await
            .unwrap(),
        crate::ClaimedWork::None
    ));
    let crate::ClaimedWork::ExistingSealed(reclaimed) = buffer
        .claim(crate::BufferClaimRequest {
            now_utc_ms: now + 11_000,
            ..request
        })
        .await
        .unwrap()
    else {
        panic!("expected expired renewed lease");
    };
    assert_eq!(reclaimed.batch.batch_id(), leased.batch.batch_id());
    assert_ne!(reclaimed.fencing_token, leased.fencing_token);
    assert!(matches!(
        buffer
            .settle(crate::BufferSettleRequest {
                batch_id: leased.batch.batch_id(),
                fencing_token: leased.fencing_token,
                disposition: crate::SettleDisposition::Delivered,
                now_utc_ms: now + 11_000,
                deadline: request.deadline
            })
            .await,
        Err(crate::BufferError::StaleFence { .. })
    ));
}

#[test]
fn given_duplicated_writer_descriptor_when_provider_drops_then_explicitly_release_its_lock() {
    let directory = CrashDirectory::new();
    let inner = super::journal::DiskJournalInner::open(
        Namespace::try_from("disk-crash/v1").unwrap(),
        directory.0.clone(),
        4096,
    )
    .unwrap();
    let duplicate = inner.writer_lock.try_clone().unwrap();
    let contender = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.0.join("journal.lock"))
        .unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(inner);
    contender.try_lock().unwrap();
    drop(duplicate);
}
