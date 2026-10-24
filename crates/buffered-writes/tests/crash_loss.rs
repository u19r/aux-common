#![cfg(unix)]

use std::{
    fs,
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use buffered_writes::{
    AtomicSink, BufferedWrites, DurabilityClass, SinkError, SinkLimits, WriteAttempt,
};

#[test]
fn given_volatile_admission_when_process_is_killed_then_restart_has_no_recoverable_write() {
    let directory =
        std::env::temp_dir().join(format!("buffered-memory-loss-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "given_child_process_when_admitted_then_wait_without_delivering",
            "--ignored",
        ])
        .env("BUFFERED_WRITES_CRASH_DIRECTORY", &directory)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !directory.join("admitted").exists() && Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child exited before admission: {status}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let acknowledged = fs::read_to_string(directory.join("admitted"));
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
    assert_eq!(acknowledged.unwrap(), "Volatile");
    let sink = disk_observed_sink(directory.clone());
    let writer = BufferedWrites::builder("memory-loss/v1", sink)
        .build()
        .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            assert_eq!(writer.flush_writes().await.items_settled, 0);
            assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
        });
    assert!(
        !directory.join("delivered").exists(),
        "volatile acknowledgement cannot survive SIGKILL"
    );
    fs::remove_dir_all(directory).unwrap();
}

fn disk_observed_sink(directory: std::path::PathBuf) -> AtomicSink<u32> {
    AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        fs::write(directory.join("delivered"), b"effect").unwrap();
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap()
}

#[test]
#[ignore = "child fixture executed by the parent SIGKILL test"]
fn given_child_process_when_admitted_then_wait_without_delivering() {
    let directory =
        std::path::PathBuf::from(std::env::var_os("BUFFERED_WRITES_CRASH_DIRECTORY").unwrap());
    let sink = disk_observed_sink(directory.clone());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let writer = BufferedWrites::builder("memory-loss/v1", sink)
                .build()
                .unwrap();
            let admission = writer.add_write_item(42).await.unwrap();
            assert_eq!(admission.durability(), DurabilityClass::Volatile);
            fs::write(directory.join("admitted"), b"Volatile").unwrap();
            std::future::pending::<()>().await;
            drop(writer);
        });
}
