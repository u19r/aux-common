use std::{
    cell::Cell,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use super::constants::LOG_DESTINATION_STDOUT;

#[derive(Debug)]
pub enum WideLogInitError {
    InvalidDestination,
    CreateParentDir,
    OpenFile,
}

impl std::fmt::Display for WideLogInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDestination => {
                f.write_str("invalid tracing log destination; expected stdout or an absolute path")
            }
            Self::CreateParentDir => {
                f.write_str("failed to create tracing log destination directory")
            }
            Self::OpenFile => f.write_str("failed to open tracing log destination"),
        }
    }
}

impl std::error::Error for WideLogInitError {}

pub type WideLogSink = Arc<dyn Fn(String) + Send + Sync>;

thread_local! {
    static REPORTING_SINK_FAILURE: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn build_log_sink(destination: &str) -> Result<WideLogSink, WideLogInitError> {
    let trimmed = destination.trim();
    if trimmed == LOG_DESTINATION_STDOUT {
        return Ok(stdout_sink());
    }
    if !Path::new(trimmed).is_absolute() {
        return Err(WideLogInitError::InvalidDestination);
    }

    let path = PathBuf::from(trimmed);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| WideLogInitError::CreateParentDir)?;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|_| WideLogInitError::OpenFile)?;
    let file = Arc::new(Mutex::new(file));

    Ok(Arc::new(move |line| {
        let result = match file.lock() {
            Ok(mut handle) => writeln!(&mut *handle, "{line}"),
            Err(_) => {
                report_sink_failure("sink_lock_poisoned");
                return;
            }
        };
        if result.is_err() {
            report_sink_failure("sink_write_failed");
        }
    }))
}

fn stdout_sink() -> WideLogSink {
    Arc::new(|line| {
        // This is the explicitly configured telemetry destination.
        // Initialization and configuration failures are returned to the caller
        // instead of printed here.
        let result = {
            let mut handle = io::stdout().lock();
            handle
                .write_all(line.as_bytes())
                .and_then(|()| handle.write_all(b"\n"))
        };
        if result.is_err() {
            report_sink_failure("sink_write_failed");
        }
    })
}

fn report_sink_failure(error_kind: &'static str) {
    REPORTING_SINK_FAILURE.with(|reporting| {
        if reporting.replace(true) {
            return;
        }

        tracing::error!(target = "wide_log", error_kind, "wide log sink failed");
        reporting.set(false);
    });
}
