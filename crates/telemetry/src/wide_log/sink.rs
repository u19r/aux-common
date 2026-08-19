use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const LOG_DESTINATION_STDOUT: &str = "stdout";

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

pub(crate) type WideLogSink = Arc<dyn Fn(String) + Send + Sync>;

pub(crate) fn build_log_sink(destination: &str) -> Result<WideLogSink, WideLogInitError> {
    let trimmed = destination.trim();
    if trimmed == LOG_DESTINATION_STDOUT {
        return Ok(Arc::new(|line| println!("{line}")));
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
        let Ok(mut handle) = file.lock() else {
            eprintln!("wide_log file sink lock poisoned");
            return;
        };
        if writeln!(&mut *handle, "{line}").is_err() {
            eprintln!("wide_log failed to write log line");
        }
    }))
}
