use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const LOG_DESTINATION_STDOUT: &str = "stdout";

#[derive(Debug)]
pub enum WideLogInitError {
    InvalidDestination {
        value: String,
    },
    CreateParentDir {
        path: PathBuf,
        source: std::io::Error,
    },
    OpenFile {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for WideLogInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDestination { value } => write!(
                f,
                "invalid tracing log destination '{value}': expected \"stdout\" or an absolute \
                 path"
            ),
            Self::CreateParentDir { path, source } => write!(
                f,
                "failed to create log destination parent directory '{}': {source}",
                path.display()
            ),
            Self::OpenFile { path, source } => write!(
                f,
                "failed to open log destination file '{}': {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for WideLogInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidDestination { .. } => None,
            Self::CreateParentDir { source, .. } => Some(source),
            Self::OpenFile { source, .. } => Some(source),
        }
    }
}

pub(crate) type WideLogSink = Arc<dyn Fn(String) + Send + Sync>;

pub(crate) fn build_log_sink(destination: &str) -> Result<WideLogSink, WideLogInitError> {
    let trimmed = destination.trim();
    if trimmed == LOG_DESTINATION_STDOUT {
        return Ok(Arc::new(|line| println!("{line}")));
    }
    if !Path::new(trimmed).is_absolute() {
        return Err(WideLogInitError::InvalidDestination {
            value: trimmed.to_string(),
        });
    }

    let path = PathBuf::from(trimmed);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| WideLogInitError::CreateParentDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| WideLogInitError::OpenFile {
            path: path.clone(),
            source,
        })?;
    let file = Arc::new(Mutex::new(file));

    Ok(Arc::new(move |line| {
        let Ok(mut handle) = file.lock() else {
            eprintln!("wide_log file sink lock poisoned");
            return;
        };
        if let Err(error) = writeln!(&mut *handle, "{line}") {
            eprintln!("wide_log failed to write log line: {error}");
        }
    }))
}
