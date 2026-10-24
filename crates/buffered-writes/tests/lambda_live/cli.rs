use std::{
    io::{self, Read},
    process::{Child, Command, Output, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use serde_json::Value;

pub(super) struct AwsTestClient {
    profile: String,
    pub(super) region: String,
}
impl AwsTestClient {
    pub(super) fn from_env() -> Self {
        Self {
            profile: std::env::var("BUFFERED_WRITES_LAMBDA_PROFILE")
                .expect("explicit test profile"),
            region: std::env::var("BUFFERED_WRITES_LAMBDA_REGION")
                .unwrap_or_else(|_| "eu-central-1".into()),
        }
    }

    pub(super) fn try_command_until(&self, args: &[&str], deadline: Instant) -> io::Result<Output> {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut child = CommandGuard(
            Command::new("aws")
                .args(args)
                .args([
                    "--profile",
                    &self.profile,
                    "--region",
                    &self.region,
                    "--cli-connect-timeout",
                    "5",
                    "--cli-read-timeout",
                    "30",
                    "--output",
                    "json",
                    "--no-cli-pager",
                ])
                .env("AWS_MAX_ATTEMPTS", "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        let stdout = read_pipe(
            child
                .0
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("missing CLI stdout"))?,
        )?;
        let stderr = read_pipe(
            child
                .0
                .stderr
                .take()
                .ok_or_else(|| io::Error::other("missing CLI stderr"))?,
        )?;
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Ok(Output {
                    status,
                    stdout: join_pipe(stdout)?,
                    stderr: join_pipe(stderr)?,
                });
            }
            if Instant::now() >= deadline {
                child.0.kill()?;
                child.0.wait()?;
                let _ = join_pipe(stdout);
                let _ = join_pipe(stderr);
                return Err(io::ErrorKind::TimedOut.into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn command(&self, args: &[&str]) -> Output {
        self.try_command_until(args, Instant::now() + Duration::from_secs(90))
            .expect("AWS CLI failed or exceeded its process deadline")
    }

    pub(super) fn aws(&self, args: &[&str]) -> Value {
        let output = self.command(args);
        assert!(
            output.status.success(),
            "AWS {} {} failed; inspect session, permissions and resource ledger",
            args[0],
            args[1]
        );
        if output.stdout.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&output.stdout).expect("AWS CLI JSON")
        }
    }
}

struct CommandGuard(Child);
impl Drop for CommandGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_pipe(mut pipe: impl Read + Send + 'static) -> io::Result<JoinHandle<io::Result<Vec<u8>>>> {
    thread::Builder::new().spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}
fn join_pipe(reader: JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| io::Error::other("CLI output reader failed"))?
}
