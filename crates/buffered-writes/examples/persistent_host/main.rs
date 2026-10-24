#[cfg(unix)]
mod constants;
#[cfg(unix)]
mod runtime;

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = runtime::HostConfig::from_env()?;
    runtime::PersistentHost::try_new(config)
        .await?
        .serve_signals()
        .await
}

#[cfg(not(unix))]
fn main() {
    eprintln!("persistent_host requires Unix process signals");
}
