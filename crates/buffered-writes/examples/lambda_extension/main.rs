mod constants;
mod runtime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    runtime::ExtensionHost::try_new(runtime::ExtensionConfig::from_env()?)
        .await?
        .run()
        .await
}
