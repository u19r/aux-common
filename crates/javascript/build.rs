fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=assets/quickjs.wasm");
    #[cfg(feature = "runtime")]
    precompile_guest()?;
    Ok(())
}

#[cfg(feature = "runtime")]
fn precompile_guest() -> Result<(), Box<dyn std::error::Error>> {
    use std::{env, fs, path::PathBuf};

    let mut config = wasmtime::Config::new();
    // Explicit TARGET uses portable CPU features for the deployment
    // architecture. Fuel and epoch instrumentation must match the runtime
    // engine contract.
    config
        .target(&env::var("TARGET")?)?
        .consume_fuel(true)
        .epoch_interruption(true);
    let engine = wasmtime::Engine::new(&config)?;
    let artifact = engine.precompile_module(&fs::read("assets/quickjs.wasm")?)?;
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    fs::write(output.join("quickjs.cwasm"), artifact)?;
    Ok(())
}
