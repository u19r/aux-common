fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=assets/quickjs.wasm");
    #[cfg(feature = "runtime")]
    precompile_guest()?;
    Ok(())
}

#[cfg(feature = "runtime")]
fn precompile_guest() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        collections::hash_map::DefaultHasher,
        env, fs,
        hash::{Hash, Hasher},
        path::PathBuf,
    };

    use sha2::{Digest, Sha256};

    let mut config = wasmtime::Config::new();
    // Explicit TARGET uses portable CPU features for the deployment
    // architecture. Fuel and epoch instrumentation must match the runtime
    // engine contract.
    config
        .target(&env::var("TARGET")?)?
        .consume_fuel(true)
        .epoch_interruption(true);
    let engine = wasmtime::Engine::new(&config)?;
    let wasm = fs::read("assets/quickjs.wasm")?;
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    let mut compatibility = DefaultHasher::new();
    engine
        .precompile_compatibility_hash()
        .hash(&mut compatibility);
    let cached = output.join(format!(
        "quickjs-{:016x}-{}.cwasm",
        compatibility.finish(),
        Sha256::digest(&wasm)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    // Fresh checkouts rerun build.rs even when sccache reuses the Rust crate.
    // Wasmtime's precompile_module does not use its built-in compilation cache.
    if !cached.try_exists()? {
        let artifact = engine.precompile_module(&wasm)?;
        let temporary = output.join("quickjs.cwasm.tmp");
        fs::write(&temporary, artifact)?;
        fs::rename(temporary, &cached)?;
    }
    fs::copy(cached, output.join("quickjs.cwasm"))?;
    Ok(())
}
