//! Development-only artifact provenance writer/checker. Never loaded in
//! customer execution.
#![forbid(unsafe_code)]
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasmparser::{Parser, Payload};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repository_root")?;
    let mode = std::env::args().nth(1).ok_or("expected write or check")?;
    let manifest = collect_manifest(root)?;
    let path = root.join("crates/javascript/assets/quickjs-manifest.json");
    match mode.as_str() {
        "write" => fs::write(
            path,
            format!("{}\n", serde_json::to_string_pretty(&manifest)?),
        )?,
        "check" => {
            let recorded: Value = serde_json::from_slice(&fs::read(path)?)?;
            if recorded != manifest {
                return Err("artifact_provenance_mismatch".into());
            }
            javascript::JsExecutor::try_new()?;
        }
        _ => return Err("expected write or check".into()),
    }
    Ok(())
}
fn collect_manifest(root: &Path) -> Result<Value> {
    let wasm = fs::read(root.join("crates/javascript/assets/quickjs.wasm"))?;
    let (imports, exports) = inspect_module(&wasm)?;
    let sys_root = load_vendor_root(root)?;
    let mut vendor_files = BTreeMap::new();
    collect_hashes(&sys_root, &sys_root.join("quickjs"), &mut vendor_files)?;
    let vendor_hash = hash_bytes(&serde_json::to_vec(&vendor_files)?);
    let license = fs::read(sys_root.join("quickjs/LICENSE"))?;
    if fs::read(root.join("crates/javascript/assets/quickjs-license.txt"))? != license {
        return Err("quickjs_license_mismatch".into());
    }
    Ok(json!({
        "schema_version":1, "protocol_version":1, "target":"wasm32-wasip1",
        "rust":"1.99.1", "wasi_sdk":"24.0", "rquickjs":"0.14.0", "quickjs_ng":"0.16.2", "wasmtime":"50.0.0",
        "profile":{"opt_level":"s","panic":"abort","strip":true},
        "wasm_sha256":hash_bytes(&wasm), "wasm_bytes":wasm.len(),
        "imports":imports, "exports":exports, "sources":source_hashes(root)?,
        "guest_lock_sha256":hash_file(&root.join("crates/quickjs/Cargo.lock"))?,
        "vendored_quickjs_sha256":vendor_hash, "vendored_quickjs_license_sha256":hash_bytes(&license),
        "rquickjs_sys_registry_checksum":sys_checksum(root)?,
    }))
}
fn inspect_module(wasm: &[u8]) -> Result<(Vec<String>, Vec<String>)> {
    let (mut imports, mut exports) = (Vec::new(), Vec::new());
    for payload in Parser::new(0).parse_all(wasm) {
        match payload? {
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import?;
                    imports.push(format!("{}::{}", import.module, import.name));
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    exports.push(export?.name.to_owned());
                }
            }
            _ => {}
        }
    }
    imports.sort();
    exports.sort();
    Ok((imports, exports))
}
fn source_hashes(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    collect_hashes(root, &root.join("crates/quickjs/src"), &mut hashes)?;
    for path in [
        "Cargo.toml",
        "crates/quickjs/Cargo.toml",
        "crates/quickjs/rust-toolchain.toml",
        "crates/javascript/Cargo.toml",
        "crates/javascript/build.rs",
        "crates/javascript/src/lib.rs",
        "crates/javascript/src/bounded_writer.rs",
        "crates/javascript/examples/quickjs_artifact.rs",
        "crates/javascript/src/constants.rs",
        "crates/javascript/src/error.rs",
        "crates/javascript/src/invocation.rs",
        "crates/javascript/src/protocol.rs",
        "scripts/build-quickjs-wasm.sh",
        "scripts/quickjs-clang.sh",
        "scripts/quickjs-rustc.sh",
    ] {
        hashes.insert(path.into(), hash_file(&root.join(path))?);
    }
    Ok(hashes)
}
fn collect_hashes(
    base: &Path,
    directory: &Path,
    hashes: &mut BTreeMap<String, String>,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_hashes(base, &path, hashes)?;
        } else {
            hashes.insert(
                path.strip_prefix(base)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                hash_file(&path)?,
            );
        }
    }
    Ok(())
}
fn hash_file(path: &Path) -> Result<String> {
    Ok(hash_bytes(&fs::read(path)?))
}
fn hash_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn sys_checksum(root: &Path) -> Result<String> {
    let lock = fs::read_to_string(root.join("crates/quickjs/Cargo.lock"))?;
    let package = lock
        .split("[[package]]")
        .find(|entry| entry.contains("name = \"rquickjs-sys\""))
        .ok_or("sys_lock_missing")?;
    let line = package
        .lines()
        .find(|line| line.starts_with("checksum = "))
        .ok_or("checksum_missing")?;
    Ok(line
        .trim_start_matches("checksum = ")
        .trim_matches('"')
        .to_owned())
}

fn load_vendor_root(root: &Path) -> Result<PathBuf> {
    let metadata = Command::new("cargo")
        .args([
            "+1.99.1",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(root.join("crates/quickjs/Cargo.toml"))
        .output()?;
    if !metadata.status.success() {
        return Err("guest_metadata_failed".into());
    }
    let metadata: Value = serde_json::from_slice(&metadata.stdout)?;
    let packages = metadata["packages"].as_array().ok_or("packages_missing")?;
    let sys = packages
        .iter()
        .find(|p| p["name"] == "rquickjs-sys")
        .ok_or("rquickjs_sys_missing")?;
    let sys_root = Path::new(sys["manifest_path"].as_str().ok_or("manifest_missing")?)
        .parent()
        .ok_or("sys_root_missing")?;
    Ok(sys_root.to_owned())
}
