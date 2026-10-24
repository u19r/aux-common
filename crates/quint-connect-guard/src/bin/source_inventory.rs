#![deny(unsafe_code)]

use std::{
    collections::BTreeSet,
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;
use syn::LitStr;

mod source_inventory_support;

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse(env::args_os().skip(1))?;
    let package = Package::load(
        &arguments.manifest,
        &arguments.trusted_guard,
        arguments.trusted_connect.as_deref(),
    )?;
    let source_snapshot = canonical_directory(&arguments.source_snapshot, "source snapshot")?;
    let source_lib_path = source_snapshot.join(
        package
            .lib_path
            .strip_prefix(&package.workspace_root)
            .map_err(|_| invalid("library source is outside its workspace"))?,
    );
    if !source_lib_path.is_file() {
        return Err(invalid(format!(
            "source snapshot is missing library source {}",
            source_lib_path.display()
        )));
    }
    let rustc = CapturedRustc::load(&arguments.rustc_log_directory, &package.lib_path)?;
    let configuration = ActiveConfiguration::load(&rustc)?;
    source_inventory_support::run(
        source_snapshot,
        source_lib_path,
        package.workspace_root,
        configuration,
    )
}

struct Arguments {
    manifest: PathBuf,
    trusted_guard: PathBuf,
    trusted_connect: Option<PathBuf>,
    rustc_log_directory: PathBuf,
    source_snapshot: PathBuf,
}

impl Arguments {
    fn parse<I>(arguments: I) -> Result<Self, Box<dyn Error>>
    where I: IntoIterator<Item = OsString> {
        let mut manifest = None;
        let mut trusted_guard = None;
        let mut trusted_connect = None;
        let mut rustc_log_directory = None;
        let mut source_snapshot = None;
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            match argument.to_str() {
                Some("--manifest") => manifest = Some(next_path(&mut arguments, "--manifest")?),
                Some("--trusted-guard") => {
                    trusted_guard = Some(next_path(&mut arguments, "--trusted-guard")?)
                }
                Some("--trusted-connect") => {
                    trusted_connect = Some(next_path(&mut arguments, "--trusted-connect")?)
                }
                Some("--rustc-log-directory") => {
                    rustc_log_directory = Some(next_path(&mut arguments, "--rustc-log-directory")?)
                }
                Some("--source-snapshot") => {
                    source_snapshot = Some(next_path(&mut arguments, "--source-snapshot")?)
                }
                Some(value) => {
                    return Err(invalid(format!("unknown source inventory option: {value}")));
                }
                None => return Err(invalid("source inventory option is not valid UTF-8")),
            }
        }
        let Some(manifest) = manifest else {
            return Err(invalid("source inventory requires --manifest"));
        };
        let Some(trusted_guard) = trusted_guard else {
            return Err(invalid("source inventory requires --trusted-guard"));
        };
        let Some(rustc_log_directory) = rustc_log_directory else {
            return Err(invalid("source inventory requires --rustc-log-directory"));
        };
        let Some(source_snapshot) = source_snapshot else {
            return Err(invalid("source inventory requires --source-snapshot"));
        };
        Ok(Self {
            manifest,
            trusted_guard,
            trusted_connect,
            rustc_log_directory,
            source_snapshot,
        })
    }
}

fn next_path<I>(arguments: &mut I, option: &str) -> Result<PathBuf, Box<dyn Error>>
where I: Iterator<Item = OsString> {
    next_string(arguments, option).map(PathBuf::from)
}

fn next_string<I>(arguments: &mut I, option: &str) -> Result<String, Box<dyn Error>>
where I: Iterator<Item = OsString> {
    arguments
        .next()
        .ok_or_else(|| invalid(format!("missing value for {option}")))?
        .into_string()
        .map_err(|_| invalid(format!("{option} value is not valid UTF-8")))
}

struct Package {
    workspace_root: PathBuf,
    lib_path: PathBuf,
}

impl Package {
    fn load(
        manifest: &Path,
        trusted_guard: &Path,
        trusted_connect: Option<&Path>,
    ) -> Result<Self, Box<dyn Error>> {
        let manifest = canonicalize(manifest, "package manifest")?;
        let trusted_guard = canonical_directory(trusted_guard, "trusted guard package")?;
        let metadata = cargo_metadata(&manifest, trusted_connect.is_none())?;
        let package = find_package(&metadata, &manifest)?;
        verify_guard_dependency(package, &trusted_guard)?;
        verify_connect_dependency(&metadata, package, trusted_connect)?;
        let workspace_root = metadata
            .get("workspace_root")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("cargo metadata has no workspace root"))
            .and_then(|path| canonical_directory(Path::new(path), "workspace root"))?;

        let root = manifest
            .parent()
            .ok_or_else(|| invalid("package manifest has no parent directory"))?
            .to_path_buf();
        let targets = package
            .get("targets")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("package metadata has no targets"))?;
        if targets.iter().any(is_custom_build_target) {
            return Err(invalid(
                "package-owned build scripts are not accepted by the provenance guard",
            ));
        }
        let lib_target = targets
            .iter()
            .find(|target| {
                target
                    .get("kind")
                    .and_then(Value::as_array)
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "lib"))
            })
            .ok_or_else(|| invalid("package has no library target"))?;
        let lib_path = lib_target
            .get("src_path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("library target has no source path"))
            .and_then(|path| canonicalize(Path::new(path), "library source"))?;
        if !lib_path.starts_with(&root) {
            return Err(invalid("library source is outside its package"));
        }

        Ok(Self {
            workspace_root,
            lib_path,
        })
    }
}

fn is_custom_build_target(target: &Value) -> bool {
    target
        .get("kind")
        .and_then(Value::as_array)
        .is_some_and(|kinds| kinds.iter().any(|kind| kind == "custom-build"))
}

fn cargo_metadata(manifest: &Path, locked: bool) -> Result<Value, Box<dyn Error>> {
    let mut command = Command::new("cargo");
    command.args(["metadata", "--format-version", "1"]);
    if locked {
        command.arg("--locked");
    }
    let output = command.arg("--manifest-path").arg(manifest).output()?;
    if !output.status.success() {
        return Err(invalid(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn find_package<'a>(metadata: &'a Value, manifest: &Path) -> Result<&'a Value, Box<dyn Error>> {
    metadata
        .get("packages")
        .and_then(Value::as_array)
        .and_then(|packages| {
            packages.iter().find(|package| {
                package
                    .get("manifest_path")
                    .and_then(Value::as_str)
                    .and_then(|path| canonicalize(Path::new(path), "metadata manifest").ok())
                    .is_some_and(|path| path == manifest)
            })
        })
        .ok_or_else(|| {
            invalid(format!(
                "package metadata does not contain {}",
                manifest.display()
            ))
        })
}

fn verify_guard_dependency(package: &Value, trusted_guard: &Path) -> Result<(), Box<dyn Error>> {
    let dependencies = package
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("package metadata has no dependency list"))?;
    let mut matching_dependencies = 0;
    for dependency in dependencies {
        let name = dependency.get("name").and_then(Value::as_str);
        let effective_name = dependency.get("rename").and_then(Value::as_str).or(name);
        if effective_name.map(normalize_crate_name) != Some("quint_connect_guard".to_owned()) {
            continue;
        }
        matching_dependencies += 1;
        let dependency_name = name.map(normalize_crate_name);
        let dependency_path = dependency
            .get("path")
            .and_then(Value::as_str)
            .map(Path::new)
            .map(|path| canonical_directory(path, "guard dependency"));
        if dependency_name != Some("quint_connect_guard".to_owned())
            || dependency_path.transpose()? != Some(trusted_guard.to_path_buf())
        {
            return Err(invalid(
                "package dependency named quint_connect_guard does not resolve to trusted \
                 quint-connect-guard",
            ));
        }
    }
    if matching_dependencies != 1 {
        return Err(invalid(format!(
            "package must have exactly one direct dependency named quint_connect_guard resolving \
             to trusted quint-connect-guard (found {matching_dependencies})"
        )));
    }
    Ok(())
}

fn verify_connect_dependency(
    metadata: &Value,
    package: &Value,
    trusted_connect: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let dependencies = package
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("package metadata has no dependency list"))?;
    let mut matching_dependencies = 0;
    for dependency in dependencies {
        let name = dependency.get("name").and_then(Value::as_str);
        let rename = dependency.get("rename").and_then(Value::as_str);
        let effective_name = rename.or(name);
        if effective_name.map(normalize_crate_name) != Some("quint_connect".to_owned()) {
            continue;
        }
        matching_dependencies += 1;
        if name.map(normalize_crate_name) != Some("quint_connect".to_owned()) || rename.is_some() {
            return Err(invalid(
                "package dependency named quint_connect does not resolve to trusted quint-connect",
            ));
        }

        let path = dependency.get("path").and_then(Value::as_str);
        if let Some(trusted_connect) = trusted_connect {
            let trusted_connect = canonical_directory(trusted_connect, "trusted quint-connect")?;
            let dependency_path = path
                .map(Path::new)
                .map(|path| canonical_directory(path, "quint-connect dependency"))
                .transpose()?;
            if dependency_path != Some(trusted_connect) {
                return Err(invalid(
                    "package dependency named quint_connect does not resolve to trusted \
                     quint-connect",
                ));
            }
            continue;
        }

        let source = dependency.get("source").and_then(Value::as_str);
        let requirement = dependency.get("req").and_then(Value::as_str);
        if path.is_some()
            || source != Some("registry+https://github.com/rust-lang/crates.io-index")
            || requirement != Some("=0.1.2")
        {
            return Err(invalid(
                "package dependency named quint_connect does not resolve to trusted crates.io \
                 quint-connect =0.1.2",
            ));
        }
    }
    if matching_dependencies != 1 {
        return Err(invalid(format!(
            "package must have exactly one direct dependency named quint_connect resolving to \
             trusted quint-connect (found {matching_dependencies})"
        )));
    }
    let resolved = resolved_direct_dependency(metadata, package, "quint_connect")?;
    let resolved_name = resolved
        .get("name")
        .and_then(Value::as_str)
        .map(normalize_crate_name);
    if resolved_name.as_deref() != Some("quint_connect") {
        return Err(invalid(
            "resolved quint-connect dependency has the wrong package identity",
        ));
    }
    let resolved_manifest = resolved
        .get("manifest_path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("resolved quint-connect has no manifest path"))?;
    let resolved_root =
        canonical_directory(Path::new(resolved_manifest), "resolved quint-connect")?;
    if let Some(trusted_connect) = trusted_connect {
        let trusted_connect = canonical_directory(trusted_connect, "trusted quint-connect")?;
        if resolved_root != trusted_connect {
            return Err(invalid(
                "resolved quint-connect dependency does not match the trusted package",
            ));
        }
    } else {
        let version = resolved.get("version").and_then(Value::as_str);
        let source = resolved.get("source").and_then(Value::as_str);
        if version != Some("0.1.2")
            || source != Some("registry+https://github.com/rust-lang/crates.io-index")
        {
            return Err(invalid(
                "resolved quint-connect dependency is not crates.io quint-connect 0.1.2",
            ));
        }
    }
    Ok(())
}

fn resolved_direct_dependency<'a>(
    metadata: &'a Value,
    package: &Value,
    dependency_name: &str,
) -> Result<&'a Value, Box<dyn Error>> {
    let package_id = package
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("package metadata has no package id"))?;
    let nodes = metadata
        .get("resolve")
        .and_then(|resolve| resolve.get("nodes"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("cargo metadata has no resolved dependency graph"))?;
    let node = nodes
        .iter()
        .find(|node| node.get("id").and_then(Value::as_str) == Some(package_id))
        .ok_or_else(|| invalid("resolved dependency graph omits guarded package"))?;
    let resolved_ids = node
        .get("deps")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("guarded package has no resolved dependency list"))?
        .iter()
        .filter(|dependency| {
            dependency
                .get("name")
                .and_then(Value::as_str)
                .map(normalize_crate_name)
                .as_deref()
                == Some(dependency_name)
        })
        .filter_map(|dependency| dependency.get("pkg").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if resolved_ids.len() != 1 {
        return Err(invalid(format!(
            "guarded package must resolve exactly one {dependency_name} dependency"
        )));
    }
    metadata
        .get("packages")
        .and_then(Value::as_array)
        .and_then(|packages| {
            packages.iter().find(|candidate| {
                candidate.get("id").and_then(Value::as_str) == Some(resolved_ids[0])
            })
        })
        .ok_or_else(|| {
            invalid(format!(
                "resolved {dependency_name} package is absent from metadata"
            ))
        })
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = canonicalize(path, description)?;
    if path.file_name() == Some(OsStr::new("Cargo.toml")) {
        return path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| invalid(format!("{description} has no parent directory")));
    }
    Ok(path)
}

fn canonicalize(path: &Path, description: &str) -> Result<PathBuf, Box<dyn Error>> {
    fs::canonicalize(path).map_err(|error| {
        invalid(format!(
            "cannot resolve {description} {}: {error}",
            path.display()
        ))
    })
}

struct ActiveConfiguration {
    values: BTreeSet<(String, Option<String>)>,
}

struct CapturedRustc {
    compiler: String,
    arguments: Vec<String>,
}

impl CapturedRustc {
    fn load(log_directory: &Path, lib_path: &Path) -> Result<Self, Box<dyn Error>> {
        let mut captured = None;
        for entry in fs::read_dir(log_directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let mut fields = bytes.split(|byte| *byte == 0);
            let Some(compiler) = fields.next().filter(|value| !value.is_empty()) else {
                return Err(invalid("rustc capture has no compiler path"));
            };
            let arguments = fields
                .map(|value| {
                    String::from_utf8(value.to_owned())
                        .map_err(|_| invalid("rustc capture contains non-UTF-8 arguments"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !is_test_compilation(&arguments, lib_path) {
                continue;
            }
            if captured.is_some() {
                return Err(invalid(
                    "rustc capture contains multiple test compilations for the package library",
                ));
            }
            let compiler = String::from_utf8(compiler.to_owned())
                .map_err(|_| invalid("rustc capture contains a non-UTF-8 compiler path"))?;
            captured = Some(Self {
                compiler,
                arguments,
            });
        }
        captured.ok_or_else(|| {
            invalid("rustc capture contains no test compilation for the package library")
        })
    }
}

impl ActiveConfiguration {
    fn load(rustc: &CapturedRustc) -> Result<Self, Box<dyn Error>> {
        if rustc
            .arguments
            .iter()
            .any(|argument| argument.starts_with('@'))
        {
            return Err(invalid(
                "rustc response files are not accepted by the provenance guard",
            ));
        }
        let mut configuration = Self {
            values: BTreeSet::new(),
        };
        configuration.insert_rustc_args(&rustc.arguments)?;
        configuration.insert_builtin_cfgs(&rustc.compiler, &rustc.arguments)?;
        Ok(configuration)
    }

    fn insert_cfg(&mut self, value: &str) -> Result<(), Box<dyn Error>> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(());
        }
        let (name, value) = match value.split_once('=') {
            Some((name, value)) => {
                let value = syn::parse_str::<LitStr>(value)
                    .map_err(|error| {
                        invalid(format!("rustc returned invalid cfg {value}: {error}"))
                    })?
                    .value();
                (name.to_owned(), Some(value))
            }
            None => (value.to_owned(), None),
        };
        self.values.insert((name, value));
        Ok(())
    }

    fn insert_rustc_args(&mut self, arguments: &[String]) -> Result<(), Box<dyn Error>> {
        let mut arguments = arguments.iter();
        while let Some(argument) = arguments.next() {
            let specification = if argument == "--cfg" {
                Some(
                    arguments
                        .next()
                        .ok_or_else(|| invalid("rustc capture has a cfg flag without a value"))?
                        .as_str(),
                )
            } else {
                argument.strip_prefix("--cfg=")
            };
            if let Some(specification) = specification {
                self.insert_cfg(specification)?;
            }
        }
        Ok(())
    }

    fn insert_builtin_cfgs(
        &mut self,
        compiler: &str,
        arguments: &[String],
    ) -> Result<(), Box<dyn Error>> {
        let mut command = Command::new(compiler);
        command.args(["--print", "cfg"]);
        if arguments.iter().any(|argument| argument == "--test") {
            command.arg("--test");
        }
        if let Some(target) = target_argument(arguments) {
            command.args(["--target", target]);
        }
        command.args(configuration_arguments(arguments)?);
        let output = command.output()?;
        if !output.status.success() {
            return Err(invalid(format!(
                "rustc --print cfg failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        for line in String::from_utf8(output.stdout)?.lines() {
            self.insert_cfg(line)?;
        }
        Ok(())
    }

    fn matches(&self, name: &str, value: Option<&str>) -> bool {
        self.values
            .contains(&(name.to_owned(), value.map(ToOwned::to_owned)))
    }
}

fn configuration_arguments(arguments: &[String]) -> Result<Vec<&str>, Box<dyn Error>> {
    let mut selected = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "-C" || argument == "-Z" {
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| invalid(format!("rustc capture has {argument} without a value")))?;
            selected.extend([argument, value.as_str()]);
            index += 2;
            continue;
        }
        if (argument.starts_with("-C") || argument.starts_with("-Z")) && argument.len() > 2 {
            selected.push(argument);
        }
        index += 1;
    }
    Ok(selected)
}

fn target_argument(arguments: &[String]) -> Option<&str> {
    arguments.iter().enumerate().find_map(|(index, argument)| {
        if let Some(target) = argument.strip_prefix("--target=") {
            return Some(target);
        }
        (argument == "--target")
            .then(|| arguments.get(index + 1).map(String::as_str))
            .flatten()
    })
}

fn is_test_compilation(arguments: &[String], lib_path: &Path) -> bool {
    arguments.iter().any(|argument| argument == "--test")
        && arguments.iter().any(|argument| {
            let candidate = Path::new(argument);
            candidate == lib_path
                || fs::canonicalize(candidate)
                    .ok()
                    .is_some_and(|candidate| candidate == lib_path)
        })
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}
