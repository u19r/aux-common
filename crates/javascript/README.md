# JavaScript

Run a synchronous JavaScript function with explicit JSON arguments in a fresh embedded Wasm instance.
The crate contains the guest artifact, its provenance, restricted host imports, and a single reviewed native-artifact loader.

## Public API

```rust
use javascript::{JsExecutor, JsInvocation, JsInvocationInput, JsSourceOrder, JsCancellation};

let executor = JsExecutor::try_new()?;
let invocation = JsInvocation::try_new(JsInvocationInput {
    source: "function add(a, b) { return a + b; }",
    function: "add",
    arguments: (2, 3),
    bindings: &[],
    source_order: JsSourceOrder::BeforeBindings,
})?;
let value = executor.run(executor.prepare(invocation)?, JsCancellation::new())?;
assert_eq!(value.get(), "5");
# Ok::<(), javascript::JsError>(())
```

Construct and reuse one executor. Construction validates the bundled guest declarations and loads its embedded, precompiled artifact.
Each `run` creates one Store and guest instance, then discards all guest state.
No runtime file, SDK, CLI, child process, tenant identity, storage client, or async runtime is required.

Arguments must serialize to an array. Tuples provide borrowed argument arrays without copying application DTOs.
A `JsBinding` aliases an argument as a global with the same object identity.
`BeforeBindings` evaluates source before installing aliases; `AfterBindings` installs aliases first.
Function and binding names use ASCII JavaScript identifiers, with reserved words excluded.
Bindings cannot repeat names or refer beyond the argument array.

`prepare` rejects invalid input and bounds serialization before execution.
`run` returns validated JSON as `RawValue`, or a fixed `JsError` category.
Errors contain no engine messages, source, argument values, or guest exception text.
The executor neither retries jobs nor performs application side effects.

## Limits and lifetime

| Resource | Limit |
| --- | --- |
| Source | 65,536 UTF-8 bytes |
| Arguments | 16 entries; 262,144 aggregate JSON bytes, excluding array separators |
| Bindings | 16 names; each identifier at most 128 bytes |
| Complete job | 1,048,576 bytes, including JSON escaping |
| JSON result | 262,144 bytes |
| Complete reply | 262,272 bytes |
| Guest linear memory | 16 MiB, including Rust, libc and QuickJS allocations |
| Wasm call stack | 512 KiB |
| QuickJS stack | 256 KiB secondary setting |
| Function table | 4,096 elements |
| Store | One instance, memory and table |
| Fuel | 1,000,000,000 units, including initialization and result serialization |
| Execution deadline | 50 ms from Store creation, measured with host `Instant` |

The 1 ms epoch thread checks absolute deadlines and cancellation.
Every host import and the final reply acceptance also check both signals.
Fuel remains finite if epoch ticking is delayed. Fuel exhaustion returns `Timeout`.
Cancellation clones share one signal. Cancellation does not release a caller's admission permit.
Keep the permit until `run` finishes and guest state drops.
Executor drop stops and joins its epoch thread. Cloned caller handles do not retain the executor.

Scheduling can delay interruption. The deadline is not a hard real-time guarantee.
Preparation invokes the caller's `Serialize` implementation outside the execution deadline; use trusted serializers.
Callers must bound concurrent jobs and prepared buffers. This crate contains no waiting queue or admission policy.
The memory limit bounds guest linear memory, not whole-process RSS, native stacks or allocator overhead.

## Sandbox contract

The guest receives only supplied source, arguments and binding names.
It has no environment, filesystem, sockets, DNS, metadata access, storage, or general host callbacks.
Do not supply secrets through arguments unless customer JavaScript is authorized to read them.
The parent owns authentication, destination policy, signing, HTTP validation, persistence and business rules.

Only Eval and Json intrinsics are installed. `Math.random` is removed before source evaluation.
Date, performance, Promise, typed arrays, shared memory, modules, console and network APIs are absent.
The guest runs no asynchronous job pump.

All imports belong to `wasi_snapshot_preview1`, with exact signatures checked before instantiation:

| Imports | Behavior |
| --- | --- |
| `environ_sizes_get`, `environ_get` | Empty virtual environment |
| `random_get` | At most 256 fixed zero bytes |
| `clock_time_get` | Fixed zero timestamp |
| `fd_fdstat_get`, `fd_close`, `fd_seek` | Only virtual streams 0–2; no host descriptors |
| `fd_prestat_get`, `fd_prestat_dir_name` | `BADF`; no directories |
| `fd_read` | Bounded job bytes and EOF through stdin 0 |
| `fd_write` | Bounded reply through stdout 1; stderr traps |
| `proc_exit` | Typed guest exit; exit 0 requires a complete valid reply |

Pointers, ranges, descriptor state and all vectors are validated before copying.
Each stream call permits at most 16 vectors. Oversized replies trap before append.
The module has one unshared 32-bit memory and one table.
The only exports are `memory`, `_start`, and reviewed compiler export `__main_void`.
A core start section, imported memory, extra imports/exports, or unsupported declarations prevent initialization.
The AOT loader accepts only immutable bytes embedded from this package’s build output.
Callers cannot provide Wasm, serialized native code, filesystem paths, or native caches.

Wasmtime and these imports are trusted components. This boundary does not promise containment after a Wasmtime escape.
It does not provide independent OS isolation, whole-process OOM recovery, or protection against every speculative-execution attack.
Default Wasmtime memory guards and Spectre protections remain enabled.

## Build-time compilation

`build.rs` compiles the fixed QuickJS Wasm guest for Cargo's `TARGET`. Cranelift runs during the build.
The deployed library uses Wasmtime with `runtime` and `std`; it contains no Wasm compiler.
Small Cranelift metadata collections remain dependencies of Wasmtime's runtime; its code generator does not.

Customer JavaScript remains a string. QuickJS interprets it inside the precompiled Wasm sandbox.
The native artifact is generated per target and locked Wasmtime version, then embedded from `OUT_DIR`.
Fuel and epoch instrumentation match the runtime configuration. An incompatible engine fails initialization.
Cross builds enable compiler backends in the build dependency and use portable target CPU settings.
Build-script reruns reuse native artifacts in Cargo's output directory when the guest SHA-256 and
Wasmtime target/compiler compatibility hash match. CI must retain its Cargo target directory to
reuse these artifacts across fresh checkouts; a cold cache compiles the guest once.

Wasmtime marks native-artifact deserialization unsafe because arbitrary native artifacts can execute host code.
The loader accepts only the immutable artifact generated during this package's build; all other crate code denies unsafe operations.
The raw guest remains embedded for declaration validation.

## Artifact maintenance

The private [producer](../quickjs/Cargo.toml) is excluded from the native workspace.
It depends on this crate without `runtime`; native hosts never compile or link QuickJS C code.
The default `runtime` feature enables the runtime and the build-time compiler.
Without `runtime`, the guest producer activates neither Wasmtime nor the native precompiler.

Build prerequisites: Rust 1.99.1 with `wasm32-wasip1` and Clippy, and an explicit WASI SDK 24.0 path.
Set `CARGO_TARGET_DIR` to an isolated build directory and `WASI_SDK` to the SDK directory.

Artifact regeneration commands require the full development checkout, which includes the
maintenance scripts and Just recipes. The public source distribution includes the prebuilt guest
and its provenance; ordinary library builds do not require those maintenance tools.

- `just quickjs-wasm-build` regenerates the artifact and manifest from the locked guest.
- `just quickjs-wasm-check` checks provenance, byte reproducibility, exact runtime policy, and the separate guest dependency audit.
- `just quickjs-script-test` checks shell orchestration with mocked external commands.
- `cargo test -p javascript` runs actual guest and hostile Wasm tests.
- `cargo run -p javascript --example add` runs the storage-free public API example.

Review import policy whenever artifact imports or exports change.
Review [Wasmtime advisories](https://github.com/bytecodealliance/wasmtime/security/advisories) and
[QuickJS-NG advisories](https://github.com/quickjs-ng/quickjs/security/advisories) before artifact updates.
rquickjs 0.14.0 vendors QuickJS-NG 0.16.2.
The artifact manifest records source and lock hashes, vendored source identity, licenses and toolchain versions.
Guest dependency audits remain separate because workspace gates cannot inspect an excluded workspace.

Tests cover generic function/business outputs, ordering, validation, guest wire revalidation, fixed errors,
state reset, concurrent calls, cancellation, memory/stack/CPU explosion, failure recovery and hostile import streams.
Hostile fixtures bypass only trusted module selection in test code; production accepts no caller Wasm.
Application-specific AuxFn delivery, admission, authorization, and packaging are outside this component's test scope.
