# Classic Lambda extension integration

Enable `buffered-writes/lambda`, or `metrics-facade/buffered-lambda` for metering consumers.
The facade exposes `LambdaIpcConfig`, `LambdaExtensionClient`, `LambdaInvocation` and `LambdaExtensionServer`.
The extension owns the writer and retention. The function process holds only an IPC client.
No constructor starts a worker. Binding reserves the writer's sole response-bound lifecycle slot;
a prestarted driver or periodic policy is rejected. A failed socket bind consumes no reservation. The extension process polls `server.run(runtime_api, filename)`
until SHUTDOWN drains, then exits promptly with its returned `DrainReport`.

The `lambda-extension` and `lambda-runtime` examples provide thin process entrypoints. The
deployed fixture remains pending. Local TCP and HTTP proof does not establish deployed compatibility.

## Wiring

Supply both processes with the same loopback endpoint and printable ASCII capability token.
`LambdaIpcConfig::try_new(address, token)` rejects non-loopback addresses, empty or oversized tokens
and non-printable tokens. The token is at most 256 bytes. Debug output hides configuration values.
Its default exchange timeout is two seconds; `try_with_timeout` accepts a positive finite override.
Bind the server before registering the extension so an early function connection can wait in the
bounded local path until the actual INVOKE event establishes its authority.

```rust,no_run
# #[cfg(feature = "lambda")]
async fn extension_process(
    writer: buffered_writes::BufferedWrites<u64>,
    config: buffered_writes::LambdaIpcConfig,
    runtime_api: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let server = buffered_writes::LambdaExtensionServer::bind(writer, config).await?;
    let report = server.run(runtime_api, "buffered-writes-extension").await?;
    if !report.is_clean() {
        return Err("buffered write drain is incomplete".into());
    }
    Ok(())
}
# fn main() {}
```

Use the full deployed extension filename as the registration name. The runtime endpoint comes from
`AWS_LAMBDA_RUNTIME_API`; the adapter accepts a loopback or link-local IP address and port. It bypasses
proxies, redirects and transparent retries. Registration has a five-second total budget. The provider
Next request deliberately has no total or idle-read timeout because Lambda can suspend the extension
while it waits. After response headers arrive, its body is limited to 64 KiB and one second.

The trusted custom runtime owns one non-cloneable `LambdaExtensionClient::<T>::new(config)`.
Immediately after Runtime API Next, call `begin_invocation(request_id, attempt_id).await` to obtain
a cloneable `LambdaInvocation<T>`. Give application work only that scoped handle. Its operations are
`add_write_item(item)` and `add_write_item_with_options(item, options)`, with no caller-supplied
phase identity. Post the Runtime API response, await its acknowledgement, then call
`invocation.after_response().await` before the next Runtime API Next. Handler return alone is not
that acknowledgement. An ordinary task spawned after a managed handler returns can freeze.

The example requires the Runtime API `Lambda-Runtime-Invocation-Id` attempt header and echoes it
on both success and error responses. The provider request ID is a correlation value: a retry may reuse it. The extension
captures the independent `Lambda-Extension-Event-Identifier` header for each provider phase. AWS
does not document an equality or derivation relationship between these two opaque IDs. Binding is
local first-binder authority granted to the trusted runtime loop, not AWS-attested linkage between
the IDs. Raw binding authority must not be distributed to background application work.

The example keeps bounded raw payload and provider IDs until the runtime binds. Decode, admission
or binding failure posts a fixed error payload to `/runtime/invocation/{request_id}/error` with the
attempt header. After the Runtime API acknowledges a success or error with 202, a bound scoped
handle can send the completion marker. If binding failed, the runtime cannot forge completion;
the extension's provider deadline bounds its wait. A rejected or missing API acknowledgement
never grants marker permission. Invalid provider headers remain a runtime protocol failure.

The marker returns the eligible-flush summary; a young batch may remain buffered with zero settled
items. A repeated marker for the current completed session returns the cached summary. Do not add
its counts again when retrying. Rebinding the same runtime attempt during its current phase recovers
the same capability after a lost Bind acknowledgement. A new provider phase fences all previous
handles. The immediately preceding attempt ID cannot bind it. The server keeps bounded state; it
does not claim to authenticate arbitrary historical attempts from a caller holding the raw bind token.

`server.run` registers for INVOKE and SHUTDOWN. INVOKE establishes identity and a deadline; it does
not trigger a flush. The server sends Next only after the completion-triggered flush finishes or
the marker wait reaches its deadline. A missing marker emits a typed lifecycle failure and grants
no response-complete delivery permission. Its expired phase cannot admit new writes. The next real
provider invocation can proceed without retaining an unbounded completion history.

For a custom host integration, `begin_invocation(event_id, request_id, deadline)`, `await_invoke_completion` and `shutdown` expose
these same boundaries. `await_invoke_completion(event_id)` derives its timeout from the deadline already
stored by `begin_invocation`; callers do not configure a second deadline. These calls are provider
authority; they are not IPC commands. Poll `serve()`
alongside that host's event loop. The built-in `run` performs this wiring without detached tasks. A shared service reservation rejects
a second serve/run owner before another provider registration; cancelling the active future releases
that reservation, while shutdown prevents restart.

## IPC version 2

Each connection carries one request and response: a four-byte unsigned big-endian length followed
by UTF-8 JSON. A frame must contain 1–1,048,576 bytes. Readers reject its length before allocation;
writers enforce the same budget during serialization. The server processes one connection at a
time under a total exchange deadline and caps delivery by the actual invocation deadline.
Submissions carry an absolute kernel monotonic admission deadline. Queueing consumes that budget;
the extension takes the minimum of caller, IPC and provider deadlines. It never renews admission after accept.
Function and extension must run on Unix in the same host and kernel time namespace, as in one Lambda execution environment.
The typed client creates the timestamp; do not substitute a wall-clock timestamp or a fresh relative timeout.

A submission is:

```json
{
  "version": 2,
  "auth_token": "configured-capability-token",
  "command": {
    "Submit": {
      "session": "extension-generated-UUIDv7-capability",
      "deadline": { "expires_ns": 123456789000000 },
      "operation_id": "stable-operation-id",
      "scope": null,
      "item": 7
    }
  }
}
```

Before submitting, send `"command": {"Bind": {"request_id": "provider-request-id",
"attempt_id": "runtime-attempt-id"}}`. The response is `{"Bound": {"request_id": "...",
"attempt_id": "...", "session": "UUIDv7", "namespace": "writer/v1"}}`. The client verifies the echoed IDs and capability version.
A completion marker uses `"command": {"InvocationComplete": {"session": "UUIDv7"}}`.
There is no function-side shutdown command. Responses are externally tagged JSON variants:
`Bound`, `Admitted`, `Completed`, `WriteFailed`, or the string `Rejected`. The Rust client owns safe typed
projection; backend error text and token contents never become public errors.

Wrong authority or a mismatched active invocation is rejected without admission. A completed or
expired invocation cannot accept another item. Only a bind racing the next INVOKE can wait, within its exchange deadline. Mutations require
the exact current capability and never wait across phases. Provider event/request and runtime
attempt IDs are bounded to 128 printable ASCII bytes. Provider event headers must contain a UUID.

The client generates an operation UUIDv7 before dispatch unless `WriteOptions` supplies an ID.
A confirmed failure preserves its definite/uncertain classification. A lost or malformed response
after dispatch returns `WriteError::Ambiguous` with that stable ID. Retry the same item through
`add_write_item_with_options` with that ID. Reusing it with different bytes returns an identity
conflict. A transport timeout bounds waiting; it cannot retract a write already accepted remotely.
For cancellation where no result can be received, supply and retain the operation ID before
starting the call. Items need no Clone implementation and the client does not retain a copy.

## Example binaries and native proof

Build both process entrypoints with the `lambda` feature. The examples use a volatile, intrinsically
idempotent maximum-register destination for numeric inputs. This demonstrates process ownership,
not durable storage or atomic receipt implementation. The common crate imports no consumer schema.

```sh
cargo +1.99.1 build -p buffered-writes --features lambda \
  --example lambda-extension --example lambda-runtime
BUFFERED_WRITES_LAMBDA_EXTENSION_EXAMPLE="$CARGO_TARGET_DIR/debug/examples/lambda-extension" \
BUFFERED_WRITES_LAMBDA_RUNTIME_EXAMPLE="$CARGO_TARGET_DIR/debug/examples/lambda-runtime" \
  cargo +1.99.1 test -p buffered-writes --features lambda --test lambda_process -- --ignored
```

Set `CARGO_TARGET_DIR` to the repository-approved target slot before these commands. Both binaries
require `AWS_LAMBDA_RUNTIME_API` and `BUFFERED_WRITES_IPC_TOKEN`. They share
`BUFFERED_WRITES_IPC_ADDR`, defaulting to `127.0.0.1:34900`; the extension also accepts port zero for
local fixtures and reports the assigned address. `BUFFERED_WRITES_FLUSH_AGE_MS` defaults to 200.
`BUFFERED_WRITES_DESTINATION_DELAY_MS` is a demonstration failure-injection setting, default zero.
The runtime input is `{"value":7}`; demonstration controls `skip_marker`,
`exit_after_response` and `hang_before_response` exercise failure boundaries. Do not expose these controls as a metering API.

The six native fixtures run both actual binaries as separate processes. The parent emulates the
provider HTTP boundary and withholds the Runtime API response acknowledgement to verify that no
completion marker, flush or extension Next occurs early. The fixtures also prove warm-buffer reuse,
missing-marker timeout followed by shutdown, bounded unresolved drain, and forced kill without a
clean receipt. A malformed-input case checks the exact invocation error path, attempt header and
error media type, holds its acknowledgement, then verifies completion and a subsequent valid call. They use independent extension event and runtime attempt IDs while repeating the
request ID. They do not prove AWS's notification delivery or the behavior of a deployed environment.

For ARM64 `provided.al2023`, the linked target is `aarch64-unknown-linux-gnu.2.34`:

```sh
cargo +1.99.1 zigbuild -p buffered-writes --features lambda \
  --example lambda-extension --example lambda-runtime \
  --target aarch64-unknown-linux-gnu.2.34
```

Package the runtime as `bootstrap` in a function ZIP. Package the extension as
`extensions/lambda-extension` in a separate layer ZIP, and attach the published layer version to the
function. Lambda extracts function code to `/var/task` and layers to `/opt`; external extension
discovery uses `/opt/extensions`. A combined function ZIP does not install an external extension.
Both files must be executable.

The repository command validates Linux ARM64 inputs and creates fresh archives without stale entries:

```sh
just buffered-lambda-package \
  "$CARGO_TARGET_DIR/aarch64-unknown-linux-gnu/debug/examples" \
  "$PWD/run-artifacts/buffered-writes/lambda-package"
```

It writes `lambda-function-arm64.zip` and `lambda-layer-arm64.zip`. The current implementation
receipt records their entries, permissions, sizes and hashes. Linking and package layout pass;
Linux execution and deployed compatibility remain pending.

## Optional deployed test fixture

Live AWS checks are not acceptance requirements. The local lifecycle command and package checks provide the required proof.
The following fixture is optional and was not run for acceptance. Deployed AWS compatibility remains unverified.

The ignored `lambda_native` tests use AWS CLI/SSO only as test infrastructure. Production libraries
have no official AWS or Smithy dependency. Supply an explicit profile, region, both archives and a
receipt directory. The profile needs Lambda function/layer, CloudWatch Logs and IAM test-resource
permissions. An optional `BUFFERED_WRITES_LAMBDA_ROLE_ARN` reuses a caller-owned execution role with
CloudWatch Logs write permission; that role is never deleted. Without it, the fixture creates a
uniquely named role with AWSLambdaBasicExecutionRole.

```sh
BUFFERED_WRITES_LAMBDA_PROFILE=dev-poweruser \
BUFFERED_WRITES_LAMBDA_REGION=eu-central-1 \
BUFFERED_WRITES_LAMBDA_ZIP="$PWD/run-artifacts/buffered-writes/lambda-package/lambda-function-arm64.zip" \
BUFFERED_WRITES_LAMBDA_LAYER_ZIP="$PWD/run-artifacts/buffered-writes/lambda-package/lambda-layer-arm64.zip" \
BUFFERED_WRITES_LAMBDA_RECEIPT_DIR="$PWD/run-artifacts/buffered-writes/lambda-live" \
  cargo +1.99.1 test -p buffered-writes --features lambda --test lambda_native \
    -- --ignored --test-threads=1
```

The first case checks warm-buffer reuse, acknowledged invocation errors and final drain after runtime
exit. The second admits a write then hangs before the response, verifies a real platform timeout,
shutdown drain and reinitialization, then completes another invocation. The fixture records JSON
application events and platform log messages. Native withheld-ACK proof establishes causal ordering;
CloudWatch ingestion timestamps alone are not a cross-process ordering guarantee.

The fixture records resource names before mutations in a unique receipt subdirectory. It publishes
one layer version, creates one function and uses one concurrent execution. All AWS CLI processes
force `AWS_MAX_ATTEMPTS=1`; invocation commands are never transparently replayed. Only a definite IAM
role-propagation rejection permits an explicit create retry. Transport-unknown creates retain their
pending authority until observed by name or left unresolved.

Normal completion and unwinding reconcile deletion of the function, layer versions, owned role and
log group under one cleanup deadline. Clean state requires repeated observed absence and no unknown
creation. An unresolved operation or failed cleanup persists `cleanup-unverified`; use its names for
manual reconciliation. A preflight failure before mutation creates no resources and skips cleanup
network calls. AWS configuration stdout is not logged because it contains the private IPC token.
Neither compilation nor an expired-SSO preflight counts as a deployed pass.

## Limits and lifecycle semantics

The token is capability hygiene within Lambda's shared process/network/security context; it does
not isolate hostile function code that can read the same environment. Applications still own
trusted tenant scopes and measurement identities. The common crate owns no business schema.

Shutdown uses the remaining provider deadline, capped at the documented external-extension limit,
with safety margin. It never creates a fresh minimum budget. The full DrainReport preserves unknown
state, unresolved and quarantined work; process owners must not infer clean drain from elapsed time.

Timers cannot run while the environment is frozen. The default age/count policy can retain young
writes until the next invocation or shutdown. Runtime crash, missing markers, forced kill, OOM or
host loss can prevent a graceful callback or final drain. In particular, an abrupt runtime failure
can remove the completion hook before the extension requests its next event. Volatile memory is
not guaranteed durable. Disk and Valkey retain their documented storage and recovery limitations.

This adapter is for classic Lambda external extensions. Managed Instances and SnapStart require
separate lifecycle/restore validation. No deployed compatibility or durability claim follows from
local protocol fixtures.

Sources: [Extensions API](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-extensions-api.html),
[Runtime API](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html),
[extension packaging](https://docs.aws.amazon.com/lambda/latest/dg/lambda-extensions.html),
[CLI retries](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-retries.html) and [execution environment lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html).
