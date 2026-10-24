# Persistent host lifecycle examples

These files run the [persistent_host example](../examples/persistent_host/main.rs).
It submits one `u64`, marks response completion, and waits for process signals. The destination
is a volatile maximum register. Repeating a maximum assignment is intrinsically idempotent;
there is no durable destination or production metering schema in this demonstration.
Both the default buffer and destination disappear on process loss.

## Run and verify locally

From the aux-common root, build and run:

```sh
cargo build -p buffered-writes --example persistent-host
cargo run -p buffered-writes --example persistent-host
```

The example prints a `ready` JSON record containing its PID-independent state. Send TERM to the
example's process to drain the young write, emit a `drained` record and exit. Use its process PID,
not the Cargo wrapper's PID. A failed drain exits unsuccessfully and reports unresolved ownership.
The library installs no process handlers; this example is the explicit signal owner.

`BUFFERED_WRITES_SHUTDOWN_GRACE_MS` caps the complete writer drain (default 1,000 ms).
`BUFFERED_WRITES_DESTINATION_DELAY_MS` injects destination latency (default zero).
`BUFFERED_WRITES_EXAMPLE_VALUE` selects the one submitted value (default 42).
USR1 models a local preStop trigger; TERM and USR1 share the first absolute deadline. A second
signal cannot renew the budget. The engine can finish earlier when delivery policy ends an attempt.
KILL has no callback and produces no clean-drain record.

Build the example, then set `BUFFERED_WRITES_HOST_EXAMPLE` to the built executable and run
`cargo test -p buffered-writes --test host_process -- --include-ignored`.
These tests use real child processes and signals. Existing assembled AuxFn TCP tests separately
cover response-body completion and disconnect boundaries; this example has no HTTP server.

## Containers and orchestration

Build from the aux-common root for the architecture selected in the sample task definition:

```sh
docker build --platform linux/arm64 -f crates/buffered-writes/deployments/persistent-host.Dockerfile -t buffered-writes-host:local .
docker compose -f crates/buffered-writes/deployments/compose.yaml up --build
docker compose -f crates/buffered-writes/deployments/compose.yaml stop
docker compose -f crates/buffered-writes/deployments/compose.yaml down
```

The Dockerfile builds a Linux executable; do not copy a macOS Cargo binary into a Linux image.
`RUST_IMAGE` is an overridable build argument and must provide Rust 1.99.1 or newer. Compose allows
20 seconds while the application requests at most 10 seconds. The exec-form entrypoint receives
TERM directly as PID 1. A real service must withdraw readiness, stop new producers and allow
admitted request bodies to finish before closing write admission.

The [Kubernetes Pod](kubernetes-pod.yaml) allows 30 seconds total. Its preStop hook sends USR1
and returns; TERM follows through the same signal owner and deadline. Load or publish the example
image for the chosen cluster before applying this file. Match image and node architecture.
The hook's execution consumes the Pod grace period. Force deletion, node loss and KILL can bypass
it. Do not budget an additional full grace period after preStop.
See [Pod termination](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/) and
[lifecycle hooks](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/).

The [ECS task definition](ecs-task.json) uses a 30-second stop timeout and a 10-second application
cap. Replace the image with a published ARM64 image and supply the execution role, VPC, logging and
service configuration required by your deployment. The sample does not register cloud resources.
Fargate's documented stop-timeout maximum is 120 seconds; the default is 30 seconds. See
[task parameters](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html).
Docker's default Linux stop wait is 10 seconds unless configured; see
[Docker stop](https://docs.docker.com/reference/cli/docker/container/stop/).

The [systemd unit](buffered-writes-demo.service) uses a 20-second service-manager limit around the
10-second application cap. Install a Linux executable at the declared path and choose a suitable
service identity. Ordinary EC2 shutdown does not imply a Spot warning. Disk buffers survive only
when their actual volume and shutdown policy preserve acknowledged journal data.

## EC2 Spot discovery

Enable `ec2` and use `SpotLifecycle::new(ImdsSpotSource::try_new()?)` instead of the ordinary Tokio
source when the application owns Spot discovery. The default endpoint is the IPv4 EC2 metadata
address. `ImdsSpotSource::try_new_with_endpoint("http://[fd00:ec2::254]")` selects the EC2 IPv6
address when enabled on a supported instance/subnet. Explicit loopback IPs support native tests;
arbitrary hosts, endpoint paths, credentials, query strings and fragments are rejected.
A host forwarding EventBridge events must preserve the interruption deadline; its event emission
time is not itself the future action time. The source bypasses environment proxies, bounds token/action responses and shares one deadline
across token acquisition, response reading and concurrent polls. No AWS or Smithy library is used.

IMDSv2 tokens are cached and refreshed before their six-hour lifetime; a 401 invalidates the token
for the next poll. Failures return typed errors and never select IMDSv1. Use `poll_once(deadline)`
for direct discovery, or attach a `WriteObserver` with `SpotLifecycle::with_observer` to observe
source failures during lifecycle polling. The default poll interval is five seconds. Configure it before starting with
`try_with_poll_interval(duration)?`; intervals below 5 ms or outside the monotonic clock range
are rejected. Response events preserve one pending poll and its schedule. Closing the adapter,
shutdown, or cancellation of the last event waiter releases discovery; one cancelled waiter cannot
invalidate another active waiter's ownership. No extra polling task is spawned.

A stop/terminate notice uses its remaining action-time window, capped by the configured host
maximum. Expired, missing or invalid action time grants no new window. Hibernation grants no
invented grace. Notices are best effort, so durable admission is still needed when process loss
cannot lose writes. See [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
and [Spot notices](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-instance-termination-notices.html).
Local metadata fixtures and native signal tests do not establish a deployed ECS, Kubernetes or
EC2 environment. Verify the selected platform and actual stop deadlines before production use.
