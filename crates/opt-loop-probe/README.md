# opt-loop-probe

`opt-loop-probe` is internal diagnostic tooling for optimization-loop runs. It records allocator activity, manager runtime measurements, component call counts, component byte totals, and sampled hotspots to JSON files.

## How to enable it

Use the probe as the process global allocator in the binary or benchmark being measured:

```rust
#[global_allocator]
static ALLOCATOR: opt_loop_probe::ProbeAllocator = opt_loop_probe::ProbeAllocator::new();
```

Enable collection with environment variables:

```sh
AUX_OPT_LOOP_ENABLED=1 \
AUX_OPT_LOOP_TARGET_ID=storage-query \
AUX_OPT_LOOP_PHASE=baseline \
AUX_OPT_LOOP_SAMPLE_INDEX=0 \
cargo run -p storage-api
```

By default, samples are written under:

```text
tmp/opt-loop/runs/<target_id>/<phase>/sample-<sample_index>.json
tmp/opt-loop/runs/<target_id>/<phase>/sample-<sample_index>-hotspots.json
```

Override paths and sampling when needed:

```sh
AUX_OPT_LOOP_SAMPLE_FILE=/tmp/probe-sample.json \
AUX_OPT_LOOP_HOTSPOT_FILE=/tmp/probe-hotspots.json \
AUX_OPT_LOOP_ALLOC_SAMPLE_RATE=512 \
AUX_OPT_LOOP_STACK_DEPTH=32
```

## Recording component work

Call the component helpers around work that may pause the optimized loop:

```rust
opt_loop_probe::record_storage_call("get_item", request_bytes);
opt_loop_probe::record_queue_call("receive_message", request_bytes);
opt_loop_probe::record_pubsub_call("publish", request_bytes);
opt_loop_probe::record_bg_job_call("ttl_sweep", 0);
```

Use `measure_future` around the manager path being compared:

```rust
let output = opt_loop_probe::measure_future(manager.run_once()).await;
```

Call `force_flush()` before process exit if the measured process exits quickly.

## Output

The sample JSON contains totals for heap allocation, peak live heap bytes, manager-specific allocation deltas, storage calls, queue calls, pubsub calls, and bg-job calls. The hotspot JSON groups sampled allocation and component-call backtraces by kind, operation, and stack hash.
