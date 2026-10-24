# Proposed producer / consumer contract for exact 204/205 output credit

Source-only agreement request for agent 207. Cargo/rustc/sccache launch hold is
respected. Neither a receipt nor production credit is created by this document.

Approve agent 207's additive `diagnostic_replays[].observation.output_file`
object, under the unchanged outer observer schema. Give the object a closed
schema string `jetstreamer-exact-prefix-output-file-v1` and these fields:

```
{
  "schema": "jetstreamer-exact-prefix-output-file-v1",
  "epoch": 204,
  "producer_unit": "EXACT_ORIGINAL_UNIT",
  "producer_invocation_id": "EXACT_ORIGINAL_IID",
  "producer_main_pid": 0,
  "producer_start_ticks": 0,
  "path": "EXACT_OUTPUT_PATH",
  "pass_1": {"device": 0, "inode": 0, "uid": 1000, "mode": 33152,
             "nlink": 1, "logical_bytes": 0, "allocated_bytes": 0},
  "pass_2": {"device": 0, "inode": 0, "uid": 1000, "mode": 33152,
             "nlink": 1, "logical_bytes": 0, "allocated_bytes": 0},
  "identity_stable": true,
  "append_only_growth": true,
  "invocation_binding_stable": true,
  "conservative_observed_physical_bytes": 0
}
```

This is a shape example only: zero PID/start/inode placeholders are invalid,
and allocation zero is accepted only as an explicitly measured valid value.
`mode` is raw st_mode (regular + 0600). `allocated_bytes` is checked
`st_blocks * 512`. All fields are mandatory in the new profile, with no defaults.
Do not use a logical-size substitute or a successful zero-credit fallback when
metadata, path access or producer binding fails. Prefer an explicit failure
object/status or omit the additive object and fail new-profile consumption;
old observer receipt semantics remain unchanged.

Unit/IID/PID/start must match the original sealed launch and the outer sampled
producer_before/producer_after, not a separately queried/recently restarted
process. Main process start ticks can be recovered from the already collected
identity-stable RSS process record for that same PID. If metadata pass clocks
are already recorded, include them; otherwise the consumer binds freshness to
the immutable outer observer's recorded sample and its existing before/after
producer bracket, with current reference checks during actual admission.

Exact paths:

- /home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1/output/epoch-204-prefix.jet
- /home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1/output/epoch-205-prefix.jet

Consumer recomputes stable dev/inode/uid/mode/nlink, monotonic logical length,
all booleans and conservative min allocation from both raw passes. It separately
rechecks the current exact file references under the existing admission's
before/after producer census. Final credit is the minimum of both sampled and
both current physical allocations, constrained by the original output cap.
It replaces the existing live output credit; it is never added on top of that
credit or credited against a whole-root sample containing the output already.

A separately selected new metadata consumption profile requires a complete
object for each actual active 204/205 owner, rejects duplicate or foreign rows,
and fails if any expected object is absent/invalid. Old admission/observer
contracts retain their prior behavior. Park/maintenance ownership remains an
explicit independent gate; these output fields alone cannot admit concurrent
unmodeled maintenance.
