# Bounded transfer recovery

The qualified v7 audit retries bounded response-body interruptions while preserving
the original failure and complete playback requirements. Deploy through a genuine
idle boundary; preserve healthy playback and the existing state/configuration.

## Exact historical failure

The retained epoch73 result is:

`/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1/results/epoch-73.json`

Its SHA256 is
`e1edc7906e39a22ec6f9ab40416eeb5452e2dfdce63b11a84f30e4ce67b5db6a`.
The failed attempt has no completed download, no playback and no plugin invocation.
Its error is exactly `streaming error: error reading a body from connection: end
of file before message length reached`. Object identity remains epoch73,
13,978,437,633 bytes, ETag `"9e950a685738661c0e65810dc98014e2-2667"`.
The code recognizes this exact inspected receipt hash and shape. Similar error
text in another old receipt grants no retry eligibility.

## New transfer failures and scheduling

New attempts persist authenticated object, bucket, version, metadata digest,
sidecar digest and sidecar ETag before transfer. Only a body-stream error or
body-read timeout receives a typed `TransferInterruption`, with its exact identity
and bytes received. GET/HEAD rejection, remote-identity change, clean short EOF,
length overflow, digest failure, disk/capacity stop and plugin/reader failure
remain untyped and are not retried. No string matching broadens those classes.

After the immutable failure result and ordinary exact-inode scratch cleanup,
the same controller may claim up to two recovery slots. Minimum delays are
30 seconds after the initial result and 120 seconds after the first retry.
Each intent is fsynced without replacement after the current-reader and capacity
gates pass, immediately before a transfer can start; it binds
the original result hash, preceding result hash, exact object, private attempt
directory and prior transfer identity. Each retry starts at byte zero and runs
the unchanged full current-plugin playback, whole-file hashes and remote checks.
The downloaded partial is removed only by the existing ownership-based cleanup.

Results are `results/epoch-N.retry-I.json`, with intents named
`results/epoch-N.retry-I.intent.json`; original `results/epoch-N.json` remains
byte-for-byte intact. Reading a chain verifies every predecessor hash, ordinal,
object, attempt directory and expected failure class. Missing, substituted or
out-of-order evidence fails closed. The latest validated result supplies summary
status; a recovered pass is additionally counted in `recovered_transfer_failures`.
Only such a pass changes an unresolved failure to a pass.

A service interruption after an intent but before a terminal retry result leaves
the slot consumed. On ordinary startup, the existing scratch recovery runs first,
then an immutable interrupted-result record closes the slot without another
automatic attempt. This preserves uncertainty about whether playback had begun,
and prevents repeated restarts from generating unbounded retries. The preserved
attempt requires manual evidence review. Completed retries and pending eligibility
otherwise resume from the original frozen numeric inventory, without resetting
completed epochs or launching another controller.

Capacity waits, reader qualification and backoff keep the prospective ticket in
memory. An interruption during those stages leaves the original failure and retry
budget unchanged. At the transfer boundary, the controller revalidates the exact
eligible predecessor, ordinal, backoff and empty owned scratch before persisting
the intent. Existing durable v6 intents retain their conservative interpretation;
absence of a new marker never reclassifies an already-spent slot.

## Qualification and deployment handoff

Qualification passed 44 ordinary tests, strict all-target Clippy and the release
build. The existing native two-filesystem test was not rerun and remains ignored.
The retry regressions cover body-EOF classification versus clean truncation
and checksum errors; all remote identity fields; two-slot persistence and
original preservation; exact historical receipt eligibility; interrupted-ticket
consumption; orphan/substituted/gapped chains; scratch cleanup prerequisites; and
success summary reconciliation, repeated interruption before the transfer boundary,
and predecessor/backoff/scratch revalidation at that boundary.

Use the parent's admitted serial build envelope and existing target; do not start
compilers while its cache retirement is unreconciled:

```text
env RUSTC=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc /home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo test --locked --manifest-path /home/sol/workspace/jetstreamer/scripts/horizon_r2_chronological_plugin_audit_20261118_v1/Cargo.toml --target-dir /tmp/horizon-r2-chronological-audit-build-20261118-v1 -j 1
```

Run all-target strict Clippy and release with the same manifest/target/compiler.
Keep the prior serial 1 CPU, 3 GiB memory, no-swap, TasksMax256 and 1800-second
envelope unless parent admits a different one. No new resource reservation is
implied. Native acceptance should verify the genuine historical epoch73 receipt
is eligible under the new image without changing it; sandbox the runner at the
next safe operational handoff and require a real retry pass/cleanup receipt before
claiming recovery. A successful mock/fixture cannot prove archive compatibility.

Parent must publish exact source on `account-updates`, seal a distinct runtime
`/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261119-v7`,
retain the current config bytes, state lock, service sandbox and resource envelope,
preserve predecessor native evidence, then switch only the idle controller.
Current playback must finish first. No `reconfigure` is needed for this fixed
retry policy. It adds no R2 operation or second service and preserves all previous
archive integrity and exact-epoch capacity gates.
