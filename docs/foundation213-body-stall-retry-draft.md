# Foundation 213 body-stall diagnosis and undeployed retry draft

This isolated worktree descends from frozen 9484e908. The actual recorded restore
failed after 6 min 56 s with the pinned SDK download-body minimum-throughput
error. The private partial advanced from 109655883776 to 109957873664 bytes:
nine complete 32 MiB ranges. Root preserved the failure and partial metadata in
foundation213-typed-hooks-range-interruption368-v1. This child did not inspect,
change, delete or truncate the actual partial or operate any service/endpoint.

## Evidence and limits

The existing buffered(8) future does stop polling the other range bodies while
its caller performs synchronous write/flush. However, pinned
aws-smithy-runtime 1.11.1 DownloadReport::minimum_throughput_violated explicitly
exempts ThroughputReport::NoPolling as user backpressure; Pending counts as a
server stall. Therefore local synchronous writing alone is NOT established as
the cause of the real 0 B/s failure. A server/network transient remains possible.
No scheduling rewrite or stall-check disablement was made.

The added disposable loopback SDK fixture deliberately keeps a second response
open while the existing buffered writer pauses for 1.5 seconds. It checks full
bytes/SHA and exactly one request for each of the two actual 32 MiB-bounded
ranges. A separate actual SDK fixture sends a partial response and then stalls,
with enabled SDK protection and a test-only zero grace period. It exercises
recovery, maximum-attempt exhaustion with original prefix retention, and an
identity mismatch after a stall remaining fatal. Neither fixture accesses a
real archive, credential, remote endpoint or host service.

## Narrow proposed behavior

Only a streaming-body error whose source chain contains the exact pinned SDK
private download-stall message receives the private retry marker. The SDK does
not export a typed classifier for that private error; an SDK format change will
fail closed. Request/header/ETag/Content-Range/Content-Length mismatches, clean
truncation, oversized bodies, checksum/SHA errors and local write/floor failures
do not acquire retry authority. The SDK's own request policy remains unchanged.

At most three complete attempts repeat the same range and If-Match. An attempt's
private Vec is discarded before retry, and no partial network buffer is written.
The first attempt retains its original SDK/service bounds; a fixed 120-second
retry-only deadline begins after the first positively classified body stall and
never renews. A 250 ms delay precedes each retry. Eight-range concurrency, the
512 MiB application buffer contract, ordered contiguous durable writes, whole
file rehash, actual floor checks and four-hour service deadline remain in force.

## Handoff status

This is source-only, undeployed work. The root agent's urgent epoch 205
continuation takes priority for shared Cargo. Any focused result must be reported
with its exact source/timing limits; final-source full tests, strict Clippy and a
frozen verbose production build plus actual dep-info/extern/native provenance
remain required before a deployable candidate exists. In particular the source
retry deadline was refined while the focused compiler was in flight, so that
job alone cannot be claimed as final-source qualification. No production
executable from this draft should be sealed or run. Frozen 9484e908 remains the
operational candidate until root explicitly accepts a newly qualified successor.

The in-flight focused run completed: 9 passed, none failed, one intentionally
ignored. The real SDK slow-writer control passed without retry, and the actual
stall recovery/exhaustion and identity-negative cases passed. This supports
transient whole-range retry behavior and provides counterevidence to the proposed
simple local-backpressure cause. It does not prove the cause of the real failure
or qualify the final refined deadline source, for the timing reason above.
