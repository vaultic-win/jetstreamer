# Foundation 213 holding readback source review

Source-only review of commit `f55b78c352d6aa9529295e67f0bae1046763a960`,
sealed helper SHA256
`1ae341e3ae27e05e8149fe89781704aa58b01359206e98f64d27401bdcb87d69`.
No fresh resource observation, journal request, network operation, service
change or R2 mutation was performed.

Preserve `horizon-foundation-prefix213-park348-v2.service`, invocation
`e855cc495d17446b983bc98771d357e8`, and its current readback. The supplied
cycle 352 marker reports 1,140,850,688 hashed bytes at 795,985 milliseconds.
That is about 1.43 MB/s and 0.91% of 125,316,500,795 bytes, approximately
24.3 hours for the whole read at that historical average. This is a diagnostic
projection, not a completion estimate. It exceeds the unit's four-hour total
start timeout, which also includes local hashing/upload and later checks.

## Exact reader

`holding_foundation213::park` calls `holding::verified_blob`, which calls
`verify_remote_sha256` with concurrency **2**, regardless of ordinary upload
CLI concurrency. At concurrency two, `remote_read_ranges` selects **64 MiB**
ranges. The last range is shorter. At most two range futures are in the ordered
buffer; the whole-object digest consumes them in source order. A slow earlier
range can prevent later completed ranges from advancing the hashed marker and
occupy the bounded window. The marker is application-level ordered/hash
progress, not a wire-byte counter.

Every range has an authenticated conditional GET with the exact ETag and
checks Content-Length, Content-Range, response ETag and full body length. Each
range body is collected, copied into a vector, then synchronously fed into
SHA-256. Verification writes to a sink, not another full local file. There is
no deliberate rate limit or pacing of successful reads. Failed sends or failed
body streams retry the complete range; 64 failures are allowed before the next
failure aborts (the diagnostic labels call these attempts). Backoff is 1, 2,
4, 8, 16, then 30 seconds. SDK internal retries can occur within each send.
There is no explicit application-level range or body timeout; SDK defaults
apply. A complete successful body with incorrect bounds or ETag fails closed
instead of retrying.

The unit sets `TOKIO_WORKER_THREADS=2`, `CPUQuota=100%`, Nice 10 and low I/O
priority. Synchronous hashing and copying occupy a Tokio worker briefly and
share one CPU quota with SDK processing. These limits could matter, but the
supplied marker alone cannot distinguish CPU pressure from a slow connection,
retry loss or ordered head-of-line blocking. No recommendation to change the
healthy unit follows from source inspection alone.

Progress emits after the first 64 MiB and then each additional 1 GiB, plus the
tail. The supplied 1,140,850,688 value is exactly 17 full ranges, an expected
checkpoint. A lack of another marker does not prove zero transfer meanwhile.

## Smallest useful bounded comparison

Existing sealed `probe-transport-203` and `probe-transport-217` profiles **do not
support holding keys**. They select only their exact top-level epoch archives;
do not repurpose either profile or substitute a holding path into them. The
genesis restore probe also does not measure this exact object/transport.

A new closed source profile should adapt the existing transport probe without
changing the live park binary or process. Bind precisely:

- Bucket `solana-archive-with-accounts-data`.
- Key `foundation_node_01/objects/e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9.blob`.
- Length 125,316,500,795; ETag `6933eb7a4efb4629b25550f0c1c433a1-1868`.
- The already retained exact prefix source and its stable regular-file identity.
- One 32 MiB window at offset 8 GiB, bytes 8,589,934,592–8,623,489,023.

Read that bounded local window once and compare every returned byte. Run one
SDK conditional range GET, then one direct HTTPS IPv4 conditional range GET
using an in-memory, 120-second presigned GET. Cap each comparison at 20 seconds,
connect at five seconds, forbid redirects/proxies, enforce 206 and all response
length/range/ETag checks, cap body collection to the expected window, and
recheck local identity. Sequential comparisons limit extra traffic to 64 MiB
and extra in-memory bodies to a small bounded amount. An optional sequential
IPv6 comparison adds 32 MiB only when that address family is available; missing
IPv6 should be recorded rather than losing the whole diagnostic receipt.

Write one private no-clobber diagnostic receipt with transport, family, bounded
bytes, elapsed milliseconds, byte digest and success/error. Never persist or
print signed URLs, credentials or authorization headers. This comparison proves
only those bytes and their transport rates; it cannot substitute for the
ongoing whole-object SHA-256, custody, retirement or publication evidence.

If direct IPv4 is fast and SDK slow, investigate SDK transport/family handling
for a future reader generation. If both are fast, investigate the ordered
two-range window, transient/retry behavior and the live unit's CPU pressure at
the next authorized coordinated observation. If both are slow, increasing
concurrency alone is not yet justified. No live restart, quota change or
unbounded benchmarking is needed for this comparison.

## Source implementation and historical transport evidence

The new separate `probe-transport-holding213` source profile implements the
closed comparison above, with SDK, IPv4 and IPv6 attempted sequentially. Missing
families are recorded as unsuccessful comparisons. Its maximum accepted body
bytes are 96 MiB across the three comparisons; SDK internal retries and protocol
overhead are not represented as application body bytes. It exposes only
`--output` and `--self-sha256`; endpoint/account, bucket, key, original local
source, ETag, object length and window are compiled constants. The receipt has
its own schema and explicitly denies custody, whole-object verification,
retirement and publication authority. This is new source, not a deployment or
permission to invoke the old sealed helper with a new command.

Read-only preserved receipts:

- `/var/lib/jetstreamer/horizon-203-transport-probe-ee307f24-v1/probe.json`,
  SHA256 `de47e570124cb266beed240ab59890c86fd7e04ec90abe771ff298c8afda6656`:
  SDK 32 MiB in 1,255 ms; IPv4 32 MiB in 2,839 ms; IPv6 body failure at 20,003 ms.
- `/var/lib/jetstreamer/horizon-217-transport-probe-20261021-v1/probe.json`,
  SHA256 `c9c197f414c20bf909f41ee8fa430ea727cf08b3272b4b9b365ab10dbf9421e5`:
  the older 1 MiB profile succeeded with IPv4 in 1,311 ms and IPv6 in 1,293 ms.

These historical results motivate the separate family comparison. They are
neither present-day rate measurements nor evidence of this holding object's
integrity, route or completion time.

Validation: four focused release tests passed (closed arguments, exact response
identity, bounded/exact bytes, family selection and denied authority). Strict
production Clippy passed with `-D warnings` on the final source. Rustfmt and
`git diff --check` passed. No production helper was deployed and no diagnostic
was executed against R2. Keep a hard deadline on any later diagnostic service:
the five-second DNS await cannot forcibly cancel a blocking OS resolver call
already started by Tokio.

## Actual private comparison, supplied by root

The bounded diagnostic has now succeeded. Do not rerun it. Root sealed the
exact production helper with SHA256
`e91c6b5c7072e1a8a80a17da4eba45a2d6990aabd9083065f03b34c88efa171d`
at `/var/lib/jetstreamer/horizon-holding213-transport-tools-e91c6b5c-v1`.
The actual private receipt is
`/var/lib/jetstreamer/horizon-holding213-transport-probe-cycle352-v1/probe.json`,
SHA256 `ee630e91fbfdb9d37896381450390fcfbc93f851888138fa278adf085b993beb`.
Every exact 32 MiB window matched the original local window digest
`13dc9431c5760ee02c3627dc2124aaae03eb582d4a65be6c12a24aee32fd3112`:

| Comparison | Elapsed | Approximate accepted-body throughput |
| --- | ---: | ---: |
| Fresh SDK client | 2,796 ms | 12.00 MB/s |
| Direct IPv4 | 2,329 ms | 14.41 MB/s |
| Direct IPv6 | 1,366 ms | 24.56 MB/s |

Root's preserved private journal through the existing 08:11 UTC cutoff contains
124 rows and zero application retry warnings:
`.codex/tmp-readiness/park213-readback-through-cycle352-private.jsonl`, SHA256
`3aaec19e117285b7cc3b1fa35f475368adf91c655fa74263c30112fe144c15ec`.
These actual results and proof bindings were supplied by root; this agent made
no additional live observation, service change or network request. The old park
unit and its invocation remain unchanged, with no later park poll implied.

Both address families and the SDK can read this exact window successfully.
These results do not justify changing address family. They do not measure
long-lived-client throughput, the two concurrent 64 MiB whole-object ranges,
the live unit's CPU quota, or whole-object integrity. Zero warning rows exclude
observed application retry warnings in that preserved interval; they do not
exclude SDK-internal retries, slow successful bodies or later retries.

## Next source hypothesis and minimum scheduled metadata

The original park creates one SDK client before upload and reuses it for HEAD,
multipart upload and whole-object readback. The diagnostic creates a fresh
client. The same frozen Cargo lock selects Smithy HTTP client 1.1.12; the SDK
client builder does not override connection-pool lifetime, HTTP version or body
read timeouts. Therefore connection reuse is a testable distinction, but source
alone cannot identify a bad connection or prove that reuse caused the slowdown.

The other concrete difference is ordered concurrency. Futures Util 0.3.32
`Buffered::poll_next` fills a `FuturesOrdered` queue only while its length is
below two. `FuturesOrdered::len` includes completed outputs awaiting an earlier
output. If one 64 MiB range finishes and its predecessor remains slow, the
completed range occupies the second slot: no third GET replaces it until an
ordered result is yielded. Both range futures are polled by the same parent
task; they are not independent spawned Tokio tasks. This is genuine bounded
head-of-line blocking, while preserving the correct digest order.

After a range is yielded, copying and SHA-256 run synchronously in that parent
task before its next await. During this time neither range body is consumed by
that task, even though the runtime has two worker threads. Readback performs
one SHA-256 pass and writes to a sink. The more expensive local proof performs
SHA-256 twice plus per-part MD5, but that phase is before or after readback,
not concurrent with this readback loop. SHA2 0.10.9 uses runtime detection for
the x86 SHA instruction backend when available; no build-time assumption about
the host CPU or numeric hash throughput follows from the source.

At root's already scheduled 08:42 UTC collection, the minimum useful private
metadata is the following. Restrict every process and socket row to the exact
park helper PID and invocation; avoid environment, command payloads, HTTP
headers, request bodies, TLS keys, signed URLs or arbitrary system-wide socket
dumps.

1. Bind unit, invocation ID, main PID, boot ID, process start time and cgroup
   path once. Record monotonic timestamps for all counters and reject PID or
   invocation changes. Include the existing bounded journal capture in this
   scheduled collection: latest readback marker, any warnings and terminal
   state. No extra readback poll is needed outside the scheduled collection.
2. Read `cpu.max`, `cpu.weight`, effective CPU affinity/cpuset once, and ancestor
   `cpu.max` values to account for a stricter inherited quota. Collect
   `cpu.stat` (usage/user/system microseconds, periods, throttled periods and
   throttled microseconds) plus cgroup `cpu.pressure`. Cumulative counters alone
   cannot locate current pressure after the initial local hashing/upload.
3. Prefer deltas from an existing identity-matched saved counter sample. If no
   suitable baseline exists, root can obtain two tiny counter snapshots one
   second apart inside this single scheduled collection, without another
   campaign/resource poll. Include each thread's user/system ticks, current
   state and wait channel at those same instants. Record clock tick frequency.
   Per-thread deltas distinguish a busy hashing/SDK thread from an idle parent,
   though neither counters nor wait channels identify a specific Rust function.
4. Enumerate only socket inode links owned by this PID, then collect matching
   TCP metadata: address family, local/peer address and port, TCP state, receive
   and send queue lengths, `bytes_received`, `bytes_acked`, retransmissions,
   RTT and, where exposed, receive window and `lastrecv`. Take the same bounded
   second counter point if needed for byte deltas. Associate each row by inode
   or socket cookie, not merely by a reused local port. This reveals whether
   one or two connections are active and whether receive queues accumulate;
   it does not reveal HTTP stream identity or HTTP/2 negotiated protocol.

Interpret conservatively: high CPU usage and increasing quota throttling,
especially with queued receive bytes, supports a CPU/consumption bottleneck.
Low CPU with low receive progress and empty queues supports waiting for the
connection/server rather than hash work. Uneven socket progress is consistent
with an ordered window held by a slow range. An HTTP/2 connection could carry
both ranges on one socket; socket count alone cannot prove missing concurrency.
A single aggregate snapshot cannot distinguish connection-pool reuse from
server pacing or prove ordered blockage. If these minimal counters do not
resolve it, the next source generation can record sanitized per-range
start/header/body-complete/ordered-hash timings under a separate closed bounded
diagnostic. No second network probe, live instrumentation or reader change is
authorized by this handoff.
