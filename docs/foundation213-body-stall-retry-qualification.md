# Foundation 213 bounded body-stall retry qualification plan

This source-only follow-up reviews draft `03b2635bb23472b80a818108d471c7f2cfd01c39`
on the isolated `foundation213-driven-range-fetch` worktree. It does not qualify
a production executable or grant restore, holding retirement, archive retirement,
publication or remote mutation. The continuation integration owns the next Cargo
window; no Cargo, target, service, endpoint or live-resource operation was used
for this review. Direct rustfmt and `git diff --check` are source checks only.

## Actual incident and preserved evidence

The genuine 9484 restore failed after 6 min 56 s with a streaming response-body
minimum-throughput error. It did not report an integrity mismatch. Its partial
grew by nine complete 32 MiB ranges from 109655883776 to 109957873664 bytes.
The original 125316500795-byte local source and that partial must both remain.
The existing evidence directory
`.codex/tmp-readiness/foundation213-typed-hooks-range-interruption368-v1`
contains the real journal, failure, manager and partial metadata; no file there
was modified. The evidence review did not read or rehash either actual archive.

The separate source-only diagnosis directory
`.codex/tmp-readiness/foundation213-body-stall-diagnosis-03b2635b-source-only-v1`
retains the earlier focused result: 9 passed, 0 failed, 1 ignored. The source
deadline changed while that compiler was running, so that result does not
qualify the final draft or this follow-up. Preserve its original compile failure,
successful test log and timing caveat.

The pinned SDK's `DownloadReport` explicitly exempts `NoPolling` as user
backpressure. Its `Pending` state counts as server stall. The actual loopback
slow-writer fixture passed without range retries. Thus no deterministic
buffered-future scheduling defect has been established. A server/network
transient remains possible; this repair does not rewrite the scheduler or disable
SDK stalled-stream protection.

## Retry and integrity boundaries

Only a streaming-body error whose source chain contains the exact pinned SDK
message `minimum throughput was specified at 1 B/s, but throughput of 0 B/s was observed`
gets the private retry marker. Request errors, failed If-Match, changed ETag,
changed Content-Range or Content-Length, truncated or oversized bodies, checksum
or SHA mismatches and local write/floor failures retain their fatal behavior.
There is no public typed classifier for this private SDK error; a changed SDK
message fails closed and requires review.

The first attempt keeps the existing SDK/service bounds. Only the first
positively classified stall opens one 120-second retry window. At most three
attempts repeat exactly the same complete range and If-Match. The 250 ms delay
and every later attempt are inside the same nonrenewing deadline. The private
buffer from a failed attempt is dropped before repeating it; no incomplete
network range reaches the writer. Eight-range concurrency, the 512 MiB
application-buffer bound, ordered contiguous durable writes, prefix rehash,
final whole-file hash, inode/owner/mode/floor checks, no-clobber publication and
fresh admission before commit remain unchanged. Tokio deadlines remain
cooperative; they are not a new preemption mechanism for synchronous writes.
The enclosing four-hour service limit remains separate and unchanged.

The follow-up makes the budget state directly testable without a clock sleep.
The deterministic state test proves that a later stall before, exactly at or
after expiry returns the original deadline; fatal identity failures receive no
retry before or after a stall; and attempt zero, three and four grant no retry.
Actual SDK post-stall tests now cover changed ETag, changed Content-Range,
changed Content-Length, failed If-Match and an ordinary interrupted body. Each
must stop after the fatal second response with its original local prefix intact.
Existing recovery, exhaustion, slow-writer, arbitrary-offset, corruption and
durability tests remain. These additions have not yet been compiled or run.

## Serialized qualification and capture

After an explicit exclusive Cargo/target grant, freeze the exact clean source
commit and tree. Set these environment values for every Cargo invocation:

```text
CARGO_TARGET_DIR=/home/ubuntu/workspace/jetstreamer/target
CARGO_INCREMENTAL=0
```

Run these steps sequentially, preserving every failure and retry log:

```sh
cargo test --locked --offline --release -j2 -p jetstreamer-r2 --all-features --bin jetstreamer-r2 holding::resumable213
cargo test --locked --offline --release -j2 -p jetstreamer-r2 --all-features --bin jetstreamer-r2
cargo clippy --locked --offline --release -j2 -p jetstreamer-r2 --all-features --all-targets -- -D warnings
cargo build --locked --offline --release -j2 -p jetstreamer-r2 --all-features --bin jetstreamer-r2 --verbose
```

The intentionally ignored root-only disposable fixture remains ignored unless
the exact fixture is separately authorized. Do not run an operational binary or
the full ignored suite to substitute for source qualification. No observer
executable is requested by this build plan.

For the successful frozen production build, capture the literal verbose rustc
command and compiler/Cargo dep-info, exact direct extern artifacts, every actual
native-search input and native Cargo link directives, build configuration,
Cargo.lock, rustc/Cargo versions and every workspace source named by production
dep-info. Record stable identities and copy/hash actual direct/native inputs
while the exclusive target lease is held; recheck those identities and hashes
after build. Check each workspace source against its frozen Git blob and confirm
the worktree remains clean. Copy/rehash the production binary, inspect ELF
dynamic inputs, and write immutable candidate provenance and checksums before
releasing the target. Reused registry artifacts are not independently rebuilt or
source-audited; do not claim a complete hermetic or transitive/toolchain closure.

## Separate operational gates

Only root can accept a fully qualified captured candidate, seal a new deployment
with the reviewed Rust sealer, bind that exact executable, and obtain a fresh
restore admission. Old admissions do not automatically authorize a changed
binary or reuse an old deadline. A real retry must rehash the preserved partial,
request only its missing suffix and retain all original identity and whole-file
proofs. Qualification tests cannot substitute for those checks.

Restoring the holding copy does not authorize retirement. After a successful
restore and genuine complete receipt, run the separately admitted normal local
retirement transaction with its current source, R2, holding, owner and race
checks. This source grants no 750 GB holding retirement or alternative cleanup
exception. Do not delete the preserved original, partial or historical receipts
as part of retry preparation.
