# Chronological Horizon R2 plugin audit

Run `audit run-public CONFIG.json` for the chronological public archive audit. It
freezes an authenticated bucket inventory, groups consecutive epoch numbers and
runs one current `account-updates` verification plugin per range. Each public HTTP
range read checks the numeric byte extent, total length, strong ETag and status.
The only persistent playback output is metadata. The authenticated sidecar check
records staging, metadata disagreement or failed sidecar inspection separately.

The `public-stream-v1` directory under the configured state holds `inventory.json`,
`progress.json`, `summary.json` and `results/epoch-N.json`. Each successful result
binds a native full-epoch report, pinned object and plugin artifact. Each attempt
retains its range command, log and exit record. A lost connection triggers bounded
same-object retries. A second failed playback leaves an unresolved epoch with both
attempts recorded, then later epochs continue. Branch or capacity interruptions
preserve completed receipts. Restarting the same persistent unit resumes the first
unfinished epoch. A separate state directory starts a new sweep.

The previous `run` and `resume-downloaded` modes retain their historical download
receipts and recovery protocol. The deployment history and scratch sizing below
describe those modes.

The independent service is the owner. An agent can inspect its JSONs or journal,
but need not stay alive for the work to continue. The filesystem lock prevents
overlapping owners of the same audit state. `KillMode=control-group` is required:
the direct child also receives a parent-death signal, while systemd must kill any
compiler grandchildren before restarting the controller. Each guarded subprocess
also owns a private process group; an in-process guard failure kills that whole
group before the controller enters its retry wait.

## Recovering a completed public report across a branch change

When a branch change interrupts a public range after an epoch has finalized, the
controller qualifies the current reader and compares its executable SHA-256 with
the reader that produced the report. An exact match lets the controller accept
that epoch under its existing audit lock after checking the sealed executables,
original invocation, complete native report, pinned inventory, current remote
object and current branch. The result records both the original playback proof
and the current build proof. A different executable starts that epoch again.

Older branch-change markers can bind a nonterminal report through the preceding
accepted epoch from the same pinned invocation. The current marker also binds
the report digest, epoch start time and clean exit for a terminal epoch.

## Current source status and inventory

The persistent service is deployed on this host. See
[`docs/horizon-r2-chronological-audit-deployment-20261118.md`](../../docs/horizon-r2-chronological-audit-deployment-20261118.md)
for its exact runtime, resource bounds and progress paths. Its v2 controller
started at 2026-11-18 22:10:35 UTC after repairing a Cargo temporary-file race
in the allocation guard. Reader qualification precedes the first download;
startup alone is not evidence that any archive passed. The initial authenticated
`ListObjectsV2` inventory at 2026-11-18 21:25:14 UTC contained:

- 225 canonical archives, epochs 0 through 960, with gaps.
- Total: 16,504,898,595,724 bytes.
- Smallest: epoch 0, 398,594,860 bytes.
- Largest: epoch 941, 385,290,386,716 bytes.

The initial inventory evidence is in the root-private directory
`/tmp/horizon-r2-chronological-audit-inventory-20261118-v1/inventory.json`.
Production captured its own inventory when its state was created, under
`/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1/inventory.json`.
Once captured, inventory membership/ETags are frozen; restart does not silently
add epochs or accept replaced remote objects. A later sweep uses another state
directory. Existing success and failure receipts both mean "attempted"; a later
repair sweep uses another state directory and preserves the first sweep, except
for the bounded append-only transfer recovery described below.

## Configuration and budgets

On `dev-samjohnson`, all audit state, downloads, builds and reader generations
now have home-filesystem backing. Persistent bind mounts retain the established
state and reader paths, so historical receipts and sealed reader destinations
remain valid. The backing directories are `state` and `readers` beneath
`/home/sol/.jetstreamer-private/horizon-root-runtime-data/r2-audit-storage-20261119-v1`.
Use the admitted DATA reserve, not the old root-filesystem floor. The archive
cap is an acceptance ceiling: each download reserves its exact object length
and bounded metadata; a reader rebuild reserves only remaining working growth.
The original ROOT configuration below is historical and must not be selected
for new work on this host.

`config.example.json` is an initial **root-filesystem** example, not permission to
start work: preserve 32 GiB free, cap an individual archive at 20 GiB, and limit
the private source checkout/build/artifact/logs to 16 GiB. The exact-epoch successor
requires `reserve_bytes + actual_object_bytes + bounded_operation_metadata`
before download. With the current 128 MiB log bound, operation metadata is
160 MiB: one bounded log and two 16 MiB JSON publication slots. Existing files
already reduce observed free space. `max_archive_bytes` is an acceptance ceiling,
not a reservation for every epoch. An equivalent sealed reader is reused without
reserving unused compiler capacity. Only a necessary reader rebuild requires
the full remaining source/build budget, against actual free bytes that already
exclude a resident archive. See [`EXACT_EPOCH_BUDGET_20261119.md`](EXACT_EPOCH_BUDGET_20261119.md)
for the pending qualification and deployment handoff; the live v3 retains its
old policy until that handoff.
During transfer and child execution, the free-space floor remains enforced; source,
build and logs are also measured against the working budget. Only one archive can
exist in scratch. Logs are bounded individually. Build jobs and playback threads
are fixed at two and four in the example; parent-approved systemd CPU/memory/task
limits remain mandatory.
Playback streams compressed buckets from that same `.jet` into memory; it does
not extract a ledger, AccountsDb or another disk working copy. The verification
plugin writes only its small structured report and process log.

A deployment on `/home/sol` must instead preserve the current campaign's admitted
growth reservation. The parent specified 7,493,617,796,914 bytes as the pending
whole-fleet baseline, which must not be replaced by the smaller root-filesystem
floor. No other filesystem is implicitly authorized. The deployed v3 keeps
scratch, source/build, evidence, and sealed reader generations on the same
filesystem. Reader generations are held separately under the root-owned
`/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1` and are charged
to the same working budget. The current deployment therefore requires state on
the root filesystem. The optional external-scratch successor described in
[`SPLIT_SCRATCH_20261119.md`](SPLIT_SCRATCH_20261119.md) keeps that state and all
reader generations in place while separating only the disposable archive copy.
That successor is source preparation, not an admitted or deployed allocation.

If the next archive exceeds the admitted archive cap or free space is insufficient,
the service writes `waiting_for_capacity` and stays alive, rechecking after 1800
seconds. It never skips that epoch to fit a later one. Therefore the root example
can process early small epochs, then waits for separately qualified capacity.
The optional scratch successor requires a private root-owned directory on a
different filesystem, pins its device/inode, and preserves both filesystem
reserves. It does not migrate the state or rewrite historical receipt paths.

To alter resource budgets, stop the service and finish qualified capacity
planning, prepare a newly sealed config with the same other fields, then run:

```text
SEALED_BINARY reconfigure NEW_CONFIG.json
```

This command acquires the same exclusive lock and saves old/new configuration
evidence before replacing the accepted config. Update the service to use that
sealed config and restart it. It does not itself authorize the new allocation.
The successor additionally permits changing `external_scratch` only when both
old and new scratch directories are empty and no ownership journal exists. It
locks both external directory identities during the transition. A journal from
another scratch configuration is never used to delete a file.

## Reader provenance and playback

For each epoch the controller fetches `account-updates` from the approved SSH origin
into a dedicated checkout. SSH explicitly reads `/home/sol/.ssh/config`, uses the
absolute Vaultic key and known-hosts paths, and selects a currently loaded agent
by `ssh-add -l`; it also reads keychain socket metadata without executing it. R2
credentials are passed only to the SDK. Git/build/plugin children receive a cleared
environment; only Git receives the SSH socket.

The controller hashes the actual tracked files of the root playback binary and
every local transitive Cargo dependency, `Cargo.lock`, workspace/package manifests,
toolchain and Cargo configuration, and the exact compiler/Cargo images and flags.
It rebuilds the release binary with `--locked --no-default-features` when this
fingerprint changes. It reuses only an artifact whose hash and complete stored
fingerprint match the freshly fetched source. Thus unrelated operator/documentation
commits need no rebuild. The first run builds its own reader; this candidate does
not blindly import an existing campaign binary without its full equivalence proof.

Every newly built reader is installed by the existing root Rust sealer, with its
independently supplied self hash and hash-bound plan. Each generation gets a new
immutable directory containing the executable and full source/build proof. The
controller verifies the root-owned sealed image and deployment receipt before
reuse. It does not overwrite a reader deployment. The service runs as root so its
guard can account for the sealer's private temporary directories and terminate
privileged child groups. It invokes the exact sealer through noninteractive sudo; do not set
`NoNewPrivileges=yes` on this service. The parent provisions the root-owned 0755
reader root and exposes only that exact root in `ReadWritePaths`.

The pipeline is statically linked, so the recorded `horizon_pipeline` artifact hash
also identifies its linked plugin. It must pass the exact linked decoder capacity
probe. Playback receives the full `EPOCH:EPOCH` interval and `--verify-only`, with
the canonical scratch directory and configured thread count. It never receives
ClickHouse or R2 credentials. Acceptance requires zero exit, verification-only
mode, the exact complete expected slot range, all VerificationPlugin counters,
the stream digest, and terminal epoch completion in order. The pipeline's durable
`--verification-report` JSON must additionally bind the exact invocation, source,
observed first/last slots, all counters and stream digest to the same playback.
Legitimate leader-skipped
slots count toward the full epoch; they are distinct from silently omitted corrupt
records. First/last slots come from actual plugin observations in that report.

The authenticated stream is bound to bucket/key, exact ETag/version, byte length,
and whole SHA-256. Canonical checksum sidecars and archive hash metadata must match
when present. The downloaded file is independently hashed and made read-only before
playback, then rehashed afterward. The remote identity and executable hash are
rechecked. Another branch fetch follows playback: relevant code changes cause a
fresh entire-epoch playback; unrelated commits are recorded with equivalence proof.

The range-transfer successor reads one conditional 64 MiB range at a time. It
requires HTTP 206, exact range boundaries, total length, ETag, version and hash
metadata, and clean end-of-body before appending that range to the single owned
scratch file. It rejects ignored ranges and changed or ambiguous response headers.
Only one range is buffered in memory; no second archive or extracted ledger is
created. The immutable transfer plan records the range size and count.

This successor retains the existing whole-attempt retry limit and starts an
interrupted attempt from byte zero. It does not retry ranges, resume a persisted
prefix, erase earlier failures or grant another attempt after exhausted retries.
After transfer it still checks the complete SHA-256, independently rereads the
file, rechecks archive and sidecar identity, and plays the entire epoch through
the current plugin. A range transfer is not a plugin verification result.
Deployment requires a separately qualified controller and an owner handoff;
editing this source does not change the running v8 service.

## State, failures, and restart

The explicit `resume-downloaded CONFIG.json` recovery command handles the
epoch77 retry whose complete authenticated download was copied during the
home-storage migration. It requires the stopped original controller, pinned
original inventory/retry/download evidence, both persistent DATA mounts, the
whole copied archive's digest and fresh authenticated remote identity. It
records the old ownership before rebinding the copied inode, qualifies the
current reader and repeats the entire plugin playback. It preserves retry1's
identity and writes its normal result before removing the copied archive, then
continues chronologically. It does not reset retry budgets or substitute the
earlier playback receipt. Use `Restart=no` for this single-use recovery entry;
an interrupted intent requires inspection. After its durable completion,
future restarts use `run`; the running controller needs no restart to continue.

- `inventory.json`: immutable ordered scope and pinned remote identities.
- `progress.json`: current phase, epoch, transfer bytes, timestamp, wait reason.
- `child.json`: current/last subprocess PID, log path, heartbeat, elapsed time,
  log size, and terminal exit or guard-stop reason.
- `summary.json`: attempted/passed/failed/pending counts after each epoch.
- `results/epoch-N.json`: immutable terminal outcome, object/hash, reader source
  fingerprint, actual invocation, verification evidence or error.
- `results/epoch-N.retry-I.intent.json` and `.retry-I.json`: at most two
  append-only transfer-recovery slots, each binding original and predecessor
  receipt hashes. The original result is never replaced. Summary counts use
  the validated latest result and expose `recovered_transfer_failures` and
  `transfer_retries_pending`.
- `attempts/epoch-N-TIMESTAMP/`: start record, fetch/build/playback logs, capacity
  probe, remote download evidence, invocation and completion reports, cleanup record.
- `scratch-owner.json`: exact owned download inode; it is not a success marker.

The terminal receipt is fsynced before the audit download is unlinked. Cleanup
requires the same regular-file inode, UID, device, and single link, under the
private audit scratch directory. A substituted inode, symlink, unknown scratch
file, or malformed state fails closed. The tiny crash window between creation of
the empty scratch file and its owner journal deliberately requires inspection if
hit; an unknown file is never guessed to be disposable.

On ordinary interruption the script records recovery, deletes only the journaled
partial/download, and retries the unfinished epoch from byte zero and slot zero.
It never treats an interrupted tail as full playback. If a receipt was already
committed, it completes cleanup and proceeds. Reader/build/credential preparation
problems wait persistently rather than declaring an archive corrupt. Download or
playback failures produce an explicit failed result. A response-body transport
error or body-read timeout may receive two additional attempts with 30/120-second
backoff after the predecessor finishes. Each restarts download and playback from
the beginning, rechecks the same remote identity, and uses the same controller.
Checksum, clean truncation, identity, capacity, authentication and plugin failures
are not retried by this policy. An interrupted recovery ticket consumes its slot
and requires evidence review, preventing crash/restart from resetting the budget.
See [`TRANSFER_RETRY_20261119.md`](TRANSFER_RETRY_20261119.md) for the exact
legacy epoch73 receipt exception and pending qualification. The result says what
failed, not that the archive is necessarily corrupt. No remote
object is deleted, overwritten, or repaired by this tool.

## Build, deploy, inspect

Use the configured repository identity for source publication; no coauthor trailers.
Build/test in an isolated, capacity-approved target, with the explicit Rust 1.98.0
compiler (do not let a detached shell select/update the global stable toolchain):

```text
RUSTC=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc /home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo test --locked --manifest-path scripts/horizon_r2_chronological_plugin_audit_20261118_v1/Cargo.toml --target-dir APPROVED_TARGET -j 2
RUSTC=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc /home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo build --release --locked --manifest-path scripts/horizon_r2_chronological_plugin_audit_20261118_v1/Cargo.toml --target-dir APPROVED_TARGET -j 2
```

The parent uses the repository Rust sealer for the final controller/config and
selects the exact service properties from the example. Precreate the state directory
owned by the service identity (`sol`) with mode 0700. Use a root-owned 0600 systemd environment file for
`HORIZON_S3_ENDPOINT`, `HORIZON_ACCESS_KEY_ID`, and `HORIZON_SECRET_ACCESS_KEY`; never
put secret values in argv or logs. Keep the source checkout separate from the live
repository. `PrivateTmp=no` is needed for existing SSH agent sockets. Run the final
metadata-only command with the final service credentials and mounts first:

```text
SEALED_BINARY inventory SEALED_CONFIG.json
sudo systemctl start horizon-r2-chronological-audit.service
SEALED_BINARY status SEALED_CONFIG.json
sudo journalctl -u horizon-r2-chronological-audit.service --no-pager -n 30
```

`inventory` only lists canonical metadata and creates audit state; it does not fetch
source, build a plugin, or download an archive. `status` is local/read-only and does
not acquire the writer lock. Routine campaign observations remain on their existing
30-minute cadence; this tool's transfer/resource checks are internal audit guards.
