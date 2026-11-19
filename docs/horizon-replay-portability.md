# Historical replay portability qualification

The v1.6.25 isolated probe exercises the pinned native snapshot serializer and
the worker's hardened loader against a small synthetic ledger. It compares an
uninterrupted replay, a separately restored bank, and replay in a fresh process.
The original synthetic replay objects and their storage are dropped before the
fresh process starts. The probe compares complete wire transaction outcomes,
account writes, write versions and the final checkpoint, including bank/accounts
hashes and cursors. An equal balance alone would be insufficient.

Run this explicitly with the exact historical toolchain, from
`historical-runtime/v1_6_25`:

```sh
cargo test --release -p jetstreamer-historical-worker-v1-6-25 \
  runtime::tests::isolated_native_checkpoint_archive_restore_probe \
  -- --ignored --exact --nocapture
```

The test is opt-in because it launches the pinned native packager (including its
system `tar` subprocess) and a second test process. Require one executed parent
test; zero tests selected is not qualification. All files are disposable private
test fixtures. This is a native serialization/restore feasibility result, not a
mainnet runtime, full epoch, partial `.jet`, or R2 qualification.

The worker protocol still rejects `ExportSnapshot`. Before using this path for
pressure relief, implement a candidate export operation bound to the immediately
preceding complete checkpoint, validate unchanged consensus hashes and cursor,
qualify the actual mainnet bootstrap and builtins, and demonstrate recovery of
the partial `.jet` writer. Then qualify authenticated holding transfer and
interrupted lifecycle recovery. Preserve healthy workers while doing so.

The native `bank_to_snapshot_archive` helper squashes, flushes, cleans, updates
accounts hashes and rehashes the bank. It also purges older archives in its output
directory. It must therefore run only in an isolated private staging directory;
it cannot be pointed directly at campaign archives or a holding namespace.
Successful synthetic serialization does not authorize those mutations on a live
producer, replace a checkpoint's evidence, or justify deleting its scratch.

The v1.7.15 worker also rejects `ExportSnapshot`. Its isolated probe is now
published in `worker/src/checkpoint_portability_tests.rs`, included only in the
worker's test module. Select
`runtime::tests::isolated_native_checkpoint_archive_restore_probe` explicitly
with `--ignored --exact --nocapture` on a qualified v1.7.15 test executable.
It freezes the real worker checkpoint before invoking serializer housekeeping,
then requires unchanged bank/accounts hashes, the complete checkpoint tuple,
and write cursor. It compares complete transaction outputs and account writes
after both same-process and fresh-process restoration, deleting the original
fixture state before the latter. This deliberately cannot pass merely because
the serializer and loader agree on a checkpoint changed during export.

Native v1.7.15 execution passed at 2026-11-19 00:22:36 UTC. Build
evidence is retained at
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-portability-v1715-20261119-v1`.
The exact historical Rust 1.52.1 build is isolated from the running workers and
the epoch-205 reader audit. A target-selection error, an intentionally stopped
LTO-inconsistent attempt, a missing shared protocol source, and a compiler
cgroup OOM are retained separately. The source copy now includes and rehashes
both the v1.7.15 subtree and shared protocol schema against published `2e7224fd`.
The v5 attempt also exceeded its 2 GB compiler limit while rebuilding crypto
dependencies. Both failed profile overrides are preserved. The successful v6
build used the workspace's default release profile with no overrides, one Cargo
job, the same 2 GB hard limit and no swap. It reused the original crypto cache
and completed normally in 2m48s with 1.2 GiB peak memory. Its invocation is
`ccffcbcca2d8442593c63393d5fe79ae` in
`horizon-v1715-checkpoint-probe-build-20261119-v6.service`. Actual Cargo evidence
records a test artifact with empty features, optimization 3 and the genuine
`--test -C embed-bitcode=no` compiler invocation. The complete source manifest
was revalidated after the build.

The Rust-sealed test executable is
`/var/lib/jetstreamer/horizon-v1715-checkpoint-probe-2e7224fd-20261119-v1/probe-tests`,
SHA-256 `c7533b3869d406f86bf7286351a9d0712faf3f181881b8ab5cd3a52f114276b7`.
The native unit `horizon-v1715-checkpoint-native-20261119-v1.service`, invocation
`e6619c17368d4a24bdbed2324d2a0bcf`, executed exactly one selected ignored test:
one passed, zero failed, with normal completion in 0.62s. That parent test
requires a clean child-process exit and matching complete restored outcomes.
Its journal is retained as `native-v1.jsonl` in the evidence directory above,
SHA-256 `50479df35a3dca11c230cd5c754b0b5f7d9449f00e9da112c0096e99e394db87`.
The deployed production worker still rejects `ExportSnapshot`; this pass
establishes synthetic native feasibility only.

The next candidate source implements one-use, checkpoint-bound v1.7.15 export.
It binds the complete frozen checkpoint and entry/write cursors, consumes the
seal on every attempt and invalidates it on intervening protocol requests or
batch processing. Export errors terminate the IPC session because storage
housekeeping may already have begun. The packager uses the native v1.7.15 bank
serializer with an in-process sparse tar writer. It checks checkpoint equality
before and after housekeeping, hashes and fsyncs the staged archive, then uses
no-clobber publication into an existing canonical private directory. It does
not invoke system tar or remove older archives. An additive storage accessor
exposes the written prefix and logical mmap capacity for lossless sparse export.

The new ignored `checkpoint_export_archive_restore_probe` exercises the actual
worker export response, archive digest and permissions, duplicate rejection,
unchanged checkpoint, full same-process continuation and fresh-process restore.
Negative tests cover malformed/stale requests, changed checkpoint fields,
intervening Ping/Hello/batch requests, unsafe output directories and existing
symlinks.

Published candidate `335af895` built normally in 2m53s at a reported 1.2 GiB
peak under the same 2 GB cap. Both production worker and test artifacts use
empty package features and optimization 3; the production worker retains the
workspace's LTO/codegen settings. The Rust-sealed deployment is
`/var/lib/jetstreamer/horizon-v1715-checkpoint-export-335af895-20261119-v1`.
Worker SHA-256 is
`8275e240f40a8ce6cbba95bf16266df4e2cd2c8fb398c4ae3a20b02e707966c3`;
test SHA-256 is
`5b177530199ced75930bf5631761b21e65bc862b5b581a075ad2dec71b2081e7`.
The source manifest remained unchanged after compilation. Use the complete
build journal captured with `journalctl --all`: JSON output without that flag
omits long compiler commands. The initial incomplete journal is retained, but
the sealed package contains the complete journal and both genuine rustc commands.

Native unit `horizon-v1715-checkpoint-export-tests-20261119-v1.service`, invocation
`a0c42c32f20f4a0087a36dfa249e3b55`, passed 51 tests with zero failures and seven
explicitly ignored tests. The separate export/restore unit, invocation
`f9cf77e6aa7b4ed9a7ddb5fa7e360e2e`, ran exactly the selected ignored
`runtime::tests::checkpoint_export_archive_restore_probe`: one passed, zero
failed, normal completion in 0.62s. Journals are retained under
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-export-v1715-20261119-v1`.
This qualifies synthetic export/restore behavior, not live worker replacement,
mainnet initialization, archive continuation or pressure admission.

The next opt-in integration probe is
`worker/tests/checkpoint_export_mainnet.rs::epoch265_actual_worker_export_and_fresh_restore`.
It pins the actual sealed worker above and the independently retained epoch-265
bootstrap SHA/size. It uses framed IPC to initialize mainnet, checkpoint and
export; after clean source-worker shutdown and removal of its scratch, it
starts a second actual worker, restores the exported snapshot with the normal
mainnet builtins, and compares the complete checkpoint and cursor. It independently
hashes the export before and after restore and writes a no-clobber fsynced native
evidence tuple. It sends no replay entries and grants no canonical-root or
archive-continuation authority. A bounded synthetic pass does not authorize
its large mainnet restore: prepare a separate full-resource admission first.

That integration target compiled normally from published `d4fe2ada` in
`horizon-v1715-mainnet-export-probe-build-20261119-v1.service`, invocation
`a4d8ac5c50f84f8b922e7c7e2694f25b`: 2m21s, 1.2 GiB peak, empty package features.
The 103-file source manifest remained unchanged, and the rebuilt production
worker is byte-identical to the already sealed `8275e240` candidate. The probe
is sealed at
`/var/lib/jetstreamer/horizon-v1715-mainnet-export-probe-d4fe2ada-20261119-v1/mainnet-probe`,
SHA-256 `c6b077b43ac030e483795ea265f7be8364043fb482994a00516db111a89477ff`.
Its static listing contains exactly the intended test. This is compilation
evidence only: no mainnet round trip was executed.

An admitted invocation must pass `--ignored --exact --nocapture --test-threads=1`
and the exact test name, with these inputs:

- `JETSTREAMER_CHECKPOINT_EXPORT_WORKER`: the sealed `335af895` worker above.
- `JETSTREAMER_SNAPSHOT_114479281`: the existing root-owned epoch-265 snapshot
  recorded in `docs/horizon-252-cohort-readiness-20261118.md`.
- `JETSTREAMER_MAINNET_LEDGER`:
  `/var/lib/jetstreamer/horizon-foundation-holding-probe-input-v1`, whose 20,144-byte
  `genesis.tar.bz2` freshly matches
  `133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945`.
- `JETSTREAMER_CHECKPOINT_EXPORT_PROBE_ROOT`: a new empty, canonical,
  operator-owned 0700 attempt directory with separately admitted growth.

The host-visible genesis file in the live epoch-251 output directory is a
zero-length mount placeholder, not reusable input. Preserve that live namespace
and use the authenticated immutable genesis above. Do not infer file absence
from `sudo rg` on this host: sudo's default PATH lacks rg; use the resolved
absolute executable or the intended privileged filesystem reader.

The existing five-lane hard obligations plus host/control reserves total
1,202,496,454,656 bytes against 1,212,136,964,096 physical bytes. The live
epoch-205 reader audit reserves another 7 GB, leaving 2,640,509,440 bytes after
the small builds close. A proposed 128 GB mainnet restore does not fit that
non-oversubscribed envelope. Preserve all healthy producers and the audit;
qualify the required admission/policy transition or use a naturally released
lane before executing the large probe. No dormant unit or trigger is armed.

Archive continuation can reuse `merge_checkpoint_restart_segments` and its
explicit V4 provenance, source-handle digests, PoH links and write-version
normalization. The existing epoch-203/213 continuation runners are intentionally
input-bound; their authority must not be generalized by reusing their flags.
The recorder still finalizes a predeclared slot range and cannot safely label
an arbitrary in-flight prefix complete. A new pressure path must close a real
segment, bind its checkpoint/export evidence, qualify native restart and
complete assembly through the normal latest-reader and canonical-root gates.

Even a successful synthetic probe leaves protocol export, actual mainnet
checkpoint/restore, partial `.jet` continuation and idempotent pressure recovery
unqualified. Before oversubscribed admission, select a genuinely resumable
victim and bind the tested checkpoint, pressure trigger and recovery path.
Preserve the five healthy replay producers and their hard limits while building
that route. The retained inventory also has a one-epoch 265 cohort, in addition
to 252–256, 257–260 and 261–264; prepare disjoint alternatives rather than
depending on the five-epoch cohort alone. None has new admission authority.

The standalone `tools/checkpoint_v4_playback.rs` fixture is published in
`f15a1711` and merged through `d8369d49`. It compiles against the genuine
`ed61722d` reader build's explicit rlib bindings without changing the reader
closure or interrupting epoch 205's audit. Its bounded build completed in
2.796 seconds at 238.6 MiB peak. The Rust-sealed artifact is
`/var/lib/jetstreamer/horizon-checkpoint-v4-playback-f15a1711-20261119-v1/checkpoint_v4_playback`,
SHA-256 `724986c9909c63c2b5dedadb75afa4586fd3b5d1b87d14b2d1544ce91e842696`.

Native invocation `329690531efd426b91747eff5de75aae` completed normally in
2.528 seconds at 714.8 MiB peak under a 2 GB hard cap with swap disabled.
Two synthetic V2 pieces assemble into V4 over all 432,000 epoch slots. The
qualified plugin and strict full verifier both exit zero; normalized writes
are exactly 1000–1013, with one epoch notification and all source updates
retained. A wrong terminal passed to the full verifier exits one. The merger
rejects a wrong source digest, wrong prefix terminal, wrong suffix terminal
and unequal restart checkpoint. None of these tests establishes mainnet
restore, canonical epoch integrity, actual R2 readback or pressure recovery.

Results are retained at
`/home/ubuntu/.jetstreamer-private/checkpoint-v4-playback-20261119-v1/native/native-results.json`,
SHA-256 `706bfd168f5233a558b530e6a43fe4145fef06c924c23aaeb84fd1ac43029e8f`.
The build command, explicit dependency hashes and genuine build journal are
sealed with the executable. Native child output and reports remain beside the
result. The next recovery dependency is actual mainnet export/restore and
parent-driven checkpoint/segment closure; synthetic V4 playback supplies no
authority to oversubscribe the five running replay limits.

The parent recorder now exposes exact-checkpoint segment closure. It requires
a complete runtime checkpoint at the predeclared output end, rejects buffered
data beyond that boundary, and compares the recorded final slot/blockhash
before writing the index/footer. It cannot shorten an already-open full epoch.
The node's ordinary historical close path invokes it when the terminal
checkpoint reaches the declared end; existing independently proven skipped
tails retain their normal close path. Actual checkpoint/export/restore
consensus equality and pressure admission remain separate caller obligations.

Recorder creation also refuses existing files and symlinks, validates the
range arithmetic, and rejects a second active recorder before touching its
output. Successful finalization fsyncs both the archive file and its parent
directory. The slot-presence implementation was moved unchanged into a shared
module so the bounded harness compiles the production recorder and presence
map directly, without substitute scheduling logic.

The final native harness at
`/var/lib/jetstreamer/horizon-checkpoint-recorder-tests-20261119-v3/checkpoint_recorder_tests`
has SHA-256 `6a81811322d923069bc28cab59cd0736bcb79d60d8e434eeb0d12be3a9ad2914`.
It compiles with warnings denied against the retained reader/node dependency
artifacts. Invocation `4208c92f25454870b30c57a09c9a6912` passed all 12 tests,
including the new checkpoint and no-clobber cases plus existing full recorder,
parent-chain and skipped-slot checks. The first test run is preserved: its
empty-block fixture incorrectly expected a post-transaction orphan. Replacing
that fixture with a real transaction exercises the intended freeze-write path;
the production recorder classification was not changed to satisfy the test.
Final native journal SHA-256 is
`f3ab5810bec920c887aa647b0f8856b74ebc206c823aa190a4b265474a85e526`, under
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-recorder-20261119-v1`.

The complete node subsequently built from the clean detached source at
`490eaa3c7a3f79a8d7af8cb5a4347f34969536c8`, with its tracked-file manifest
revalidated after compilation. Invocation `2886b299ba6441a6b8241e88053c1138`
finished in 10 minutes 22 seconds with a reported 1.8 GiB peak beneath the
2,000,000,000-byte cap. Rust 1.98 used offline locked dependencies, one build
job, default features, release LTO disabled, 16 codegen units and GCC 15's
BFD linker. This bounded configuration is distinct from the prior default-LTO
build's 14.3 GB peak; it does not establish a general build-memory bound.

The candidate is sealed at
`/var/lib/jetstreamer/horizon-checkpoint-node-490eaa3c-20261119-v1/jetstreamer-node`,
SHA-256 `170fc2934cc8a3a2f66713bb6245497486695a2dc667b74056827b8c0852fcfb`.
Its package retains the source manifest, actual Cargo artifact/features,
compiler commands, effective build settings and complete journals.
An initial bounded probe preserved the expected candidate-runtime opt-in
rejection. With that existing opt-in and the qualified worker binding restored,
invocation `6f877efaf54b4d95a3920a2278a98418` accepted the sealed epoch-265
singleton manifest and rejected the deliberately wrong snapshot filename
before initialization. It exited 1 as expected, using 113,496,064 bytes under
a 256,000,000-byte cap with private networking. Its journal SHA-256 is
`4447e368af98e2205088a4e6990fc500b35a27b639dea0fb2247a8a23f994508`.

These checks qualify the build and that bounded input-gate path. No live
worker, reader or guard was replaced. Predeclared segment replay/export/fresh
restore, canonical root equality and resource-pressure qualification remain
required before replay deployment; no additional lane was admitted.

The synthetic native fixture now retains a durable transcript for production
recorder qualification. The prefix tick is executed by the historical runtime;
the snapshot is exported through its actual handler. After the original banks
and storage are dropped, a fresh process restores that snapshot and repeats the
suffix transaction and tick. The transcript compares the entire restored
checkpoint, transaction outcomes, account writes and terminal checkpoint, and
retains the exported snapshot bytes. Select the ignored test
`runtime::tests::checkpoint_export_recorder_transcript_probe` with
`JETSTREAMER_CHECKPOINT_TRANSCRIPT_ROOT` set to a new empty canonical private
directory. Use umask 0077 for the historical tempfile implementation. The
initial sandbox's broader temporary-directory mode was correctly rejected;
the private-mode retry passed without relaxing the exporter.

Source `edd3057c` built under the 2 GB cap in 5m57s, with empty test features
and a reported 1.8 GiB peak. The sealed native test image is
`/var/lib/jetstreamer/horizon-checkpoint-transcript-edd3057c-20261119-v1/native-tests`,
SHA-256 `2dcf1e7e597d3d87bbe5a75342ecae4db1fc97494dbde39eea13da9d2e978a4a`.
Invocation `394431cf77c8438f84349bbd274f13b0` passed exactly one selected test
in 0.69s. Its journal SHA-256 is
`d32fd5f88bccb279c498cf0dddeff72571bed8f022b8c3759dc0389aef54a4a3`.

`tools/checkpoint_native_recorder.rs` consumes that real transcript through
the production recorder modules, closes two exact checkpoint segments, merges
them through the existing V4 implementation, and compares every encoded account
field, payload, transaction attribution, normalized write version, signature
and fee. The first segment carries the already-frozen synthetic bank at slot 0;
it is not a genesis replay beginning at slot 1. The initial merger rejection
of that incorrect genesis label is preserved, and the corrected label describes
the actual fixture state without changing reader validation.

The final harness is sealed at
`/var/lib/jetstreamer/horizon-native-recorder-a733e258-20261119-v2/checkpoint_native_recorder`,
SHA-256 `015e2715ecf2dcd6609994996ae094cdb9866d9fc5bdb8ee236bddfdafc66163`.
Invocation `30bbe67954ac430996ded2eafb57f677` completed normally with a
500,146,176-byte peak under its 2 GB cap. Both slots, all 12 account writes
and the transaction matched. The qualified strict full verifier recomputed
both blocks with zero PoH mismatches and matched the supplied synthetic
terminal. An altered restored bank hash was rejected by the merger. Result
SHA-256 is `c91da93bf08d7bd125ed63960a54059d914635a35be58e3264d2d4bf38a20da3`;
its native journal SHA-256 is
`d1fe5afa1e33464aa9ae2a2536c4d3a28a425ffc1169c4bfdb6141b1e4a4a87d`.
Evidence is retained under
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-transcript-20261119-v1`.

This joins native recovery outputs to the real archive writer and reader, but
the recorder consumes the retained transcript after the native run. It does
not exercise a live parent checkpoint/stop/resume controller, a full epoch,
mainnet state, canonical-mainnet terminal evidence, or full plugin playback
of an R2 object. Those gates remain open, and no live deployment changed.

The parent now has an explicit `--qualification-checkpoint-export=DIR` path
(source `7b2d4338`). It is limited to standalone focused v1.7.15 qualification
with exactly one explicit `--verify`, the exact canonical terminal checkpoint,
a fresh segment output and an empty private canonical export directory. Cohort,
carried-state, restart and registered runtime-handoff modes remain separate.
After closing the segment, it exports the terminal snapshot and issues a fresh
native freeze. Every checkpoint field, bootstrap field and emitted write cursor
must remain identical, and that second freeze must emit no additional writes.
Only after ordered worker shutdown and full segment-manifest readback does it
publish and reread the snapshot manifest. Shutdown acknowledgment does not prove
kernel reaping has completed or authorize scratch deletion.

The bound snapshot-manifest writer compares the measured size and digest with
the worker export before publishing the no-clobber manifest. A mismatch must
leave no success sidecar; the prior measuring writer remains available for its
existing callers. `tools/checkpoint_export_tests.rs` compiles the production
policy, evidence types and snapshot-manifest modules directly. The sealed test
image is
`/var/lib/jetstreamer/horizon-checkpoint-focused-tests-20261119-v1/checkpoint_export_tests`,
SHA-256 `52cf4ee385947bff07786c2e57096bee83d135b6ba0a153ae5d9e06b85cf6584`.
Invocations `2614a18c360a4b769ea3845a10a3b7c8` and
`801fa28e7ccc4aa0a4335713fd7d66ec` passed three policy tests and seven manifest
tests respectively. Coverage includes every frozen evidence field and cursor,
new writes, incompatible modes, private-directory and symlink rejection,
changed export bytes, readback, and no-clobber publication. The initial build
failed because the linker temporary directory was read-only; the retry gave
that build an isolated writable temporary directory and succeeded under the
same 2 GB cap, with a reported 277.9 MiB peak.

These are policy and evidence-publication tests. Mainnet export/restore and
the pressure-stop lifecycle remain pending. This source change does not authorize a sixth lane,
arbitrary early-prefix completion, or use of the private epoch-203/213 restart
routes for other epochs. Evidence is retained under
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-focused-export-20261119-v1`.

The full node subsequently built from clean published `7b2d4338` in
`horizon-checkpoint-focused-node-build-20261119-v1.service`, invocation
`35bd887f239d4c2cbd1f53e39f21ddab`. It completed normally in 4m36.922s with
a reported 1.3 GiB peak under the 2 GB cap, using the existing release/no-LTO,
16-codegen-unit, single-job Rust 1.98 configuration. Actual Cargo evidence binds
the default features and a newly built executable; the complete tracked source
manifest was revalidated afterward. The Rust-sealed candidate is
`/var/lib/jetstreamer/horizon-checkpoint-focused-node-7b2d4338-20261119-v1/jetstreamer-node`,
SHA-256 `bae18fcfe0b345c58d35a9ce1b21d821d6b054b7ea48ebdbfbec9acdc9d78407`.

Five isolated invocations of that exact node rejected empty and duplicate export
paths, export without focused qualification, mixing focused export with the
registered-handoff environment, and an absent export directory. Every case
exited 2 with its expected diagnostic before runtime initialization, under
256 MB caps and private networking; observed peaks were below 3.3 MB. Complete
journals and effective settings are retained with the build evidence. These
qualify the actual CLI rejection paths, not successful parent replay/export,
mainnet restoration or a pressure-stop transition. No live worker was replaced.

The next synthetic qualification drives a live native worker through the
production `HistoricalRuntimeClient`, export validator and recorder, rather
than consuming only a completed native transcript. Source `3096ee7d` adds a
test-only IPC fixture with its own synthetic backend and genesis identity;
`049d3c67` adds the parent harness, and `e7bafc92` binds the new live export
digest separately from the retained baseline snapshot. The fixture does not
add a mainnet handshake bypass to the production runtime.

The parent executes the prefix, freezes and closes its recorder, exports the
snapshot, then requires a fresh freeze to preserve every checkpoint field and
the write cursor without new writes. After ordered shutdown it verifies that
the source scratch has been reaped. A fresh native process restores the export;
its complete checkpoint and suffix outputs match the uninterrupted baseline.
The suffix recorder closes and the restored worker's scratch is also reaped.
V4 assembly preserves both slots, all 12 account writes and one transaction.
The strict full verifier passes PoH, and an altered restored checkpoint fails
assembly. These results exercise production IPC and recorder components, not
the full firehose-driven `run_geyser_replay`, mainnet, a full epoch, R2 plugin
playback, or a durable pressure-stop/restart controller. They authorize no
additional replay admission or local retirement.

Native unit `horizon-checkpoint-live-parent-native-20261119-v2.service`,
invocation `d80e486536fc4a93b2b832b39c953e1f`, completed normally in 1.400s
with a reported 477.9 MiB peak under a 2 GB cap. Its Rust-sealed parent is
`/var/lib/jetstreamer/horizon-checkpoint-live-parent-e7bafc92-20261119-v2/checkpoint_native_recorder`,
SHA-256 `36fcfa4c0b6a01eeaafab26a8d79f06cfddc6ba86fd4aa6a9e0b7eaa708857a8`.
The native test image is
`/var/lib/jetstreamer/horizon-checkpoint-live-ipc-worker-3096ee7d-20261119-v1/native-tests`,
SHA-256 `b83fc678eee23b08f7a113de75d635e6400c16c000199ef967288585db2825a4`.
The sealed package retains the synthetic baseline, launcher, source and
dependency evidence. Its seal-plan SHA-256 is
`ff74c97c36433bb9ed52de05ee93fee8cc04de4aedf30d567e373421753b8ff1`.

Results are retained in
`/home/ubuntu/.jetstreamer-private/checkpoint-live-ipc-20261119-v1/native-v2/`:

| Evidence | SHA-256 |
| --- | --- |
| `native-results.json` | `7daf8b3235617779f9713d267e6b7dc70bc0ba554f345e81c30fb56103e041e7` |
| `live-client-results.json` | `344265a05867ca506d9a182ed036d0021d38e8df451ea7b5b10e41ccc4ff798f` |
| Assembled archive | `63ef6b02f806267d53a962d1dd65fda349dbc46f906e92c2021445610c12d11a` |
| Live exported snapshot | `b7f2c9829a68936cc40d6c1616e55265ebd940992763466375be96f6f9731669` |
| Strict full verifier | `d18723f637fca14622c22cff8303a3815b5e22ce3cf3963298d1a2374050e751` |

Build, seal and invocation evidence is retained under
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-live-ipc-20261119-v1`.
The first modern build failed for missing direct-source dependency bindings;
the corrected build retained the qualified reader dependencies. Native v1,
invocation `52390a43848c4705b5161b9b1a8f3c3a`, passed live recovery and strict
verification but failed its final check by comparing the live export to the
older baseline snapshot digest. That failure and its outputs are preserved.
The corrected v2 reran the complete path and independently revalidated both
snapshot identities; no live fleet deployment or epoch-205 reader binding
changed.

Source `a7f15626` extends this fixture across independent parent processes.
Set `JETSTREAMER_NATIVE_PARENT_PHASE=controller` alongside the live worker
settings. The controller runs an export parent to clean exit, waits for it,
then starts a separate resume parent. The export parent uses the production
snapshot-manifest writer and readback, and fsyncs a private no-clobber receipt
binding its own image, launcher, native worker, baseline transcript, closed
prefix, complete frozen checkpoint and snapshot sidecar. The resume parent
requires the independently supplied receipt digest, revalidates those inputs,
and restores solely from durable files. This is a synthetic qualification
controller, not the fleet's production pressure controller.

The direct-source build completed in 7.499s with a reported 393.1 MiB peak
under a 2 GB cap. Its Rust-sealed harness is
`/var/lib/jetstreamer/horizon-checkpoint-parent-restart-a7f15626-20261119-v1/checkpoint_native_recorder`,
SHA-256 `89b0db9314f8888d4b658efec05ea4ed14a69b26d7ad7c7fc7b23e793a2d82b5`.
The seal plan is bound by
`68879cee3d901174a02e4606bb2891b86d8e1cb769c2c8249efc81a3a3f631af`.
Source publication and remote containment preceded the native invocation.

Unit `horizon-checkpoint-parent-restart-native-20261119-v1.service`, invocation
`88ef690b2bfc4e9ab926a588d2972ae6`, succeeded in 1.427s with a reported
477.9 MiB peak under the same cap. The fresh parent reproduced both slots,
all 12 writes and the transaction, assembled V4 and passed strict full PoH.
An incorrect receipt digest failed before worker restoration; a duplicate
resume failed without changing the successful result or checkpoint receipt.
The existing same-parent path also passed after the refactor, invocation
`b34a2605cfa4497bbe15ea3a03999bd5`, in 1.312s with a reported 482.1 MiB peak.

Private results are in
`/home/ubuntu/.jetstreamer-private/checkpoint-parent-restart-20261119-v1/native-v1/`:

| Evidence | SHA-256 |
| --- | --- |
| `parent-controller-results.json` | `95af34c474a46d912be403c068167b852b07722876032ef4ee5f33513eb57a93` |
| `parent-checkpoint.json` | `49e8470acffcb157d3884b154a31f20617e4584ff22e60f9697891bd53080fbd` |
| `native-results.json` | `e10bf37d08809935ebd8d5731d7bea28860fdd2dc121d152a43f9aa9137a1456` |
| `live-client-results.json` | `b158132f10b8541dccd467e971c248e7758e42de38c28a49801c3e4469363f7e` |

Build, source, seal and invocation evidence is in
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-parent-restart-20261119-v1`.
The comparison result in `same-parent-v1/native-results.json` has SHA-256
`972ada5e5667a385205999a8f97b5896093a1b4ccf2f070256acfac63b89be68`.
This proves clean parent exit and file-backed restart in the synthetic path;
it does not establish crash recovery at intermediate publication steps,
pressure-triggered stopping, the complete firehose parent, mainnet recovery,
holding upload/restore, full-epoch or R2 playback qualification. Those gates
remain required before controlled oversubscription or another lane admission.

The independent-parent fixture originally bound the prefix digest but deferred
its deep decode until final assembly. Source `c2b0f908` closes that recovery
gap with the production `checkpoint_bundle` module. Before restoring the suffix
worker, the reader fully validates the retained prefix and snapshot, then
requires the same source runtime, worker image, complete terminal tuple and
exact output boundary. It retains open-file identities for both archives and
both manifests across the combined validation. The caller still owns plan
authentication and custody through subsequent use.

The production focused-export completion path now uses this shared relationship
check before publishing the snapshot manifest. It reuses the segment manifest
returned by the existing complete source reread, avoiding a third archive scan
during normal completion. The independent-parent fixture now writes and reads
the production prefix manifest too; its v2 checkpoint receipt binds that
manifest's digest. This supplies a recovery validation component without
creating a general replay-admission or pressure-stop route.

Two direct-source tests reject changed runtime/worker identities, every
terminal field, unbound source digests and a segment extending beyond the
snapshot. The native export-parent/fresh-resume-parent test also passed with
the deep prefix validation preceding suffix-worker initialization. Its unit
`horizon-checkpoint-bundle-native-20261119-v1.service`, invocation
`49483fddbdec4357be3ccf7a9a61649d`, completed in 1.954s with a reported
486.4 MiB peak under a 2 GB cap. Both slots, 12 writes and one transaction
survived V4 assembly and strict full PoH verification; changed receipt,
duplicate resume and altered assembled checkpoint rejection still passed.

The Rust-sealed harness is
`/var/lib/jetstreamer/horizon-checkpoint-bundle-c2b0f908-20261119-v1/checkpoint_native_recorder`,
SHA-256 `72765a21eebf1e57fa9c7037e980b14fcbf22cc2169e3c763b143a4f393e3353`.
The test image SHA-256 is
`c29c5ad9ca1f3a5930476d27fd4283219e42e02de1ce77453d80cabea5cd3296`;
the seal-plan SHA-256 is
`e10267ba1efdcf26ff0a4b08253ff82f26f1fd3f3fad5f436ef914e2830be659`.
Build and invocation evidence is retained under
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-bundle-20261119-v1`.
Results in the corresponding private `native-v1/` directory are bound by:

| Evidence | SHA-256 |
| --- | --- |
| `parent-controller-results.json` | `e528ddf7c06200739b3078718576b57f74baa91ba31f1f8ccce6d885baca6fc1` |
| `parent-checkpoint.json` | `1ebd7e4cf19546b6d224aa8e4432dcf59e6f40186dbc227d7ee23a2c0935ba72` |
| `native-results.json` | `49fcb91231a2b86828982b5211613f5c5e6388ad7827bc7af1fa258489c22286` |

The full default-feature node then built from clean published `c2b0f908` in
`horizon-checkpoint-bundle-node-build-20261119-v1.service`, invocation
`91af16b7b5224237b15ddbde873f5cfb`. It completed in 4m16.657s with a reported
1.2 GiB peak under the 2 GB cap. Cargo reported a freshly built executable;
the complete tracked source manifest was revalidated afterward. Its immutable
Rust-sealed candidate is
`/var/lib/jetstreamer/horizon-checkpoint-bundle-node-c2b0f908-20261119-v1/jetstreamer-node`,
SHA-256 `08b32810ec40eae0de8da24fe8d78a7e57c1b574941db39c236fd511aa2f8739`.
The node seal-plan SHA-256 is
`682fd4c6bba65c1bad1679731e6520bbff5765e57d93df43dedf8027e703f0c1`.
This verifies the production integration builds; it does not claim a successful
full firehose/mainnet checkpoint run or authorize replacing a healthy worker.

The next recovery component records an atomic, no-clobber checkpoint-publication
intent after prefix validation and ordered shutdown, before publishing the
snapshot manifest. It binds canonical prefix/snapshot paths, the fully verified
segment and the worker's exact snapshot digest, size, runtime and terminal state.
The focused production completion path logs the durable intent path and digest.
The normal publisher still rejects duplicate publication.

Explicit `recover_checkpoint_publication` requires the independently retained
intent digest and owner-only custody. It holds the destination writer lock,
deeply rereads the prefix, creates a missing snapshot manifest from the exact
bound export, and fully validates the resulting bundle. A surviving manifest
must match exactly; it is never overwritten. Open-file identities are retained
and rechecked through recovery, including the intent and both source archives.
Recovery fsyncs the matching manifest and its directory even when an earlier
parent may have exited between rename and directory fsync. The caller must
authenticate the controller plan, exclude a live producer and preserve custody;
this component alone proves neither process reaping nor permission to resume.

The synthetic controller supports `JETSTREAMER_NATIVE_PUBLICATION_INTERRUPT`
values `intent` and `snapshot`. Its export parent exits abruptly at the selected
durable boundary without a final parent receipt. A distinct recovery parent
rejects an incorrect intent digest, recovers publication, repeats recovery
without rewriting evidence, and atomically publishes the parent receipt. The
ordinary independent resume parent then executes the suffix and normal V4/full
PoH checks. These targeted interruptions do not cover crashes during worker
export, before the intent exists, during suffix execution or every filesystem
operation, and do not qualify pressure admission or mainnet recovery.

Published source `dc98355f` passed three focused production-module tests and
all three native controller modes. The harness is Rust-sealed at
`/var/lib/jetstreamer/horizon-checkpoint-publication-dc98355f-20261119-v1/checkpoint_native_recorder`,
SHA-256 `a3c0cd6b4ba1ddede05c989295d709d5d2578b824eadf7fea9bbf71f228e51d9`.
Seal-plan SHA-256:
`7a5624726e636f905490cde3d5d9d001d88ffdc66bbb563983ef0f0a7ba41252`.
The direct-source build used 422.7 MiB and 24.204s under a 2 GB cap; source
hashes were revalidated afterward. All native runs retained the same cap.

| Mode | Actual invocation | Wall time | Reported memory peak |
| --- | --- | --- | --- |
| Exit after durable intent | `404f3843cda541229adbbde3acdec614` | 2.503s | 500.6 MiB |
| Exit after snapshot manifest | `81db31db1974442a902f6cefa5f12a36` | 2.476s | 499.3 MiB |
| Normal parent restart | `f67a76a693e14f24879ae7b9090cb3d7` | 1.920s | 500.2 MiB |

The two interrupted runs recovered publication and completed both slots,
12 writes and the transaction through V4 assembly and strict full PoH.
Wrong intent/receipt digests and duplicate suffix resume were rejected.
Repeated publication recovery preserved the existing intent and manifest bytes.
Results remain in the corresponding `native-intent-v1`, `native-snapshot-v1`
and `native-normal-v1` directories beneath
`/home/ubuntu/.jetstreamer-private/checkpoint-publication-20261119-v1`.
Their `parent-controller-results.json` SHA-256 values, in that order, are:

- `02f1ac9d076390f9b8d61bf7cc4fb18c7f53a61910cd224669d2a9529a8728a1`
- `78e3e7e6a79054e52a62b7fbda2a150302895659d4bf56405a182302b4a834d9`
- `ba1e6a752c0a24a1b6e3314b733c49f972cb23a7aa270b1c9c2205071599e028`

Build, source, native journals and seal evidence are retained under
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-publication-20261119-v1`.

The full default-feature production node also built successfully from clean
detached `dc98355f`, invocation `a2b42dc649964047bebed93cec986b8f`, in
4m14.715s with a reported 1.2 GiB peak under the 2 GB cap. The complete tracked
source manifest was revalidated. Its Rust-sealed candidate is
`/var/lib/jetstreamer/horizon-checkpoint-publication-node-dc98355f-20261119-v1/jetstreamer-node`,
SHA-256 `488bed397cc14d9a726cdb9c7fd289101fa93a89783fac93b7c67c6bbc562fcd`.
The seal-plan digest is
`fc87ae94c6d546853330e3e89f95f46b5f1639b6798c2e68b43c0d92c69c711a`.
The package retains the actual node compiler commands, Cargo artifact, terminal
unit evidence and source manifest; the complete build journal remains in the
private diagnostics directory. Compilation does not qualify the full production
controller, pressure-triggered checkpoint selection or mainnet replay.

### Closing an earlier production-recorder checkpoint

Published source `fce21056` adds `close_checkpoint_prefix_source` to the
production recorder. After producers have drained and freeze writes have
arrived, it accepts a complete checkpoint strictly inside the declared range.
It rejects future buffered metadata or account writes and requires the last
recorded block and blockhash to match the checkpoint. Closing writes and fsyncs
the index/footer without inventing skipped frames for the unexecuted suffix.
The original header, provenance and epoch metadata retain their longer range;
this closed source therefore remains explicitly incomplete and private.

The separate `reencode_closed_checkpoint_prefix` API reads every source bucket
and frame, requires exact contiguous coverage through the checkpoint with no
extra frames, checks cross-bucket anchors and strict blockhash links, and requires
a nonzero terminal blockhash on the final frame. It writes a fresh dense V2
prefix with narrowed range/epoch metadata, preserving runtime provenance,
write versions and semantic event order. Ordinary `reencode_archive_prefix`
still requires a complete source. Callers remain responsible for source
custody/digests, a no-clobber sink, independent output validation and native
snapshot equality; this transformation is not a torn-file recovery route.

All 138 archive tests passed (one preexisting ignored test), including exact
and mid-bucket cuts with several destination bucket sizes, missing/extra
frames, wrong terminal hashes, metadata/range errors and truncated input.
All 13 production-recorder tests passed, including preservation of freeze
writes, rejection of future buffered input and explicit incomplete coverage.
The first new recorder fixture incorrectly expected a post-transaction write
after a zero-transaction block; it was corrected to execute a transaction.
No production write-phase semantics were changed to accommodate that fixture.

With `JETSTREAMER_NATIVE_EARLY_PREFIX=1`, the real-worker fixture now opens a
three-slot recorder, closes it at the first frozen block, rereads and converts
the incomplete source, then uses the ordinary independently validated bundle
for export-parent exit/reap and fresh-parent restore/suffix execution. V4
assembly retained all 12 writes and the transaction across both executed slots;
strict full PoH passed, wrong receipt binding and duplicate resume were rejected.
The successful invocation was `18c5d159100c49c8b98ea14147d4351f`, 3.145 seconds
and 502.9 MiB reported peak under a 2 GB hard cap. An earlier attempt failed the
worker's private-directory gate because its unit lacked `UMask=0077`; its
artifacts and failure are retained, and the successful attempt uses a distinct
empty private output directory with that unit setting.

The Rust-sealed harness is
`/var/lib/jetstreamer/horizon-checkpoint-prefix-fce21056-20261119-v1/checkpoint_native_recorder`,
SHA-256 `9924491298b36f04517c1ca9d94366294d6098347a8547172ffdb65242774c90`.
Results are in
`/home/ubuntu/.jetstreamer-private/checkpoint-prefix-20261119-v1/native-early-v2`.
Its `parent-controller-results.json` SHA-256 is
`fff195b1c6f793238e2a1f7c6bce20b2184b4aa653171c5ea7527ae5062d4236`.
The retained incomplete source SHA-256 is
`9ae9bfe42900b9938c91bf1be11c4d63cd86564c44abec202c30ee6c2a2a4122`;
the dense prefix SHA-256 is
`df1806f660647d840ae3506dec9ee2bc7c62fc63340085e5ee432bb8550318ea`.
Build/test/native journals, exact compiler commands and source bindings are in
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-prefix-20261119-v1`.

Production firehose quiescence, pressure-selected checkpoint/reap/resume,
mainnet export/restore and holding remain separate outstanding gates. This
library change also requires qualification against the latest reader branch
before closing epoch 205's final audit. An isolated current-reader and full
node build is in progress from the published revision, preserving the active
audit's original dependency closure; no running replay has been changed.
