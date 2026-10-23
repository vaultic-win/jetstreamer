# Corrected/capped v1.4.25 checkpoint portability: source audit

This is a source audit and a bounded experiment plan, not a checkpoint, export,
resume, runtime-promotion, publication or retirement receipt. No running worker
was contacted, stopped, restarted or changed. No resource observation, build or
remote mutation was performed for this audit.

The exact current candidate is worker SHA-256
`fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759`,
compiled from the corrected v1.4.25 source with `capped-shrink-candidate` using
Rust1.46.0. The healthy141 root qualification and the prepared136 route remain
separate and retain their existing admission and runtime authority.

## Actual export and restore path

`historical-runtime/v1_4_25/worker/src/main.rs`, `Worker::handle_body`, explicitly
returns `UnsupportedOperation` for `RequestBody::ExportSnapshot`. It does not
dispatch to a native serializer. `FreezeCheckpoint` calls
`RuntimeState::freeze_checkpoint` in `worker/src/runtime.rs`; that requires a
complete Bank and zero uncommitted tick hash count, freezes/roots/squashes it,
drains freeze-time account writes, performs account-storage maintenance, and
returns the bank/accounts hashes, last blockhash, capitalization, transaction
count, tick height, writes and next raw write version. This is a logical tuple,
not a restorable artifact.

There is a real pinned native serializer. Under
`historical-runtime/v1_4_25/vendor/solana-runtime-1.4.25/src/`:

- `snapshot_utils.rs::add_snapshot` calls
  `serde_snapshot::bank_to_stream(SerdeStyle::NEWER, ...)` with selected snapshot
  storage Arcs. This is schema `1.2.0`, not the v1.0.7 worker's `1.0.0` layout.
- `serde_snapshot/future.rs::Context::serialize_bank_and_storage` serializes the
  typed native Bank and AccountsDB. Its Bank fields include blockhash queue,
  bank/parent hash, parent slot, transaction/signature counts, tick heights,
  capitalization, rent/fee/epoch state and builtin/message-processor data.
  `serialize_accounts_db_fields` includes the raw global `write_version`, slot,
  selected AppendVec identities/current lengths and bank-hash information.
- `serde_snapshot.rs` restores the raw write version into the new AccountsDB;
  this must still be compared explicitly with the exported cursor. The selected
  AppendVec bytes and rooted status-cache deltas are separate mandatory members.
- `serde_snapshot/tests.rs::test_bank_serialize_style` already constructs rooted
  and non-root forks, serializes/copies their storage, restores a Bank, checks
  balances including excluded fork/dead accounts, and asserts Bank equality.
  These source tests are evidence that the layout exists; this audit did not
  rerun them or establish fresh-process continuation equivalence.

The worker's `snapshot.rs::load_archive` already admits `1.2.0`, calls the pinned
`bank_from_stream(NEWER, ...)` with the corrected additional-builtin table,
rejects unreferenced AppendVecs, restores and validates rooted status-cache
deltas, and verifies filename accounts hash and `verify_snapshot_bank()`.
`RuntimeState::initialize` then sets `write_cursor` from the restored AccountsDB,
`last_entry_hash` from `Bank::last_blockhash`, and entry/tick counters to zero.
That initialization is suitable only for a fully completed slot boundary and
next-slot continuation, after an explicit equality check. It cannot express a
mid-entry or mid-slot checkpoint. Source lineage must remain separately bound:
the new initialized source names the exported snapshot instead of the original
bootstrap. Account-maintenance counters and leader-cache contents reset too;
their effect on subsequent consensus/output must be tested, not assumed harmless.

Do not call `snapshot_utils::archive_snapshot_package` against a campaign or
holding output directory. It renames its archive and invokes
`purge_old_snapshot_archives` on that archive's parent. It also launches host
`tar`; merely hashing the worker would not bind that producer implementation.
The v1.0.7 worker's `snapshot.rs::export_archive` is useful packaging precedent
for in-process compression, isolated staging, descriptor hashing and
`persist_noclobber`, but its Bank serialization and cleaning API are different.
It cannot be copied verbatim into v1.4.25.

## Output continuity is independently missing

`jetstreamer-horizon/src/archive/writer.rs::ArchiveWriter` keeps the open bucket,
index, file offset, dedupe/encoder context, diff state, last blockhash and staged
slot sections in RAM. It has no recovery/open-append constructor. Its public
constructors immediately write a new header. `jetstreamer-node/src/horizon.rs`
also retains slot assemblies, metadata, emitted-slot/hash anchors and pending
account updates; `HorizonRecorder::create` uses `File::create`. Reopening a
partial through this constructor truncates it. A Bank snapshot preserves none
of these writer states, and a copied partial does not recreate them.

Use a separately finalized V2 prefix and a new V2 suffix. Existing machinery is
`HistoricalSegmentManifest`,
`HistoricalReplay::from_restored_checkpoint`, and
`archive::merge_checkpoint_restart_segments` with explicit V4 provenance. The
merger binds source digests, decoded events, raw-write ranges and the PoH handoff;
it grants no canonical root or publication authority. Existing exact144/203/213
continuation tools demonstrate the shape, not authority for141/136. The141
original-entry profile additionally fixes bootstrap60911751/terminal61328765
and rejects partial source resume. A new private bounded profile must preserve
those checks and independently bind its next-slot source cursor; do not weaken
the running profile or reuse another epoch's `RestartProof`.

## Smallest safe implementation and next bounded experiment

First implement a test-only native1.2.0 serialization round trip. It requires no
new production protocol or runtime route, and can use
`RuntimeState::from_test_bank` plus the existing rooted-bank fixtures. Reserve a
separate historical build target with the parent before compilation. Proposed
build bounds are the already-used Rust1.46.0 offline/locked jobs2, CPU200%,
MemoryHigh12GiB/Max16GiB, no swap, Tasks512, private network and read-only source.
Use only disposable temporary state, with a distinct10GiB whole-fixture stop and
30-minute execution deadline; these are experiment limits, not a native141 peak.

1. Create an isolated deterministic Bank with the corrected builtin table,
   execute fixed successful and failing transactions through a complete slot,
   freeze/root/drain and record the full checkpoint tuple and raw emitted writes.
   Include at least one rooted status-cache signature so duplicate detection is
   exercised. Retain this uninterrupted branch.
2. In a new empty staging tree, call native `bank_to_stream(NEWER, ...)`, capture
   only its selected flushed AppendVecs and sorted rooted status-cache deltas,
   and write version `1.2.0`. Do not invoke the upstream archive packager or any
   retention helper. Record each member's exact path, length and digest and
   ensure the Bank tuple and raw write cursor did not change during export.
3. Re-exec the isolated test executable as a fresh process, with its own private
   scratch and the test-only synthetic-genesis route. Restore through the same
   typed `bank_from_stream`/status-cache logic as `load_archive`; compare the
   complete tuple, raw write cursor and cache roots/signatures before accepting
   any next-slot entry. Never add synthetic-genesis acceptance to production
   `RuntimeState::initialize`, which correctly requires mainnet.
4. Supply exactly the next complete slot's canonical entries to both branches.
   Compare every raw account write including write version/signature attribution,
   transaction result, entry hash, and the next checkpoint tuple. Add a replayed
   signature to test duplicate detection and a skipped-parent transition to test
   slot/PoH boundary handling. A matching accounts hash alone does not pass.

Only after this passes should a separately gated candidate add native export:
`RuntimeState` needs a one-use successful-checkpoint export seal, consumed on any
attempt and invalidated on other requests, following the v1.0.7 protocol pattern.
Require the same complete frozen rooted slot, exact32-byte expected accounts
hash and no unconsumed writes. Package the real `NEWER` serializer, selected
flushed AppendVecs and status cache in-process into an empty private staging
directory; fsync, publish no-clobber, hash through the persisted descriptor, and
recheck every consensus/output cursor. Do not change protocol discriminants.
Missing seal, stale slot/hash, interrupted export, occupied destination and
changing members must fail closed. Test default and capped builds separately.

The next stage is a private **two-output-segment** equivalence run: close and
independently read the prefix at the same completed-slot checkpoint, bind its
full digest/manifest and original source index/data generations, restore in a
fresh process, start a new output at the first next non-skipped slot and entry0,
and prove no source transaction is duplicated/skipped. Bind original and
replacement invocation IDs and worker/parent/source hashes. Compare the merged
decoded output with uninterrupted execution; byte equality alone is inappropriate
when headers carry independent creation times or different segment provenance.
Then require a real bounded native141/136 input sample and later trusted root,
full/plugin/boundary gates, authenticated holding round trip and interrupted
transition recovery. No stage authorizes stopping a healthy producer early.

Native serialization and output continuation remain **unqualified**. No capacity
gain from parking a live141/136 replay is demonstrated by this audit.

## Staged test-only implementation

`historical-runtime/v1_4_25/worker/src/checkpoint_portability_fixture.rs` now
implements the first experiment behind `#[cfg(test)]`. Both entrypoints are
ignored in normal suites. The fixture uses public `add_snapshot(V1_2_0)` to
invoke the exact native private serializer, selected flushed AppendVec copies,
the pinned status-cache serializer and in-process bzip2/tar. The child re-execs
the exact same hashed test executable and restores with the existing worker's
`snapshot::load_archive`. It compares the full root tuple/cache/signature, raw
writes and outcomes through slots2and4 (slot3skipped), both terminal checkpoints,
and an actual duplicate-signature rejection. Synthetic genesis remains test-only.
The source/manifest bind genesis, archive and each member digest. No protocol
export or recorder append path is added.

Execution requires an initially empty, mode0700, sol-owned canonical directory
under `/var/lib/jetstreamer-checkpoint-fixtures`. The fixture refuses `/home`
and symlinked roots, caps selected AppendVec bytes at512MiB, checks a10GiB
whole-fixture physical limit between bounded steps, and retains its exact
evidence tree on success or failure for review. These checks do not replace the
parent's OS-volume admission or external service deadline/memory/task limits.

Do not run these commands until the parent admits OS-only disk growth, proves
the Rust1.46 offline cache and grants exclusive ownership of the chosen build
target. Use the separately admitted `CARGO_TARGET_DIR`; never overwrite a
target owned by another agent. In a bounded read-only-source build service:

```sh
cargo +1.46.0 test --manifest-path historical-runtime/v1_4_25/worker/Cargo.toml \
  --release --offline --locked -j2 \
  -p jetstreamer-historical-worker-v1-4-25 \
  --features capped-shrink-candidate --no-run
```

Stage and hash the resulting test executable outside the shared target before
releasing that target. Then run that exact executable in the separately admitted
test service with no network, CPU200%, MemoryHigh12GiB/Max16GiB, no swap,
Tasks512, a30-minute execution deadline and only the exact OS fixture root
writable. Set `JETSTREAMER_HISTORICAL_POH_THREADS=2` and
`JETSTREAMER_V1425_PORTABILITY_FIXTURE_ROOT` to that root; invoke:

```sh
/absolute/staged/worker-test-executable --ignored --exact \
  runtime::checkpoint_portability_fixture::native_v12_fresh_process_raw_output_equivalence \
  --nocapture --test-threads=1
```

Do not invoke the child test independently or run all ignored worker tests.
Repeat with a separately built default profile only after the capped experiment
has been reviewed and its evidence retained. Native tempfile3.1.0 follows the
service umask: the fixture unit must set `UMask=0077`; retain the explicit0700
assertion for both the initial root and generated child directory.

### 2026-10-23 semantic result and guard limitation

Exact executableSHA256
`7d0678d3d1edf4f75240bc7d7a800fd1093d61ef3ae7a77fe1348ed74425c539`
passed the synthetic capped fresh-process test in invocation
`d71223de47484c3ab6f8faff5e95e764`, exit0. The archive was restored in a new
process and every unchanged raw-output/checkpoint/cache/signature assertion
passed. Evidence remains beneath
`/var/lib/jetstreamer-checkpoint-fixtures/native-v1425-capped-20261023-v1/native-v12-Nr269C`:
`child-success.bin`SHA256
`2a9791532aca1d5f857ea5776e7d38a3295fc0741dc13e2b18a1661250f684a8`,
`plan.bin`SHA256
`ce20682ec92be91ca440111f207df36fbd8dc3f3823a670bdeff54666a28c230`,
and snapshotSHA256
`9a572def77759a46458c3a6e72a4f2b65cc6bed3cdc46b7f2707151c56e89aec`.

This is semantic evidence only. The watcher initially failed because its
per-invocation private receipt directory had not been created. A later terminal
receipt and no-trip check do not establish continuous guard coverage. Do not
describe this invocation as guard-qualified. No live replay stopping/resume,
writer append recovery, production export, mainnet, publication or R2 lifecycle
has been qualified by this test.

The closed Rust barrier in `jetstreamer-utils/src/v1425_fixture_barrier.rs`
prevents a new attempt from executing until a root-owned release token binds
the exact fixtureIID/PID/startticks, immutable launch/executable hashes, first
durable no-trip watcher sample, exact live watcherIID/PID/startticks, and a fresh
floor sample. The launcher waits at most120seconds and execs the unchanged
fixture in place. Both processes retain the original unit/IID/PID/startticks.
Root publishes the token by a no-clobber rename after fsync; preexisting paths,
symlinks, mismatched identities, absent/terminal watchers and timeout fail closed.
The watcher accepts only the exact sealed launcher command or a release-bound
transition to the exact fixture command and executable hash. Production and
disposable builds have separate compile-time unit/path selectors; the disposable
probe cannot select the real fixture. Real execution still needs separately
reviewed sealed launch/unit plans and fresh OS admission.

Disposable barrier qualification is retained in
`/usr/local/lib/jetstreamer/horizon-v1425-barrier-disposable-qualification-20261023-v1`.
The19ordinary tests passed (one unrelated storage-capability test remained
ignored). Actual systemd attempts denied release without a first watcher sample,
with a wrong plan digest, and after the sampled watcher stopped. An unreleased
launcher timed out after120seconds without executing its probe. The positive
attempt `19cae858144e40fb8b8cf8266a8f790a` retainedPID1179114 and startticks113521943
through exec; watcher `4f764aac8ee1439ca288fb832cd6d9c8` recorded the authenticated
transition and natural completion, both exit0. Root tests also denied symlinks
and preexisting tokens; identity tests denied changedIID/PID/start/hash and
unready/terminal watcher shapes. These are disposable-barrier qualifications,
not a new run of the native fixture.

The proposed real immutable package is
`/usr/local/lib/jetstreamer/horizon-v1425-fixture-barrier-20261023-v1`;
its `review.json` and `fixture.service` require separate parent review before
installation or execution. Before that run, preserve the exact prior successful
tree through a separate closed custody operation, recreate the empty0700
fixture root, re-admit the OS floor with all retained allocations, and seal the
new actualIID/PID/startticks/monotonic watcher plan and exact watcher unit. Neither
the real barrier package nor its sealed review authorizes production resume.

### One authorized guarded fixture result

The real guarded attempt completed successfully in fixture invocation
`e1f9211414d1485b9f290f34c7c8e774`, with watcher
`f1d49ce2a6cd45c99eb3b7043708452d`. The unchanged native fixture executable
and every semantic assertion passed. The original launcherPID1182622 is the
native fixture's recorded creatorPID, and the restoring childPID is1183181.
The first durable no-trip sample and fresh root-owned atomic release preceded
execution. The watcher produced natural completion without a stop intent, and
trusted PID1 journal history binds its exact invocation to successful exit.
Its inactive manager fields were subsequently cleared; the collector uses the
preserved journal history, rather than treating empty current fields as identity
evidence.

No `authenticated-exec-observed.json` exists for this invocation: the test
completed between the watcher's five-second samples. Do not claim a separate
observed execution sample. The pre-release guard readiness, live watcher check,
release binding, native child proof and natural terminal receipt are retained.
The post-terminal bound guard check found4,771,840physical fixture bytes and
234,735,509,504available OS bytes, above the209,506,426,310minimum including
the conservative modern-growth reservation.

The closed Rust collector independently decoded the native fixed-width bincode
child marker, bound its plan/executable/archive hashes and original creatorPID,
required the exact first/release/natural/postcheck evidence and successful PID1
watcher history, and fsynced a private no-clobber result. Its result and all10
bound evidence members are sealed in
`/usr/local/lib/jetstreamer/horizon-v1425-guarded-fixture-result-e1f9211414d1485b9f290f34c7c8e774`.
`guarded-synthetic-result.json`SHA256 is
`7f3c2c49778d32f95cb44f0247e195f752ccb5180078f0f468418b1f1028f2b9`.

The prior unguarded semantic success remains intact in private custody under
`/var/lib/jetstreamer-v1425-native-fixture-semantic-retained-20261023-v1`;
its completionSHA256 is
`151624b7a10e1be8b2ea81cd610d936abdd66ab3c69f9a2418af6966eb2f9053`.
All failed trees remain retained too. This experiment establishes only the
bounded synthetic capped native checkpoint/continuation equivalence described
above. Production export, live replay stopping/resume, writer append recovery,
mainnet qualification, publication and R2 lifecycle remain unqualified.

## Existing141 deadline evidence

No new poll was taken. The coordinated observer at
`/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261023T182600Z.json`
has SHA-256
`dde879bd02d342a9879eb21b82766880257c2442a39fa692f56d1f1f7eb67ff8`.
Its last slot60926156 and rate1.0021996518807004slots/s leave402609slots to
root61328765. The matching `qualification141-estimate.json` under the
`20261023T182600Z-controller-rebind-capped141-repair185-repair183-upload144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1`
routine-cycle directory binds that observer and records elapsed13936388ms,
remaining546525910ms and129600000ms downstream allowance.
Its SHA-256 is
`b1734ae57f99d311005eb265168b206ce82da2b3c14593ec66f20cb63c3b884e`.

The5day runtime cap is432000000ms. At that sample, its remaining execution
window was418063612ms (4days20hours7minutes43.612seconds). Root replay at the
observed rate projects401725345ms (4days15hours35minutes25.345seconds), leaving
only16338267ms (4hours32minutes18.267seconds), before any extra terminal work.
The minimum sustained remaining rate is0.963032870slots/s: about3.91% below
the observed rate. The projection currently fits, but has a tight deadline
margin and is not a guaranteed bound. Do not silently extend that cap.

The dashboard's larger estimate also includes15234suffix slots at the same
assumed rate and36hours of explicit unmeasured planning allowances:24hours for
suffix source/restoration/qualification and12hours for delivery. That suffix is
outside the running root invocation. Its ETA cannot establish that the current
invocation can execute the suffix, nor imply a qualified native resume path.
