# Native export: proposed default/capped qualification

This is a proposal, not admission or execution authority. Reviewed code commit:
`27687ffb5f2671a1cc9ad3a6746b0dd6b4f3027e`, isolated branch
`codex/v1425-native-export-candidate-20261023`, source directory
`/home/sol/workspace/jetstreamer-v1425-native-export-20261023`.
Any later proposal-only commit must have identical worker/vendor/protocol/lock
trees to that code commit, and the admitted manifest must bind the actual clean
source commit and file hashes. No compiler, Cargo resolution, test, guard or
fixture command below has been executed for this candidate. No live141 request,
deployment, restart, archive GET or R2 change is included.

## Immutable inputs and offline preflight

Use the existing read-only OS cache:
`/var/lib/jetstreamer-v1425-portability-cache-20261023-v1/cargo-home`.
The old preparation proof is `proof/result.txt` under that cache preparation
root, SHA256
`7395d1cc8dd3898f08cc0327eeca3786c60e4f10caa4a23a56329f57d01a8a35`.
It resolved285packages/nodes under9c00333e. It is cache availability evidence,
not a fresh candidate resolution or space admission.

| Input | SHA256/pin |
|---|---|
| Rust toolchain |1.46.0; rustc1.46.0(04488afe32020-08-24), x86_64-unknown-linux-gnu |
| Cargo executable | `e0e3d4353717bdbb3dcf1aa741d268957b8ad9ae063b1a8943a69c1bd07c3b4c` |
| rustc executable | `77ba1bbdbac88f5618db1b9db3e1a8df80ea834c7a7e793c98182c6d718e50a4` |
| rustdoc executable | `e8d3498a25ca705532afa28fa46875eb38e00447af096611053691550a511040` |
| librustc_driver-1cd905f603d5b1d4.so | `bb4b9f765b63f922741e24cb1a923b9f041801c3a1622545e097e19cc34cbefa` |
| historical Cargo.lock | `039f82f6f484f133fec7c7acd561ed46feee81ec9bdae0f589a37c23c8d40998` |
| historical workspace Cargo.toml | `b3f1c870497d2006965cc7c88d4508ed0bf06b41e9d52a1a9618223978777c24` |
| worker Cargo.toml | `fa834ee395d47f880c5aaf7da354b881bca13f772e01e95e62051450cfb39114` |
| worker build.rs | `460be5202157332d9defd5accc4ed9fe0cca7480c7456a82a8cd60aa177bb02e` |
| native Solana revision | `893cc7647248a3536fb6e6d0b5e51c71446b862d` |
| native serde_snapshot.rs | `9a6ca01b166b247f6dc5a3d973b641c72ac1a4167d98ab5daaacca32559b8985` |
| unchanged future.rs/clock LAYOUT_SHA | `4baee9ce91616985b8872b6f77fc3358cce5ca44ef95a7d337d235598d7148db` |
| unchanged protocol schema | `fd7d627a45cbda300e9689396e6538da126f6e765af90400f77d6d516ef34ce1` |

Before admission, the qualified read-only cache checker must bind the candidate
commit/lock, frozen cache archives/index/git sources and unpacked source digests,
toolchain executables plus their runtime/standard-library closure, compiler/linker
identity, and complete default/capped resolution graphs. Expect the same285
package identities; record the worker's empty/default versus
`capped-shrink-candidate` feature difference explicitly. Do not equate graphs by
absolute worktree paths or treat an older source proof as the new result.
Read-only source/cache, PrivateNetwork, `--offline --locked` and no online fallback
are mandatory. No copying/unpacking an entire shared cache or writing under home.

## OS admission: preserve every existing allocation

Retain the immutable base budget
`/usr/local/lib/jetstreamer/horizon-v1425-portability-os-budget-20261023-v2/budget.json`,
SHA256`2e95927a3c49972630c9de458e32359a859b90de7b0fa9b195d6dbb1083ed620`.
Its old source/target permission is not an export-build authorization. A fresh
supplement must bind it and the new exact profiles while preserving:

| Reservation | Bytes |
|---|---:|
| Retained free-space floor |205,211,459,014|
| Modern growth reservation |4,294,967,296(4GiB)|
| New legacy build, staging, guard and receipts |8,589,934,592(8GiB)|
| Combined qualification/retained test root |10,737,418,240(10GiB)|
| Required initial available space |228,833,779,142|

Thus new reserved growth is23,622,320,128bytes(22GiB), with **zero reduction** of
the retained floor. Free-space readings already include existing allocations;
do not subtract retained fixture/cache/build bytes twice or claim a reclaim.
Preserve all prior legacy targets, immutable packages, failed/successful fixtures,
audit inputs and the other candidate lineages. The current cache census must
establish actual headroom; no old237GB/234GB observation is a fresh admission.
If current available space is below228,833,779,142, do not start this proposal.

Use a new root-owned canonical OS parent
`/var/lib/jetstreamer-v1425-export-build-20261023-v1`, device2304, with `target/`
and `tmp/` owned by UID/GID1001 and root-owned `sealed/` and private receipts.
All build outputs, both feature variants, temporary files, sealed compiler/test/
worker/guard packages and source/log receipts fit the **combined8GiB parent**.
The sealer supports canonical root-owned ancestry beneath /var/lib; this keeps
its new allocations in the counted parent. Do not write the old shared target,
clean dependencies or borrow another owner's target. A fresh target avoids
invalidating the qualified legacy cache/guard lineage; if it reaches8GiB, stop
and report instead of deleting artifacts or enlarging the reservation silently.

Use a separate root-owned qualification parent
`/var/lib/jetstreamer-v1425-export-qualification-20261023-v1`, also device2304.
It contains default/capped ordinary-test temp roots, dedicated initially empty
0700fresh-fixture roots and all retained attempt evidence. Its combined cap is
10GiB across both profiles, not10GiB per lane. Run everything serially.

Build guard minimum available:220,243,844,550bytes(floor+4GiBmodern+10GiBtests).
Fixture guard minimum:209,506,426,310bytes(floor+4GiBmodern), with the full8GiB
build/staging reservation already accounted for and its parent still capped.
Take fresh completion-event admission before each phase/attempt, retaining every
previous byte. Do not borrow the modern4GiB reservation merely because no modern
builder is currently running.

## Exact proposed compiler argv

Working directory is the isolated source above. Absolute tool directory:
`/home/sol/.rustup/toolchains/1.46.0-x86_64-unknown-linux-gnu/bin`.
Sealed build units set CARGO_HOME as above, CARGO_TARGET_DIR to the new parent's
`target`, and TMPDIR/TMP/TEMP to its `tmp`. Set absolute RUSTC/RUSTDOC paths,
RUSTUP_TOOLCHAIN=1.46.0, DOCS_RS=1, CARGO_PROFILE_RELEASE_DEBUG=0 and a closed PATH
beginning with that tool directory. Preserve workspace release opt-level3,
LTO=true and codegen-units1. No feature flags on the virtual workspace manifest.
The following commands are audit argv for the future reviewed Rust coordinator,
not a shell campaign script or permission to execute them now.

```sh
/home/sol/.rustup/toolchains/1.46.0-x86_64-unknown-linux-gnu/bin/cargo metadata --manifest-path historical-runtime/v1_4_25/worker/Cargo.toml --offline --locked --no-default-features --format-version 1
/home/sol/.rustup/toolchains/1.46.0-x86_64-unknown-linux-gnu/bin/cargo metadata --manifest-path historical-runtime/v1_4_25/worker/Cargo.toml --offline --locked --no-default-features --features capped-shrink-candidate --format-version 1

/home/sol/.rustup/toolchains/1.46.0-x86_64-unknown-linux-gnu/bin/cargo test --manifest-path historical-runtime/v1_4_25/protocol/Cargo.toml --release --offline --locked --no-default-features -j2 -p jetstreamer-historical-protocol --lib --no-run --message-format=json

/home/sol/.rustup/toolchains/1.46.0-x86_64-unknown-linux-gnu/bin/cargo test --manifest-path historical-runtime/v1_4_25/worker/Cargo.toml --release --offline --locked --no-default-features -j2 -p jetstreamer-historical-worker-v1-4-25 --bin jetstreamer-historical-worker-v1-4-25 --no-run --message-format=json
/home/sol/.rustup/toolchains/1.46.0-x86_64-unknown-linux-gnu/bin/cargo build --manifest-path historical-runtime/v1_4_25/worker/Cargo.toml --release --offline --locked --no-default-features -j2 -p jetstreamer-historical-worker-v1-4-25 --bin jetstreamer-historical-worker-v1-4-25 --message-format=json

/home/sol/.rustup/toolchains/1.46.0-x86_64-unknown-linux-gnu/bin/cargo test --manifest-path historical-runtime/v1_4_25/worker/Cargo.toml --release --offline --locked --no-default-features --features capped-shrink-candidate -j2 -p jetstreamer-historical-worker-v1-4-25 --bin jetstreamer-historical-worker-v1-4-25 --no-run --message-format=json
/home/sol/.rustup/toolchains/1.46.0-x86_64-unknown-linux-gnu/bin/cargo build --manifest-path historical-runtime/v1_4_25/worker/Cargo.toml --release --offline --locked --no-default-features --features capped-shrink-candidate -j2 -p jetstreamer-historical-worker-v1-4-25 --bin jetstreamer-historical-worker-v1-4-25 --message-format=json
```

Bind exact Cargo JSON package/target/profile/features and executable paths using
reviewed Rust selection, not a filename glob. Seal the default test executable
and production binary immediately before capped commands can replace conventional
target paths. Seal the capped pair and protocol test executable separately. The
production binaries are compile evidence only and must not be launched/deployed.
No diagnostic feature, poh-force-soft or synthetic production init selector is
enabled. Source/lock hashes must remain unchanged after every command.

## New closed guards and release barriers

The old45fa...guard and0170...barrier bind older roots/units/7d0678...fixture.
They cannot be retargeted by editing a unit. Implement/review/qualify new Rust
profiles and seal new packages; preserve all old packages and receipts.

Use closed selectors for protocol/build-default/build-capped, unit-default/
unit-capped and fresh-default/fresh-capped. Bind only the exact new roots and
fixed per-profile unit names. Compiler profiles admit the pinned Cargo executable
and exact argv above; test profiles admit only their newly sealed test digest and
the exact list/unit/fresh argv below. Do not accept arbitrary unit/path/command
options. The build cgroup includes rustc/linker children, with KillMode=control-group.

For every actual invocation, a<=120second pre-exec launcher keeps its PID,
startticks, unitIID and monotonic start through exec. Before root publishes one
atomic no-clobber release token, require: precreated private per-IID receipts,
sealed launch/watch/unit plans, a durable first no-trip sample, exact live watcher
IID/PID/startticks/command/hash, exact waiting target identity and a fresh floor.
The token binds all those identities, selected feature/profile, launch/test or
Cargo hashes and first-sample digest. Failed/older releases cannot authorize a
new attempt. Recheck the watcher at exec and authenticate the target transition.

The new build parent has mixed root/1001ownership by declared subdirectory and
must be counted completely. Permit only the previously reviewed internal jemalloc
sibling-file aliases after exact canonical/owner/hash proof; no generic symlink
following. Ordinary tests intentionally create symlinks, hardlinks and FIFOs.
Their separate profile must count owned inode blocks without following/opening
those entries, conservatively count hardlinks, reject devices/foreign owners/
filesystems and constrain all test writes to the disposable unit root. Do not use
the old all-aliases-forbidden fixture scan for that negative-test phase. Fresh
fixture leaf roots retain the strict no-alias/nonregular/external-hardlink census;
the global10GiB parent is still counted without following retained test aliases.
No profile grants cleanup, unlink, remote or R2 authority.

Before real compiler/test use, disposable qualification must deny wrong IID/PID/
start/feature/hash/argv, absent/unready/terminal/restarted watcher, preexisting or
symlink token, timeout, foreign ownership/device, outside-root aliases, root-byte
cap and floor breach. Prove exact stopped-unit custody/recovery and same-PID exec
with a harmless probe. Preserve all denial evidence. Do not weaken receipt,
cursor, output or command assertions to obtain a pass.

Use Type=exec, Restart=no, RemainAfterExit=yes for terminal identity retention,
Delegate=no, UMask0077, CPU200%, MemoryHigh12GiB/Max16GiB, swap0, Tasks512,
RuntimeMaxSec1800, LimitCORE0, PrivateNetwork, ProtectSystem=strict and
ProtectHome=read-only. Only declared target/tmp or current test roots are writable;
/tmp and /var/tmp remain read-only. Keep the watcher lifecycle/permissions needed
for exact /proc and private-root reads; prove any changed sandbox equivalently.
Compiler and fixture watchers remain safety guards, not another campaign poll loop.

## Staged test sequence and stop conditions

1. Finish read-only source/cache/space admission and qualify the new compiler
   guard/barrier. Execute the admitted compilation argv serially, stopping on the
   first failure. Seal every artifact/log/manifest without deleting failed output.
2. Qualify the exact new test guard profiles against the sealed test hashes and
   their full required test-name census. Run the protocol executable with
   `--test-threads=1`, preserving export request/response and legacy discriminant
   coverage. Listing commands are separate bounded invocations of the same hash.
3. Run each worker test executable, default then capped, with
   `--test-threads=1` and no `--ignored`. Bind per-profile TMPDIR inside the shared
   qualification parent and preserve retained export artifacts. Require all
   ordinary runtime/loader/framing tests plus14new exporter tests: ten lifecycle/
   API/native-byte tests and four filesystem/writer tests. The forced one-byte
   metadata overflow must yield Error, consume the seal, retain a<=1byte Bank file
   and publish no SnapshotExported response; native Bank/cache bytes must match
   unchanged helpers. No ignored mainnet/input-dependent test is implicitly run.
4. With fresh admission and empty0700leaf, run only this exact ignored test on
   the default executable, then preserve its tree and repeat on capped:

   ```text
   --ignored --exact runtime::checkpoint_portability_fixture::native_export_dispatch_fresh_process_raw_output_equivalence --nocapture --test-threads=1
   ```

   Set JETSTREAMER_V1425_PORTABILITY_FIXTURE_ROOT to that profile's admitted leaf,
   JETSTREAMER_HISTORICAL_POH_THREADS=2, SOLANA_RAYON_THREADS=2,
   RAYON_NUM_THREADS=2, RUST_MIN_STACK=134217728 and private TMPDIR/TMP/TEMP.
   The fixture's cfg(test) metadata ceiling is512MiB per file; selected storage
   remains<=512MiB. The child is invoked only by its parent test. Do not run all
   ignored tests or invoke the restore child independently.
5. Require complete fixture output and child marker, unchanged full tuple/cache/
   signature/raw-write/output assertions, exact parent/child executable binding,
   watcher natural completion, no stop frontier, trusted terminal identity/history
   and post-terminal physical/floor proof. Record an absent actual-exec-observed
   receipt honestly when a subsecond test falls between five-second samples.
   Seal the exact source-to-build-to-test evidence chain and all failures.

Wrong output/hash/cursor/cache/signature is a substantive mismatch: stop/report
and preserve bytes. A setup error gets a separate diagnosis/review before another
attempt. Do not relabel incomplete evidence as qualified or enlarge caps, alter
features, borrow space or restart another owner's worker to make progress.

Passing this sequence qualifies only the bounded synthetic export API and two
compiled feature profiles. Production stdio/Initialize still needs separately
reviewed trusted mainnet-compatible bounded input. No live export, worker route
promotion, epoch-specific suffix plan, recorder append, canonical checkpoint,
publication, R2 sidecar, local retirement or account-updates merge is authorized.
