# Epoch 210 native cold preparation

The closed Rust [native lifecycle commands and operator protocol](epoch210-native-lifecycle.md)
cover admission, running capture, fleet/status registration and independent
terminal capture. Preparation artifacts alone remain insufficient for launch.

This is dormant preparation for the independent singleton described in
[epochs209–212](epochs209-212-singleton-qualification.md). It does not qualify a
Bank, launch replay, promote a runtime, or authorize publication. Keep epoch
207's root-MD5 blocker open. Existing healthy full209 work remains unchanged.

| Binding | Exact value |
| --- | --- |
| Retained package | `/var/lib/jetstreamer/horizon-focused-210-complete-span-store8-ca2e38b-v1` |
| Bootstrap slot | 90719638 |
| Bootstrap accounts hash | `3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ` |
| Snapshot bytes | 8579041139 |
| Snapshot SHA-256 | `3f67f416d254d7fb795bc902d5c47a6ae374fa36c173c00411d4b541fc610ccd` |
| Generation / CRC32C / MD5 | `1628731675837475` / `rBQmbQ==` / `pBPdxBtyTOt6A7LhXryC8Q==` |
| Genesis bytes / SHA-256 | 20144 / `133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945` |
| Metadata report SHA-256 | `5a3df330f13cb1bd67053ee8f3eecb1300136eeb94f0b0b7842bea7d777bfbf1` |
| Manifest fingerprint | `sha256:723578e0e7eef4daa09b68bb2a45263f61bcb19ce49daef094d3174ee1f65b6b` |
| Snapshot bindings SHA-256 | `877aeb63674523f1d4cc6937f993a57204bc39999e8e378ea84a6ac1ae5409a8` |
| Full output | 90720000 through 91151999 inclusive: 432000 slots |
| Canonical final root / accounts hash | 91151575 / `xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx` |
| Mandatory post-root output | 424 slots |

## Actual preparation evidence

The sealed singleton metadata preparer produced the exact epoch210 report in
`/var/lib/jetstreamer/horizon-singleton-210-nativeprep-v1/`. The sealed node's
actual `--singleton-preflight` CLI then passed offline with networking disabled.
The checked-in fixture is the captured stdout, not a synthesized success:
`jetstreamer-utils/tests/fixtures/native210/singleton-preflight.json`.
It reports `worker_started:false`, `snapshot_restored:false`, zero replay
entries, the exact final root and all 424 post-root slots. These facts establish
metadata and command capability only.
The actual stdout is separately sealed at
`/var/lib/jetstreamer/horizon-210-native-preflight-v1/singleton-preflight.json`,
SHA-256 `648b2678d5a71bbb6300c11c17dcacb86391138ac05ceff90a83f6d54bff503e`.

The optimized v1.6.16 test artifact was built with rustc 1.51.0, release,
locked/offline, two build jobs and incremental compilation disabled. Its SHA-256
is `2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6`.
The exact file-integrity regression executed one test and passed. The ignored
native selector was listed; it has **not** been executed:

```text
runtime::native210_input::native_epoch210_cold_input_matches_canonical_accounts_commitment
```

The test-only shared reader rejects changed, writable, symlinked or incorrectly
owned inputs and wrong epoch scratch namespaces. The native test requires the
exact single-link immutable snapshot and genesis, rehashes their bodies, restores
the bootstrap, freezes its canonical accounts commitment, and requires zero
bootstrap writes and unchanged cursor, transaction count, capitalization,
last blockhash and tick height. It emits an epoch210-specific marker. Existing
ordinary worker runtime semantics and the epoch209 harness are unchanged.

## Dormant deployment

Seal the test artifact at
`/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test`.
Build the guard with `epoch210-native-main-guard`; its closed tuple admits only
that exact executable digest, unit
`archive-210-v1616-native-input-actual-v1.service` and root
`/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1`.
It requires MainPID greater than one, a 300000000000-byte whole-root limit,
3500000 VMAs and no bounded experiment exceptions. All prior native tuples are
preserved; other epoch features remain explicit build choices.

The [persistent service template](epoch210-native-input-service.service) is
intended for `/etc/systemd/system/` under that exact unit name. Preparation does
not install, enable or start it. Do not substitute an ephemeral `systemd-run`
unit: terminal capture needs the original PID1 invocation properties and journal
after exit. Do not use `RemainAfterExit`, which changes the expected terminal
shape. Precreate its empty owner0700 run root and scratch for the admission
checks; do not start the unit before admission succeeds.

The unit requests 112 GiB high/128 GiB hard memory, no swap, eight CPUs, 512 tasks,
2700 seconds and no restart or network. These are candidate bounds, not a claim
that current capacity admits them.

The reviewed metadata-only helper is `jetstreamer-native210-prepare`:

```text
PREPARER SPEC --spec-sha256 SPEC_SHA --self-sha256 PREPARER_SHA
```

Its immutable root-owned spec uses schema
`jetstreamer-private-epoch210-native-preparation-spec-v1`, bound-file objects
`harness`, `guard`, `singleton_preflight` (each `path` and `sha256`), and a fresh
precreated root0700 `output_directory` named
`/var/lib/jetstreamer/horizon-native210-preparation-UNIQUE`.
The guard must be separately sealed under
`/var/lib/jetstreamer/horizon-210-native-main-guard-v1/`.
The helper validates actual CLI preflight, rehashes the small sealed inputs and
genesis, and stats the immutable snapshot. It deliberately does not rehash the
8.5 GB snapshot body; the actual native test must do so. It creates no-clobber,
fsynced `native-cold-plan.json` and `preparation.json`. Every native, launch,
replay, runtime-promotion and publication authority remains false.

## Required integration before native execution

1. Add an epoch210-specific admission, running capture, terminal capture,
   central fleet origin and status path. Bind these exact new artifacts and
   plan; never copy epoch209 proof or assume closed epoch228 commands authorize
   210. Until those profiles exist this preparation is not launchable.
2. Reuse one accepted coordinated sample, with current owner/free/cgroup race
   checks, to census every actual replay and auxiliary, including healthy
   full209, full227, 204/205/225 and any native228 or other new owner. Reserve
   their remaining whole-root growth and hard memory growth. Preserve the
   largest bound guard minimum-free baseline, current century floor and all
   remaining reservations. No capacity claim follows from this document.
3. Keep the installed persistent file inactive until admission succeeds. Bind original PID1
   invocation/MainPID and prove the guard's first actual sandboxed no-trip
   fire. Register the exact origin promptly through an authenticated lifecycle
   event that permits the epoch210 blocked-qualification transition. Publish
   `verification` status with the original start time through that lifecycle.
   Keep the single 1800-second observation cadence; no separate poll loop.
4. Preserve the original journal and PID1 properties. A typed terminal proof
   must check exact epoch210 marker, one successful native test, canonical
   bootstrap commitment, zero entries/writes and PID1 success. Capture that
   evidence before any unit collection; retire only the owned status through
   the authenticated inactive-status protocol.

The source integration points are `jetstreamer-r2/src/main.rs`, the exact
profiles under `src/fleet/native209*` and `native228*`,
`src/pipeline_status/native_input.rs`, and `src/inactive_status/`.
For current full209 accounting inspect `native228_full209::{split,memory}` and
`native228_peer209::{disk,memory}`. The composing `native228_admission` helpers
are private and its admission is closed to epoch228; reuse requires a reviewed
epoch210 profile or scoped factoring, not passing epoch210 through a 228 command.

## Full singleton and delivery gates

Native input success qualifies only this bootstrap/worker combination. Full 210
needs its own exact node/profile, fresh complete-fleet admission and protective
guard. Require root 91151575 and its canonical commitment, **all 424 post-root
slots**, and exactly 432000 output slots through 91151999. Require independent
full/current-plugin checks, authenticated upload, whole-object remote readback,
source revalidation and canonical sidecar commit. Adjacent boundaries remain
mandatory before ordinary local retirement. Do not replace these gates with
the prior complete-span receipt or native bootstrap evidence.
