# Closed native265 protective guard

Source candidate only. No build, native test, deployment, admission or guard
qualification has been performed by this source agent. Main owns those steps.
No shared guard/reader crates are modified; `root_budget.rs` is the reviewed
descriptor-anchored two-pass whole-root physical scanner copied unchanged from
`jetstreamer-utils/src/horizon_standalone_guard_root.rs`.

The only producer is `horizon-265-native-input-20261119-v1.service` under
`/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1`.
Its exact harness is
`/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input`,
SHA256 `0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9`.
The only permitted child is selected historical worker `c3b2c334`, at the exact
path already pinned in the harness. Unknown paths, image hashes, units, roots,
plan fields and process members fail closed.

Before the immutable first-guard token exists, the cgroup must contain exactly
the harness. After that token binds this guard plan and actual boot/IID/MainPID,
one direct child is permitted. Each observation binds both processes' mapped
image bytes and inode metadata, start ticks, parentage, cgroup, ubuntu identities,
zero effective capabilities, NoNewPrivileges and VMA counts. MainPID must be the
original PID1 child/start time; the worker must be its direct child. Root-private
no-clobber process pins forbid a later child generation, replacement inode or
changed image. Cgroup delegation/nested cgroups and extra processes are rejected.
The harness alone is allowed after its known child has actually disappeared;
that state alone is not successful completion. Membership stabilization is bounded
to three captures within a guard sample; no separate campaign polling occurs.

The guard retains the filesystem floor,128000000000-byte hard memory cap,
100000000000-byte high threshold, zero swap,512-task limit,3500000 VMA limit per
process and506191984640-byte whole-root physical cap. It checks both PID1 and
kernel resource settings and rejects OOM events. The root device/inode/owner/mode
is pinned before the first sample, preventing replacement with an empty directory.
Unreadable process/resource/root evidence triggers the protective stop path.
The guard has no start, restart, deletion, admission, export or remote API route.

## Main's plan and deployment contract

Keep the existing `jetstreamer-horizon-standalone-guard-plan-v1` and
`native_main` shape expected by the sealed harness's `gate.rs`; add required
`boot_id` and `main_start_ticks` captured from the actual waiting harness.
Set the receipt directory exactly to
`/var/lib/jetstreamer/horizon-native265-guard-receipts-<producer-IID>`.
All normal plan fields are required: unit/IID, filesystem`/`, minimum free bytes,
worker root, maximum worker VMAs, maximum root physical bytes and native main
PID/executable/SHA. `bounded_measurement` and `bounded_canary` must be absent/null.

```text
horizon265-native-guard PLAN --plan-sha256 SHA --self-sha256 SHA --validate-plan-only
horizon265-native-guard PLAN --plan-sha256 SHA --self-sha256 SHA
```

Use the normal immutable deployment sealer. Precreate the root-private0700
receipt directory; render and seal the exact service template with its only
writable path that directory. Qualify final sandbox read access, the root scanner,
native process transitions and actual protective stop. Bind the real timer first
fire and PID1 start/deactivation history to the harness token; never synthesize
a sample from a static plan validation. The service's60-second timeout covers
the scanner's30-second internal bound plus finite image checks and5-second
systemctl calls. Account for256MiB guard and all controller overhead in admission.

The first successful sample uses the exact existing standalone sample schema
and `workers:[[harness_pid,vmas]]` required by `gate.rs`. Subsequent samples add
the child to `workers`; all contain mapped process evidence and memory observation.
Samples and stop intent are fsynced and published without clobbering. A trip
rechecks boot/IID/MainPID/start before `systemctl stop --no-block`; it never
signals a replacement generation or treats the stop request as proven drainage.
Natural terminal transitions have separate diagnostic receipts and cannot be
used as a first no-trip sample. Terminal receipts bind retained unit state,
empty/absent cgroup and disappearance of original pinned processes; failed drain
observations are retained explicitly. The ordering-only retention target must
keep the original unit available—collected/missing units fail closed.

Main must combine complete guard history, actual clean PID1 completion, native
result and kernel drainage before any qualification or capacity release. Terminal
receipts explicitly deny those policy authorizations. No `guard_trips:0` or
runtime-success receipt is fabricated by this guard.

Source tests cover closed-profile mutation, foreign invocation/boot/restart,
pretoken child refusal, extra/nested/duplicate processes, tricky proc stat parsing,
mapped inode replacement, and physical scanner symlink/depth/accounting behavior.
Run locked/offline tests and strict Clippy in Main's serial bounded build envelope;
source parsing/format checks are the only validation performed by the source agent.
