# Durable observer rollover, source proposal

`jetstreamer-horizon-observer-rollover` runs one coordinated sample per invocation
through the pinned existing Rust sampler. One persistent systemd timer invokes it;
there is no application polling loop. This is source-ready only until its native
regressions, exact artifact and deployment are qualified. It does not refresh the
fleet, publish R2 status, admit lanes, start replay or upload anything.

The root-private append-only selector is the ordered `attempts/NN.../commit.json`
journal. Every entry binds its no-clobber intent, exact predecessor bytes, sampler,
plan and resulting sample. A single advisory kernel lease prevents overlapping
rollover owners. Runtime inputs and the executable must be root-owned, regular,
non-symlinked, single-link files with exact hashes. The plan and template are
immutable Rust-sealed members. The initial seed remains untouched.

Each activation verifies the whole bounded journal, derives only the predecessor,
unique output and not-before fields of a fixed identity-bound config, and samples
only after the actual successful predecessor's recorded timestamp plus at least
1,800 seconds. Failed attempts consume an interval too. The systemd timer's
completion-relative interval adds a conservative delay after any long attempt.
The child has a parent-death signal and the service must use control-group kill
semantics, so an orphan sampler cannot overlap lease recovery.

If a complete sample exists without a selector commit, recovery validates its
predecessor, cadence and exact before/after owner bindings, syncs it and commits
without resampling. A partial sample is preserved forever and the next due
attempt gets a new path. Configs, intents, results and commits are atomically
published with renameat2(RENAME_NOREPLACE), no-clobber with file and directory fsync. A changed ordinary owner
rejects rather than replacing its IID, hiding it or restarting a producer.
Unavailable private diagnostic rows retain the existing sampler semantics.

The fixed ordinary roster deliberately fails closed when a healthy epoch ends.
An accepted immutable successor plan/template must handle that transition. No
automatic lane discovery or user-requested cadence bypass is implemented here.
User-requested out-of-band observations remain authorized, but must be coordinated
with this lease and adopted through an explicit reviewed successor; do not run an
unlocked parallel sampler or silently select the newest file from a directory.

## Plan schema

All paths are absolute. Hashes below are placeholders that Main must replace with
actual qualified source/artifact/receipt hashes before sealing:

```json
{
  "schema": "jetstreamer-observer-rollover-plan-v1",
  "root": "/home/ubuntu/.jetstreamer-private/snapshot-caches/observer-rollover-v1",
  "sampler": {"path": "/var/lib/jetstreamer/PINNED/jetstreamer-horizon-observe", "sha256": "ACTUAL_SAMPLER_SHA256"},
  "template": {"path": "/var/lib/jetstreamer/horizon-observer-rollover-v1/template.json", "sha256": "ACTUAL_TEMPLATE_SHA256"},
  "seed": {"path": "/absolute/accepted-seed.json", "sha256": "ACTUAL_SEED_SHA256"},
  "minimum_interval_seconds": 1800
}
```

Template `previous_sample` must equal the seed path and its minimum interval must
match the plan. Preserve its exact ordinary/private roster and original IIDs.
It must be an existing sampler config v2, routine reason, with at least one
ordinary owner. This first generation excludes the epoch 203 RAM auxiliary and
native-input diagnostics. The root and its `attempts` child must already be
root-owned 0700; do not repurpose any historical directory. The new state root is
under `snapshot-caches` to fit the retained epoch 233 import's existing read-only
mask; Main must confirm current sandbox applicability before setup.

## Isolated build and native qualification

Do not run Cargo without Main's fresh admission. Proposed isolated build root:
`/home/ubuntu/.jetstreamer-private/snapshot-caches/observer-rollover-build-v1`,
with private CARGO_HOME, target and TMPDIR, a read-only exact source worktree,
read-only existing registry/git cache references and private lock, no networking,
Rust 1.98.0, two compiler jobs, no default features. Proposed finite envelope:
8 GiB memory hard / 6 GiB high, zero swap, two CPU cores, 12 GiB aggregate future
disk planning plus 1 GiB external metadata, 3,600-second maximum per stage. These
are conservative proposals, not measured peaks, quotas or present capacity.
Main must retain all current replay/import/delivery/build obligations and the
normal stop/drain margin before approving any stage.

First stage, in the exact frozen worktree with the separately admitted private
target, absolute Rust 1.98.0 cargo/rustc/rustdoc and `CARGO_INCREMENTAL=0`:

```text
cargo test --release --frozen --locked --offline -j2
  -p jetstreamer-horizon-observe --bin jetstreamer-horizon-observer-rollover
  --no-default-features -- --test-threads=1
```

Then separately bounded strict selected-bin Clippy (`--tests -- -D warnings`) and
release build with the same flags/source/target. Run selected existing observer
regressions too before production deployment. Freeze all tracked source bytes,
Cargo manifests/lock, native tools and actual reports. No successful test count
or artifact digest is prefilled. Seal the actual rollover binary plus plan and
template using the existing qualified Rust `jetstreamer-seal-deployment`, its
independently supplied self hash and exact no-clobber seal plan. Never hand-build
a production package or replace the pinned sampler.

Before using the real roster, an isolated synthetic sampler fixture must prove
an entire real timer pair of rollovers while Main is idle, too-early activation
without observation, concurrent lease rejection, deliberate crash after sample
publication before commit, partial sample recovery and changed-owner rejection.
Bind the actual unit's timeout, kill mode, parent-death child behavior, root
traversal/mounts, exact ptrace permission for the existing unprivileged worker
map/RSS reads and no-clobber receipts. Tests in the new source cover the core
journal/identity cases, but are not native capability evidence.

## One-cadence migration

1. Leave the already armed observer and healthy replay untouched while building.
2. At an agreed boundary, retain the final accepted one-shot sample as the exact
   immutable seed. Check its hash, original identities and next not-before.
3. Prove the old one-shot timer/service is terminal and cannot fire again. Any
   already staged future one-shot must be explicitly disarmed by Main before the
   new cadence is activated. Do not replace a timer in place or daemon-reload
   while another live actor forbids it. Archive original units/configs/receipts.
4. Create only the freshly admitted private root/attempts directories; seal the
   exact artifact, plan and template no-clobber; install distinct unit names.
5. Activate the new timer once with its initial delay derived from the accepted
   seed; demonstrate its first real receipt and automatic second invocation.
   Timer presence alone is not proof. Future resource observations must all use
   this owner/lease; no second model-managed cadence remains.
6. Keep independent safety guards and producers unchanged. Fleet/status updates
   and user-requested sample adoption require separately qualified integration.

The templates here are inert review inputs. They do not authorize native setup,
unit installation, build, launch, R2 mutation or a real resource poll.
