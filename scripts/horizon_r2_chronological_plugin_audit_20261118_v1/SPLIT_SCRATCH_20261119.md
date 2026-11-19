# Separate archive scratch preparation

The successor has passed source tests, a real two-filesystem test and all-target
Clippy. Production capacity admission and deployment remain pending. The current
v3 service, accepted configuration and resource booking have not changed.
Only the disposable archive would move; state and historical evidence stay put.

## Capacity decision

The frozen inventory's first archive above the current 16 GiB cap is epoch 74,
17,431,722,097 bytes. Epoch 75 is 20,323,361,261 bytes and epoch 84 is
40,316,425,692 bytes. Raising the cap alone only postpones the same root-space
failure. The largest object is epoch 941, 385,290,386,716 bytes. A **360 GiB**
archive allocation is 386,547,056,640 bytes, exceeding that object by
1,256,669,924 bytes. Only one archive is resident at a time.

The prior layout inspection found only two persistent filesystems: root at
470,774,005,760 bytes and DATA at 15,240,760,295,424 bytes. At that inspection,
root had 50,596,712,448 bytes available. Even ignoring the remaining build
reservation, preserving the existing 32 GiB root floor while receiving the
largest object would require 419,650,125,084 bytes free, a deficit of
369,053,412,636 bytes at that historical observation. No such root cleanup set
has been qualified. The unused-looking tmpfs allocations are memory, already
promised to the campaign and audit, so they are not additional working capacity.

The proposed DATA location is a new private child:

`/var/lib/jetstreamer/horizon_runtime_data/r2-chronological-audit-scratch-20261119-v1`

Its existing parent is root-owned mode 0700 on device 64512, inode 99958431.
It has a root-owned ancestry through `/var/lib`, avoiding the mutable
`/home/sol` ancestry. The child has **not** been created or assigned an inode.
The existing state, source, build, attempt/result receipts and immutable readers
stay on root at their current paths. There is no move or rewrite of old evidence.

The accepted 00:49:25 fleet has complete DATA commitments of
6,794,761,027,378 bytes and conservative available DATA of 7,469,406,863,360
bytes. Adding 360 GiB to that commitment alone leaves 288,098,779,342 bytes.
**This arithmetic is not admission:** the parent's next epoch170 preparation
must include its incremental peak and all enforced live floors/remaining growth.
The DATA audit allocation could block that backfill and must not silently take
its capacity. Parent must first qualify a complete simultaneous fit or retire/
park enough closed inputs. Existing audit memory 24 GiB, CPU quota 400%, four
playback threads and two build jobs remain unchanged. Root working budget remains
16 GiB and its free-space reserve remains 32 GiB.

## Source behavior

`Config.external_scratch` is optional and absent from existing serialized configs.
It binds an exact absolute directory, device, inode and separately admitted free
space reserve. The reserve is the current complete replay obligation/floor for
DATA, not the root 32 GiB floor and not an estimate copied from this document.
The existing max-archive field remains the single-copy allocation cap.

- External scratch must be a root-owned private directory with root-owned,
  non-writable, non-symlink ancestry on a different filesystem from state.
- A directory flock excludes another audit using the same scratch through a
  different state directory or pathname. The existing state flock is retained.
- Before download, root must cover its floor plus remaining working budget;
  DATA must independently cover its own reserve plus the actual archive size.
  Source/build/log allocation remains charged only to root.
- Every guarded subprocess checks both floors before spawn and during execution.
  The download checks both floors before each write. Directory identity is
  revalidated in those checks, so an absent/replaced mount fails closed.
- The scratch journal additionally binds the exact external directory/allocation.
  Old journals are accepted only with the old root-scratch configuration.
  Cleanup retains the exact owned-inode, canonical-key and unknown-file gates.
- Reconfiguration can change scratch only with no journal and both directories
  empty, under the state and directory locks. It records old/new config evidence
  before replacing the accepted config. It never moves or deletes an archive.

No R2 method, inventory scope, reader equivalence, full playback acceptance or
old result receipt changes are introduced.

## Source qualification and remaining deployment gates

Eight new ordinary tests cover
split reservation arithmetic, default-config compatibility, invalid reservations,
journal/config mismatch, in-flight relocation rejection, cross-state directory
locking, old-journal decoding and rejection before child spawn. Existing tests
were adapted to the common dual-filesystem guard. The ignored root test
`local::tests::external_scratch_full_roundtrip_on_two_admitted_filesystems`
exercises actual cross-filesystem identity/locking, empty-directory transition,
owned partial recovery, wrong-inode refusal and preservation of unknown files.

The parent admitted and used this qualification build envelope:

- Existing isolated target: `/tmp/horizon-r2-chronological-audit-build-20261118-v1`.
- One build at a time, `-j 1`, CPU quota 100%, MemoryMax 3 GiB,
  MemorySwapMax 0, TasksMax 256, timeout 1800 seconds per command.
- At most 2 GiB additional target/log allocation; parent must establish a current
  root fit with the active audit's remaining reservation before starting.
- Preserve existing cached build/evidence files; no cache deletion is proposed.

The command inside the parent's admitted native build unit is:

```text
env RUSTC=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc /home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo test --locked --manifest-path /home/sol/workspace/jetstreamer/scripts/horizon_r2_chronological_plugin_audit_20261118_v1/Cargo.toml --target-dir /tmp/horizon-r2-chronological-audit-build-20261118-v1 -j 1
```

Actual qualification units:

- `horizon-audit-split-tests-20261119-v1.service`: 29 passed, zero failed,
  one explicitly ignored native test.
- `horizon-audit-split-tests-20261119-v2.service`: rebuilt the test image after
  fixing only the native fixture's explicit directory modes.
- `horizon-audit-split-native-test-20261119-v2.service`: the ignored native
  test passed on genuine root (device 2304) and DATA (device 64512) filesystems.
  Its root-owned private fixture parents are
  `/var/lib/jetstreamer/audit-split-storage-tests-20261119-v1` and
  `/var/lib/jetstreamer/horizon_runtime_data/audit-split-storage-tests-20261119-v1`,
  with a 1 MiB allowance on each. The first failed fixture run is retained.
- `horizon-audit-split-clippy-20261119-v2.service`: all targets passed with
  warnings denied, including the corrected native fixture.
- `horizon-audit-split-release-20261119-v2.service`: production release succeeded
  for the final source. Artifact SHA256:
  `cb5893b480a0662dd8ed9487b224c3088794f4ccad9a978e918e5710dd3ad2fa`.

The native fixture exercises storage mechanics, not production capacity. The
new 360 GiB scratch reservation has not been booked or deployed. Root cache
cleanup separately reclaimed 3,948,605,440 allocated bytes; that makes space
for the current v3 audit's next archive but does not qualify later large objects.

Before deployment: publish exact source to `account-updates`; qualify and seal
the new runner/config; obtain fresh whole-fleet admission including the added
DATA reservation; provision/pin the destination; preserve old controller native
state; hand off only when it is idle with empty scratch (the capacity wait at
epoch74 is one suitable boundary); use `reconfigure`; expose only the new scratch
path in `ReadWritePaths`; and activate one controller over the same state.
Full actual archive download/playback/cleanup through that exact sandbox is
still required as operational qualification. The new source is not permission
to restart the healthy v3 service or reduce replay reservations.
