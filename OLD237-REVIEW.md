# Exact old epoch 237 partial retirement: source-only handoff

Status: source formatted and tests prepared; **no build, test, payload hash, live census,
R2 operation, archive mutation, service action, or deletion was executed**.

Baseline: `cad23e44786c4c6db464bb65f6c173b6551a7bec`.
Branch: `repair/old237-partial-retirement-v1`.

## Decision and evidence

Use the existing authorized failed-output retirement policy for this exact
generation. Do not spend another full upload plus remote readback on diagnostic
bytes that the deployed route cannot append-resume. R2 holding remains available
if a subsequent review discovers genuinely useful unsaved evidence, but this
change neither uses nor extends that transport.

The original producer `horizon-qualify-237-general-target1-v1.service`, invocation
`f77854054df74e468e717668051429c9`, was stopped by the root-physical guard at slot
102753469 of required terminal slot 102815999. PID1's authenticated `Stopping` and
`Stopped` events distinguish this from naturally completed replay. Its mutable
scratch was retired with the archive and cohort metadata unchanged. The saved
precheck states there is no qualified in-place resume cursor. The earlier scratch
retirement's preserved segment-manifest list is empty.

In exact deployed node source commit
`46b4b4ad551b9f7866a8aa6fb8569dc9e9917908`,
`preserve_resumed_cohort_output` preserves prior private cohort archives as backups
before `run_geyser_replay`. Selecting the same cohort directory does not append to
the partial archive. This is a source finding, not an inference from a
`running-private` metadata label.

The independently launched successor
`horizon-qualify-237-general-target1-budget620-v2.service`, invocation
`3949b88a4ca34fc892a19f219cebd476`, has a fresh `budget620-v2` state and output
root. Its saved unit explicitly unsets `JETSTREAMER_ROOT_COHORT_RESUME_RUN` and
loads the retained bootstrap snapshot. The saved actual launch and unit source
are independently pinned by the tool. No current successor observation was
made by this source task.

All ten small historical evidence paths and independent digests are compiled
into `RECORDS` in the new binary. It also rereads the retained original cohort
metadata without reading any snapshot/archive input body. A future source
stat/hash mismatch or completion evidence blocks retirement.

## Exact target and authority

The new binary exposes no target/path/prefix override. Only this file can move
to quarantine and be unlinked:

```
/home/ubuntu/.jetstreamer-private/qualification-237-general-target1-v1/state/destination-b101133264beb5653bf62c0288153254f04c04e1c5d6370a8b4d4b07441b8f54/work/root-cohort-237-237/run-1213927-1793421489530010065/archives/epoch-237.jet
```

Historical identity: device 66305, inode 11311387, UID/GID 1000:1000, regular
mode 0600, nlink 1, logical length 149096347639, blocks 291204144,
mtime/ctime 1793563520971972622 ns. Rename changes ctime; that one attribute is
checked against the historical value before rename, while the other attributes
and a full body SHA remain mandatory in quarantine. The code records the
original ctime in the durable operation identity.

Only the exact failed partial is eligible. Preserve the old run directory,
scratch root, logs, manifests, cohort metadata, immutable deployments, compiler
targets and all bootstrap inputs. Do not count its historical logical length or
block allocation as guaranteed reclaim. Confirm actual capacity independently
after completed retirement.

## Implementation boundaries

The dedicated `jetstreamer-utils` binary
`jetstreamer-horizon-retire-old237-partial` avoids replacing the shared R2 helper.
It has no R2 client, directory deletion, producer stop/start, publication,
checkpoint promotion, or arbitrary-target behavior. No Cargo feature is added
or required. Retained `native210-small`/`native227-small` helper features are
untouched because that helper is not replaced.

Before mutation it requires independently supplied self/plan/body SHA-256,
hash-bound root-owned historical records, an exact source identity, inert old
producer/guard/timer, no queued old jobs, no foreign staged unit referencing the
old generation, and no command/maps/cwd/root/exe/fd/inode references. An
incomplete process scan fails closed. Loaded terminal originals are retained;
enabled links or foreign staged recipes fail closed for operator review.
The original unit's sampled result and exit fields are retained in intent.

A root-owned 0700 state directory on the source filesystem holds an advisory
single-operation lock, atomic no-clobber fsynced receipts and the quarantined
file. The sequence is original full hash -> durable intent -> fresh closure ->
no-clobber rename -> quarantine full hash -> durable custody -> durable unlink
intent -> fresh closure -> exact single-file unlink -> fsynced completion.
All durable crash boundaries can resume using the same plan. An unexpected
namespace reappearance, digest/identity drift or missing custody stops recovery.
Uncommitted temporary receipt files never become canonical evidence.

## Remaining native gates owned by Main

1. Review/format the source; run the focused tests and production build under
   fresh resource admission. Suggested commands (not run here):

   ```
   cargo fmt --all -- --check
   cargo test -p jetstreamer-utils --no-default-features --bin jetstreamer-horizon-retire-old237-partial
   cargo build --release -p jetstreamer-utils --no-default-features --bin jetstreamer-horizon-retire-old237-partial
   ```

   Use an isolated compiler target. A proposed bounded envelope is one Cargo job,
   200% CPU, at most 8 GiB hard memory, no swap and 30 minutes; derive actual
   reservations from current host admission rather than assuming these fit.
   Never clean or replace another compiler target. No tests/builds were run by
   this source task.

2. Obtain the missing old-partial body SHA in an admitted read-only hash task;
   the saved metadata contains no payload digest. Do not invent one. The tool
   independently rereads the full source and full quarantine, so the first
   execution entails two more full local reads. Its hash logging emits progress
   for each 10 GB. Budget I/O/time and protect healthy producers accordingly.

3. Seal the reviewed binary using the required immutable deployment sealer.
   Independently capture binary SHA and plan SHA. Provision only
   `/var/lib/jetstreamer/horizon-old237-partial-retirement-v1` as root:root 0700
   on device 66305; the binary intentionally does not create arbitrary dirs.
   Keep its executable and plan in a separate sealed package. Example plan:

   ```json
   {
     "schema": "jetstreamer-old237-partial-retirement-plan-v1",
     "archive_sha256": "ACTUAL_INDEPENDENTLY_OBSERVED_BODY_SHA256",
     "local_failed_output_retirement_authorized": true,
     "archive_publication_authorized": false,
     "remote_mutations": false
   }
   ```

4. Independently establish a fresh campaign no-relaunch/no-reference closure,
   original source stat, current capacity, actual healthy successor owner, and
   any new terminal/publication evidence. Run the binary's `--check-only`
   first under explicit admission. It hashes the candidate but performs no
   retirement writes. If a foreign/stale staged unit blocks the check, review
   that exact unit; do not weaken the scan or blindly delete the unit.

5. Admit real execution with finite CPU/memory/runtime/I/O limits. The sandbox
   must allow process/systemd inspection, the exact original **archives parent**
   for rename (a file bind mount prevents rename), and the exact root-private
   state directory. It needs no network, no input/archive-wide writable tree,
   and no access changes. Give sufficient timeout for full local hashes; a
   timeout leaves a resumable durable boundary rather than disposal authority.

6. Confirm the durable completion and exact source/quarantine absence. Only a
   fresh independently qualified filesystem observation can release storage
   credit or permit another lane admission.

This packet grants no runtime mutation by itself. The existing campaign policy
already authorizes qualified failed-output retirement; all listed native gates
remain mandatory and belong to Main.

## Independent review successor

The source successor closes two gaps identified in independent review. Maps
inspection now parses each kernel row's major/minor device and inode, so a bind
alias mapping with its descriptor closed still blocks retirement. An unreadable
or malformed maps row fails closed. Staged-recipe inspection looks for original
actor unit names as well as the old pathname, catching a foreign timer's
`Unit=horizon-qualify-237-general-target1-v1.service`. External recipe symlinks
are followed through at most eight inspected links; cyclic, dangling,
oversized/non-regular targets fail closed. A positively identified root-owned
`/dev/null` mask is understood as a mask. Only the exact direct inert originals
under `/run/systemd/system` may retain their inspected recipes; enabling/alias
links elsewhere do not receive that exception.

The selected-bin suite now contains 14 tests. New negative fixtures cover alias
maps identity, actor-only timer recipes, external symlinks, oversized recipes
and no-clobber collisions. Temporary-filesystem fixtures exercise the same
atomic receipt, no-clobber rename and single-child unlink primitives as
production, close and reopen directories at every durable boundary, resume to
completion twice and preserve a neighboring sentinel file. These are real
filesystem test bodies prepared in source, **not tests already executed**.
