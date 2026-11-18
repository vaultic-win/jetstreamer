# Chronological R2 audit deployment

The persistent service `horizon-r2-chronological-plugin-audit-20261118-v1.service`
was enabled and started at 2026-11-18 21:46:22 UTC. Its initial invocation is
`9273f20a0025480bb12809beb52dea82`, controller PID 1534775. It fetched
`account-updates` and began compiling the reader at 21:46:39 UTC before epoch 0.
This records startup, not a successful archive playback.

The authenticated inventory contains 225 canonical archives, 16,504,898,595,724
bytes total, spanning epochs 0–960 with gaps. The runner processes its frozen
inventory in numeric order. It saves each result before deleting its own scratch
copy; source archives and R2 objects remain intact. A successful result requires
whole authenticated readback, complete current-plugin playback, actual boundary
observations, matching structured report/log counters and a clean exit.

Inspect it without a model or agent:

```sh
sudo /usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v3/audit status /usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v3/config.json
sudo journalctl -u horizon-r2-chronological-plugin-audit-20261118-v1.service -n 30 --no-pager
```

State, progress, child activity, inventory, results and attempt logs live under
`/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1`. The installed
runner SHA-256 is `df419d9a398f3dd777e996c5a11d1fbc3cff8f5e9f11603c981aded906494954`.
Its source was published as `c8755794cd267a2843b480ed5d9c6aa740c0aad9`;
15 tests and strict Clippy passed before deployment. Reader generations are
separately sealed beneath `/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1`.

The service uses the root filesystem, preserving 32 GiB free, with a 16 GiB
archive cap and 16 GiB working budget. It has CPU quota 400%, current memory limit 24 GiB,
two build jobs and four plugin workers. These are audit resources, not replay
lanes, and must be included in subsequent whole-host admission accounting.
The first archive exceeding this cap is epoch 74; qualify larger scratch capacity
or a state migration before reaching it. The script waits rather than skipping
an epoch or consuming replay reservations. The largest queued archive is epoch
941 at 385,290,386,716 bytes. Restart recovery is independent of conversation
state and retains completed results.

Campaign continuity at startup: epoch 166 remains the only observed replay lane.
The accepted 21:19:25 UTC sample shows slot 71,730,174, 2.2812 slots/sec and zero
restarts. All 19 active status JSONs were refreshed with authenticated readback.
The sole next replay observer is armed for 21:49:25 UTC. Epoch 141 holding is
still running; no newly parked bytes have been credited or locally retired.
The next epoch 167 admission remains dependent on actual reclaimed space.

## Allocation-scan repair and v2 resumption

The first build was stopped by the allocation guard at 21:51:10 UTC when a
temporary Cargo file disappeared between enumeration and metadata inspection.
The controller preserved that failed attempt and waited for reader recovery.
The repair treats only disappeared entries as zero retained allocation; other
inspection failures still stop the subprocess. Four deterministic regression
tests cover both removal windows, other errors, and symlink non-traversal.
All 19 runner tests and strict Clippy passed; the v2 deployment helper passed
three tests and strict Clippy.

The fix is published as `bf365e75d2a424efe08c5757e17de63aac836943` on
`account-updates`. The v2 runtime is sealed at
`/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v2`.
Runner SHA-256:
`7472ca22405ea0a08e58987fd13e90970e02cbcc4bb13eb83cb553fbdd910b5d`.
The same persistent service restarted at **22:10:35 UTC**, invocation
`6de50b080c4e48f79dc095d03255d493`, controller PID 1568376. It entered
`qualifying_reader`, and authenticated branch fetch plus bounded Cargo metadata
completed successfully. No archive pass is claimed by this resumption record.

The v1 config is preserved byte-for-byte. State, credentials, resources, reader
generations, and historical attempts remain at their existing paths. Frozen
inventory SHA-256 remains
`d38d5146d50b7788cf5866fa0f7f5aeefade92fbf0496398fee334b480b7084e`.
Only the waiting audit controller was replaced; campaign replay was not restarted.

Epoch 141 recovery also advanced: the exact completed hash control's fragment,
native terminal state and journal were preserved before closing it. A fresh
staged-reference scan returned no references. The exact retirement executable
passed its durable-transition test and is sealed at
`/usr/local/lib/jetstreamer/horizon-holding141-retirement-20261118-v1`.
The holding transfer still must finish authenticated readback and custody before
the compressed local input can pass its check and retirement commands. No space
from that transfer has been credited yet.

## Native build scratch repair and current deployment

The second reader build exited 101 at 22:13:24 UTC: `protobuf-src` could not
create a temporary directory in `/tmp` under `ProtectSystem=strict`. This was
a separate build-environment failure, after the allocation-scan repair.
Cargo and its native build children now receive `TMPDIR` under the private
audit state at `build-tmp`. That directory is included in the existing allocation
guard. Tests exercise an actual native `mktemp` subprocess and reject a symlink
escape. All 21 runner tests and strict Clippy passed; the v3 deployment helper's
three tests and strict Clippy also passed.

The fix is published as `672cb179761cec1fa60a4237ac1934c69d58fbab`.
The current sealed runtime is
`/usr/local/lib/jetstreamer/horizon-r2-chronological-plugin-audit-20261118-v3`;
runner SHA-256 is
`8b08a767c4e002d90cb08c8a3878502adfdd79d934de80572418620d55511260`.
The service restarted at **22:25:45 UTC**, invocation
`9fc843c1adec49bd95eb836be2ca87b9`, PID 1590101. Reader compilation resumed,
and the native protobuf configuration log now ends with `configure: exit 0`.
There are still **0 passes and 225 pending archives** at this build checkpoint.
In this campaign conversation, the user's term **replay service** refers to this
R2 archive audit, not the historical epoch-generation lane. Report its rate separately.

The audit memory booking was corrected before this resumption: MemoryMax is
24 GiB and MemoryHigh is 20 GiB, with the previous reader process unchanged
during that property update. Both the persistent drop-in and v3 unit defaults
carry those limits. The additive budget receipt is
`/var/lib/jetstreamer/r2-audit-additive-budget-20261118-v1/allocation.json`
(SHA-256 `f99e0d79b062a86f13d808eafed4cb4d53c7325c154934b0c2b59f4f78fa8a46`).
It retains the original 761,131,708,416-byte campaign commitment and separately
adds 25,769,803,776 bytes for the audit. Commitments plus the 17,179,869,184-byte
reserve total 804,081,381,376 bytes against 810,902,843,392 bytes of host memory.
The next replay admission must enforce this additional memory and four CPU cores;
the old preparation receipt alone does not include them. No promises were ended.

At the 22:19:25 UTC campaign observation, epoch 166 remained the sole generation
lane, at 2.0900 slots/sec and 1,062.30 transactions/sec, zero restarts. All 19
active R2 status objects were refreshed and read back. The next observer is armed
for 22:49:25 UTC. Actual DATA free space was 7,296,540,360,704 bytes. Six obsolete
epoch 185/186 work snapshots were retired with durable receipts, totaling
43,702,026,240 allocated bytes. Epoch 183's additional 7,042,052,096-byte copy
is qualified in published source `a3a8913c`, but still needs sealed execution.
Epoch 136 duplicate cleanup remains blocked by retained accounting-reader inputs.

## First completed audit cycles

At the user-requested 22:43 UTC check, the v3 service was active with its unchanged
invocation and zero restarts. Epochs **0, 1 and 2 passed**, with no failed results
and 222 archives pending; epoch 3 was downloading. The durable results are
`results/epoch-{0,1,2}.json` beneath the audit state directory. Each binds the
authenticated object, complete plugin report, actual counters and clean exit.
Reader equivalence was established against `account-updates` commit
`c1c9fe4898de188e59d064ab7ef508389931afa0`.

Epoch 2's playback log runs from 22:42:34.057902509 to 22:43:03.722435923 UTC:
29.664533414 seconds for 432,000 slots and 25,536,956 transactions, approximately
14,563 slots/sec and 860,858 transactions/sec. Epochs 1 and 2 consumed 138 and
169 seconds between successive attempt starts, respectively: approximately
23.45 epochs/hour including transfer, source checks and cleanup. This early
small-archive sample is not a completion forecast for the full 16.5 TB inventory.
Epoch 0's 745-second attempt included the initial build and is excluded from
that cycle-rate estimate.

Epoch 183's obsolete private snapshot has now been retired. Its durable receipt
is `/var/lib/jetstreamer/snapshot183-private-retire-20261118-v1/target-0-completion.json`:
7,042,052,096 allocated bytes removed, source and quarantine absent, sealed
retained input preserved. Together with the six epoch 185/186 copies this is
50,744,078,336 allocated bytes retired. Actual free space remains a separate
admission measurement because epoch 166 continues to grow.

The two workspace cache checks failed closed on staged unit references; neither
cache has been retired. The debug check includes unrelated private build paths
whose names contain `target/debug`; the release-deps check has similar matches.
Qualify exact path matching without dropping real current or staged consumers.
Epoch 141's holding object remains in authenticated readback; no local retirement
or capacity credit is claimed before custody and the separate retirement gates.

## Cleanup and launch preparation after the 22:49 observation

The 22:49:25 UTC sample records epoch 166 at slot 71,742,367, 2.4393 slots/sec,
1,149.62 transactions/sec and zero restarts. All 19 active status objects were
conditionally refreshed and authenticated through readback. The sole next
observer is armed for 23:19:25 UTC. The operational fleet now carries the audit's
additional 24 GiB and four CPU cores explicitly; it confers no admission authority.

The corrected cache matcher is published as `b97eb77a`. Nineteen targeted tests
and strict Clippy for the complete checker module closure passed. Whole-library
Clippy still reports 14 unrelated snapshot-module diagnostics. Eight obsolete
failed diagnostic units were closed after preserving their raw native state,
fragments, journals and historical qualification evidence under
`/var/lib/jetstreamer/sol-cache-terminal-custody-20261118-v1`.

Both workspace cache retirements completed: `target/debug` and
`target/release/deps`. Their receipts are respectively
`/var/lib/jetstreamer/horizon-dev-cache-check-sol-debug-retire-20261118-v2/completion.json`
and `/var/lib/jetstreamer/horizon-dev-cache-check-sol-release-deps-retire-20261118-v2/completion.json`.
The two private epoch 152 snapshot copies also retired successfully, removing
3,134,062,592 allocated bytes and preserving the authenticated legacy deployment
input. Their receipts are `target-{0,1}-completion.json` under
`/var/lib/jetstreamer/snapshot152-private-retire-20261118-v1`.
Cache-entry block sums are not a measurement of net reclaimed filesystem space;
actual DATA available space after these retirements was 7,310,603,911,168 bytes.

Epoch 167's launcher is sealed at
`/usr/local/lib/jetstreamer/horizon-retry6-single167-launch-20261118-v1/launch`,
SHA-256 `664196244f6beb1e874533e25dedaac341b4adae933618680d197a59f17cf99d`.
Eight tests and strict Clippy passed; source, manifests, logs and artifact proof
are sealed alongside it. It enforces the audit allocation in addition to the
original campaign promises. This is prepared launch tooling, not an admitted lane.

Fresh candidate measurement completed through the native 22:56 control:
`/var/lib/jetstreamer/retry3-preparation-20261113-v1/epoch167/local3retry6/physical-1795042581-1629353.json`
(SHA-256 `6c513918d01aba3db6add4a2969122f2834f28a184803b142838e121e4fd6110`).
It retains 119,201,542,144 bytes with two complete stable captures. The preparation
helper now takes the current observer, status, successor and physical receipt as
explicit inputs. The observation helper also derives successor filenames from
the successor's date, with a passing midnight regression test, so its cadence
does not stop at November 18. Epoch 141 custody and exact local retirement remain
the next capacity dependency; no future reclamation is counted as available.

At the 23:13 UTC audit check, **12 archives passed and none failed**; the service
was playing epoch 12 with the same v3 invocation and zero restarts. Its next
routine audit observation is no earlier than 23:43 UTC. The independent epoch166
resource/status cadence remains 23:19:25 UTC.

Epoch 141's full 189,943,475,031-byte authenticated readback completed successfully
at approximately 23:10 UTC. Its original holding process remained active during
the subsequent local source revalidation; no custody or local retirement was
claimed at the 23:15 check. Preserve that process and advance retirement when
its exact successful terminal invocation and custody receipt become available.

Before retirement, source review found a producer/consumer mode mismatch: the
holding manifest stores `st_mode & 0777`, but the exact141 consumer expected
`0100444`. Published fix `c1fca70c` accepts the producer's `0444` representation
while retaining the exact root-owned immutable local source checks. Both the
new test using the actual manifest writer and the existing transition test pass.
Use the new sealed retirement executable:
`/usr/local/lib/jetstreamer/horizon-holding141-retirement-20261118-v2/jetstreamer-r2`,
SHA-256 `045d10440c6c9a01eefe240aa0fefa09e8daceae2527baf4dc62dcd8ee67742e`.
The old v1 retirement image retains the mismatch and must not be selected.
Native build/test state, test output, changed source and artifact provenance are
sealed alongside v2. The existing `deploy_retire141 check-plan` and `retire-plan`
metadata commands remain usable; execute those plans through the v2 image.

## Completed holding custody and audit throughput

Epoch 141 holding completed at approximately **23:21 UTC**, with the original
parker invocation `1c113358b7a14265a4e2d8d16576d6ae` exiting successfully. Its
custody receipt is
`/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/custody-435e917094c39e05a8df2ac97cbba71e8470261112dcc2be30fdf56a013c0688.json`.
It binds complete authenticated remote readback and local source revalidation for
189,943,475,031 bytes, SHA-256
`7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b`.
The corrected v2 retirement check started at approximately 23:24 UTC using
`/var/lib/jetstreamer/holding141-retirement-deployment-20261118-v1/check-plan.json`
(SHA-256 `bc98dfd68f4c144ab03bec877711cfe093ddf5cdd09d94f1769ffce312c1d616`).
It is rehashing the exact local source. This is not yet a retirement completion
or a free-space credit. Preserve the parker's terminal identity through retirement.

At the user-requested **23:24 UTC** audit check, 16 archives had passed, none had
failed, and epoch 16 was downloading. The ten complete cycles for epochs 6–15
took 1,790 seconds from epoch 6's attempt start to epoch 16's attempt start:
**20.11 epochs/hour**, or 179 seconds per epoch, including download, source checks,
playback and cleanup. Epoch 15's playback itself took 29.605064950 seconds for
432,000 slots and 25,738,617 transactions: approximately 14,592 slots/sec and
869,399 transactions/sec. This small-archive rate is not a forecast for the
remaining larger archives. The next routine audit check is no earlier than
23:54 UTC; the campaign observer remains scheduled for 23:49:25 UTC.

The metadata-only `plan_launch167` helper now binds the completed preparation and
its exact DATA contract into the sealed launcher's plan. It creates only private,
no-clobber metadata and cannot start replay. Both it and the updated observation
helper passed strict Clippy and release builds; the midnight observation test
also passed. The observation helper carries completed epoch 141 custody and,
once present, the validated retirement receipt without treating its block count
as actual reclaimed space. Fresh measurement, preparation, launch checks and
real guard protection remain required before counting epoch 167 as running.

The v2 retirement check was stopped without mutation at approximately 23:38 UTC.
Its debug executable had read only 10,955,522,048 bytes after about 13 minutes
(PID 1648218, start ticks 339093373), roughly 14 MB/sec. A complete pass at that
speed would exceed the retirement consumer's 900-second prior-check freshness
limit. The exact original source was present and neither retirement intent nor
completion existed before the check process was terminated. No ready archive,
holding object or replay service was changed. Preserve this failed attempt;
do not weaken the freshness or whole-file proof requirements.

An optimized successor build is running in
`horizon-holding141-retirement-optimized-build-20261118-v2.service`, using the
original Sol-owned Cargo cache and target. It retains the dev profile with
debug info disabled, optimizes the r2 package at level 1 and SHA-256, MD5, digest
and block-buffer packages at level 3. The first optimization attempt failed
before compilation because its Root Cargo cache lacked the offline index;
the corrected attempt uses the original build identity. Qualification and normal
immutable sealing must precede another check. The existing custody/check plan
remains usable; no check receipt was produced by the slow attempt.

Epoch 170 guard qualification also advanced: 98 tests pass, along with strict
production/test compilation and Clippy. The localized manifest now exposes the
guard separately and requires the existing `preparation` feature for the
preparer. `deploy_guard170` preserves the five genuine executions and prepares
the exact successor deployment. Epoch 170 still requires a sealed guard, its
own native witness, and genuine epoch 167 admission/protection before preparation.
