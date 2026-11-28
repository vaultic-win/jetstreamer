# Chronological R2 audit deployment

The current controller is the home-backed `runtime-v9` described in the
November 19 22:50 section. The earlier deployment sections retain historical
identities and resource settings; use the live service and state JSONs for
current progress.

## Home-storage migration — 2026-11-19

At 19:51:42 UTC the same audit service started its explicit downloaded-epoch77
recovery on the home filesystem. Invocation `99c7ddc48af140efb131b784a6b064d2`,
controller PID `2227285`. At 19:53:18 UTC its child began full epoch77 plugin
playback. This records an active replay, not a new completed audit result.

State and reader paths below are now persistent bind mounts from
`/home/sol/.jetstreamer-private/horizon-root-runtime-data/r2-audit-storage-20261119-v1/`:
`state` backs the original `/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1`,
and `readers` backs the original `/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1`.
Downloads, source checkout, build cache, temporary files, logs, receipts and
sealed reader generations all reside on home. Both mounts are required by the
service. Original logical paths, result receipts and reader seals are preserved.
The verified old ROOT copies were removed after the switch, recovering about
28 GB on root. Existing replay workers were not restarted.

The sealed controller is `runtime-v8/audit` below the same home-backed directory,
SHA256 `60bd1919c887aebace36a64c6abbda51c8834dd4bc918e123f9d56835cfe341a`.
Source commit `a3c8d610` was merged and pushed to `account-updates` at `6ac1dc0d`.
All 56 tests passed, with one preexisting external-scratch native test ignored;
strict all-target Clippy and release build passed. The actual service sandbox
was separately checked for home-backed identities and write access.

The audit preserves the campaign's 6,794,761,027,378-byte DATA obligation and a
2-GiB Cargo-cache allowance as its configured free-space floor. Its 16-GiB
working cap, 24-GiB memory cap, CPU quota 400%, two build jobs and four playback
workers remain bounded. Each new download reserves the exact archive size;
385,290,386,716 bytes is the acceptance ceiling, not a per-epoch reservation.
Future replay admissions must include the audit's home allocation and actual
current runtime, rather than the obsolete zero-DATA/ROOT configuration.

The recovery verifies the copied epoch77 archive's entire digest and current
authenticated remote identity, records the old scratch ownership before
rebinding the new inode, and repeats full playback with the current branch's
reader. Retry1 and all earlier outcomes remain intact. `Restart=no` prevents
an interrupted recovery from resetting its retry budget. After its durable
completion, future controlled restarts use `run`; this controller continues
chronologically without restarting when recovery succeeds.

Migration and native evidence are retained under `migration-evidence` and
`qualification` beside `runtime-v8`. The sections below describe earlier
deployments and their historical resource settings.

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
sudo /var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1/runtime-v9/audit status /var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1/runtime-v9/config.json
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

The v3 optimization-only retirement image (`07b86621ad56341731a60a284a92198c7fb5e6a85ad8c230f05975b1dcb80518`)
passed all four targeted tests but still hashed only about 120 MB/sec: its
read-only check reached 17,381,195,776 bytes in 145 seconds. That check was also
stopped before any retirement intent or mutation. At that rate the next full
pre-retirement hash would still exceed the unchanged 900-second freshness gate.

The exact141 path now has a bounded parallel implementation of the same three
digests, retaining file descriptor/path identity checks before and after reading.
It uses one buffer of at most 64 MiB and at most three concurrent hashers. The
ordinary archive uploader's hash path is unchanged. Cross-checks cover empty,
partial and multiple parts, changed input, invalid part sizes and symlinks.
Three retirement tests pass; the separately invoked throughput test also passes.
With r2 and the digest packages optimized at level 3, the median 128 MiB test
took 0.269550363 seconds versus 0.380176613 seconds serially (about 498 MB/sec
versus 353 MB/sec). All three digests match in each of three rounds. This is a
bounded benchmark, not yet a completed full-file check. Production build and
v4 sealing remain required before retrying retirement.

Epoch 170's guard is now sealed at
`/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry7-data-guard-20261118-v1/guard`,
SHA-256 `2572c20c10b1473a9438e8d08d4aaf6ccb06fa9aa47e3508fe90e6bcaddddc6b`.
Its 98 tests and four strict configurations passed. The actual own-image witness
also succeeded in invocation `2ec28eb7bff842da86337b3e25d4c245`, saved as
`/var/lib/jetstreamer/epoch170-retry6-live166retry7-guard-deployment-20261118-v1/own-native-witness.json`.
A fresh witness will still be needed for admission; this receipt does not launch
epoch 170 or supply the missing live epoch 167 identity.

At **23:49:25 UTC**, epoch 166 reached slot 71,750,479 at 2.3964 slots/sec and
1,100.66 transactions/sec, with zero restarts. All 19 status objects were
refreshed and authenticated in `cycle2349-live166-19-20261118-v1`. The next
observer is armed for **2026-11-19 00:19:25 UTC**. Conservative DATA available
was 7,305,799,737,344 bytes; epoch 141's local input has not been retired.

At the **23:56 UTC** audit check, **26 archives had passed, none had failed**,
and epoch 26 was downloading under the unchanged controller PID 1590101.
The next routine audit check is no earlier than **00:26:39 UTC**.

## November 19 audit rate and next-lane preparation

At the user-requested **00:01 UTC** audit check, **28 archives had passed, none
had failed**, and epoch 28 was downloading. The ten completed cycles for epochs
18–27 covered 30,819,625,246 archive bytes in 1,974 seconds: **18.24 epochs/hour**,
or 197.4 seconds per epoch including download, plugin playback and cleanup.
Epoch 27's native log records playback from 00:00:34.812194120 to
00:01:09.425871283 UTC: about 34.614 seconds for 432,000 slots and 33,582,495
transactions, approximately 12,480 slots/sec and 970,208 transactions/sec.
This is a small-archive measurement, not a forecast for the larger remaining
inventory. The next routine audit check is no earlier than **00:32 UTC**.
The independent campaign observer remains scheduled for **00:19:25 UTC**.

The optimized parallel epoch 141 retirement image is sealed at
`/usr/local/lib/jetstreamer/horizon-holding141-retirement-20261118-v4/jetstreamer-r2`,
SHA-256 `821539a5dd4e66b85de336646479e7abe07494174ec44cfc9ad55b81094a48dc`.
Its full-file check started at approximately 00:04 UTC. No local deletion or
free-space credit is claimed before a durable retirement completion. The exact
check plan remains `bc98dfd68f4c144ab03bec877711cfe093ddf5cdd09d94f1769ffce312c1d616`.

Epoch 170's preparer production build, all **303 tests**, and strict production
Clippy completed successfully under the three retained
`horizon-170-live166retry7-preparer-{production,tests,clippy}-20261118-v1.service`
units. The `deploy_prepare170` metadata helper checks their exact invocation IDs,
source equivalence to published build commit `00745fa4`, features, artifact and
test evidence before normal runtime sealing. This does not supply genuine live
epoch 167 evidence, fresh admission, or the outstanding operational positive test.

The v4 epoch 141 check completed successfully at **00:10:21 UTC**, recording
`receipts/retire141-check-bc98dfd68f4c144ab03bec877711cfe093ddf5cdd09d94f1769ffce312c1d616.json`
under the private holding state. The retirement plan was created and execution
started immediately afterward, using plan SHA-256
`389e593db906ae9ac8440e5186c22d8be5f7c2df5a13f095c5c24b09ccb98e11`.
The active terminal session is **22374**. Preserve it through the full original
and quarantined-file hashes; do not start a duplicate or count capacity before
`retirements/epoch141-completion.json` exists. After actual deletion, immediately
refresh epoch 167's physical measurement, prepare, and run the sealed guarded
launcher. Keep the scheduled 00:19 campaign observation/status refresh.

Epoch 170's preparer is now sealed at
`/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry7-prepare-20261118-v1/prepare`,
SHA-256 `095d99efd0b0c6d657fb806943ecad86b0a19ea3528d273ca5d48d577e9bfaff`.
Its adjacent `artifact-proof.json` has SHA-256
`c106402b757c68f260fe79f5d7744ff85c3c214c93d6c79346bd3f12d0f52b4e`.
The helper is published as `023dc3ba`. Genuine admitted/protected epoch 167,
fresh two-peer preparation, its own fresh DATA witness/contract and a qualified
guarded epoch 170 launcher remain required. Parent owns the continuation;
no repair sub-agent is running.

## November 19 00:49 recovery and actual epoch 167 launch

Epoch 141's holding retirement completed, removing **189,943,668,736 allocated
bytes**. Its authenticated remote custody remains intact. Completion is
`/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch141-completion.json`.
The obsolete private epoch 160 bootstrap snapshot was also retired, removing
**1,811,841,024 allocated bytes** while preserving its fully hashed immutable
deployment copy. Its inactive restore definition was preserved and masked before
the full bootstrap reference scan was accepted. Custody is under
`/var/lib/jetstreamer/epoch160-obsolete-restore-custody-20261119-v1`; retirement
completion is `/var/lib/jetstreamer/snapshot160-private-retire-20261119-v1/target-0-completion.json`.
Neither retirement claims a net filesystem free-space delta or mutates R2.

Epoch 167 preparation completed at 00:25:05 with the full 21,903,847-byte native
census. The launcher now consumes its actual
`current_fit.required_raw_available_bytes` field and accepts the census within
a checked 32 MiB bound. The complete outer preflight initially failed its
7,493,274,261,298-byte DATA requirement; cleanup opened that gate without
changing the floor. All ten launcher tests, including the actual full outer
preflight, and production Clippy passed. Required source was published before
admission in `f6a26478064713bedc4ff96e9f4cd9eb15119852`.

Sealed launcher:
`/usr/local/lib/jetstreamer/horizon-retry6-single167-launch-20261119-v3/launch`,
SHA-256 `42b293d3481dd33f487452dd42238d01ce2abee386982e80781ba44acb90aef8`.
The sealed check passed and the real launch completed at **00:45:18 UTC**.
Producer PID **1718241**, invocation **fdfadeb7b76d4760a37983b402fd2771**,
has genuine timer-driven first-guard proof. Admission and protection are under
`/var/lib/jetstreamer/retry6-single167-guarded-launch-20261118-v1/epoch167/`.
The admission digest is
`99213a3ed3afecdde46a9b9b362fc6968c92755d6f85c5903872e7f466a04177`.
This startup proves guarded bootstrap, not transaction replay.

The sole 00:49 observer was replaced at the same clock to include actual epoch
167. Its accepted sample is
`/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root0049-live166167-20261119-v1.json`,
SHA-256 `b3dc771d7a9b30c2f50353f75c6f9359290104ea2f9479ab695874f848756b03`.
Epoch 166 was advancing at **2.3252 slots/sec**, **1,120.36 transactions/sec**,
slot 71,758,744. Epoch 167 remained in bootstrap; both identities were stable
with zero restarts. Counts: one executing replay, one active bootstrap, desired
concurrency 13. The next routine observation is no earlier than **01:19:25 UTC**.
All nineteen statuses were authenticated and refreshed from this sample:
`/home/sol/.jetstreamer-private/r2-status-receipts/cycle0049-live166167-19-20261119-v1/COMPLETED.json`.
That cycle is now every epoch's status predecessor. Earlier targeted epoch167
corrections are retained under `event-disk-fit-167-20261119-v1` and
`event-guarded-bootstrap-167-20261119-v1` in the same status root.

Epoch 170's corrected launcher passed eleven tests, a production build and strict
Clippy using units `horizon-single170-launch-corrected-{tests,production,clippy}-20261119-v1`.
Its sealer now binds these executions and published source `f6a26478`. Actual
two-peer staging, physical measurement, fresh own-image witness/contract and the
complete operational preparation remain before guarded admission. Do not reuse
the old one-peer stage helper or substitute forecast peer identities.

The R2 audit's user-requested **00:33 UTC** check found **36 passed, zero failed**,
with epoch 36 downloading. Epochs 26–35 completed in 2,304 seconds: **15.625
epochs/hour**, 230.4 seconds/epoch including download, playback, checks and cleanup.
Epoch 35 playback took 30.730 seconds for 432,000 slots and 25,720,561 transactions.
The unchanged audit service has zero restarts. Next routine audit check is no
earlier than **01:03:38 UTC**. Its 16 GiB archive cap still needs a qualified scratch
expansion before the first oversized archive at epoch 74. No audit restart or
DATA reservation change has occurred. An attempted delegation again received
an encoded task payload and was interrupted; parent retains continuation.

At 00:54 the corrected epoch 170 launcher was sealed at
`/usr/local/lib/jetstreamer/horizon-retry6-single170-launch-20261119-v1/launch`,
SHA-256 `91d99b494420cdf63680ced191c7bbbb53a83046ca4af60b511ee2771b411cca`.
Its adjacent artifact proof SHA-256 is
`fb2f647dec28eef1d3111ada991681364e776ce7302bc10910faaa6e57dc9d56`.
This is qualification evidence only; no epoch 170 preparation or launch occurred.

The reconciled fleet now updates every nested status and binds both actual
producer admissions, classifying epoch 167 as bootstrap. It is
`/var/lib/jetstreamer/root0049-live166167-observation-20261119-v2/ROOT_COMPLETE_OPERATIONAL_FLEET.json`,
SHA-256 `62ef665dd8c42a27bb3b9e0edaf4c51bfe20315cfd877d6eb1a4712d3a91c6b0`.
The v1 attempt encountered the existing join configuration and stopped before
arming a timer; its evidence remains. The v2 route uses a distinct immutable
configuration. Exactly one successor timer is armed:
`horizon-observer-root0119-live166167-20261119-v1.timer`, for **01:19:25 UTC**.
Its config is
`/usr/local/lib/jetstreamer/horizon-live166167-observer-config-0049-20261119-v2/next-observer.json`,
SHA-256 `22c9326872a8c793ab757e89a3b0e29529a639db57b965619cd52fb15a0d66e0`.
Expected sample: `sample-root0119-live166167-20261119-v1.json` in the normal
observer state directory. Use `observe_cycle_two` for this two-producer cadence;
do not reuse the sole-166 helper. Its classification tests and strict Clippy pass.

## November 19 22:50 ranged-transfer deployment

The chronological audit passed epochs 0–78. Epoch 79 exhausted its original
transfer plus two bounded retries, each with a response-body transport failure;
it remains unverified. Epoch 80 also encountered two interrupted transfers.
These failures are transport evidence, not proof of archive corruption.

Source `63c030f8bc7802c1f31ef3c4825d64aea5ac4d19`, published to
`account-updates`, replaces a whole-object response with sequential authenticated
64 MiB ranges. The full standalone suite passed 64 tests with zero failures and
one preexisting two-filesystem fixture ignored. Strict all-target Clippy and the
release build passed. The new SDK-path tests cover conditional requests, exact
HTTP 206/range/object identity, interruption, contiguous whole-file hashing, and
the distinction between idle timeout and overall deadline. Full current-plugin
playback, owned-copy cleanup and the original retry budget remain required.

The normal Rust sealer installed `runtime-v9` beneath the HOME-backed root
`/var/lib/jetstreamer/horizon_runtime_data/r2-audit-storage-20261119-v1`.
Its executable SHA-256 is
`70d64c543ed79d8a05f3f2a9afd920ab5612133d4c6f89bfc9bffba1dcfe2ba2`;
its seal receipt SHA-256 is
`9848e46959219be23eba60280bffcc94d7121767951c8cc2691d372ab5ab8739`.
The configuration bytes and resource limits are unchanged.

The owner handoff occurred during epoch 80's empty-scratch retry wait, after
the failed attempt's result and cleanup were durable and before retry 2 was
consumed. `range-v9-transition/STOP_INTENT.json` and `STOPPED.json` bind that
boundary and verify all previous result, inventory and recovery hashes remained
unchanged. The old controller released the exclusive lock. The same service then
started v9 at **22:50:13 UTC**, using ordinary `run` after its sandboxed
metadata-only inventory preflight. Its PID is **2285828**, invocation
**67725d9ba7aa4de994840564f44d963c**. No replay producer was restarted.
`range-v9-transition/START_EVENT.json`, SHA-256
`c043d9d42a50bd2aac7b1ab0c865f3a0ee1759fe6adc6da657aed4d5b5ad2257`,
binds the unchanged reservations and the new owner.

At the coordinated 22:50:52 observation, replay epochs 166 and 167 were both
advancing with zero restarts. All 19 in-range status reports were refreshed and
authenticated. The subsequent audit observation recorded **7,650,410,496 bytes**
of epoch 80's 22,553,556,716-byte download at 22:55:28 UTC. This establishes
transfer progress only. Epoch 79 still needs a separately qualified recovery;
the deployment does not reset its exhausted retries or relabel it passed.

The replacement observer consumers were qualified with 41 passing tests,
strict Clippy and release builds, published in
`2186cd7ee424be6d41019fbaaa54ddc89fbba2dc`, and sealed in `observer-v9`.
Use that directory's `cycle` for the current two-replay fleet. Its accepted
fleet is `root2250-live166retry8-167retry7-homeaudit-observation-20261119-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json`
under `/var/lib/jetstreamer/horizon_runtime_data`; its sole successor observation
was scheduled for **23:25:52 UTC**. The same-clock epoch170 handoff below
supersedes that pending two-peer timer. Earlier immutable images remain intact.

## November 19 23:13 epoch170 admission and observer join

Epoch80's ranged download completed and full plugin playback began at
**23:09:09 UTC**. No pass is claimed until its terminal result is committed.
The archive audit continues independently of replay admissions.

The actual v9 audit identity was included in newly qualified epoch170
`prepare-v5`, `launch-v8`, and `stage-v9` deployments under
`/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1`.
Qualification passed 314 preparer, 21 launcher and 12 staging tests, plus strict
Clippy and release builds. Required source was published before admission.
The retained bounded admission invocation
`72029c086303444e871d150505fc5222` completed at **23:13:18 UTC**.
Epoch170 producer PID **2295526**, invocation
**ebd212d2045145259449d1d5c3d65353**, passed fresh admission and its first
timer-driven guard. Its R2 status was conditionally updated and authenticated.
This is guarded bootstrap until the coordinated observer establishes replay.

The join exposed two observer assumptions that were corrected against the
actual worker: its executable is beneath `scratch/.historical-runtime`, and
scratch/cohort metadata belongs to the admitted `sol` producer. Root-owned
admission and guard evidence still requires root ownership. The resulting
observer suite passed 43 tests and strict Clippy; the normal sealer installed
`observer170-v3` under the same epoch170 HOME base. Use its `cycle170` after
the three-worker sample. The old two-peer timer was stopped and drained before
arming `horizon-observer-root2325-live166retry8-167retry7-170retry6-20261119-v1.timer`
for the unchanged **23:25:52 UTC** clock. Handoff evidence is under
`/var/lib/jetstreamer/horizon_runtime_data/epoch170-join2325-20261119-v1`.
