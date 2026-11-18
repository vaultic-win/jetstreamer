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
