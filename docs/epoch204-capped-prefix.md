# Private epoch 204 capped-shrink prefix

`jetstreamer-epoch204-shrink-root-prefix-resource` is a separately compiled
profile using the existing bounded resource runner. It binds the retained
88127580 snapshot (`d3114597…`, 8,215,471,895 bytes), unchanged 025757b9… parent
and 4aeca563… v1.6.16 capped-shrink worker. Its two checkpoint names cover only
88127580→88559361. Replay starts 88127581; canonical output is 88128000→88559361
(431,362 slots). The remaining 638 epoch 204 slots are unqualified.

The 300 GB decimal scratch limit is the user's current century allowance. Fresh
admission must also protect existing invocation-bound growth, current scans and
the century archive-size floor. The72-hour bound, exact known-root manifest and
natural zero-exit completion are mandatory. A progress marker cannot qualify
the prefix. No checksum, import, R2 mutation or runtime promotion is authorized.

Use `--storage-capability` first under the exact immutable input package and
sandbox. Pre-create the run root and its `scratch`, `output`, `receipts` and
`ledger` children as the replay user, all mode 0700. This branch hashes every input, copies only genesis, records the exact
prepared parent command and exits before worker spawn, scratch observation,
snapshot restore or archive creation. Its receipt never admits replay. Actual
launch still needs independent fresh fleet/memory admission, disjoint ownership,
and a proven invocation-bound protective guard. Native checkpoint comparison,
suffix replay, complete V4 assembly, full/current-plugin verification and
publication remain separate qualifications.

The `jetstreamer-r2 admit-prefix204` command requires the actual 203 scan admission,
the exact no-spawn204 capability, a fresh complete fleet/observer pair, and fresh
225/205 protective guard receipts. It preserves both replay invocations and the
actual 203 scan, checks their configured and kernel memory limits, uses this
century's 1.5× aggregate-RSS allowance for the new lane, and repeats the complete
census before writing an immutable admission. The protected disk allowance is
the recomputed century floor plus 640 GiB for 225,300 GB for 205 and 128 GiB for the scan;
the candidate adds 300 GB scratch plus 160 GiB output/margin. The scan's completion
or handoff requires reconciliation before this exact admission can be reused.

`capture-prefix204` separately verifies the actual new invocation, exact command,
live sandbox, 300 GB own-root/VMA guard and the first real protective timer fire's
PID1 success. Fleet registration is observational and grants no new replay or
publication authority. Neither command can borrow 205's capability or receipts.
