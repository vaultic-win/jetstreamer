# Epoch227 v1.6.25 native-input lifecycle

This route qualifies only restoration/freezing of the retained98063464 snapshot
with the separately sealed FULL-profile v1.6.25 test runner. It never launches
entries, promotes an era, creates an archive/sidecar, or grants R2 authority.
The failed v1.6.20 attempt and its data remain intact.

The unit is `horizon-native-input-227-v1625-7a831420-v1.service`, with new root
`/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-v1`.
Use the dormant template in `scripts/epoch227-v1625-native-input.service`.
Its SHA256 is `f7b921b31063265ff15cc8b6c84e73837c9e4473a9a724f91551911ff2c1a15f`.
Only the parent operator may install/start it after fresh complete admission.
Keep it persistently loaded after exit; this terminal path refuses a collected unit.

The FULL runner is
`/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner`,
SHA256 `df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef`.
Its exact ignored selector is
`runtime::tests::native_epoch227_v1625_cold_input_matches_canonical_accounts_commitment`.
The corresponding FULL worker SHA256 is
`7a831420bb1498ddb0268309ce69f615c7f0c6d90cfab940896a03dc38b5336a`.
The bounded worker and test runner have different hashes and cannot substitute.

The tested guard feature is `epoch227-v1625-native-main-guard`.
The sealed guard is
`/var/lib/jetstreamer/horizon-227-v1625-native-main-guard-v1/jetstreamer-horizon-standalone-guard`,
SHA256 `c06f20aca5a87358bd23ea6a22607b978545f38828c04a4aa693f2bd14718a9b`.
The Rust preparer generated the dormant plan now sealed at
`/var/lib/jetstreamer/horizon-227-v1625-native-cold-plan-v1/native-cold-plan.json`,
SHA256 `1285c668693e09e4b5dd087fd9698e208b90c3b9ed1efb32d003d5ff7631df21`.
Preparation restores no snapshot and grants no execution permission.

The uploader exposes three independent, self-hash/spec-hash-bound commands:
`admit-native227-v1625-input`, `capture-native227-v1625-input`, and
`capture-native227-v1625-terminal`. Their specs use respectively
`jetstreamer-private-epoch227-v1625-native-admission-spec-v1`,
`jetstreamer-private-epoch227-v1625-native-capture-spec-v1`, and
`jetstreamer-native227-v1625-terminal-capture-spec-v1`.
Running capture permits only `mode:"running"`; it requires a real first
sandboxed guard fire, stable original MainPID/IID, exact unit file and effective
sandbox, then writes the immutable origin at
`/var/lib/jetstreamer/horizon-227-v1625-native-capture-actual-v1/intent.json`.

Admission shares the existing closed disk/memory arithmetic, century-floor
calculation and maximum existing guard baseline. It reserves128GiB maximum
memory and300GB scratch, with8CPU affinity,45-minute bound and no restart.
It requires each of the four live producers204,205,209,225(shared226) to retain
its exact observed invocation, original guards and remaining growth. It also
retains the failed original227 diagnostic/IID/launch/gate/current-manager evidence;
an unexplained omission or stale active original227 is rejected. Any newly live
native210 or other unmodeled auxiliary blocks this four-owner admission. The
parent coordinates launch order and fresh complete evidence.

Central fleet registration adds only the new native claim and its exact metadata
event. Preserve the original failed227 diagnostic and its launch evidence.
The claim remains private input verification and keeps227's failed repair gate;
neither a running claim nor successful input proof is archive completion.
The coordinated observer supports both exact227 runtime tuples independently and
rejects cross-runtime, wrong-epoch or diagnostic-runner telemetry.

Publish the real active native phase as dashboard `verification` using the
existing gated pipeline publisher and authenticated readback. Refresh on the
single normal30-minute cadence; the capture event supplies initial status.
Actual terminal proof independently binds the original running origin, full
raw journal, ordered canonical marker/test/PID1-success, exact zero-restart
loaded terminal owner, and fresh complete unchanged census. Never rerun a Bank
to reconstruct its outcome or borrow the v1.6.20 qualification.
After an accepted terminal fleet event, the existing gated inactive-status
cleanup recognizes only this exact native owner's matching publication. It
protects live replacements and downstream work, conditionally deletes only the
status key, verifies authenticated absence and preserves receipts/history.

All new replay, full-root, current-plugin, publication, upload and sidecar gates
remain independent. In particular this component does not make the existing
generic v1.6.20 node a valid v1.6.25 bounded/full parent.
