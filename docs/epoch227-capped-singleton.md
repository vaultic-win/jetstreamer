# Epoch 227 capped singleton candidate

Build the original pinned v1.6.20 worker with the exclusive
`epoch227-capped-qualification` feature under rustc 1.51.0. This is a separate
candidate from epoch223's prefix and from the v1.6.25 diagnostics. It admits
only cold snapshot 98,063,464 and entries 98,063,465–98,495,999. The additional
`epoch227-capped-warmup-diagnostic` feature reduces the upper bound to
98,063,480; it cannot substitute for the full singleton worker. Neither feature
changes the default worker or permits another epoch. Combining either profile
with epoch223 or singleton execution diagnostics fails compilation.

The only execution change caps the physical AccountsDb shrink debt at 250,
matching the existing epoch223 storage maintenance candidate. Transaction,
account loading, fees, PoH, Bank hashing and native account updates remain the
original runtime. Synthetic regressions check the exact bounds, reject malformed
out-of-scope batches before decoding or Bank mutation, and confirm storage debt
recovery preserves capitalization, Bank hash, last blockhash, balances and the
global write cursor. These tests do not establish native snapshot equivalence
or full replay qualification.

The retained input package is
`/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1`. Do not redownload or
duplicate its 10,261,480,487-byte snapshot. Its exact SHA-256 is
`77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07`;
the independently pinned accounts hash at slot 98,063,464 is
`4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR`.

The ignored `native_epoch227_cold_input_matches_canonical_accounts_commitment`
test in the warmup build rehashes this exact input, restores it through the
native snapshot loader and freezes the bootstrap Bank without replay entries.
It requires an empty owner-private canonical scratch directory named `scratch`
beneath `/home/ubuntu/.jetstreamer-private/native-input227-v1620-*`, supplied as
`JETSTREAMER_EPOCH227_V1620_TEST_SCRATCH`. Its output compares the canonical
accounts commitment and requires no bootstrap account writes, unchanged native
transaction count and unchanged write version. Seal the executable and plan;
coordinate its memory, disk and runtime envelope with the complete live fleet
before execution. A successful cold-input test authorizes neither replay nor
publication.

The shortest full delivery route uses the existing ordinary node's
`--root-checkpoint-cohort` mode with singleton range 227, the retained
`preflight227-singleton.json`, fingerprint
`sha256:99fa3de5ed1da720b76e33196d4ef4da9dda57202f12af90eaab60f84f9ecd31`,
`--verify`, and the exact retained snapshot override. Bind the separately sealed
capped worker through `JETSTREAMER_HISTORICAL_WORKER_V1_6_20`, opt into the
candidate runtime and use a fresh isolated private output/run root.

The cohort route requires a canonical root within the final epoch, not exactly
at its last slot. This manifest supplies root 98,495,291 with accounts hash
`GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq`. The existing verifier must
observe that exact root, continue through the final 708 slots, and finish while
native terminal completion, ordered archive chain and full output coverage
98,064,000–98,495,999 all pass. No prefix assembly or checkpoint restart is
needed if that unmodified full route succeeds. Independent full/current-plugin,
boundary, authenticated upload/readback and sidecar gates remain unchanged.

Use the user's 300 GB decimal century scratch planning allowance separately
from output, margin and century floor. Fresh complete fleet admission, actual
guard protection, native input proof, exact-package capability and real replay
qualification remain required. Do not treat the old uncapped peak, an early
CLI rejection, a sealed package or these source regressions as those proofs.

## Admission and guard handoff

`epoch227-singleton-service.service` is a dormant review template for
`horizon-singleton-227-capped-710f6523-v1.service`. Prepare its fresh owner-private
run root and `output/` child before loading it. Reject an existing epoch227
archive, active owner or retained attempt rather than restarting over it. The
parent copies and binds its worker as `historical-worker` inside the private
generation, as required by the existing standalone guard.

The separately sealed Rust `jetstreamer-epoch227-input-capability` accepts an
absent receipt path beneath root-private
`/var/lib/jetstreamer/horizon-227-input-capability-*` and `--self-sha256 HEX`.
It rehashes the fixed original node, capped worker, retained snapshot, genesis,
preflight and capped deployment seal, validates singleton/root scope and writes
one durable no-clobber receipt. It starts no worker, restores no snapshot,
creates no archive, polls no fleet and contacts no R2.

Fresh admission must bind that capability and the successful native cold-input
proof, one accepted complete fleet/resource observation, authenticated R2
inventory, recomputed century floor, every live claim's remaining growth,
protective guard identities and all auxiliary jobs. Account for native223 while
active; afterward bind its terminal result and retained scratch. Recheck protected
identities and actual resources before and after admission. Reserve1.5 times the
maximum observed aggregate lane RSS for this century, using the user's150GB seed
only while actual evidence has not superseded it. The service's150GB high/225GB
maximum are cgroup ceilings, not observed RSS. Check CPU, VMA and I/O separately;
do not borrow another host's lane count or another century's resource model.

The pending disk envelope is471,798,691,840 bytes:300GB decimal scratch,128GiB
output and32GiB margin. Initial free space must exceed that envelope plus the
current century floor and every other protected remaining growth claim. The
guard floor excludes this lane's own envelope but preserves that same protected
remainder. Its plan uses schema
`jetstreamer-horizon-standalone-guard-plan-v1`, the exact service invocation ID,
`filesystem:"/"`, the entire run root as `worker_root`,
`maximum_worker_vmas:3500000`,
`maximum_root_physical_bytes:471798691840`, and a root-private receipt directory.
The own-root cap includes private output; scratch alone still has a300GB planning
allowance. Seal the invocation-specific plan only after the service identity
exists. Deploy the reviewed own-tree guard and its persistent safety timer;
prove its first actual no-trip receipt has the exact invocation and one bound
worker before unattended admission. A zero-worker startup sample is insufficient.
Guard failures, budget errors or changing identities prevent that admission.
This safety cadence must not add a second replay observation loop.

Existing epoch204/205 admission commands have closed prefix contracts and cannot
admit this singleton by substituting its inputs. The campaign owner must add the
exact227 admission/launch contract to the Rust fleet tools, binding current
observation, native proof, capability, guard and service sandbox. Keep the service
dormant until integration and first-fire proof pass; then register epoch227 in
the single30-minute status-publication and downstream handoff cycle.

The separate `singleton227`, `singleton227_admission` and
`singleton227_capture` Rust fleet modules implement that closed contract.
The campaign owner wires their declarations and CLI forwarding functions in
the shared fleet/main modules. Admission CLI shape is
`admit-singleton227 SPEC --spec-sha256 HEX --self-sha256 HEX`; capture has the
same shape with `capture-singleton227`. Both require an immutable root-owned
helper. The admission spec binds `schema`, `mode` (`native-cold` or `replay`),
`observer`, `fleet`, `capability`, optional `native_input`, `resource_plan`,
`protected_guards` keyed by every live replay unit, and private `output`.
Each binding is `{path,sha256}`. Native-cold mode forbids a preexisting native
qualification; replay mode requires the actual successful qualified receipt.

The resource plan schema is
`jetstreamer-private-epoch227-singleton-resource-plan-v1`. Bind `epoch:227`,
`mode`, exact `unit`/`run_root`, `candidate_incremental_peak_bytes`,
`maximum_scratch_bytes:300000000000`, `guard_minimum_free_bytes`,
`required_initial_free_bytes`, exact `worker_sha256`/`snapshot_sha256`, and false
`publication_authorized`/`r2_mutations`. Derive the protected floor from the
accepted complete authenticated inventory and all active owner's reviewed
envelopes, then seal this plan; do not transcribe a stale floor from another
attempt. Output must be an absent `admission.json` beneath a root-private
`/var/lib/jetstreamer/horizon-227-admission-*` directory. Exact repeated specs
recover the existing receipt without renewing freshness.

Capture specs bind `schema`, `mode`, `admission`, `guard`, `guard_plan`, and an
absent private `output` beneath `/var/lib/jetstreamer/horizon-227-capture-*`.
The native zero-entry service has its own review template,
`epoch227-native-input-service.service`, and exact unit name
`horizon-native-input-227-capped-710f6523-v1.service`. It uses disk scratch,
112/128GiB high/hard memory caps, eight CPUs and a45-minute execution ceiling.
Its guard uses the entire native attempt root, a300GB physical cap and the
admission's exact protected floor. Use the separately compiled
`epoch227-native-main-guard` profile, never the ordinary replay guard. Its
`native_main` binding names the exact optimized native test executable,
SHA-256 and live MainPID. It requires that PID to be the only cgroup process,
checks its actual mapped executable inode and digest through `/proc/PID/exe`,
and counts its VMAs. Escaped/replaced executables, unreadable maps and additional
processes stop the exact bound invocation. The ordinary historical-worker route
and healthy sealed guard deployments remain unchanged. Native capture requires
one explicit native owner below the VMA ceiling and an actual successful terminal
test. It binds the successful test journal to the exact guard
invocation/PID, preserves raw consensus integers, checks the canonical bootstrap
commitment and requires zero replay entries and bootstrap writes.

Use persistent safety services/timers named
`horizon-native227-protective-v1.service/.timer` for cold input and
`horizon-singleton227-protective-v1.service/.timer` for entry replay. They run
the reviewed immutable own-tree guard, with only its private receipt directory
writable, root UID, private network,1GiB hard memory, one CPU and256 tasks.
Capture requires the exact guard invocation's PID1 successful completion and
an active waiting safety timer. Native qualification never authorizes entry
replay or archive publication. Register active native input verification in the
campaign fleet and publish its dashboard status through the generic reviewed
verification publisher, binding the live native origin and accepted fleet.
Use the coordinated observer and ETA binding when entry replay actually starts.

The native harness must be the optimized historical rustc1.51 build at
`/var/lib/jetstreamer/horizon-227-native-test-optimized-v1/native-input-test`,
SHA-256 `1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3`.
The earlier debug harness remains preserved and is not qualified for this launch.
The new native guard is sealed at
`/var/lib/jetstreamer/horizon-native227-main-guard-e53a03e5-v2`, SHA-256
`e53a03e5a97ace54439db60ee3776117af68beebb892d03f34cfa8cceef118d9`.
Entry replay retains its independently reviewed old guard/hash.

Set `native_running:true` in a native capture spec to create a protected live
`intent.json` before the test finishes. It requires the actual MainPID/VMA guard
fire and live sandbox, emits no qualification claim, and includes a generic
`verification_status` object describing the active native input check. Use
`native_scope`, `native_claim` and `native_live` hooks when registering this
intent as a private cold-snapshot pipeline in the campaign ledger. The same
capture command without that flag later requires the actual successful terminal
test and writes `native.json`. Neither intent nor qualification is an entry
replay or a sidecar countdown. The campaign owner must bind any dashboard
verification-status publication to its reviewed publisher and ETA model.
