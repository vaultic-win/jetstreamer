# Full epoch 209 independent singleton handoff

This is the closed full209 route, separate from the already successful native
bootstrap. The ordinary compatibility registry remains unchanged. The node must
verify canonical root 90719638, continue through all 361 following slots, and
produce exactly 432000 output slots, 90288000 through 90719999. No successor
epoch's replay or snapshot is required to finalize or upload209.

## Bound deployment

| Member | Absolute path | SHA-256 |
| --- | --- | --- |
| Node | `/var/lib/jetstreamer/horizon-singletons209-212-node-0d2856e7-v1/jetstreamer-node` | `e4b1df9aa6430456e703c283a7ed3512f5b5ada489d016b98e9d47332836ec4f` |
| Worker | `/var/lib/jetstreamer/horizon-v1616-shrink-budget-worker-003fe15-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget` | `4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc` |
| Preflight | `/var/lib/jetstreamer/horizon-singletons209-212-metadata-0d2856e7-v1/preflight209-singleton.json` | `cd82831678b99ea6c217e476bb6343c8f5f3f308a93dd74db325ec1f50798a75` |
| Successful native proof | `/var/lib/jetstreamer/horizon-native209-terminal-proof-v1/proof.json` | `6a63cb7f95c67e9defa58cb232878cf5ebc4296c99469461e50e0ab846c5bf85` |
| Whole-root guard | `/var/lib/jetstreamer/horizon-209-singleton-main-guard-v1/jetstreamer-horizon-standalone-guard` | `9eb141c40202fb34616b624e2977c8fb9b4e8b30cde151a24db952ebeff919df` |
| Full verifier | `/var/lib/jetstreamer/horizon-full209-verification-tools-v1/verify_archive` | `6b757a5549bb6ae5dfb0c880274b54c7fa6e2fd2980c10af3455556a1c174260` |
| Current plugin pipeline | `/var/lib/jetstreamer/horizon-full209-verification-tools-v1/horizon_pipeline` | `d542cbefd3ddff4e4d707daed4142039b8a5bb89cbd3f7acca082351c2bc60cf` |

The native proof records the actual successful invocation; do not rerun its
Bank. Capacity probes of the verifier/plugin establish format capability only.
They are not receipts for the future full archive.

## Preparation and admission

All helper commands use the sealed `jetstreamer-r2` binary, exact immutable spec
path, `--spec-sha256 HEX --self-sha256 HEX`. Bind actual digests after each
no-clobber receipt is produced. No proposed value substitutes for an execution.

1. `prepare-singleton209-inputs` accepts schema
   `jetstreamer-private-epoch209-singleton-input-capability-spec-v1` and fields
   `schema, output`. Output is exactly
   `/var/lib/jetstreamer/horizon-209-singleton-capability-v1/capability.json`.
   It rehashes node, worker, preflight, cached snapshot and genesis without
   restore, resources, replay or network access. Retain the capability digest.
2. Prepare only a fresh mode0700 owner1000 run root
   `/home/ubuntu/.jetstreamer-private/qualification-209-singleton-capped-v1`
   containing an empty mode0700 `output/`. Admission rejects old attempt data.
3. `admit-singleton209` accepts schema
   `jetstreamer-private-epoch209-singleton-admission-spec-v1`, `mode:"replay"`,
   bound files `observer, fleet, capability, native_input, resource_plan`, a map
   `protected_guards`, and `output` below a fresh
   `/var/lib/jetstreamer/horizon-209-singleton-admission-*/admission.json`.
   Use the complete current accepted observation; never resample for this helper.
   Its live race checks do not replace the coordinated resource observation.
4. Resource-plan schema
   `jetstreamer-private-epoch209-singleton-resource-plan-v1` binds `epoch:209`,
   `mode:"replay"`, exact `unit, run_root, node_sha256, worker_sha256,
   snapshot_sha256, guard_sha256, manifest_fingerprint`,
   `candidate_incremental_peak_bytes:471798691840`,
   `maximum_scratch_bytes:300000000000`, `memory_max_bytes:225000000000`,
   `memory_high_bytes:150000000000`, `maximum_runtime_seconds:259200`, and the
   recomputed `guard_minimum_free_bytes, required_initial_free_bytes`.
   The latter equals protected floor plus471798691840. The protected floor is
   at least the current twice-average-century `.jet` floor plus every other
   owner's remaining guarded growth. Preserve full227 whole-root credit and
   remaining hard-memory growth,204/205/225 and all auxiliaries. All six fields
   `runtime_promotion_authorized, full_epoch_qualified,
   canonical_sidecar_authorized, publication_authorized, remote_mutations,
   r2_mutations` are false.

The historical terminal-from333 fleet contains four owners. It is not current
launch authority after another owner starts. In particular, a live223v2 repair
is rejected until its exact registered envelope/guard/memory model is supported
or its independently validated terminal proof is bound through optional
`terminal223` in the admission spec. That binding must validate the existing
`jetstreamer-private-warmup223-native20-terminal-v2` validator, exact actual
IID `58ab3d9221a6452685b8eab3ceabdb49`, original v2 runner/plan/origin,
preserved journal and controlled result gates. Its observer and predecessor
fleet must equal this admission's accepted pair, so the saved334 live sample
can carry forward only after that actual owner terminates. A proof supplied
for another observation, origin, invocation or warmup profile is rejected.

The helper preserves the complete original fleet and unit census as evidence;
only derived arithmetic excludes the positively terminal owner/sample/guard.
It grants no credit for retained disk or presumed memory reclamation. Actual
free space and memory remain bracketed before/after, every other owner remains
protected, and the existing terminal-owner/no-later-invocation checks run
before/after admission and launch capture. Capture and status binding retain
the exact terminal proof and accounting evidence. This path never starts or
terminates223 and does not qualify its prefix or close its repair.

Do not omit223, pretend it is the older native-only profile, subtract its
reservation while live, or launch against the old333 receipt. Freshness remains1800seconds;
the225GB reservation must also fit the century's1.5x observed RSS ceiling and
the90percent host-memory target after protected hard-memory growth.

## Actual producer, first guard and capture

The [dormant service](epoch209-singleton-service.service) is named
`horizon-singleton-209-capped-4aeca563-v1.service`. Copy genesis only after
admission. The exact command has no focused or preflight-only option. Never
start from this document alone: the campaign owner owns admission and dispatch.

After actual start, bind its actual IID in a
`jetstreamer-horizon-standalone-guard-plan-v1` with `filesystem:"/"`,
`worker_root` equal to the entire run root, `maximum_root_physical_bytes:471798691840`,
`maximum_worker_vmas:3500000`, the admitted protected `minimum_free_bytes`, and
a private root-owned `receipt_directory`. No native, bounded-canary or
bounded-measurement exception is permitted. Use the sealed guard's
`--plan-sha256` and `--self-sha256` checks. Require an actual sandboxed no-trip
first fire, one real worker and exact PID1 successful completion.

The guard service/timer names are
`horizon-singleton209-protective-v1.service/.timer`. Capture requires root
oneshot, no restart, strict system/read-only home, private network,
`NoNewPrivileges=yes`,1GiB memory,256tasks,100percent CPU and only the exact
receipt directory writable; its timer must be active/waiting. Keep the guard's
protective cadence separate from routine resource/status observations.

`capture-singleton209` accepts schema
`jetstreamer-private-epoch209-singleton-capture-spec-v1` and bound files
`admission, guard, guard_plan`, plus `output` below a fresh
`/var/lib/jetstreamer/horizon-209-singleton-capture-*/launch.json`.
It requires capture within900seconds of admission, exact effective service
sandbox/environment, native proof, unchanged complete owner census and actual
guard identity. The resulting launch authorizes neither qualification nor R2.
Register its actual diagnostic claim before routine fleet/status reconciliation.

## Status and independent delivery

Use `status-publish-full209` with schema `jetstreamer-full209-status-plan-v1`.
Bind `mode` (`launch-event` or `observation`), `observer, fleet, launch`, private
`receipt_directory, estimate_receipt`, positive
`initialization_allowance_millis, fallback_slots_per_second`,
`downstream_allowance_millis`, `estimate_basis, estimate_evidence`.
The downstream map includes all seven positive allowances:
`archive_close, boundary, full_verification, plugin_verification, upload,
readback, sidecar_commit`. Preserve the original producer clock. Launch-event
publication then the single coordinated1800second observation cycle covers all
active work. Use only legal wire phases; this adapter reports `verification`
during initialization and `replay` during actual transaction execution.

The status adapter resolves the actual generation's private `.jet`, then the
imported `output/epoch-209.jet`; it never invents a path or archive size. A full
producer must terminate cleanly with complete cohort/root/tail/native evidence
and a correct local archive/sidecar pair before independent delivery starts.

The independent commands are:

```text
/var/lib/jetstreamer/horizon-full209-verification-tools-v1/verify_archive ROOT/output/epoch-209.jet --full --internal-full --threads 8
/var/lib/jetstreamer/horizon-full209-verification-tools-v1/horizon_pipeline 209:209 ROOT/output --threads 8 --verify-only
```

`ROOT` in these command templates is the fixed full209 run root above. Admit
each stage's real resource envelope and actual owner separately. Full and
current-plugin verification must record success bound to the same unchanged
complete archive digest before upload. A command line or successful capacity
probe is not a verification receipt. Use reviewed receipt-producing Rust
orchestration; if it has not yet been deployed for209, keep delivery dormant
until that bridge is implemented and tested. Do not synthesize generic
receipts, reuse another epoch's receipts, or silently add new shell/Python
business logic. The source preparation here does not claim that bridge is live.

The existing `status-publish-pipeline` accepts this genuine launched origin's
`evidence.units`; retain the full209 origin unit/IID/start clock when handing
off to actual `full-verification`, `plugin-verification`, `upload-readback`
owners. Use bounded units such as `horizon-full-verify-209-singleton-v1.service`,
`horizon-plugin-verify-209-singleton-v1.service`,
`horizon-upload-209-singleton-v1.service`. Wire phases are `verification`,
`upload` or `readback`; the estimate always includes sidecar publication.

After both independent receipts, use the existing Rust `jetstreamer-r2 sync`
with the fixed output directory, `--epochs 209-209`, private authenticated
receipt directory and the existing shared upload serialization/lock. The
orchestrator must enforce those receipts before invoking sync; sync itself does
not infer the verification policy. Never start an overlapping progressive
coordinator. Do not pass `--delete-local`. Whole-object authenticated R2 SHA-256
readback, source revalidation and matching sidecar publication remain mandatory.
Only after that commit may the exact owned status JSON be conditionally removed.
No anonymous URL or public-access check is required.

Both208/209 and209/210 independent boundary receipts are still required for
local retirement. A missing successor does not delay209's independently
verified upload or remote sidecar, but must retain its local pair. Never replace
or weaken these gates to reduce an ETA.
