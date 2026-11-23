# Retire obsolete files from completed Horizon epochs

This standalone Rust tool removes explicitly selected private files for epochs
201–300 after their **complete** canonical archive is verified in R2. It supports
superseded partial archives, failed attempts and disposable caches whose bytes
are intentionally different from the complete archive. It never writes to R2.
Use `jetstreamer-r2 retire-local` for canonical local pairs instead.

The operator must establish each file's epoch association and check staged
dependencies before setting the two authorization fields in a plan. The plan
contains exact paths and filesystem identities, hash-bound whole-readback
receipts, a hash-bound qualified R2 inventory executable, inactive systemd units,
and a fresh audit filename. See the strict `Plan` structure in `src/main.rs`.
Keep compact provenance and verification evidence outside the selected files.

Build and test using this crate's manifest and locked dependencies. Seal the
binary and root-owned plan with `jetstreamer-seal-deployment`. Supply credentials
through the existing Horizon environment, never through the plan or arguments:

```text
horizon-retire-completed PLAN PLAN_SHA256 SELF_SHA256 --check-only
horizon-retire-completed PLAN PLAN_SHA256 SELF_SHA256
```

Both invocations acquire the existing local mutation lock, inspect consumers,
and obtain fresh authenticated inventory. Execution repeats identity and consumer
checks and fsyncs intent/completion records around each unlink. It refuses
symlinks, multiply linked files, small metadata and files outside the private
root, except the exact obsolete epoch 246 bootstrap snapshot selected by the
`external_bootstrap_review` route. That route permits one hard-coded path and
epoch, requires an immutable Main review binding its exact identity, original
copy completion, staged-consumer evidence and all four original consumer units,
and hashes the file against its original accepted SHA-256. It retains all normal
R2 readiness, no-consumer, mutation-lock and identity checks. It does not allow
retiring the deployment directory, sibling metadata, or any other external file.
The audit is created without overwriting any existing evidence. If a run
is interrupted, retain its audit and prepare a new exact plan and audit filename
for only the remaining files; never reuse an old identity or claim a planned
deletion succeeded without checking its outcome.

On 2026-11-18 the exact external epoch 246 bootstrap route passed nine tests,
strict Clippy, a clean captured release build from published `8decfe9b`, and
native check-only validation. The sealed executable is
`/var/lib/jetstreamer/horizon246-retirement-20261118-v1/horizon-retire-completed`,
SHA-256 `89aa3a83100904c7ae0f46e9334ff5554df4fdb86fc5161a117492dc1df1d37e`.
Its original invocation `99de86d86b1843a38a1f78e7ac50fdc9` completed normally.
The exact retirement plan and Main review are sealed in
`/var/lib/jetstreamer/horizon246-bootstrap-retirement-plan-20261118-v1` and
`/var/lib/jetstreamer/horizon246-bootstrap-retirement-review-20261118-v1`.

Execution revalidated the target, matched fresh authenticated R2 inventory to
the original whole-object receipt, repeated the consumer checks under the shared
mutation lock, and removed **13,110,140,928 allocated bytes**. The audit is
`/home/ubuntu/.codex/diagnostics/horizon246-bootstrap-retirement-review-20261118-v1/retirement-audit.jsonl`.
The selected snapshot is absent; all four sibling metadata files remain.
No R2 object was modified. The completed plan cannot be reused as another file's
authority, and the remaining immutable metadata is retained as audit evidence.

Build with `--features anza-parked-183` for the exact closed Anza lane-a epoch 183
copy. Supply the native `holding_custody` receipt as an additional path and
SHA-256 binding in the plan. The tool checks the terminal holding worker and
authenticated scratch body and manifest, then checks canonical R2 readiness
under the original controller, holding, and local mutation locks. Use the
same check-only and execution commands shown above.
