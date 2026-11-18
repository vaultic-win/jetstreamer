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
