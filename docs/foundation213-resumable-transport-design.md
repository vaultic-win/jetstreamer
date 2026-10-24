# Source-only Foundation 213 partial restore continuation

Base: cb69cfcd70105217e71f58d43bae46208957ae71, directly, preserving its descriptor-anchored retirement and same-mount quarantine fixes. This worktree is distinct from 75007955 and the canary branches. No active transfer, e158 fleet/status helper or actual 55eccc74 holding runtime is changed.

The new opt-in command is `holding-foundation213-restore-resumable`, with schema `jetstreamer-foundation213-resumable-restore-plan-v1`. Existing restore entrypoints and `restore_blob` behavior remain unchanged. The opt-in command accepts only the exact reviewed Prefix213 custody/mapping and retains the same serialized transition lock, remote owner/manifest/HEAD checks and fresh complete admission. No remote mutation or replay authority is added.

The byte path opens the one existing root-owned nlink1 regular `.<sha>.partial` without following symlinks, validates its exact path/descriptor identity, mode0600 or complete0400, expected length bound, and protected disk floor. It locally hashes the entire actual prefix from offset0 through its current length, requires unchanged inode/length/mtime/ctime/ownership/mode across that read, and positions the writer at exactly that arbitrary byte offset. No alignment rounding or truncation is allowed. The local prefix hash is not a completion proof.

Only the missing suffix is fetched, using a narrowly bounded conditional If-Match range primitive, exact response ETag/Content-Range/length checks and ordered delivery. New range planning starts at the actual prefix length. Eight requests use ranges capped at32MiB: eight payload buffers plus a conservative duplicate collection/copy allowance fit within512MiB. Existing callers retain their current concurrency/range planner. New transport flushes durable progress at complete range boundaries; failed writes leave only a contiguous prefix, which the next invocation rehashes locally.

The running SHA256 includes the local prefix and every suffix byte in canonical order. The exact complete expected SHA256 and full byte length must match before any sealing. The complete local file is also rehashed/revalidated before chmod0400. A true whole-file0400 partial is reusable without network, but is independently rehashed. The original fresh admission callback still runs immediately before no-clobber rename; a stale callback leaves the complete0400 partial available for the next genuinely fresh admission. Existing post-restore remote identity/native checksum/admission checks remain.

New receipts must distinguish local prefix rehash plus conditional suffix readback from a fresh full-object network readback. They may claim whole-file expected SHA256 verification only after actual complete proof. No partial digest, length, ETag or saved cursor is success evidence by itself. No object/archive overwrite, removal, cleanup, deployment, network probe, live archive read, host job or operational retry is authorized by this source work.

Offline fixtures cover zero/interior/nonaligned/full prefixes; precise requested offsets; stale/changed ETag failures; corrupt prefixes; short/oversized responses/files; symlink/hardlink/changed prefix identity; interrupted range/write retries; stale precommit retaining0400; and correct complete SHA256. Tests will use in-memory fake range fetches and disposable files. Root owns actual retry only after genuine terminal and fresh complete admission.

## Concrete source and retirement coupling

Implementation is in `jetstreamer-r2/src/holding_resumable213.rs`; the opt-in dispatch is in `holding_foundation213.rs`. Existing generic `restore_blob` and the legacy Foundation restore command are unchanged. The new command uses a separately bounded SDK GET primitive (no application retry-from-zero loop), checks exact conditional If-Match/ETag/Content-Range/Content-Length and bounds streamed body collection before copying it. Transient failure retains contiguous bytes for a later genuinely admitted attempt.

The new receipt schema is `jetstreamer-foundation-holding-resumable-restore-v1`. It records actual local-prefix and network-suffix counts plus full expected-SHA256 proof, an independent complete local rehash and revalidated remote identity. `remote_sha256_readback` is true only when no local prefix was reused. `retirement::restoration_transport` now accepts only this exact Prefix213 form with counts summing to the exact full length and every complete-proof flag; all original mapping/custody/ETag/owner/segment/no-authority, complete-file rehash, fresh capacity, closed-reference and anchored quarantine/unlink gates remain. Legacy receipt semantics remain unchanged.

Operational continuation is explicitly **standalone new-command restore, then fresh new-tool retirement**. Root must first observe the existing maintenance job genuinely terminal and obtain a fresh complete restore admission. Root may then use the newly qualified/sealed cb69-descended binary for `holding-foundation213-admit-restore`, the new resumable restore command/schema, and, after another genuine fresh closure/admission, `holding-foundation213-retire` bound to the new restoration receipt. The old cb69/55eccc74 binary must never be given the unsupported new receipt or relabel it. No automatic legacy maintenance retry/finalize adapter is added. Root owns any later journal/finalizer reconciliation separately.

Full root-owned nlink1 identity is checked again before complete verification/sealing, and after the precommit callback. The initial inode, uid, gid and permitted mode must survive the tail download; controlled sealing changes only mode to0400. A conflicting hardlink, ownership/mode change or path replacement is preserved and never renamed into the final blob. A disposable root-only fixture tests actual stale admission retaining/reusing0400 and injected filesystem identity changes before final proof and during the callback; it touches no host/R2 paths and uses only a local fake server.

## Qualification (source-only, 2026-10-24)

Build settings preserve the shared release profile, with `CARGO_INCREMENTAL=0`,
`CARGO_TARGET_DIR=/home/ubuntu/workspace/jetstreamer/target`, `--offline --release -j2`,
and no custom rustflags/linker/debug settings. The prior sealed source qualification
records helper `55eccc74` from `4cb41b04`; its surviving qualification manifest does
not record command-line flags. The preserved source capacity review explicitly
records `--all-features` selecting `native227-small`. Accordingly the new candidate
is qualified and built with `--all-features` (both `native210-small` and
`native227-small`), directly descended from cb69. This does not transplant the
75007955 retirement implementation.

- Default-feature R2 suite:646 passed,0 failed,48 ignored.
- All-features R2 suite:646 passed,0 failed,48 ignored.
- Exact all-features root-owned disposable fixture:1 passed,0 failed. It used only
  temporary local files and an ephemeral loopback HTTP endpoint.
- Default and all-features strict release/all-target Clippy:passed.

Logs are preserved at `/tmp/foundation213-resumable-full-tests-v1.log`,
`/tmp/foundation213-resumable-allfeatures-tests-v1.log`,
`/tmp/foundation213-resumable-allfeatures-root-fixture-v1.log`,
`/tmp/foundation213-resumable-clippy-v2.log`, and
`/tmp/foundation213-resumable-allfeatures-clippy-v1.log`. The initial root fixture
failed because its temporary parent mode was not explicitly0700; only fixture
setup was corrected, and `/tmp/foundation213-resumable-root-fixture-v1.log` is
retained. Production identity/permission checks were not relaxed.

Frozen production build provenance and copied-candidate SHA256 are written to the
separate unsealed candidate directory after commit. Root owns all sealing, sandbox
qualification and operational admission. No deployment or R2 mutation is part of
this qualification.
