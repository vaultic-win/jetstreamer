# Exact condition-blocked old220 peer capture

This separate workspace preserves the pinned `horizon-old220-peers1012` library
and original five role specifications. The imported source packet is identified
in `IMPORT-PROVENANCE.json`; its source files and fixtures were rehashed before
import. The separate workspace keeps its original dependency lock and avoids
changing the main workspace dependency graph.

The opaque condition-blocked proof retains original recipes, commands, history,
environment and conditions, and independently verifies each installed negative
marker guard and its sealed package. Potential program inputs and unqualified
historical loader behavior remain separate from currently admitted reads.
It cannot authorize old220 retirement or replace the complete global closure and
immediate-predecessor integration still required by that operation.

`jetstreamer-old220-peer-capture ADMISSION ADMISSION_SHA256 SELF_SHA256` is the
finite native capture adapter. It accepts only a fresh Root-sealed admission,
normal artifact/source lineage, actual Root service MainPID/start time/IID/cgroup,
512MiB memory, no swap, two CPU quota,128 tasks and180-second service lifetime.
It checks actual kernel identities/capabilities/limits and the strict sandbox,
including before/after mountinfo equality and the exact result-directory mount.
Writable API mounts are explicitly limited to private `/dev` (tmpfs), `/dev/pts`
(devpts), `/dev/shm` (tmpfs), `/dev/mqueue` (mqueue) and `/proc` (proc); other
ordinary data paths must be read-only. It publishes one Root-private result by
fsyncing a private temporary file, renameat2(RENAME_NOREPLACE), then directory
fsync. A pre-existing result is never replaced. Its queries use bounded anonymous
streams and finite process-group timeouts, preserve raw replies, and use only
read-only systemctl/busctl queries. It never executes legacy jobs or calls GCS.

The normal lineage schema is
`horizon-old220-peers1061-normal-lineage-v1`. Bind the actual normal binary,
normal build receipt, full frozen source manifest, empty Cargo features,
normal binary/library `test=false`, `test_fixtures_enabled=false`, and the exact
SHA256 map for lib.rs,condition_blocked.rs,predecessor_summary.rs,native_capture.rs,
capture_main.rs,specs.json,Cargo.toml,Cargo.lock. The source map is checked against
bytes embedded in the compiled normal adapter. Admissions use the strict
`horizon-old220-peers1061-native-capture-admission-v1` shape in native_capture.rs.
The effective own-property map must match completely before and after capture.

The `source_manifest` and `normal_build` fields now point to separately sealed
**qualification acceptance documents**, not directly to the original receipt
formats. Main must generate them only after independently checking the genuine
complete manifest and actual normal artifact/build/extern evidence. They are
explicit Root attestations of those checked relations. Original receipts remain
independently SHA-bound and are read/revalidated; this adapter does not interpret
their older schemas or infer their acceptance from their mere existence.

Each Bound below has exactly `path` and `sha256`. The source acceptance has exactly:

```json
{
  "schema": "horizon-old220-peers1061-source-acceptance-v1",
  "original_frozen_manifest": {"path": "ABSOLUTE_ORIGINAL_MANIFEST", "sha256": "EXACT_SHA256"},
  "compiled_source_hashes": {"lib.rs": "EXACT_SHA256"}
}
```

`compiled_source_hashes` must contain the complete exact eight-member map listed
above, identical to the lineage map and compiled bytes. The abbreviated example
is not an admissible document. The build acceptance has exactly:

```json
{
  "schema": "horizon-old220-peers1061-build-acceptance-v1",
  "original_normal_build": {"path": "ABSOLUTE_ORIGINAL_BUILD_RECEIPT", "sha256": "EXACT_SHA256"},
  "source_acceptance": {"path": "ABSOLUTE_SOURCE_ACCEPTANCE", "sha256": "EXACT_SHA256"},
  "binary": {"path": "ABSOLUTE_SEALED_CAPTURE_BINARY", "sha256": "EXACT_SHA256"},
  "cargo_features": [],
  "binary_test": false,
  "peer_library": {
    "file": {"path": "SEALED_BINARY_DIRECTORY/libhorizon_old220_peers1012-CARGO_ID.rlib", "sha256": "EXACT_SHA256"},
    "cargo_features": [],
    "test": false
  },
  "actual_extern_crate": "horizon_old220_peers1012",
  "actual_extern_file": {"path": "ACTUAL_BUILD_EXTERN_RLIB_PATH", "sha256": "EXACT_SHA256"}
}
```

`source_acceptance` equals lineage.source_manifest, and `binary` equals the
admitted binary. The peer-library file must be a Root-immutable sealed copy next
to that binary. Its filename and SHA must match the actual normal rustc `--extern`
artifact; the original build pathname may differ from the sealed copy. The
adapter authenticates the sealed rlib bytes. Main must verify the original build
receipt really links that original rlib, normal features/test metadata, source
manifest and binary before issuing these attestations. Source acceptance, build
acceptance and all nested evidence use the existing Root/single-link/no-write/
canonical-path custody checks. No fixture or foreign-library attestation may be
substituted.

The fixed sandbox additionally requires `PrivateDevices=yes`, `PrivateTmp=no`,
`PrivateMounts=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes` and
`ProtectControlGroups=yes`. RootDirectory/RootImage, MountImages, extension
images/directories, BindPaths/BindReadOnlyPaths, TemporaryFileSystem, managed
Runtime/State/Cache/Logs/Configuration directories, ReadOnlyPaths and
InaccessiblePaths must be empty. `ReadWritePaths` contains only the result parent.
The root mount must be read-only; exactly one writable result-parent mount must
refer to the same underlying host directory. Actual mountinfo and its SHA plus
the explicit writable API/result mount list are included beside the peer summary.
This finite profile may need a freshly admitted unit; do not weaken it to fit an
old launch. No native launch has been qualified by these source changes.

The review is fixed at
`/var/lib/jetstreamer/horizon-old220-peers1060-review-v1/review.json`.
Use `condition_blocked_requirements()` to inspect its deliberately unqualified
shape. Main must supply genuine existing guard/source/history evidence and
independent potential-input reviews. Never turn null placeholders into asserted
acceptance. Source tests do not establish native capture or retirement acceptance.

After normal build qualification and Rust sealing, separately admit the native
positive capture and disposable negative controls. Wire the actual resulting
opaque proof into a versioned old220 profile and every mutation/resume boundary
only through the full original index integration. Unknown predecessor images,
changed native envelopes and missing global closure must continue to reject.
