# Epoch 213 private verification

`jetstreamer-epoch213-private-verify` closes the independent full/current-plugin
verification steps for the exact `ae43646` checkpoint-continuation experiment.
It does **not** admit V4 to ordinary import, publish an archive, create a checksum,
write progressive-uploader `.ok` receipts, retire inputs, or access R2. A separate
reviewed exact-provenance publication admission remains mandatory.

The runner is intentionally build-bound to the original producer unit and
invocation, original node/plan, exact prefix/suffix/snapshot, independently derived
provenance expectation, and the capacity-qualified v3 full verifier and pipeline.
Other epochs, producer generations, tool transitions, and output locations are
not implicitly supported.

## Before launch

Wait for clean terminal success of the actual producer. Preserve its original
assembly, prefix, suffix, manifests, snapshots, and receipts. Seal a root-owned
copy of its completed `continuation.json`; the runner independently checks its
exact producer identity and complete 432,000-slot assembly claim. That claim is
only an input to verification, never a substitute for the scans.

Use the normal coordinated observation and fresh resource admission. Account for
one additional complete private `.jet` copy, verifier/pipeline memory and tasks,
all live growth claims, the complete 225 diagnostic budget when applicable, and
the current century floor. The runner's static protected-space lower bound is
not a fresh admission receipt. Recompute before launch; a new ordinary lane or
verification phase can change the memory envelope. Do not reuse the 213
assembly-only memory scheduling estimate for verification overlap.

Create a new empty root-owned 0700 direct child of `/var/lib/jetstreamer` named
`horizon-213-private-scan-UNIQUE`. Keep it outside immutable deployment bundles
and the public Horizon directory. Seal the runner and a separately hash-bound
plan with the Rust deployment sealer. The plan schema is strict:

```json
{
  "schema": "jetstreamer-private-epoch213-verification-plan-v1",
  "producer_outcome": {"path": "/absolute/sealed/continuation.json", "sha256": "EXACT_COMPLETED_OUTCOME_SHA256"},
  "provenance_expectation": {"path": "/absolute/sealed/expectation.json", "sha256": "f7bb330186a8fbcc438b0fa49e903af5be5a1c30092f7cd434a86f6b2916bea5"},
  "full_verifier": {"path": "/absolute/sealed/verify_archive", "sha256": "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9"},
  "plugin": {"path": "/absolute/sealed/horizon-pipeline", "sha256": "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547"},
  "private_directory": "/var/lib/jetstreamer/horizon-213-private-scan-UNIQUE",
  "protected_free_bytes": 2773361332950,
  "maximum_archive_bytes": 137438953472,
  "threads": 8
}
```

The example protected byte value is only the minimum accepted baseline; replace
it with the fresh admitted protected amount if greater. The 128-GiB archive cap
keeps the copy within the separately reviewed 384-GiB diagnostic envelope. An
oversized output is a failed gate requiring review, not permission to raise it.

Launch as a persistent non-restarting systemd service with `KillMode=control-group`,
explicit fresh CPU/memory/task/runtime bounds, and the minimum capability needed
to traverse retained user-private evidence. `ProtectHome=read-only` is compatible
with the original input; `ProtectHome=yes` is not. Grant writes only to the new
private scan directory. Preserve the producer's terminal identity until the
runner's second check. A cleared inactive `InvocationID` is accepted only with
the exact original producer's assembly-completion journal and subsequent clean
manager deactivation, alongside unchanged terminal service properties. If systemd
collects that completed transient unit, only `not-found/inactive/dead` with empty
invocation and cleared zero exit fields is accepted, still requiring the original
root-sealed outcome and exact completion/deactivation journal. Never recreate or
restart the producer to synthesize terminal state. Foreign invocations and
missing/ambiguous journal evidence fail closed.
Invoke:

```text
jetstreamer-epoch213-private-verify /absolute/sealed/plan.json --plan-sha256 HEX --self-sha256 HEX
```

## Evidence and failure behavior

The runner fsyncs `intent.json`, makes one new private `epoch-213.jet` copy,
fsyncs it and makes it mode 0400, independently hashes retained source and copy,
then runs strict `--full` with the independently known initial anchor, canonical
terminal blockhash, and exact source-derived V4 provenance digest. It hashes the
copy again and fsyncs `full.json`. It next runs the pinned current pipeline with
`213:213 --threads 8 --verify-only` and hashes the same inode again. Child
environments exclude credentials. Both scans log durably to distinct files.

`verification.json` is written no-clobber only after both scans succeed, the
source and staged identities remain stable, the exact producer remains terminal,
and both source and copy remain checksum-free. It binds the source/copy digest,
identities, plan, producer receipt, independent expectation, both binary hashes,
exact commands, log hashes, and phase timings. All publication, sidecar,
runtime-promotion, retirement, and R2 authorities remain false.

Failure preserves every source and private artifact. Never overwrite logs or
rerun into a nonempty attempt directory. Diagnose the sealed failure, then use
normal exact-reference retirement and fresh admission before any new attempt.
Do not restart the healthy original replays to test this runner.

The final importer must revalidate this evidence and the exact provenance,
prepare destination permissions before its own inode validation, and perform
transactional if-absent publication with checksum last. Only after that separate
reviewed gate may digest-bound full/plugin receipts be materialized for the
progressive uploader. Adjacent-boundary checks remain independently required for
local retirement, not for initial R2 upload.

The separately scoped `jetstreamer-epoch213-publish` implementation is documented
in [epoch213-v4-artifact-publication.md](epoch213-v4-artifact-publication.md).
Its own sealed exact-artifact plan and capability proof remain required; this
private verifier does not launch or authorize it.
