# Private epoch-140 initial-boundary comparison

`jetstreamer-epoch140-initial-boundary` compares the original archive's first-block
summary from the exact successful private full reread with independently sealed,
finalized metadata for slots 60,479,999 and 60,480,000. It has no network access,
archive-write, replay, sidecar, publication, or R2 operation.

This is a build-bound diagnostic, not an ordinary recovery profile. Its source
identity, original verifier invocation, qualified collector and plan digests, and
independent RPC request/response digests are fixed in the reviewed source. A changed
attempt or collector requires explicit review and qualification, not a rewritten
receipt or an expanded ambient allowlist.

The separately hash-bound, root-owned immutable plan has this shape:

```json
{
  "schema": "jetstreamer-epoch140-initial-boundary-plan-v1",
  "full_receipt": { "path": "/absolute/private/evidence.json", "sha256": "EXACT_SHA256" },
  "rpc_request": { "path": "/absolute/sealed/block-request.json", "sha256": "EXACT_SHA256" },
  "rpc_response": { "path": "/absolute/sealed/block-response.json", "sha256": "EXACT_SHA256" },
  "output": "/absolute/root-private/comparison.json"
}
```

Do not seal a production plan before the real full-reread collector receipt exists.
The tool requires the private transient v2 receipt, its exact clean terminal
invocation, full post-reread source hash/identity, immutable verifier/collector/plan,
and the bound log and raw journal metadata. It rejects the legacy v1 schema rather
than reinterpreting it. The unchanged original mode-0440 archive is only inspected
for identity and timestamps; this comparison does not repeat its whole-file hash.

Seal the tool and plan with the normal Rust deployment sealer, precreate a fresh
root-owned mode-0700 output directory, then run the exact sandbox check:

```text
jetstreamer-epoch140-initial-boundary PLAN --plan-sha256 HEX --self-sha256 HEX --check-only
```

Use an otherwise read-only, non-restarting systemd sandbox with only the exact
output directory writable and DAC_OVERRIDE for the private source traversal.
After a successful check, remove only `--check-only` for a separate recorded
invocation. Existing outputs are never replaced. Check-only creates no output.

The resulting private receipt reports `canonical_first_block_comparison_passed`,
but deliberately retains `initial_anchor_proven: false` and
`ordered_chain_gate_still_required: true`. It neither recovers hidden skipped-slot
PoH hashes nor qualifies a prefix, native restart, manifest, continuation, plugin,
canonical archive, or publication. Those remain independent gates.

The ordinary tests use synthetic positive/negative receipts. The ignored local
source test reads only the independently sealed real RPC package, with no archive
access or writes:

```sh
HORIZON_EPOCH140_RPC_FIXTURE_ROOT=/usr/local/lib/jetstreamer/horizon-epoch140-initial-boundary-rpc-20261021-v1 \
  cargo test -p jetstreamer-utils --bin jetstreamer-epoch140-initial-boundary \
  real_sealed_rpc_boundary_sources -- --ignored
```

That source test alone does not establish a comparison with the real archive.

## Separate anchored-chain evidence

The full-verification evidence collector also has an explicit private v3 profile
for the exact `horizon-epoch140-anchored-chain-20261021-v1` invocation. Its plan
schema is `jetstreamer-horizon-anchored-chain-evidence-plan-v3`; the existing v2
internal-full profile remains distinct and unchanged in scope. The transient
profile additionally requires `anchored_chain.full_verification` and
`anchored_chain.first_block_comparison` bindings to the independently recorded,
root-sealed copies of the two successful prior receipts.

The v3 command must be the exact non-full, non-segment `--chain --anchor` command.
Both its per-archive `RESULT: OK` and `CHAIN RESULT: OK` must appear exactly once
in the PID/EXE/argv/invocation-bound terminal journal. Collection independently
rehashes the complete unchanged source after the chain check. A successful v3
receipt can mark this source's incoming anchor proven, but still explicitly
denies complete-prefix qualification, replay, manifest and publication authority.
Never replace, rename or reinterpret the internal-full v2 receipt as that proof.
