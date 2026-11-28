# Epoch 265 sealed input packet

This is the next bounded input prerequisite for a replacement of the historical
epoch-265 attempt. It checks the retained bootstrap, selected node, capped worker,
genesis, singleton manifest and a new immutable three-member 264/265 compact-index
cache. It does not run the node, contact a remote service, launch a worker, copy
or delete input files, or admit a lane.

The historical producer failed at slot 114480089, transaction 1368, because 65
instructions exceeded the old inline limit of 64. The checker retains that exact
incident and requires the selected node build binding at commit
`1ae137f752f605463e52dad3055ab8cb161b64e2`. It also verifies sealed copies of that
commit's `limits.rs`, `message_instructions.rs` and `convert.rs` against exact
digests. Those sources contain the shared instruction arena, packet-derived
limit, 65-instruction regression and authenticated 67-instruction fixture.
Checking source bytes is not executing these tests or replaying past the failure.
The receipt always says `codec_tests_executed=false` and
`native_runtime_qualified=false`.

## Prepare and qualify

The November 19 bounded qualification passed nine tests, strict all-target
Clippy and the locked/offline release build under a 2 GB memory limit. The
evidence is retained in Foundation's private
`horizon265-input-packet-build-20261119-v3` diagnostics directory. This qualifies
the checker implementation. A production input packet subsequently passed on
November 19 at 15:52 UTC under a 512 MiB memory limit. It authenticates the
retained bootstrap, node, worker, genesis, three codec sources and all three
sealed indexes, including their CID metadata and nonoverlapping bucket bounds.
The packet is retained at
`/home/ubuntu/.codex/diagnostics/horizon265-input-cache-20261119-v1/input-packet.json`
with SHA256 `f7dbb6eedd4f47c940c959639d399ea3af68343f18fc894c736170f6dc089153`.
The original index files remain preserved; the new immutable cache is
`/var/lib/jetstreamer/horizon265-index-20261119-v1`. This is input custody only:
all eight authority flags remain false, and the remaining execution gates below
are still required.
Retain commands, source hashes, actual service completion and binary digest
when rebuilding.
Publish the source to `origin/account-updates` before any epoch admission. Seal
the new checker and input-plan deployment with the qualified Rust sealer.

Before copying the old indexes, establish their closed owner, custody and absence
of consumers through the normal campaign checks. Obtain genuine source digests
under a bounded operation and seal these three files with
`horizon251-sealer` SHA256
`faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a`:

| Epoch | Kind | Bytes |
|---|---|---:|
| 264 | slot-to-cid | 15875725 |
| 265 | slot-to-cid | 15484110 |
| 265 | cid-to-offset-and-size | 10904092766 |

The source directory is
`~/.jetstreamer-private/qualification-265-singleton-46b4b4a-v1/output/compact-indexes`.
Exact names and CIDs are in `src/profile.rs`. Reserve 10935452601 bytes of overlap;
retain the originals until separately qualified retirement. Use a new deployment
named `/var/lib/jetstreamer/horizon265-index-...`; its seal must contain exactly
the three index members with mode `0444`. No large hash or copy belongs inside
the later 50-second launch transaction.

Seal byte-identical copies of the three codec source files obtained from the
exact node commit, and create a root-owned mode-0700 output directory. The plan
has exactly these keys:

```json
{
  "schema": "horizon265-input-packet-plan-v1",
  "cache": "/var/lib/jetstreamer/horizon265-index-GENERATION",
  "cache_seal": {
    "path": "/var/lib/jetstreamer/horizon265-index-GENERATION/deployment-seal-receipt.json",
    "sha256": "ACTUAL_SEAL_DIGEST"
  },
  "codec_sources": [
    {
      "repository_path": "jetstreamer-horizon/src/limits.rs",
      "source_commit": "1ae137f752f605463e52dad3055ab8cb161b64e2",
      "file": { "path": "SEALED_ABSOLUTE_PATH", "sha256": "DIGEST_FROM_PROFILE" }
    }
  ],
  "output": "/ABSOLUTE_ROOT_PRIVATE_DIRECTORY/input-packet.json",
  "authority": {
    "native_runtime_qualified": false,
    "codec_tests_executed": false,
    "replay_launch_authorized": false,
    "admission_authorized": false,
    "publication_authorized": false,
    "resource_release_authorized": false,
    "remote_mutations": false,
    "r2_mutations": false
  }
}
```

This example is deliberately incomplete: populate all three `codec_sources`
entries using the pinned source hashes in `src/profile.rs`, replace every
placeholder, and seal the plan. The checker rejects incomplete source inventories.

```text
horizon265-input-packet check-plan PLAN --plan-sha256 SHA --self-sha256 SHA
horizon265-input-packet verify PLAN --plan-sha256 SHA --self-sha256 SHA
```

`check-plan` authenticates only static metadata, source bindings, and cache seal.
`verify` additionally hashes about 27.5 GB of sealed inputs, checks file identities
before/after and again before the receipt, and parses compact-index metadata and
bucket bounds. It rejects incorrect epoch/kind/CID, malformed or overlapping
buckets, foreign members, replaced files and preexisting output. Hash progress
is logged at most once per minute from the active read loop. The resulting
no-clobber receipt is fsynced together with its directory. Parsing is a structural
check, not a production-reader or authenticated CAR probe.

## Remaining execution gates

1. Bind an actual codec-test receipt for the exact relevant source; packet tests
   verify refusal of wrong provenance, not the archive codec's behavior.
2. Bind current service-effective CAR-header/CID evidence and both selected-node
   negative probes. A prior filename rejection does not prove initialization.
3. Qualify the selected capped worker with this bootstrap, or establish reviewed
   exact relevant runtime equivalence. The old successful initialization used a
   different worker and cannot simply be reused.
4. Finish the closed 265 launcher using current retained obligations and genuine
   terminal/drain releases. Include audit, delivery, control, growth and filesystem
   floors. A single 247 release cannot admit both the 128 GiB native211 experiment
   and the 128 GB 265 replay.
5. Qualify the actual guard/startup transaction and extend the closed terminal and
   delivery routes to 265 before launch. Full replay and latest-branch local/plugin,
   remote-playback, sidecar and retirement gates remain mandatory.

All eight authority flags remain false even on successful packet verification.
