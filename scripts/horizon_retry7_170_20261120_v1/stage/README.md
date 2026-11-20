# Epoch 170 retry7 stage source

This standalone package adapts the actual `stage170retry8.rs` predecessor for
epoch170 `local3retry7`. It writes witness, measurement, preparation and launch
plans. It does not start a replay or replace admission/guard qualification.
Predecessor sources and the shared HOME audit module remain unchanged.

The historical retry5 plan and retry6 base contract keep their original paths.
The successor preserves the original terminal lineage and closes every producer,
guard service and guard timer for retry4, retry5, retry6 and retry7. Retry5 and
retry6 stop-completion receipts must match their known exact SHA-256 values;
the preparer independently authenticates their stop intents and sampled plans.

## Exact artifact inputs

All three production artifact hashes are resolved and pinned in `main.rs`.
There are no optional environment variables or fallback hashes.

| Input | Runtime suffix below the recovery directory | SHA-256 |
| --- | --- | --- |
| Preparer | `prepare-v1/prepare` | `2da96f6774c4224127900e5ff120076d238b4b1441c799aecf233c8d5a08e17d` |
| Preparer proof | `prepare-v1/artifact-proof.json` | `a28aa25753dec6fe7aabd42ef04f3acf460e26b95a4d09381975fd52ebb364db` |
| Guard | `guard-v1/guard` | `6b9b398287815ca9581ed3fbd5e15e772eceef3eacd31a7463822288b5641c6a` |
| Launcher (`LAUNCHER_SHA`) | `launch-v1/launch` | `336fdd9ab543247472f4e882bf45461d666bc992db5c44f7ecd61b68dae11588` |

The recovery directory is
`/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1`.
Stage evidence uses its `stage-state` child; preparation uses
`preparation/epoch170/local3retry7/prepared.json`; launch plans use
`launch-state/launch-plan.json`, with output under `launch-state/epoch170`.
The launch plan schema is `horizon-retry7-single170-launch-plan-v1`.

## Required operational inputs

Root must supply an independently hash-bound configuration and the qualified
stage image's SHA-256. Keep the predecessor config's exact bindings for `fleet`,
`observer`, `status`, `inventory`, `next_observer`, `peer167_admission`,
`peer167_protection`, the operation's selected contract and the preparation's
`measurement`. Both live peers, 19 authenticated statuses, complete fleet
DATA/memory obligations and the continuing HOME audit are still required.

The new config additionally requires:

```json
{
  "fresh_subtree_identity": {
    "path": "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1",
    "device": "REPLACE_WITH_ACTUAL_POSITIVE_INTEGER",
    "inode": "REPLACE_WITH_ACTUAL_POSITIVE_INTEGER"
  }
}
```

The strings above deliberately fail validation: both identity values must be
actual integers from the newly created retry7 directory, never retry6's inode.
The directory must retain owner1001, mode0700, HOME backing, canonical path and
the operation-specific empty/staged contents. Root must also precreate the
private, HOME-backed `stage-state` directory.

Witness generations use
`horizon-170-retry7-witness-TAG-20261120.service`,
`stage-state/guard-witness-TAG`, and `data-contract-TAG` beneath the recovery
directory. Generate and normally seal the successor guard's own native witness;
the preparation witness must be no older than120seconds. An old guard witness
does not authenticate this guard.

Invocation remains:

```text
stage CONFIG --plan-sha256 CONFIG_SHA --self-sha256 STAGE_SHA witness
stage CONFIG --plan-sha256 CONFIG_SHA --self-sha256 STAGE_SHA measure TAG
stage CONFIG --plan-sha256 CONFIG_SHA --self-sha256 STAGE_SHA prepare TAG
stage CONFIG --plan-sha256 CONFIG_SHA --self-sha256 STAGE_SHA launch-plan
```

`TAG` is four decimal digits. `prepare` takes the separately bound measurement
from the config. Whole-lane retained retry6 storage remains charged; no old
scratch, R2 offload or forecast earns capacity credit. The stage preserves the
fleet's additional obligations and the inherited review's fresh-subtree overlap;
Root's final capacity qualification must retain every concurrent build allowance
(including epoch168's4GiB plus16MiB outside allowance when applicable).

## Qualification and publication still required

The stage passed strict all-target Clippy, a release build and all 15 native
tests. The test suite ran as the replay user (UID 1001) in the fixed HOME-backed
build image. The launcher passed all 21 native tests, including the separate
check of the actual epoch 169 holding invocation. Its sealed production hash
is the launcher hash above.

The stage checks the published bytes of its own Rust source, manifest, lockfile
and imported audit module against `origin/account-updates`.

After qualification, Root still supplies the actual fresh directory identity,
fresh accepted cycle and capacity evidence, new guard witness/contract and
normally sealed stage image. The prepared receipt and metadata launch plan do
not prove that replay was launched or that admission/guard protection completed.
