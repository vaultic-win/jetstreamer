# Epoch 228 cached preparation and remaining gate

The retained v4 manifest provides an exact root bootstrap at 98495291, generation
1633013483898142, accounts hash
`GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq`. Its existing compressed cache is
10510540911 bytes, SHA-256
`da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3`.
No acquisition or authentication refresh is required for this offline work.

There is no root checkpoint inside epoch 228 (98496000–98927999) in that retained
authority. The first later root is 98928278, generation 1633247230841050, accounts
hash `6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra`. It requires 279 slots of
epoch 229 after epoch 228 ends. The ordinary singleton validator requires a root
inside its final requested epoch; declaring 228–228 with this checkpoint fails
that unchanged gate. Do not move the root backward, substitute an hourly anchor,
drop the gate, or call the focused output a canonical epoch archive.

The existing `--qualification-end-slot=98928278` mechanism can describe that
bounded verification tail, but produces a432279-slot focused artifact. A reviewed
extractor/assembly and full/plugin qualification route is still needed to obtain
the canonical432000-slot epoch 228 output while preserving the279-slot proof.

The sealed capped 227 worker is also inapplicable: it accepts only snapshot
98063464 and entries 98063465–98495999. Epoch 228's bootstrap is 98495291 and its
first output slot 98496000 is already outside that worker's exclusive upper
bound. A new closed 228 storage-cap profile must cover its exact bootstrap,
708 pre-output slots from 227, full 228 and 279 verification slots in 229. It must
retain the original v1.6.20 consensus path and cap only storage shrink debt.
Cold native input qualification, bounded resource admission, actual guard,
fleet/status registration, canonical/full/plugin checks and delivery gates
remain independent requirements; preparation promotes none of them.

`jetstreamer-cached-singleton-prepare` is a reusable offline preparation engine
with a closed currently reviewed profile `epoch228-v1620-root-tail`. It verifies
the frozen source SHA and canonical manifest fingerprint, preserves exact root
metadata, rehashes the existing node/genesis/cache, and writes an immutable
manifest, epoch-hash map and input capability. It uses no worker, Bank, GCloud,
network or R2 client and takes no replay/resource observations.

The strict plan schema is `jetstreamer-cached-singleton-prepare-plan-v1`, with
`profile`, exact `{path,sha256}` bindings `source`, `node`, `genesis`,
`bootstrap_cache`, and root-private `output_directory` directly beneath
`/var/lib/jetstreamer/horizon-cached-singleton-228-*`. Seal tool and plan through
the native sealer, then execute:

```text
jetstreamer-cached-singleton-prepare PLAN --plan-sha256 SHA --self-sha256 SHA
```

Its minimal metadata manifest covers 228–229 with intended publication prefix 228.
That is preparation for existing whole-cohort/recovery validation, not a claim
that a fresh cohort runs only 279 slots of 229: the existing whole-cohort route
continues through 99359999. Manifest publication-prefix metadata alone also does
not enforce fresh-replay remote publication scope. Keep 229 local/private with
explicit delivery scope and a qualified publication path, or implement the
short focused-tail route before using it as an independent singleton. Epoch 301
is not included and remains private.

Outputs are `manifest.json`, `epoch-hashes.json`, and `capability.json`. Their
receipt explicitly records those limitations and denies runtime, replay and
publication authority. Idempotent retries retain identical immutable files and
refuse changed evidence. The exact next efficient step is the separately pinned
capped 228 profile plus qualified focused-tail extraction, rather than relabeling
the capped 227 binary or weakening the ordinary singleton checkpoint gate.

The actual offline preparation is durable at
`/var/lib/jetstreamer/horizon-cached-singleton-228-preparation-v1/`:

- `manifest.json`: SHA-256 `dc97bb568a1274c3e2381405a4cb5d2d6ded35917a57a1e6f497ce91507739da`,
  body fingerprint `sha256:723b672fec90a472e2991b87743941dd4df0a6acb682832bd4887db479b09f23`;
- `epoch-hashes.json`: SHA-256 `41c99cdb6da5990cff72ee893d292b3db40eb9786b0ae0018409b380d4cfbd47`;
- `capability.json`: SHA-256 `215a0ca0b4acf966935edb83fdb06eaea114c93c2b2c1e9cc36c19755cb1e8ce`.

The sealed preparer is
`/var/lib/jetstreamer/horizon-cached-singleton-preparer-749349cb-v1/jetstreamer-cached-singleton-prepare`,
SHA-256 `749349cb469c706fcaa14a6b76b1fabaa605b2e34e367a703b6211f18b045caa`.
Its sealed plan is
`/var/lib/jetstreamer/horizon-cached-singleton-228-plan-v1/plan.json`, SHA-256
`0658487e7cc5fc881c48c9aa638c3f2d15ea0ff1545a1baa20697b37551adade`.
The 10.5 GB bootstrap was rehashed in place without creating another copy.
Keep this receipt tree private. Any future unprivileged worker input must be
separately deployed through the native sealer into a read-only input bundle;
do not relax the private evidence directory to make it readable.
