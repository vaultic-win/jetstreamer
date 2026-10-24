# Prepared prefix completion to private V3 assembly

This route is source preparation. No actual-prefix completion, new prefix
reread, handoff execution, archive scan, Bank run, admission, service launch or
R2 mutation has been performed. There is no operational plan populated with
future hashes. Keep the healthy native20 prefix unchanged.

## Existing independent reader: use its exact native20 profile

The current `jetstreamer-qualification-verify` source already supports
`qualification-223-v1620-prefix-*`, full workera651b7a6, native20 revision
77bdb45d and the431,523-slot known-root span. No new reader algorithm or
permissive generic fallback is needed. Build/test/seal this current executable;
do not assume an older sealed native25 tail reader includes that profile.

After the actual prefix naturally completes with original terminal manager
success, root preserves its original receipt, manifest and journal. Under a
separately bounded read-only verification owner running as ubuntu, the exact
reader arguments are:

```text
SEALED_QUALIFICATION_VERIFIER
  /home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1/output/epoch-223.jet
  --private-root=/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1
  --expected-epoch=223
  --expected-output-start-slot=96336000
  --expected-bootstrap-slot=96335538
  --expected-terminal-slot=96767522
  --expected-runtime-profile=solana-v1.6.20
  --expected-worker-sha256=a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20
  --receipt=/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1/receipts/epoch-223.native20-prefix.validation.json
```

This is an argument specification, not a launched command. The actual sealed
reader digest, safe execution envelope and unoccupied no-clobber receipt path
must be bound at that time. The reader must finish its full archive/manifest
reread, both canonical-root checks and exact native20 identity checks. Preserve
and root-seal copies of its actual receipt, producer completion and manifest,
plus original terminal/PID1 journal evidence. No receipt or digest is predicted.

## Existing metadata handoff gate

Run the already qualified/sealed f44af401 tool-only gate only after those actual
inputs exist. Its binary digest is
137b5a3a767604ea4c9f7405dd0af7af0eb860f30e5ece52ce49017825d35c22.
Follow `epoch223-cross-runtime-handoff-plan.md`; keep its immutable request and
actual output. It binds the exact corrected native25 input d79e374e, requires
full consensus tuple equality and plans validator-local cursor normalization.
Its output grants no assembly or publication authority.

The gate implementation now lives in a shared source module used by both the
CLI and assembler. Its existing schema, predicates and metadata output stay
the same. The old sealed f44 gate remains the required gate authority; a new
binary produced during the shared-module refactor is not silently substituted.

## Missing executable link: prepared private V3 assembler

`jetstreamer-epoch223-private-assemble` supplies the actual file-to-file merge
entrypoint. It cannot replay or restore a Bank and has no R2 or sidecar-writing
code. Its strict root-owned immutable plan schema is
`jetstreamer-private223-v3-assembly-plan-v1`, containing `handoff_request`,
`handoff_receipt`, `admission` (each `{path, sha256}`) and fixed `output_root`:

`/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1`

CLI arguments are `PLAN PLAN_SHA256 SELF_SHA256 [--check-only]`. The check-only
path rehashes its self/plan and the real metadata evidence, recomputes the shared
gate, requires the old qualified gate's actual matching receipt, and constructs
validated V3 provenance. It does not read admission, query host/services, open
epoch archives or create output. Even this check awaits actual future inputs.

Actual execution additionally requires both original source services inactive
after exact zero-restart success, a fresh root-owned0700 empty output root on
the source filesystem, exact persistent owner identity and a separate fresh
resource admission. The assembler requires unit
`horizon-assemble-223-native20-native25-v1.service`, root, Type=exec,
Restart=no, zero restarts,24h RuntimeMax,64GiB MemoryMax,48GiB MemoryHigh,
swap0, CPU400%, Tasks512, UMask0077, PrivateNetwork=yes,
ProtectHome=read-only, ProtectSystem=strict, NoNewPrivileges=yes and exactly
the fixed output root writable. Root's unit must retain only the traversal
capability needed to read the existing user-private inputs; never relax them.
If an original transient source unit has been fully unloaded, this generation
refuses that ambiguous current-state observation. A separately qualified exact
manager-absence/no-live-source-owner adapter is required before launch in that
case; historical success alone is not current absence evidence. Do not relaunch
an old producer, invent its current fields or weaken the gate to work around it.

The assembler pins both opened private sources, requiring uid1000, mode0600,
one link and no checksum sidecar. It invokes the existing `merge_runtime_segments`
with their independent manifest digests/terminal hashes and exact native20/
native25 V3 provenance. V4 remains same-runtime-only. The shared merger hashes
and decodes the complete sources, checks PoH and all metadata/update phases,
rejects write gaps/duplicates/missing events, and performs the checked normalized
mapping. No raw cursor equality, padding, truncation or event dropping occurs.

Output is no-clobber mode0600 `epoch-223-private-v3.jet`, bounded to160GiB and
24h. Every write preserves the independently admitted filesystem floor, which
must be at least2TB plus any older protected claims; cgroup memory/CPU/task
bounds protect the host. It fsyncs the output/directory, rechecks both original
source identities and owners, hashes the completed output through a pinned
handle and writes a private no-clobber `assembly.json`. `intent.json` is durable
before output creation. Failure preserves all inputs and partial output; there
is no automatic retry, cleanup, resume or replacement authority.

## Explicit remaining admission gap

The existing epoch144 assembly admission/fleet adapters are closed to144 and
cannot be borrowed. A reviewed actual223 adapter producing
`jetstreamer-private223-v3-assembly-admission-v1` remains required before this
assembler is launchable. Its contract binds the actual assembler, handoff
request/receipt, prefix/tail digests, output filesystem/device,160GiB maximum
output,64/48GiB memory limits,24h time limit, complete accepted fleet ledger,
fresh invocation-bound observer and all preserved older guards/century claims.
It records protected disk/memory reserves and a sample no older than15minutes.
The assembler rehashes those bound ledger/observer files and refuses missing,
stale, mismatching or insufficient capacity evidence. It does not manufacture
that independent admission. Do not hand-write a positive admission JSON or
treat the metadata gate's equality fact as capacity authority. Qualify this
adapter only against the real completed prefix and fleet present then.

## Separate final checks

Private merger success is not an independently verified complete archive or
publication approval. Its completion leaves independent final full verification,
current plugin verification, runtime promotion, canonical sidecars, publication,
retirement, repair closure and R2 authority false. Prepare the final private V3
full/plugin/fleet adapters separately; do not route this source through a
single-runtime V2 verifier or the203 same-runtime V4 publisher. Only after all
normal full/plugin/boundary/publication checks may the normal authenticated
uploader commit a matching sidecar. Keep223 open until the verified ready pair.
