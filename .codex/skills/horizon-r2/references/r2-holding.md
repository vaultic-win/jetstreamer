# Host-specific R2 scratch / cold holding

Use this only after explicit user permission for an R2 scratch/holding area. This is cold object
storage for eligible closed files, not live POSIX scratch and not a publication destination.

## Name and authority

- Ask the user for the unique directory/prefix name for this host before the first write. Use the
  user-provided name; do not choose a hostname-derived default. Validate it as a nonempty relative
  key prefix with no traversal or ambiguous components, and keep every holding key beneath it.
  Record the host/prefix mapping. If it conflicts with another host's ownership or existing keys,
  resolve the conflict with the user rather than silently sharing or broadening the prefix.
- R2 directories are key prefixes; no FUSE mount, placeholder directory object, public URL,
  anonymous verification, or per-object ACL is needed. Use the configured authenticated bucket.
  A prefix is not an access-control boundary: if the bucket is public, its holding objects may be
  public too. Never put credentials, private keys, cloud SDK configuration, or sensitive logs there;
  private content requires an explicitly approved private destination.
- Scratch permission authorizes append-only parking and authenticated restoration inside this
  host's approved prefix. Use collision-resistant/content-addressed artifact keys and no-clobber
  creation. It does not authorize remote overwrite, deletion, lifecycle expiry, bucket-policy changes,
  another host's namespace, or any canonical archive/sidecar mutation. Obtain separate explicit
  authority before destructive remote cleanup; do not treat the word "scratch" as deletion permission.

## Eligible data and custody

- Candidates include closed immutable snapshot/download caches, CAR inputs, and useful diagnostic
  or retained-prefix artifacts that can be restored safely. Prefer ordinary verified eviction and
  generation-pinned redownload when that is simpler than paying to retain a reproducible cache.
  Measure recoverable local bytes before assuming this will unlock another lane.
- Never evict open or mmap-backed AccountsDb/ledger files, live replay scratch, active/staged inputs,
  resumable state without a qualified checkpoint/restore path, or required immutable deployment
  members. A generic R2 FUSE mount does not preserve the latency and filesystem behavior required
  by the historical replay engine. A future tiered runtime needs independent qualification.
- Use reviewed, tested, sealed Rust park/restore tooling that is bound to the exact host prefix and
  artifact identities. If the deployed tools do not support holding objects, qualify that path
  before using it; do not rename arbitrary files as canonical `.jet` archives or bypass uploader gates.
- Before parking, prove the source is closed/stable and bind its path, byte length, SHA-256, purpose,
  epoch/generation where applicable, and the manifests/metadata needed for restoration. Preserve raw
  evidence bytes. Upload no-clobber, independently verify the complete remote bytes through
  authenticated readback, revalidate the local source, and fsync a private custody receipt.
- Only then consider retiring the exact local copy, with a fresh process/staged-reference check
  and every original artifact-specific retirement gate intact. A holding receipt is not a full,
  plugin, boundary, canonical publication, or R2-ready receipt. Canonical complete archives still
  require their normal retirement proofs. Never delete valid work merely to simplify scheduling.
- Restore into explicit private staging with authenticated identity/digest checks and no-clobber
  publication before a job can consume it. Account for full restoration space and time in admission;
  parked bytes are not immediately available local inputs.

## Idempotent stopped-job offload and resume

The user authorizes this lifecycle for campaign jobs: **checkpoint and stop → upload and verify →
delete exact local copies → restore and verify → resume**. This extends holding eligibility to a
stopped job's closed checkpoint/scratch set after its real restore path has been qualified. It
does not authorize deleting or overwriting any R2 object. Prefixes belong to their explicitly
authorized hosts: `dev-samjohnson` uses the user-provided `node_02/`, recorded in
`/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json`.
`foundation_node_01/` belongs to a different server's authorization and is not a default.
Use each host's durable mapping and check prefix ownership before first write; other hosts still
require their own user-provided mapping. A mapping does not establish transport or resume qualification.

- Use a durable job ID and transition journal with exclusive ownership. Bind epoch/phase, exact
  original invocation and runtime/worker/package hashes, checkpoint position and restart cursor,
  source lineage, every file's relative path/length/hash/mode, and restoration requirements.
  Preserve raw consensus bytes and exact integers. A SIGSTOP image is not a portable checkpoint;
  open mappings and RAM-only state must be durably captured by the supported runtime first.
- Qualify the lifecycle on an isolated bounded job before using it as pressure relief. Verify that
  it resumes after the recorded checkpoint with correct cursor/lineage, without duplicated or
  skipped output, then passes independent content/checkpoint validation. Compare with uninterrupted
  execution where feasible. A round-trip byte copy alone does not prove replay resumption.
- Journal intent before each mutation, completion after durable proof. Re-entering a completed
  phase must revalidate its exact evidence and become a no-op; an interrupted phase reconciles
  actual state and continues. Never restart a healthy duplicate, signal an unrelated/reused PID,
  overwrite a key, or discard a valid checkpoint to make a retry pass. Conflict means preserve
  both sides and diagnose. Conditional create/readback and content-addressed keys make uploads
  retryable: an existing matching object is reused after verification, a mismatch is a hard error.
- Stop only the chosen exact job after checkpoint completion; prove it terminal and its mappings
  closed. For memory pressure, this releases RAM; freezing without stopping retains RSS. Upload
  the complete immutable restore set no-clobber and verify all bytes plus the manifest. Fsync its
  private custody receipt before deleting any local member. Deletion is authorized only for those
  exact backed-up members, after the fresh reference check, and is retry-safe when already absent.
  Preserve receipt, manifest, transition journal and any independent integrity evidence locally.
- Restore into private staging with sufficient space. Reuse already matching restored members,
  reject conflicting paths, verify every manifest entry and whole-file hash, restore required
  permissions, and commit the complete set atomically/no-clobber. Resume exactly one new invocation
  from the recorded checkpoint; install/prove its guard and bind the replacement invocation in the
  fleet. Repeated resume requests must discover that invocation rather than launch another one.
  A stopped/parked job stays in the repair/active-work ledger with an executable resumption action.

## Qualifying replay portability

Track qualification separately for each exact worker/runtime and output format. Record the last
successful stage, immutable evidence, the next bounded experiment, and its resource limit. Use
these stages: native checkpoint export; fresh-process restore and continued replay; output
continuation equivalence; authenticated holding round trip; interrupted-transition recovery.
Passing an earlier stage does not imply a later one passed. In particular, a checkpoint hash or
an archive assembled from an existing source is not proof of a portable runtime checkpoint.

Check the actual worker's export capability before launching a costly test. Some historical
workers implement `FreezeCheckpoint` but reject `ExportSnapshot`; implement and test the missing
native export in an isolated candidate rather than stopping a healthy producer to discover this.
Keep the original runtime and inputs available until fresh-process continuation is proven.
Inspect native serializer helpers for bank mutation and automatic archive retention/purge behavior.
Use an isolated empty staging directory, preserve pre-export consensus hashes/cursors, and verify
them afterward; never point a helper that purges older snapshots at campaign or holding artifacts.

For continuation equivalence, compare the checkpoint's bank/accounts hashes, slot and entry
cursor, transaction count and write-version cursor, then compare resumed output with an
uninterrupted bounded replay. Include the output writer's own recovery state: a restorable bank
alone does not establish that the partial `.jet` can be appended without duplication or loss.
Preserve raw consensus bytes and use independent full/plugin verification before publication.

Exercise interruption after remote completion but before receipt persistence, during local
retirement, during restore, and after launch but before launch-receipt persistence. Recovery must
reconcile matching existing objects/files and the exact live invocation, preserving conflicts
and preventing duplicate jobs. Use disposable isolated fixtures; do not inject failures into
healthy campaign jobs or delete remote test objects without separate authority.

During unattended work, advance the next bounded stage while healthy jobs run and refine these
instructions from the observed result. Keep experiment completion events separate from routine
replay observation, retain the 30-minute cadence, and prioritize delivery of already-verified
epochs over an optional experiment competing for the same resources. Report the qualified stage
accurately; authorized holding space adds no demonstrated replay capacity until recovery works.

## Integration with the control loop

Keep holding objects outside canonical inventory/readiness accounting. Record parked artifacts,
their custody receipts and restoration requirements in host-local state. On the existing 30-minute
cycle and permitted handoff/status events, include reclaimable space and restoration cost in the
mandatory next-lane fit decision. Offloading does not replace CPU, memory, I/O, VMA, compatibility,
century-floor or guard qualification. Do not create a separate holding-area polling loop, and do
not let waiting for the user's prefix name block independent useful campaign work.
