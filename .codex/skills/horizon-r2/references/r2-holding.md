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

## Integration with the control loop

Keep holding objects outside canonical inventory/readiness accounting. Record parked artifacts,
their custody receipts and restoration requirements in host-local state. On the existing 30-minute
cycle and permitted handoff/status events, include reclaimable space and restoration cost in the
mandatory next-lane fit decision. Offloading does not replace CPU, memory, I/O, VMA, compatibility,
century-floor or guard qualification. Do not create a separate holding-area polling loop, and do
not let waiting for the user's prefix name block independent useful campaign work.
