# Foundation holding: retained artifact review

This is a source and metadata review on 2026-10-24. It authorizes no remote write,
local deletion, service change, replay launch, or runtime-state offload. No new
replay/resource observation, process-reference scan, or whole-archive hash was run.

## Existing host authorization

The host is `horizon-vaultic` (`/etc/hostname`). The existing root-owned, sealed
mapping is
`/var/lib/jetstreamer/horizon-r2-holding-foundation-node-01-user-mapping-v1/mapping.json`,
SHA-256 `50736c4c6633b4a97f4a717a1ba5f83374b4e2af4b7ef22c90ed4e007cad35b6`.
It records the user's exact choice `foundation_node_01/` and append-only parking
and authenticated restoration. Ownership checking, transport qualification and
holding writes are recorded as not yet performed. This mapping is distinct from
the `dev-samjohnson` / `node_02/` mapping accepted by existing `holding.rs`.

## Epoch207 has no reclaimable retained archive

A targeted filename census beneath the private root, excluding live scratch,
AccountsDb, unpacked snapshot and cache trees, found only these epoch207 `.jet`
files. Each has device66305, one link, UID/GID1000, mode0644, length0 and zero
allocated blocks:

| Path beneath `/home/ubuntu/.jetstreamer-private/qualification-207/` | Inode | Modified/changed Unix seconds | Reclaimable bytes |
| --- | ---: | ---: | ---: |
| `diagnostic-output-failed-v1/epoch-207-through-89855469.jet` | 9784386 | 1791079817 | 0 |
| `diagnostic-output-failed-v2/epoch-207-through-89855469.jet` | 9784405 | 1791081711 | 0 |
| `diagnostic-output-failed-v3/epoch-207-through-89855469.jet` | 9784403 | 1791083949 | 0 |

The 2026-10-07 staging receipt mentions a manually stopped, 7.04%-complete v4
output at `qualification-207/diagnostic-output/epoch-207-through-89855469.jet`.
That path is now absent. Its mention does not establish a current source, digest,
original terminal identity, or restoration set. Do not create eligibility from it.
No archived replay output was found in the newer complete-span output directory.

The 2026-10-05 scratch cleanup already reclaimed the old epoch207 scratch; its
71,793,295,360-byte historical size is not current capacity. The 2026-10-07 compact
index cleanup recovered 27,858,628,608 bytes and explicitly preserved `.jet` files.
Neither receipt explains the absent v4 output; preserve that uncertainty.

## Concrete alternate: the old epoch213 prefix

`/home/ubuntu/.jetstreamer-private/qualification-213/diagnostic-output-selected-store8-v2/epoch-213-through-92447542.jet`
is still present. Its current metadata matches the saved post-archive failure:
length125,316,500,795; allocated125,316,632,576 bytes; device66305; inode18063496;
one link; UID/GID1000; mode0600; mtime/ctime1791629969. The saved independent digest
is `e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9`;
this review did not rehash it. The original producer was
`horizon-qualify-213-selected-store8-v2.service`, invocation
`331a5c69fd0a4f2e8dd35f7ace0f51a4`, stopped after its complete431543-slot prefix
with a parent-reap timeout9 and no restart.

The accepted fleet341 already records epoch213 as remote-ready, so the old
continuation assessment's proposed repair is obsolete. Keep the original prefix
and assembly provenance nonetheless. Offloading this source would recover about
125.3GB only after fresh closure/reference review, qualified custody and separately
reviewed local retirement. No current lane increase has been established.

Two further epoch213 copies are different policy cases:

- `/home/ubuntu/horizon/epoch-213.jet`:125,368,013,231 bytes, inode174110883;
  canonical SHA-256 `953e8c9efbdfc0dc49e4f066d30046e3b44e1a13e065b340a5bcc7b093632261`.
  Its full/plugin receipts exist, but the configured boundary receipt directory is
  empty. Ordinary local retirement remains blocked; holding is no exception.
- `checkpoint-continuation-213-ae43646-v1/output/epoch-213-checkpoint-restart-v4.jet`
  beneath the private root:125,368,013,231 bytes, inode187156493, with that same
  canonical digest in the saved verification receipt. Publication explicitly
  preserves this original assembly and denies retirement. Do not label it a
  failed disposable prefix or retire it through a holding shortcut.

## Narrow adapter proposed for review

Keep the existing node02 commands and mapping validator unchanged. Add separate
Foundation entry points and an exact Foundation mapping type that accepts only
the sealed mapping above, host `horizon-vaultic` and prefix `foundation_node_01/`.
Do not silently translate the node02 schema or choose a prefix from the hostname.

Extract transport primitives from the existing reviewed implementation instead
of implementing another multipart protocol:

1. Share the existing conditional owner create/readback logic after each host's
   mapping validator. Identical existing owner bytes are idempotent; different
   owner bytes, or a nonempty prefix without an owner, are hard failures. Use
   content-addressed `objects/SHA.blob` and `manifests/SHA.json` keys, never root
   canonical keys, overwrite, deletion or per-object ACLs.
2. Reuse `upload_object`, independent multipart ETag/composite-checksum checking,
   and `verify_remote_sha256`. Rehash and revalidate the same local inode after
   complete authenticated remote readback, then create the manifest and fsync a
   private custody receipt. An existing matching object still needs whole-byte
   verification. Custody grants no canonical publication or local retirement.
3. Reuse conditional authenticated `read_remote_sha256_resumable`, protected-floor
   chunk writing, partial-file identity checks, fsync and `RENAME_NOREPLACE` for
   restoration into a root-private directory. Bind exact original name, ownership,
   mode, lineage and required metadata; content remains a holding blob until a
   separate no-clobber consumer handoff. Neither restoration nor a byte round trip
   grants replay/checkpoint/resume authority.

The artifact adapter must validate the exact reviewed nonzero file, hash/length,
stable single-link identity and public-chain content class; exclude credentials,
configuration, logs, status objects, canonical files and deployment members. For
the old213 prefix, bind the original producer failure, all later assembly/verifier
owners, publication and accepted ready-pair evidence. Fresh terminal/no-replacement
checks and before/after process-reference scans cover the source and its owning
tree. Review staged services, manifests and future input references separately;
an inactive process is not proof that an artifact is unused. Keep metadata needed
to restore the exact bytes and prohibit consuming a parked path before restoration.

Foundation restore admission needs its own reviewed201-300 resource adapter.
Never reuse node02's101-200 fleet path, capped186 budget, or fixed reserve. Bind the
latest accepted coordinated fleet/observer and all current invocation-bound guard
claims, preserving their floors and complete remaining growth, then add the full
restore requirement. Reject unknown/native peers until modeled. Resource evidence
comes from the existing30-minute loop; metadata ownership checks are not another
replay/resource polling loop.

First qualify transport with a small, dedicated copy of known public genesis
bytes, not an immutable deployment member. Exercise interruption after remote
completion before receipt persistence, matching retries, conflicting owner/object/
destination bytes and interrupted restore. Leave remote test objects append-only.
Then qualify the exact retained-prefix path and restoration set. Local retirement
is a separate exact-file operation after durable custody, complete restore
qualification and fresh ownership/reference/staged-input checks; it preserves
receipts and every original archive-specific gate. Never offload live/mmap-backed
AccountsDb, SIGSTOP images, or unqualified resumable state.

No Foundation mutation entry point, eligibility receipt, or retirement authority
has been added by this review. A nonzero candidate and the adapter must pass root
review, tests, sealing and actual transport qualification first.
