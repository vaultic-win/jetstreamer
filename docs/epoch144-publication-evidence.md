# Exact epoch144 pre-publication evidence

`jetstreamer-epoch144-publication-evidence` validates the two distinct private
assembly-only scan receipts. It is not a publisher, archive verifier, resource
admission check, or substitute for the later importer's independent copy/hash.
It deliberately has no network client, archive write, canonical checksum,
standard `.ok` receipt, runtime promotion, or retirement operation.

The fixed dev-samjohnson profile retains the original timeout and the successful
assembly-only fallback as different owners. It requires the exact full and
plugin plans, tools, successful terminal scanner invocations, strict full scan
arguments with canonical anchor/terminal and independently derived provenance,
current byte-consuming plugin arguments, identical original inode identities,
and the pinned source-derived manifests/outcome/launch/boundary evidence. Both
scan logs are bounded, hashed and included in the resulting evidence. Neither a
still-running plugin nor a missing final receipt can pass. A valid private scan
must continue to deny publication authority.

The source remains the root-owned mode0600 original, length109177480876 and
SHA256 `153d3e5e5b7cbdc31bb4229315786000b84442a75b3b83cf4a50184b20b84a33`.
The scanner's ten-element identity array is preserved verbatim; it is not
converted into epoch213's different verification schema. No archive hash or
copy is performed by this evidence collector. It checks the retained open inode
and pathname against both receipts and explicitly records
`fresh_archive_hash_performed: false`.

Seal the executable and a root-owned immutable plan through the deployment
sealer. A plan has exactly these fields:

```json
{
  "schema": "jetstreamer-private144-publication-evidence-plan-v1",
  "full": {"path": "/var/lib/jetstreamer/horizon-epoch144-assembly-only-verification-20261022-v1/full/verification.json", "sha256": "EXACT_FULL_RECEIPT_SHA256"},
  "plugin": {"path": "/var/lib/jetstreamer/horizon-epoch144-assembly-only-verification-20261022-v1/plugin/verification.json", "sha256": "EXACT_PLUGIN_RECEIPT_SHA256"},
  "output": "/var/lib/jetstreamer/horizon-epoch144-publication-evidence-UNIQUE/evidence.json"
}
```

Precreate only the exact root-private output directory. Invoke with the plan
path, `--plan-sha256 HEX --self-sha256 HEX`, and first `--check-only` under the
intended root sandbox. Check-only performs evidence reads but writes nothing.
Actual collection writes one fsynced no-clobber private receipt. Keep all
assembly, prefix/suffix, scan logs, plans and receipts untouched.

## Remaining import and delivery gates

This source addition alone is not deployed qualification or local publication.
After both actual scans finish, the evidence tool still needs its actual sealed
sandbox check and collection. A separately qualified exact-artifact publisher
must consume this evidence, preserve the original, independently copy/hash a
distinct inode, validate complete V4 coverage/provenance, and enforce an
absence-only checksum-last local transaction. On this host the public directory
is `/home/sol/horizon`, owner sol UID1001 and group horizon GID1003, mode3770;
do not reuse epoch213's host UID/GID/path constants. Revalidate those properties
and statx mount identity before handoff. Separate writable bind mounts can make
an otherwise same-device rename fail with EXDEV; use an actual kernel capability
probe and narrow write confinement.

The additional109GB copy requires fresh admission from the coordinated v2
sample, eligible century floor evidence and complete remaining-growth claims.
Inherited multi-producer protected bytes are not the century floor. Preserve
live guards and producers. Standard full/plugin uploader gates may only be
created after a qualified exact local import; authenticated R2 upload/readback
and sidecar publication remain separate. Local retirement additionally needs
both adjacent boundary receipts. Do not wait for a public origin URL.
