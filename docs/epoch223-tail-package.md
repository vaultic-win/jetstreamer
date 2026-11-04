# Epoch-223 tail package capability

`jetstreamer-epoch223-tail-attest` is a closed, non-authorizing validator for
the immutable `horizon-focused-223-v1625-tail-b364126a-v3` package. It is not an
extension of complete-epoch attestation: its receipt explicitly describes only
slots 96,767,523–96,767,999 (477 slots), with complete-epoch coverage, snapshot
schema verification, fresh admission, launch and publication all false.

The tool verifies its independent executable/plan SHA-256 values and persistent
service identity, the root-owned immutable native deployment receipt and exact
member census, every member's whole-file digest and stable inode/metadata, and
the exact known parent, worker, snapshot, genesis and checkpoint bytes. It
checks the original generation-bound snapshot metadata specifically at epoch
224's bootstrap, not the report's first epoch. That old report is used only to
identify the retained snapshot generation; its runtime/publication plan is
never adopted for epoch 223.

Native `SHA256SUMS` includes the generated deployment receipt in addition to
the eight declared payload members. Verify that generated entry against the
independently supplied receipt digest, then exclude it only from the declared
payload comparison. The first sealed attempt rejected this census safely;
preserve that failed service and its journal. A regression binds the actual
nine-line native checksum table rather than an invented eight-line format.

Four actual-release probes run as UID/GID 1000 in a new isolated private root:
reject the early failed-prefix recovery entrypoint; reject a wrong-but-nearby
snapshot slot; and reach the correct focused v1.6.25 route before rejecting an
intentionally absent exact-slot snapshot; then successfully finish actual
post-bootstrap planning with the real sealed snapshot and checkpoint file,
preseeded verified genesis, and both `--epoch223-tail-comparison` and
`--epoch223-tail-preflight`. The fourth probe must report the exact selected
v1.6.25 revision/worker, canonical bootstrap, 477-slot output range, no worker
or archive creation, and no qualification/publication authority. An early
missing-snapshot rejection alone did not exercise the terminal-planning gate
that stopped the original tail parent before replay. Require precise exit codes and
log markers, reject replay indications and archive/sidecar/segment evidence,
and revalidate the complete package after all probes. Run the tool under a
persistent read-only systemd sandbox, with network disabled and only exact
receipt/private-probe creation paths writable. Root needs the minimal traversal
and UID/GID-drop capabilities plus `CAP_CHOWN` for the new user-owned probe root
and genesis copies; bind the same minimal set through bounding and ambient
capabilities. Children drop to UID/GID 1000 with no capabilities. Do not weaken
private directory modes. Use the `qualification-223-v1625-tail-capability-*`
namespace and the schema-v2 capability receipt; old three-probe receipts are
not authority for this package. Set the probe service's `UMask=0077`: negative
probes create directories before their expected snapshot rejection, and the
fourth probe must find those directories still user-owned and private. The
v5 sandbox inherited `0022` and correctly failed that gate; preserve its root
and logs, then use a fresh plan/root/receipt generation with the corrected mask.

The next four-probe attempt (v6) passed the initial top-level preflight, but
the subsequent parent attempt found an additional post-bootstrap requirement
inside the actual replay entrypoint and stopped before any worker or archive.
Preserve that failure too. Require the nested schema-v2 planning report, not
the earlier schema-v1 report: it must reach the shared actual pre-worker
barrier, validate the candidate checkpoint policy and compiled worker profile,
and resolve the exact packaged worker executable. A planning-only result has
a distinct type and cannot be consumed as completed replay evidence. The
ordinary/cold trusted-terminal and post-bootstrap obligations remain unchanged.

The root-private logs and capability receipt are fsynced and no-clobber. A
failed attempt is retained and cannot be retried in the same root or receipt
directory. The tool does not delete its probe scaffolding or claim a live-process
reference scan; separate normal reference-gated retirement is required.

Capability success is not real snapshot loading, cold-prefix qualification,
full-epoch peak qualification or a canonical sidecar gate. A separately
supported diagnostic fleet contract, fresh resource admission, real snapshot
checks, exact invocation-bound guard and first real sandboxed fire still
precede the tail replay. See `epoch223-v1625-qualification.md` for that isolated
candidate; keep the original failed epoch and all canonical publication gates.

The R2 fleet observer has a separate closed `horizon-qualify-223-v1625-tail-*`
contract. It binds this exact package and successful four-probe capability
receipt, the 477-slot range, private paths, zero-restart identity and actual live
command, including the comparison flag but never the preflight flag. Its
ordinary natural-drainage guard has no target-stop exemption.
The 416-GiB experiment envelope and protected older growth claims are minimum
contract bounds, not resource admission. Fleet recognition neither launches the
comparison nor authorizes full-prefix qualification, canonical sidecars or R2
mutation. Keep the original epoch-223 repair open through this comparison.
