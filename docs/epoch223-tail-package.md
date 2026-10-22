# Epoch-223 tail package capability

`jetstreamer-epoch223-tail-attest` is a closed, non-authorizing validator for
the immutable `horizon-focused-223-v1625-tail-bd60006d-v1` package. It is not an
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

Three actual-release probes run as UID/GID 1000 in a new isolated private root:
reject the early failed-prefix recovery entrypoint; reject a wrong-but-nearby
snapshot slot; and reach the correct focused v1.6.25 route before rejecting an
intentionally absent exact-slot snapshot. Require the precise exit codes and
log markers, reject replay indications and archive/sidecar/segment evidence,
and revalidate the complete package after all probes. Run the tool under a
persistent read-only systemd sandbox, with network disabled and only exact
receipt/private-probe creation paths writable. Root needs the minimal traversal
and UID/GID-drop capabilities; do not weaken private directory modes.

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
