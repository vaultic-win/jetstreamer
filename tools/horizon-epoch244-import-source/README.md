# Epoch 244 native import source

This Rust tool renders source-only systemd import and namespace-probe units for
committed epoch 244. It binds the private archive identity, native batch receipt,
manifest, node, and independent hash report. The generated unit keeps the
canonical epoch lease writable and masks unrelated home data read-only.

Rendering does not install or start the units. A sealed runtime, successful
native namespace probe, fresh fleet admission, and invocation-bound first guard
sample are required before native import. Completion still requires independent
full, plugin, and boundary verification, authenticated R2 delivery, and local
cleanup.

## Guarded import operator

`horizon-epoch244-import-operator` is the invocation-bound launch route for the
sealed source unit. Its `inspect` command checks the native namespace proof,
archive identity, live three-lane observer, memory and disk admission, and R2
absence without starting the importer. Its `launch` command uses the same checks,
starts the source unit, seals a guard plan bound to the actual systemd invocation,
arms the protective timer, validates the first genuine guard result during the
60-second pre-start window, and seals a readable token under that invocation ID.
The unit's remaining pre-start checks require that exact token before native work.

The retry operator accepts only the known first attempt that failed in pre-start
before native execution. It verifies the failed import and guard invocation IDs,
the inactive old timer, the installed source unit, the empty import log, and the
absence of an old token. It resets that unit's start limit, starts the same sealed
import service with a new invocation ID, and seals a replacement guard and timer.

The operator binds the failed epoch 239 v1 verifier invocation IDs and the
replacement v2 invocation IDs. It charges each active v2 verifier at its sealed
memory cap, rejects an unknown verifier transition, and waits for enough host
memory reserve before admitting the import. A successful, inactive v2 verifier
releases its memory charge only when its root-owned completion receipt binds the
exact epoch 239 archive, verifier, and script hashes.

Run `inspect` again with the latest coordinated observer receipt and its SHA-256
immediately before launch. The operator rejects a sample more than 30 minutes old.
The sealed operator and guard binary are separate from the source-only renderer;
their exact deployment paths and hashes are recorded in their seal receipts.
