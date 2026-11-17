# Epoch 239 native import source

This Rust tool renders source-only systemd import and namespace-probe units for the native committed-cohort
import. It checks the exact private archive identity, sidecar, native batch
receipt, manifest, node, and independent hash report. It masks the current home
tree read-only except the source archive and canonical destination. The unit has
an actual-invocation guard-token gate.

Rendering neither installs nor starts either unit. The probe runs the same
read-only mask set under the real service namespace and checks every mask,
source and destination mount, and same-device import access without writing.
A sealed package, successful native probe, fresh Main admission, and first guard
sample remain mandatory before the importer starts its native command.

## Guarded import operator

`horizon-epoch239-import-operator` is a separate one-shot Rust binary. `inspect`
checks the sealed importer and guard images, the native namespace proof, the
private archive identity, a fresh coordinated three-lane observer, physical
memory and disk capacity, and authenticated R2 inventory. It makes no change.

After sealing the operator image, `launch` repeats those checks and writes a
root-owned admission. It links the sealed importer, starts its 60-second
prestart gate, seals an invocation-bound guard plan and units, and starts the
guard timer. It accepts only the actual first zero-trip guard sample while the
same importer invocation remains in start-pre. It then uses the approved Rust
sealer to publish a no-clobber token under that invocation ID. The importer
can begin its native command only after the token file exists. A failure before
the token leaves the importer unable to pass its prestart gate.

The operator does not upload, delete, or mutate R2. The running importer and
its protective timer still need operational observation, native import
completion checks, full/plugin/boundary verification, and R2 delivery.
