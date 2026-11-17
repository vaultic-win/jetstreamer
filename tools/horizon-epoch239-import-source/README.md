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
