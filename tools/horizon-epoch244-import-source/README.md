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
