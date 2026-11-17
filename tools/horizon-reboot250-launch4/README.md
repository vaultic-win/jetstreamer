# Guarded fourth replay lane for epoch 250

This one-shot Rust launcher prepares epoch 250 alongside the three live epoch
247, 248, and 249 replays. It uses the accepted epoch 250 input and the sealed
static service at `/var/lib/jetstreamer/horizon250-reboot-20261117-static-v2`.
Each replay has a separate root and index cache. The epoch 250 service binds
its own accepted cache and snapshots read-only.

The immutable launch plan declares that fourth-lane fit is **not yet proven**.
Only a fresh, root-owned Main admission can accept one guarded experiment. It
must bind the current three live invocation IDs and guarded handoffs, a clean
coordinated sample at least 1,800 seconds after the preceding observation,
current no-trip guard receipts, full host memory and disk accounting, and a
complete service census. The launcher requires three executing lanes before
it may propose four, and the admission expires within five minutes.

`inspect` is read-only. `prepare` creates the epoch 250 state and installs only
an inactive producer. `preflight-launch` checks its loaded service and mount
properties. `launch` starts the producer under the original 60-second prestart
gate, binds its actual invocation to the guard, and seals a token only after
the first real guard fire and sample. A later clean coordinated sample of all
four lanes is required before expanding again.

This route does not mutate R2, retire local archives, or affect the separate
replacement launchers for a terminal epoch 247, 248, or 249.

The 2026-11-17 source qualification passed 16 tests, strict Clippy, and a
release build. The release executable SHA-256 is
`a8b5f68931870ed47494ab6613dbdd0f30894d198cca858b9d6dd74ca00ba631`.
The immutable launcher is sealed at
`/var/lib/jetstreamer/horizon250-reboot-20261117-launcher-4live-v1`;
its plan SHA-256 is
`4442974022bb1894394e81a0a137926ef7dc770b03a459a2365c68b01e0b23a2`.
The deployed binary's read-only `inspect` completed with `inputs_unchanged`,
`source_templates_unchanged`, and `no_units_changed` true. No admission or
replay launch was performed.
