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
`4bb320d5e79d324d084be28dc5f63b38dba5525f30a28e378c47654c36be7813`.
The first preparation attempt preserved its failed state after finding a
preexisting temporary CAR header proof directory. Those six proof files were
preserved outside the accepted input root. The next attempt uses a distinct
state and deployment namespace; it still requires fresh Main admission.

The revised launcher is sealed at
`/var/lib/jetstreamer/horizon250-reboot-20261117-launcher-4live-v2`;
its plan SHA-256 is
`242457c1b535daadd3cc2618b3fb915ff44b039e7457a620ba67d192726526f3`.
The deployed binary's read-only `inspect` completed with `inputs_unchanged`,
`source_templates_unchanged`, and `no_units_changed` true. The first attempt's
admission and failed preparation are preserved; no replay launch occurred.
