# Epoch 250 replacement after epoch 247

This one-shot Rust adapter prepares epoch 250 to replace a positively terminal
epoch 247 while epochs 248 and 249 remain active under their original invocation
IDs. It uses the accepted epoch 250 input and sealed static service at
`/var/lib/jetstreamer/horizon250-reboot-20261117-static-v2`. The two live replays
use separate roots and index caches; the epoch 250 service binds its own accepted
cache and snapshots read-only. No fourth-lane memory fit is claimed.

The launcher requires a fresh root-owned Main admission bound to its exact
sealed plan. The admission must bind a terminal epoch 247 proof, the original
epoch 247 guarded startup handoff, fresh capacity and census evidence, and the
unchanged guarded handoffs for epochs 248 and 249. The launcher independently
checks the old producer, guard and timer are closed and the two remaining replay
workers are healthy. An admission expires within five minutes.

`inspect` is read-only. `prepare` creates the epoch 250 state and installs only
an inactive producer. `preflight-launch` checks the loaded unit and mount
properties. `launch` starts the producer under its original 60-second prestart
gate, binds the actual invocation to the guard, and seals its token only after
the first real guard fire and sample. The operator must then observe useful
replay and maintain status and fleet evidence.

This route is dormant until epoch 247 is terminal and all ordinary admission
and guard gates pass. A terminal epoch 248 or 249 needs its own route. Keep the
original epoch 249 replacement launcher available; this package does not
replace or mutate it.

The 2026-11-17 source qualification passed 16 tests, strict Clippy, and a
release build. The release executable SHA-256 is
`37d7223f2980ab4f3db18af1f6befea6824e52d7252c662adf6c91adbba62c88`.
The immutable launcher is sealed at
`/var/lib/jetstreamer/horizon250-reboot-20261117-launcher-247terminal-v1`;
its plan SHA-256 is
`95ccf7721e62ea858f94069939ae9acd88670600181848fcf4e1415f8f06ddc0`.
The deployed binary's read-only `inspect` completed with `inputs_unchanged`,
`source_templates_unchanged`, and `no_units_changed` true. This does not
authorize admission or replay while epoch 247 is still running.
