# Epoch 250 one-shot replacement launcher

This Rust launcher adapts the qualified epoch 249 guarded startup route to the
accepted epoch 250 inputs. It is **only** a replacement for a positively terminal
epoch 249 while epochs 247 and 248 remain active under their original invocation
IDs. A different first terminal lane needs a distinct reviewed admission route.
No fourth-lane memory fit is claimed.

The exact producer, guard source, timer source, and service-effective CAR-header
proof are sealed at `/var/lib/jetstreamer/horizon250-reboot-20261117-static-v2`.
This v2 producer mounts the existing accepted epoch 250 `input/` directory
read-only, including both GCS-restored snapshots. The accepted root already
contains the snapshots, receipts, and genesis. `prepare` creates only the new
state, temporary, compact-index mount, guard token and receipt directories.

## Exact dormant commands

The sealed launcher and plan are at
`/var/lib/jetstreamer/horizon250-reboot-20261117-launcher-v5/`. Source packet
`packet-v5/` includes a deliberately unaccepted admission template. The
launcher commands are `inspect`, `prepare`, `preflight-launch`, and `launch`.
Only `inspect` has been run. It checks immutable source and input bindings
without changing units. The other commands require a fresh root-owned Main
admission bound to the exact sealed plan and a terminal epoch 249 proof.

That proof must bind the original epoch 249 guarded startup handoff and affirm
its producer and guard have drained, its replay slot is released, and its prior
archive is preserved. The launcher independently checks epoch 249 is closed,
epochs 247 and 248 are healthy with unchanged invocations, and every additional
busy campaign service is named in the admission's exact census. Capacity and
disk claims must match fresh bound evidence. The admission expires after at
most five minutes and the observer must be younger than thirty minutes.

After admission, `prepare` installs only an inactive producer.
`preflight-launch` checks loaded systemd properties and mount declarations.
`launch` starts the producer under its original 60-second prestart delay, binds
its actual invocation to the guard, validates the first real timer fire and
guard sample, and only then seals the invocation token. A failed attempt is
preserved and never automatically retried. Main must still observe useful
transaction replay and maintain fleet/status evidence after startup.

## Qualification and remaining gates

Offline tests, strict Clippy and release build passed. The release launcher
SHA-256 is `92d209fdbb593ada4b74afa01f92b55d183219e9c0fff1b2b4e15e3274213713`.
Its read-only `inspect` passed against sealed plan SHA-256
`3bdf39ee87c2f6901e92fcaee2e39c49cc7e05cfa89b624afc1cee8e8460573f`.
The sealed static v2 receipt SHA-256 is
`9bbc1af99e689c1ddf614a8a79c91d561e18a66716782658f6b2c8688de6be1f`.
No replay or guard was started by this qualification.

Fresh terminal, resource, census and owner evidence; Main admission; inactive
preparation; sandbox preflight; and actual first-guard handoff remain. The
accepted snapshot files and current 247–249 replay lanes stay untouched.
