# Guarded fifth replay lane for epoch 251

This one-shot Rust launcher admits one isolated epoch 251 experiment alongside
the unchanged epoch 247–250 invocations. It adapts the qualified fourth-lane
startup transaction, including the 60-second prestart gate, 50-second operator
deadline, genuine first timer fire, actual invocation-bound guard receipt, PID1
events and immutable token publication. It never writes to R2 or retires data.

The candidate uses MemoryMax 128,000,000,000 and MemoryHigh 100,000,000,000 bytes
on CPUs 0–15. All four existing hard limits remain 251,041,591,296 bytes. The
64 GiB host reserve covers non-lane resident usage and five guard maxima; the
candidate control allowance is 1,610,612,736 bytes. Total hard obligations are
1,202,496,454,656 bytes. Admission also checks available memory against all
remaining hard growth and the century RSS reservation ceiling. A 90% desired
utilization target is not a hard-limit ceiling.

Disk admission takes zero occupied-allocation credit, reserves four complete
existing root caps, recomputes the century floor from digest-bound canonical
full/plugin/remote evidence, preserves the largest current inherited guard
floor, then adds the candidate's complete 506,191,984,640-byte root cap. Main
must adjudicate the heterogeneous historical verification schemas and supply
the complete qualified century census. The preliminary static assessment's old
floor is never fresh admission authority.

Every mutation requires a separately hash-bound, root-owned Main admission
valid for at most five minutes. The normalized observer must bind the actual
clean native sample and fleet; all four live services, limits, CPU affinities,
timers, cgroup memberships and node/worker images are checked again. Current
no-trip guard receipts must bind the original handoffs. Unknown replay owners
and changed identities fail closed.

Epoch 251 reuses its authenticated immutable bootstrap, genesis and singleton
manifest. The final checkpoint expectation comes from that manifest; no final
snapshot copy is needed. Its exact three-member cache is mounted at predecessor
250 and current 251 index paths. The host genesis file is an empty mount
placeholder; the actual genesis source is immutable. The retained network-proof
files are checked without treating the curl probe as deployed-node replay proof.

Commands:

- `emit-source-templates DIRECTORY`: emit a plan and unaccepted admission template.
- `inspect PLAN PLAN_SHA256 SELF_SHA256`: validate actual sealed inputs, cache,
  source templates and pristine candidate tree without changing units.
- `prepare`, `preflight-launch`, `launch`: additionally require
  `ADMISSION ADMISSION_SHA256`. Preparation installs only an inactive producer.

Qualification on 2026-11-18: 19 tests, strict Clippy and release build passed.
The separately sealed executable is
`/var/lib/jetstreamer/horizon251-fifth-20261118-launcher-v1/horizon251-launch5`,
SHA-256 `2bdbd03bb30a5ec336a6e610323fae3717ac6af2291f592029fed988d0f48478`.
Its launch plan SHA-256 is
`0f633e184a7d971fc61428693c0033685927053784d30d1a2877581f2811da4d`.
The deployed executable passed read-only `inspect` in
`horizon251-launch5-inspect-20261118-v1.service`.

The static v2 package retains the same dormant names and guard but extends the
candidate runtime from 72 hours to five days: the smaller profile's unmeasured
planning estimate is 80 hours of replay. Systemd accepted all three unit files.
No candidate unit has been installed or launched by this qualification.
Full replay at this smaller memory profile remains unproven. Fresh admission,
the actual guard transaction and a later clean expanded-fleet sample remain
required before the fifth lane can become the proven operating point.
