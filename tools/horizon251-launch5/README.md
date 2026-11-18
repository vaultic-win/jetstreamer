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

`century FLEET FLEET_SHA INVENTORY200 INVENTORY200_SHA OUTPUT SELF_SHA` is
a separate metadata-only helper for the admission's century census. It retains
the exact, previously accepted 29-epoch floor and checks the five subsequent
deliveries (205, 210, 239, 244 and 246) against full/plugin receipts with pinned
verifier and runner hashes. All 34 entries must match canonical R2 readback
receipts and the complete 200–300 inventory. It writes root-owned, digest-bound
JSON documents suitable for the launcher's existing gate bindings. It claims
no new verification of the inherited 29 epochs and grants no launch authority.
New or missing ready epochs require adjudication before changing its accepted
input set. Four tests cover incomplete census, changed verification identity,
readback requirements and overflow/rounding; strict Clippy also passes.

`capture-admission REVIEW REVIEW_SHA SELF_SHA` captures fresh normalized owner,
observer, fleet, capacity, census and guard evidence from a root-owned Main
review. The review binds the exact launch plan, unaccepted admission template,
observer, fleet, century census and source-publication proof, along with the
actual Main PID/start ticks/boot, prospective launcher unit and explicitly
reviewed coexisting services. It grants no unit mutation or replay start itself.
The final admission is issued only after the production validator accepts its
full resource arithmetic and the native census identifies all four unchanged
owners with no unknown worker. Captured guard receipts must still satisfy the
launcher's 120-second freshness bound at use; admission expires in five minutes.

Source publication records must bind node, worker, launcher, guard, sealer,
producer/guard templates and the admission-capture executable to root-owned
provenance, exact artifact hashes and full source commits. Read-only Git checks
verify each commit against the fetched remote head and reject a changed head.
Main must establish the actual artifact/source correspondence before accepting
that review; a seal containing only an executable is not a compiler/source
manifest. Existing healthy owners retain their immutable deployments while
historical source gaps are resolved. The original sealed launcher v1 is retained;
this new capture command has not yet been sealed or used for native admission.
The expanded launcher suite has 21 passing tests and strict Clippy passes.

The `horizon251-standalone-guard` target compiles the repository's existing four
standalone-guard source modules directly. It provides a bounded build route for
a new candidate with complete source/compiler capture, without replacing any
running guard. The selected `epoch223-native20-prefix-guard` feature preserves
the older guard's profile in addition to the ordinary standalone namespace;
the other declared features remain disabled. This target passed 38 tests and
strict Clippy. Native isolated qualification and new immutable candidate unit
bindings remain necessary before selecting its artifact for epoch 251.

The fresh guard build from published commit
`c63c73b4149fae3a869e82b52ea3fd6e8a596e8a` is sealed at
`/var/lib/jetstreamer/horizon251-published-guard-20261118-v1`. Its executable
SHA-256 is `938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d`.
That package retains all four Rust modules, Cargo manifest/lockfile, Git source
identities, unchanged before/after source hashes, compiler version, actual
verbose rustc commands, Cargo artifact/fingerprint evidence and the genuine
PID1 build journal. The clean offline build used Rust 1.98.0, two jobs, a 2 GiB
hard limit and the single declared profile feature; PID1 recorded success.

Its explicit non-signaling native root capability passed on the unchanged epoch
250 invocation in `horizon251-published-guard-native-20261118-v1.service`.
Receipt:
`/home/ubuntu/.codex/diagnostics/horizon251-published-guard-native-20261118-v1/receipts/root-capability-2c5e860ecf66498d819639dc2ae5476c.json`.
The receipt records no trip, `producer_signaled=false` and
`protective_guard_proven=false`. No existing guard, timer or worker was replaced.
The old guard's required source patch is already published as `62363cf5`, with
the same stable patch ID as the historically recorded `48924289`; the new build
addresses missing original compiler/source capture, not a missing guard patch.

The `horizon251-sealer` target directly compiles the repository deployment sealer.
It passed eight tests, strict Clippy and release compilation. A fresh offline,
locked, verbose build from published commit `db7a9bea562a5f18ce42de394e064d4675e54fa9`
used Rust 1.98.0, two jobs and a 2 GiB cap. Its source, manifest/lockfile, compiler
commands, Cargo artifact/fingerprint and successful PID1 journal are sealed at
`/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1`.
Executable SHA-256:
`faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a`.
Native positive sealing and refusal to replace the same destination both passed;
evidence is in
`/home/ubuntu/.codex/diagnostics/horizon251-published-sealer-native-20261118-v1`.
The candidate launcher source now selects this sealer.

Next: complete source provenance for every selected candidate artifact, bind a
qualified guard into a new candidate-only immutable configuration and launcher,
then capture fresh Main admission and execute the actual first-timer startup.
Keep retained-owner guard hashes separate from the candidate's new hash.
The retained launcher v1 still selects the old guard. The next launcher v2
selects the captured node, new guard/sealer, captured-node input receipt and
static v3 package. Retained owners continue to require the original guard hash.
The v2 source passed 22 tests and strict Clippy. Its deployment and fresh
admission remain separate steps. Latest account-updates reader qualification remains a
separate archive-publication gate described in
`docs/horizon-current-reader-audit-20261118.md` at repository root.

The captured node passed both required no-replay input probes with candidate
runtime opt-in: the wrong fingerprint failed at the fingerprint gate, and the
correct manifest decoded before a deliberately wrong snapshot filename was
rejected. Probe invocations were `63db3d36523447ca88013139029db22d` and
`a720df223e724318a8fe18369e97adfb`. The first setup generation stopped earlier
because intermediate directories were root-owned; those failures are preserved.
The corrected probes left only logs and empty epoch locks, with no archive or
replay scratch. Their Main-reviewed evidence and actual terminal/journal files
are sealed at
`/var/lib/jetstreamer/horizon251-captured-node-probe-acceptance-20261118-v1`.
The bound review SHA-256 is
`26b1a2a123fb5848e42e241758e1fda264baa5ee3b528ad0f7ad19d89e10099a`.
These probes do not claim worker initialization or complete replay.

Launcher v2 was built with captured source/compiler evidence from published
`d8d48839`, sealed at `/var/lib/jetstreamer/horizon251-fifth-20261118-launcher-v2`,
and passed read-only inspection. Executable SHA-256:
`8c3cc2e4fdd632bcb5e20a14825f9b35bb0a533828c56348c791731a2e9336cb`;
launch plan SHA-256:
`33b60420175a86814689e8766ebc25501c6e8932b61dde509c7a1be22286b256`.

At 2026-11-18 21:11 UTC, fresh admission, preparation, loaded-unit preflight
and the original first-timer startup transaction passed. The source-publication
record binds nine artifact roles to published source and captured evidence;
the freshly captured admission retained all four original owner identities,
hard limits and guard receipts. Epoch 251 invocation
`cd2477bfec7f4e498545762c633e7bb0` passed the real first guard invocation
`af5b0ac8b0394f519365f7ca7ff795b1`. The handoff is
`/var/lib/jetstreamer/horizon251-fifth-20261118-state-v1/launch-v1/guarded-startup-handoff.json`,
SHA-256 `257c38a1a32aa57980a53289a385d8e4b3dc9b6cd0edb148d4f3a87861a4404f`.
PID1 started the node at 21:12:07 UTC; it accepted the exact manifest and began
revalidating the cached bootstrap. Useful transaction replay and a clean expanded
fleet observation are not yet proven. This is four established replay lanes
plus one admitted initialization, not a proven five-lane operating point.
The epoch 251 status was conditionally refreshed and read back with a 102-hour,
high-uncertainty allowance: two hours startup/restore, 80 hours replay and
20 hours current-reader verification and delivery. No archive was published.
