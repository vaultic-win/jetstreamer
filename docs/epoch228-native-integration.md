# Dormant epoch228 native-input integration

This integration registers only the bootstrap-only cold native test, not entry replay,
archive qualification, route promotion or publication. The test has been compiled but
has not run. It must reconstruct slot98495291 without replay/bootstrap writes and match
`GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq` before any later focused228 work.

The exact dormant producer unit is
`horizon-native-input-228-capped-1bfa8d51-v1.service`; its source template is
`epoch228-native-input-service.service`. Its immutable worker/test packages are separate
from the source CLI. `epoch228-native-cold-plan.json` records all exact input paths,
including the snapshot in the retained228–230 package and genesis in the227 bootstrap
package. Neither input is copied or restored during source preparation.

Prepared immutable packages:

- Guard: `/var/lib/jetstreamer/horizon-228-native-main-guard-b7da8d62-v1/jetstreamer-horizon-standalone-guard`,
  SHA256 `b7da8d629d6e2500a0533c71cf05916e52b6ff136bb75b9a3bad74a72947f67b`.
- Cold plan: `/var/lib/jetstreamer/horizon-228-native-cold-plan-v1/native-cold-plan.json`,
  SHA256 `3e954d65dff36c26453c68983003a9e3ae3e269bacb5917e50a191e3243d9734`.
- Test: `/var/lib/jetstreamer/horizon-228-native-test-optimized-d3fe9c72-v1/native-input-test`,
  SHA256 `d3fe9c72d542237c97504e0b680fe51e2eb4365b8a9343a631f9bc7512529827`.

The guard's separate `epoch228-native-main-guard` feature admits the complete228
unit/root/executable/digest tuple through the same whole-plan validator as runtime.
It accepts only an actual MainPID greater than1, a single mapped executable in its
cgroup,300000000000 bytes of whole-root physical scratch,3500000 VMAs, and no bounded
stop exemption. A static template or passing source test proves no live protection.

The CLI provides `admit-native228-input`, `capture-native228-input`, and
`capture-native228-terminal`, each taking a separately SHA-bound spec and self SHA as
with native209. The admission spec uses schema
`jetstreamer-private-epoch228-native-admission-spec-v1`, mode `native-cold`, and binds
observer/fleet/cold_plan/resource_plan/protected_guards/output. Its output must be
`/var/lib/jetstreamer/horizon-228-native-admission-ATTEMPT/admission.json`.
The resource plan uses schema `jetstreamer-private-epoch228-native-resource-plan-v1`:
exact228 identity and fingerprints,128GiB hard memory,300GB scratch, the accepted
century floor and every protected owner's remaining growth. Compute the protected
floor from a fresh accepted census; do not reuse an example constant. All authority
flags checked by the native registry remain false.

The admission path reuses209's full227/207/legacy223 accounting and separately accounts
for an accepted native209 peer, including its exact origin, current protective guard,
remaining hard-memory growth and full300GB scratch reservation. It deliberately grants
no209 scratch credit. Unknown/new owners, including an unsupported223v2 generation,
fail closed. Their exact reviewed adapter must be integrated before admission, rather
than removing them from the accepted fleet, substituting a zero growth estimate, or
erasing preserved failed223v1 evidence. Source preparation performs no resource poll.

After fresh admission, the main controller owns producer start, fresh actual IID/PID
binding, separately sealed guard plan and protective service/timer. Capture requires
`horizon-native228-protective-v1.service` to have completed a genuine PID1 success with
its matching guard invocation and its timer active/waiting. The first guard must fire
within900s of admission. Running capture writes the exact
`/var/lib/jetstreamer/horizon-228-native-capture-actual-v1/intent.json` origin; the central
fleet must register it without changing unrelated owners, gates or history.

Publish the generic pipeline dashboard status with phase `verification`, zero `.jet`
bytes, the exact registered origin/claim and the current accepted observer/fleet.
Perform authenticated readback and bind that receipt. Later updates share the normal
30-minute observation cadence. Internal qualification work is never hidden.

Terminal capture binds that immutable original start, the exact sealed journal, raw
integer commitment fields, successful test result, original child PID and PID1 terminal
success in order. The test's2700s execution bound is checked against its original start,
not against when the operator later captures the journal. Central terminal events and
status-only cleanup preserve unrelated owners and require real loaded inactive state;
no synthetic unit state or sidecar is accepted. No228 producer/guard unit has been
installed or started by this preparation.
