Epoch 205 admission rejected a genuine completed epoch 207 protective guard on
2026-10-25 at 07:51 UTC. The failed metadata-only invocation was
`horizon-meta-admit205-bounded8-v4.service`, invocation
`fede9d861ffb4ea4b2b3c879529e834d`; it exited naturally with status 1 and
`closed peer protective evidence changed, stale, tripped or omitted an obligation`.
No epoch 205 producer or real continuation guard was launched.

The qualified ec43bd3f helper required `guard.producer.unit`. The actual standalone
guard schema emits the unit in its immutable plan and producer cgroup; it does not
emit `producer.unit`. The preserved guard is
`sample-576e528add8e41a2b5b794e8c7de82de.json`, SHA-256
`52e28879667be131c8dd163a76c825bad2943dac963bef6337720c5a6dcf3629`.
The original v4 admission spec and terminal journal/properties remain under
`.codex/tmp-readiness/epoch205-admission-guard-refresh-v4/`, including
`closed-peer-schema-diagnostic.json`. No original evidence was changed.

The successor is based on qualified commit
`24524cddda6c0b5faf6b068cc1da34cfb8fdfc11`. Its narrow adapter correction
authenticates the unit through the exact profile's immutable plan unit, guard
plan path and digest, producer cgroup, and invocation IDs. Existing PID matching,
latest completed PID1 guard selection, timer state, clocks, stop protection,
worker count/VMA limit, disk limits, error fields, no-mutation assertions, and
complete raw fleet census remain mandatory. The same adapter also serves the
exact epoch 233 profile; no generic producer or phase exemption is introduced.

Pure regression fixtures include byte-identical genuine guard and plan files,
the actual diagnostic claim, and an explicitly labeled projection of the genuine
launch receipt's profile fields. Provenance records their original bindings.
These test inputs are not issuer receipts and grant no operational authority.
Tests exercise the accepted real guard shape and reject changed unit, cgroup,
invocation IDs, plan path/digest, guard digest, clocks, stop/disk/worker limits,
mutation flags, errors, and missing obligations.

The original observer 397 and source custody are historical after expiry. They
must not be refreshed by changing timestamps. A new admission spec lineage may
be prepared only after the corrected tool qualifies and genuine fresh observer,
source custody, and latest completed guards exist. No launch is authorized until
that issuer produces a positive fresh admission. Shared Cargo target access is
reserved to the root's explicit build lease; source preparation alone does not
authorize Cargo, an admission retry, or replay/resource polling.
