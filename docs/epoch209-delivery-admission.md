# Bounded full 209 delivery admission

`admit-singleton209-delivery SPEC --spec-sha256 SHA --self-sha256 SHA` is a
root-only, sealed Rust metadata command. Source is unqualified until its focused
tests, full checks, build and root deployment seal pass. It starts no service,
reads no archive body and makes no R2 request. The existing independently sealed
c09 `deliver-singleton209-output` helper remains unchanged and must serve all
three delivery stages with the same helper SHA.

The immutable admission spec uses
`jetstreamer-private-epoch209-singleton-delivery-admission-spec-v1`, fields
`delivery_spec`, `resource_basis`, `unit_file`, nullable `environment_file`, and
`output`. Bound files carry exact absolute `path` and lowercase `sha256`.
`resource_basis` is the complete reviewed maintenance object containing accepted
`observer`, `fleet` and exact `protected_guards`. Output is `admission.json`
directly under a fresh root-private
`/var/lib/jetstreamer/horizon-209-singleton-delivery-admission-*` directory.
It must remain outside the stage's writable attempt directory.

The command reuses original launch, source terminal, actual v2 cohort and pair
metadata checks. Plugin admission additionally requires its existing successful
full receipt; upload requires both full and current plugin receipts. Metadata
admission never substitutes for the actual scans, archive hashes, whole-object
authenticated readback, canonical sidecar commit or boundary-gated retirement.

Closed stage profiles are full 32 GiB hard/16 GiB high, plugin 64 GiB hard/32 GiB
high, upload 16 GiB hard/8 GiB high, with 1 GiB incremental local metadata. The
shared capacity check preserves every typed current capped peer, all inherited
floors and guarded disk growth, the validated original native 223 available
memory floor, and actual remaining peer hard-memory growth. It adds only the
candidate stage hard cap, once. Unknown/restarted/changed peers fail closed.

The exact canonical Type=exec unit is checked against a private rendering in
the admission module and its effective loaded fragment, with no drop-ins or
pending daemon reload. It uses the pinned c09 helper and exact delivery spec,
no restart, 512 tasks, no swap, 800 percent CPU and bounded runtime. Both soft
and hard LimitFSIZE are 67108864 bytes, LimitCORE is zero, /tmp and /var/tmp are
inaccessible, and stdout/stderr go to one explicit regular coordinator.log.
Only the attempt directory and, for upload, the fixed private R2 receipt
directory are writable. The full, plugin and upload route censuses plus these
inherited limits fit the separately admitted 1 GiB metadata allowance. Reaching
a limit fails the attempt while preserving prior bytes; never truncate logs.

Admission brackets complete accepted owners, all three downstream units, exact
effective caps, file bindings and terminal/pair metadata. It refuses live or
pending downstream work and obtains the existing upload lock for upload
preflight. Actual upload independently obtains that same lock. The immutable
receipt is valid for at most 900 seconds; parent must still enforce freshness
when starting the exact admitted unit and retain failed attempts for accounting.

No second capture implementation is added: existing later coordinated fleet
reconciliation and generic `status-publish-pipeline` bind actual stage IID,
MainPID and direct command, preserve the original full 209 launch/IID clock,
and use verification/upload/readback phases through matching sidecar commit.
Retain all private history. The admission receipt does not authorize treating
that stage as an ordinary replay or bypassing a same-sample predecessor gate.
