# Epoch198 delivery observation

The separately pinned `cohort198_finalization` profile recognizes only the
existing dev-samjohnson epoch198 reader-fix singleton. It does not borrow the
other host's216–219 allowlist, change its producer or grant any replay,
verification, publication, deletion or R2 archive mutation authority.

`producer-finalization`/`finalization` can be claimed only while the exact
original producer is active/running with its pinned invocation, PID, command,
zero restarts, immutable node digest and immutable preflight report. Four unique
original-user journal events must precede the coordinated observation and be
strictly ordered: trusted root checkpoint85,967,282 with its manifest accounts
hash, complete terminal checkpoint85,967,999, snapshot-verification completion,
and complete432,000-slot singleton archive close. Numeric fields are parsed as
checked u64 integers. These events are observational evidence, never independent
full/plugin verification or a ready-pair receipt.

The existing phase-aware pipeline status publisher retains the original
producer-start clock and authenticates its complete live census, fleet claim,
estimate evidence, exact local archive and conditional R2 status readback.
Phase-capable publication-receipt readers and completion cleanup must be deployed
together before the new phase is published. All normal archive publication,
upload, whole-object readback and canonical sidecar gates remain unchanged.

Source support is not live adoption. Before replay ends, separately qualify a
new immutable R2 package and its actual host inputs, a coordinated observer/fleet
transition that stops requiring a historical worker after replay, and the exact
model/status handoff. Do not invoke the finalization observer repeatedly while
the producer is still replaying or manufacture terminal events. A producer that
has exited is not an active finalization claim. A still-live controller awaiting
import needs its own separately qualified handoff; this profile does not add one.
An actual live serialized importer uses the existing exact `local-publication`
claim. Preserve all terminal and failed states in the full-range repair ledger.

Keep the current replay and its existing observer/timers unchanged during this
preparation. A later deployment must consume genuine terminal events, not the
synthetic unit-test fixtures, and must retain the normal30-minute resource
cadence. A mixed or failed sample is not authority for an early retry.

## Event evidence capture

`jetstreamer-r2 observe-delivery-198 PLAN --plan-sha256 HEX --self-sha256 HEX`
can capture the exact active finalization owner's events before preparing a
coordinated handoff. It takes no resource sample, consumes no resource cadence,
accesses no R2 endpoint, updates no status object and grants no handoff or
publication authority. Do not run a second polling loop with this command.
Use it only after a genuine completion/phase event or within the existing
coordinated control cycle. An absent event is a failed gate, not permission to
retry blindly or invent terminal evidence.

The immutable root-owned plan schema is
`jetstreamer-epoch198-delivery-observation-plan-v1`. It has `output`, positive
integer `not_before_unix_seconds` and `expires_unix_seconds` bounding at most
1,800seconds, exact `expected_unit`, `expected_invocation_id` and
`expected_exec_start_sha256`, plus mandatory false `replay_launch_authorized`,
`publication_authorized` and `r2_mutations` fields. Output must be a direct
`proof-*.json` member of the precreated root-private directory
`/var/lib/jetstreamer/horizon-epoch198-delivery-observations-v1`.

The command authenticates its immutable running executable through
`/proc/self/exe`, the separately bound plan digest and the unchanged before/after
owner. It rehashes the exact parent/manifest and writes a private no-clobber,
file-and-directory-fsynced receipt only after genuine terminal evidence passes
the event window. The receipt retains the actual event timestamps and denies
status publication, replay and archive publication. A later handoff must still
check its freshness and reauthenticate ownership against the coordinated sample.

`--check-only` validates the actual owner, immutable inputs, plan and output
absence without reading terminal journal events, enforcing a future event
window, writing a proof or consuming cadence. Its success explicitly does not
establish finalization. Keep this as a dormant preparation until the event;
preflight never authorizes running a finalization claim while replay continues.

For this exact epoch198 origin only, a pipeline status plan may explicitly set
`receipt_directory_uid: 1001` with
`receipt_directory: /home/sol/.jetstreamer-private/r2-status-receipts`.
That preserves the existing shared publication history used by the fleet and
completion cleanup. The root writer still uses the common private-directory
write preflight under DAC_OVERRIDE; it never chmods the user's directory or
requires CAP_FOWNER. The exact original producer invocation, directory owner,
canonical path and owner-only mode remain mandatory. Other profiles retain the
default root-owned directory policy; this is not an arbitrary foreign-directory
override.
