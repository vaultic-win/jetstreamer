# Post-replay dashboard status

`jetstreamer-r2 status-publish-pipeline PLAN --plan-sha256 HEX [--check-only]`
publishes operational metadata only. It never uploads, changes or deletes an
archive or sidecar, launches work, or grants publication authority.

The reviewed root-owned plan uses schema
`jetstreamer-horizon-pipeline-status-plan-v1`. It binds a fresh coordinated v2
observer and fleet ledger, the exact active delivery unit/invocation/ExecStart,
and the original epoch producer's launch receipt. Elapsed time comes from the
unique root systemd manager start event for that original invocation. The
delivery stage must have started before the coordinated sample; do not backdate
a new handoff onto an earlier sample.

Supported claim/status phases are `local-publication`/`publication` and
`upload-readback`/`upload` or `readback`. A positive MainPID, zero restarts and
the exact live fleet claim are mandatory. Bind the complete before/after unit
census. Explicit same-epoch publisher/uploader peers may be terminal, but no
competing peer may be live. Other fleet identities must remain unchanged.

The plan includes `epoch`, `phase`, `binding`, `{path,sha256}` bindings for
`observer`, `fleet`, `origin_launch`, and each `estimate_evidence` member,
nonempty `estimate_basis`, positive `estimated_remaining_millis`, exact
`jet_path` and `expected_jet_size_bytes`, `peer_units`, and a root-private
`receipt_directory`. The estimate is the current reviewed best guess through
remote readback and canonical sidecar commit, not merely through upload.
The source must be a canonicalized singly linked regular complete archive.

`binding` contains `unit`, `invocation_id`, `expected_exec_start`, `claim_phase`,
`origin_unit`, `origin_invocation_id`, `model_path`, `model_sha256`, `fleet_path`,
and `fleet_sha256`. Set `model_path` to the final sealed plan path and leave
`model_sha256` empty in the input. Runtime fills it from the separately verified
CLI digest, avoiding a self-referential hash.

Seal the binary and plan before production use. `--check-only` validates local
evidence and live identities without R2 mutation. Normal execution uses the
same conditional status PUT and authenticated exact-byte readback as replay
statuses. Its distinct pipeline publication receipt retains actual delivery
identity rather than fabricating replay IDs. Completion status deletion and
inactive-owner cleanup accept that receipt schema; neither weakens their
independent ready-pair or terminal-ownership gates.

Use this path within the existing 30-minute observation cycle, not as another
poll loop. A completion or authenticated handoff is a lifecycle event; an old
ETA is never evidence that a delivery stage remains live.

For the exact sealed 216–219 legacy producer, the separately qualified
`producer-finalization` claim maps to status phase `finalization`. The origin
unit/invocation must remain the same producer. Both fleet reconciliation and
status census authenticate the final checkpoint/verification/archive-close
journal events and parent digest. This is an estimate through import and all
remaining independent verification, upload and readback, not replay progress
or a ready archive assertion. Update phase-capable status readers and completion
cleanup binaries through their normal immutable deployment handoff before
publishing this new phase; do not leave an old reader rejecting its receipts.

Fleet status classification distinguishes live receipt ownership from an actual
production claim. A private qualification may still own an old status receipt,
but that does not make its production countdown valid. `owner_binding_matches`
records ownership separately from `production_claim_eligible` and ETA freshness.
This classification grants no deletion authority: a live diagnostic owner must
not be passed off as terminal to use inactive-owner cleanup.
