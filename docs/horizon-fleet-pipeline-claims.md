# Observational delivery claims

The fleet plan accepts an optional `pipeline_claims` array, separate from
non-publishing private `diagnostics`. Each entry contains `epoch`, `phase`,
`unit`, `invocation_id`, `expected_exec_start`, and a nonempty `evidence` array
of exact `{ "path": "/absolute/file.json", "sha256": "..." }` bindings.

Supported phases are `local-publication` (unit namespace `horizon-publish-N-*`)
and `upload-readback` (`horizon-upload-N-*`). Bind the complete `ExecStart`
property from the actual invocation, not a substring or proposed command.
Only a loaded, zero-restart, exact-invocation service with a positive MainPID
in `active/running` or oneshot `activating/start` is active. Terminal claims
remain history, not active work. Reconciliation binds the unchanged before/after
unit census and authenticates the ordinary R2 inventory as before.

These entries grant no launch, artifact publication, compatibility promotion,
upload, retirement, or remote mutation authority. The separate publisher and
uploader retain their existing evidence gates. A live pipeline also requires
an evidenced `post-replay-pipeline` gate and cannot overlap a live private
diagnostic, ordinary replay, or another delivery invocation for that epoch.
The campaign bounds apply, so an epoch-301 claim is rejected for a 201–300 plan.

Add the claim after authenticating the launch, and consume it in the normal
30-minute cycle. Do not introduce an extra resource observation or repurpose
the bounded-diagnostic same-sample admission exception for delivery. The ledger
records pipeline invocations in both `pipelines` and, when live, `active`.
It intentionally does not make a replay status object's old ETA current merely
because a delivery stage is now active.

The narrowly qualified `producer-finalization` phase covers only the exact
sealed 216–219 v5 producer and its original invocation. It authenticates the
immutable parent digest and requires the original user's journal events for
the final checkpoint, snapshot verification and archive close in that order,
all no later than the coordinated sample. The ledger retains those events.
It does not require a historical worker to remain alive after archive close,
does not label the parent ordinary replay, and grants no independent full
verification or publication evidence. Other producers need separate qualification.

`controller-import-handoff` separately covers that exact cohort after clean
producer success and committed private batch publication. It authenticates the
unchanged controller/script, pending assignment with no import owner, source
batch digest, terminal producer, and the original batch-commit journal event
before the sample. It invalidates when the controller begins importing; an
actual importer must then use its own exact `local-publication` claim. Neither
handoff observation launches work or weakens any import or verification gate.
