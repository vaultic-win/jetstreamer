# Horizon delivery-stage census

`jetstreamer-r2 fleet-reconcile` observes delivery separately from replay and
private qualification. Keep full-verifier, current-plugin verifier and uploader
units in the complete campaign `tracked_units` list before their event-driven
handoff can start. Discovery fails closed on an unbound live delivery unit.

After the handoff, bind each live stage with its exact invocation ID, complete
effective `ExecStart`, immutable evidence and `post-replay-pipeline` epoch gate.
Supported claim phases are `full-verification`, `plugin-verification`,
`local-publication` and `upload-readback`. Independent full/plugin checks and the
receipt-waiting uploader may coexist for one epoch. Two live claims for the same
epoch and stage remain an error; a replacement must not masquerade as another
independent stage.

For `local-publication`, the ordinary adaptive importer namespace
`jetstreamer-root-import-CONTROLLER-eSTART-END-SEQUENCE.service` is also supported.
The controller ID must be nonempty; epoch and positive sequence numbers must be
canonical decimal integers. The entire importer range must fit the assigned
campaign, including its publication end boundary. This only permits observing
the exact importer invocation/command and publishing its properly bound phase;
it grants no import, replay, runtime, or archive-publication authority.

A legacy delivery unit may cover a range, such as
`horizon-plugin-verify-216-219-cached-v1.service`. Give each claimed epoch its own
entry with identical unit, invocation, command and evidence. The entire unit
range must fit the assigned campaign, and duplicate epoch/unit entries fail.
In particular, an uploader named for 298–301 cannot claim epoch 300 under a
201–300 campaign: the private verification tail is not upload authority.

These are observational claims, not launch, compatibility, verification,
publication or status-JSON authority. They do not replace any archive receipt or
make a ready pair. The identity-bound `status-publish-pipeline` publisher accepts
`verification` only for a bound full/plugin verifier, `publication` for local
publication, and `upload`/`readback` for the uploader. Independent live stages may
coexist, but every non-handoff unit must still match the exact fleet census.
Never relabel a terminated replay as live. Keep all changes in
the existing coordinated 30-minute cycle, or an explicitly authorized event or
user-requested status cycle, rather than running another resource poll.

For a legacy controller lacking the newer diagnostic launch receipt, the
publisher's `origin_launch` input may instead bind the exact authenticated replay
status-publication receipt. The publisher revalidates that receipt's canonical
key/path, epoch, replay phase, producer ID and authenticated readback, rehashes its
historical v2 observer, and checks both original producer unit names and stable
zero-restart identities. Elapsed time still comes from that original invocation's
unique root manager-journal start, not the status timestamp or verifier start.
This historical evidence is only an elapsed-time origin; it never supplies a
current live claim or current resource/admission evidence.

Before publishing a verification-phase status, migrate the relevant completion
cleanup service to a sealed binary that validates the same extended binding.
An older cleanup binary must not be assumed to understand a newer receipt merely
because its schema name is unchanged. Keep the old receipts and prove the new
receipt decoder and source bindings without mutating remote objects first.
