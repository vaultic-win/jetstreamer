# Epoch203 independent V4 verification

`jetstreamer-epoch203-private-verify` uses the immutable-file copying, hashing and
scan mechanics shared with the retained213 verifier, with a separately compiled
203 profile. It is bound to the original ed66145 producer/IID/PID and plan, exact
prefix/suffix/native-snapshot digests, the independently derived1073-byte V4
envelope84ec6771…, and the finalized RPC parent87695999 and terminal88127999.
The original213 profile and its ten contract tests retain their bindings; no
existing sealed deployment or receipt is replaced or relabeled.

The203 plan schema is`jetstreamer-private-epoch203-verification-plan-v1`. It uses
the fields documented for the213 private verifier and additionally requires
`boundary_metadata: {path, sha256}` binding the independent67c39d14… candidate
receipt. The runner rehashes that receipt's four raw RPC responses and checks
the actual compiled anchor hashes. RPC metadata remains candidate input: the
complete strict full scan must independently recompute the assembled archive's
PoH chain and match both anchors and the exact source-derived provenance digest.

Wait for the original producer's natural success and exact completion/PID1
journal. Seal its real completed outcome, make a fresh resource admission that
protects every then-active lane and the recomputed century floor, and create a
new empty root-private direct child named`horizon-203-private-scan-UNIQUE`.
Account for the additional complete private archive copy and verifier/plugin
working sets. The fixed baseline protects the known225and205growth claims and
century floor; it is a rejection minimum, not authority to omit later admissions.
The128-GiB archive cap and8-thread scan setting require separate review if changed.

The203 runner also performs fresh scan-only admission before opening the assembled
archive. It requires the exact225/205 invocations and their current caps, a complete
campaign service census including itself, fresh untripped protective guard receipts,
and its actual128-GiB/8-core sandbox. It charges the distinct scan hard cap alongside
both existing producer caps against90% host memory, checks available memory and
protected disk space, and repeats the census/identity checks before writing a durable
private`admission.json`. This does not admit another replay or authorize publication.

Run from a native-sealed immutable package with a separately sealed plan:

```text
jetstreamer-epoch203-private-verify PLAN --plan-sha256 HEX --self-sha256 HEX
```

It opens no assembled archive before exact terminal evidence passes. It preserves
the original assembly, copies to private`epoch-203.jet`, independently hashes the
same unchanged source/copy, performs strict full verification followed by the
pinned current-plugin scan, and records durable phase/output evidence. It creates
no canonical checksum, uploader receipts, public archive or R2 object. Fresh full
and plugin success still needs a separately reviewed exact203 publication gate;
adjacent-boundary and local-retirement requirements remain independent.

`jetstreamer-epoch203-publish` is the separate local publication gate. Its code
retains the proven absence-only transaction and Landlock confinement mechanics
from the213 publisher, with independently supplied203 producer, snapshot, native
comparison, source provenance, RPC anchors and private-runner bindings. The213
publisher, sealed binaries and receipts remain untouched. The203 gate additionally
requires the actual scan admission and exact scanner invocation's clean PID1
completion, and rehashes all four raw RPC boundary responses. Its fixture-only
`--capability-probe` does not open any campaign archive.

Do not deploy or launch publication until its tests and private filesystem probe
pass and the actual203 full/plugin verification finishes successfully. Use the
same publication plan fields and rename-compatible sandbox described in
[the213 publication procedure](epoch213-v4-artifact-publication.md), substituting
the203 schema, private/work namespaces and the203 boundary-candidate digest. Bind
the actual203 verification receipt, archive digest/length, fresh fleet/inventory
and resource admission independently. Moving the additional private verification
copy must preserve the original assembly and all evidence. Authenticated R2
delivery, sidecar commit and adjacent-boundary retirement remain separate stages.

`jetstreamer-r2 admit-publication203` issues the separate fresh resource admission
and prepares `publication-plan.json` after the actual final verification receipt
and exact scanner PID1 completion exist. Its sealed spec binds the accepted
observer/fleet, recomputed century floor, all three replay guard receipts, exact
publisher and filesystem capability. It preserves225/205/204 by invocation,
authoritative PID and immutable command identity, and allows only a rename of the
additional verified copy,64MiB metadata growth and a16GiB publisher (the retained213
publication used an8GiB high/16GiB hard limit and peaked at8GiB). It neither
opens archive bytes nor starts a job. Seal its exact generated plan with the
native deployment sealer before publication. Repeated matching admissions reuse
the original record and deadline; they do not renew permission or replay work.

`capture-handoff203` records the actual live local-publication or upload/readback
invocation only after the previous stage has cleanly completed. The compiled
commands restrict publication to the exact203 plan and delivery to epoch203,
the actual full/plugin runner allowlists and deferred local retirement. The
event retains the previous resource sample's clock and advances a separate phase
event clock. A matching `metadata_event` permits immediate fleet reconciliation
without an extra resource poll, while preserving every earlier pipeline and
diagnostic claim. Its complete census rejects a live or failed prior stage.
It does not authorize publication, upload or any remote mutation. Remove the
event selector when constructing the next normal30-minute fleet plan; keep its
evidence and pipeline history. These events never fabricate a new resource sample.
