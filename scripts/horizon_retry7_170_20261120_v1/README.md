# Epoch170 retry7 recovery

This successor is not admitted or deployed. Its predecessor stopped at
2026-11-19 23:56:55 UTC after a bounded writer query failed. PID1 was processing
a global daemon reload for 13.474 seconds, overlapping a query limited to ten
seconds. The guard discarded the subprocess result, so the timeout diagnosis
is strongly supported but not proven by a retained exit status.

The guard preserves its one-shot ten-second query, stderr rejection, exclusive
16 KiB stdout bound, exact writer absence checks, DATA custody, VMA limit,
whole-lane cap and fail-closed stop behavior. Failure evidence now includes
the query phase, elapsed time, exit code or signal, output lengths and escaped
bounded output prefixes. The outer DATA error retains this detail.

Only epoch170 `local3retry7` is added to the namespace allowance, with the same
6,829,053,656,882-byte raw floor and 309,237,645,312-byte whole-lane cap. Earlier
attempts and source files remain unchanged. Most dependencies are imported by
explicit relative paths from the published retry6 source; they are part of the
build source closure and must be included in its proof and deployment seal.

Use supported transient systemd units for builds and qualification. Do not run
a global `systemctl daemon-reload` while existing guards depend on bounded PID1
queries. A host-wide reload is not an acceptable failure-injection test with
healthy lanes running. Do not widen query timeouts, add retries, skip writer
validation or alter live guards to compensate.

Before launch, qualify the source and native sandbox, publish it to
`account-updates`, normally seal the exact guard, capture its own native witness
and DATA contract, qualify a fresh preparer/launcher with the actual retry6
terminal lineage, and obtain fresh whole-fleet admission. Preserve the retry6
artifacts and all resource promises. The old 2315 witness cannot authenticate
the rebuilt guard. The whole-lane cap includes retained old attempts; no
reclamation or capacity credit is implied by this source change.
