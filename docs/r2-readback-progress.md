# R2 readback progress observations

Future builds of `jetstreamer-r2` emit JSON lines on stderr during the existing
ordered whole-file readback. This adds no requests, changes no range/retry policy,
and does not alter archive, sidecar, receipt or retirement gates.

`r2-readback-start` binds the object key, expected length, ETag and SHA-256.
`r2-readback-progress` reports cumulative `hashed_bytes` after a successfully
downloaded ordered range has been written and fed into the whole-file hasher.
The first range, each additional GiB and the final tail are reported, with
`elapsed_millis` measured monotonically from that read's start. Retried range
requests, buffered out-of-order downloads and socket counters do not advance it.
All progress events explicitly say `whole_file_sha256_verified: false`, including
the final byte-count checkpoint. Only `r2-readback-verified`, emitted after both
length and whole-file SHA-256 checks pass, sets that field to true.

These lines are observations, not durable integrity receipts or readiness proof.
Bind consumers to the exact uploader service invocation and child PID, and to
the matching read-start event. A new start resets progress even for the same key;
never combine bytes across attempts or substitute progress for the authenticated
archive receipt. A missing checkpoint is not proof of process termination. The
same observations appear during a restore, so establish command ownership before
using them as upload/readback ETA evidence.

The uploader separately logs the start and successful completion of its existing
local source revalidation after remote integrity proof. Readback completion is
not sidecar commit: source revalidation, sidecar creation/readback and durable
archive-receipt publication still remain. An ETA consumer must model them and
any actual lock queue rather than counting down or clamping an overdue estimate.

This source change does not modify any sealed running binary. Keep healthy
uploaders unchanged; deploy a newly sealed client only through its separate
qualification, admission, ownership and status-model transition gates.
