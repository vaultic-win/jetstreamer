# Epoch 141 native metadata rejection evidence

The full-census native driver retains planner rejections as private diagnostic
evidence. It does not weaken the strict recovery planner's `is_connected` check.
The October 22 first attempt failed with `target SlotMeta is not connected`
before writing any target candidates. Its ordered loop and empty candidate
directory identify the first target (60911776, parent 60911771) by inference;
that attempt did not retain the raw value or complete the post-close rehash.

For a newly qualified, freshly admitted attempt, a successful native metadata
read followed by planner rejection returns a typed diagnostic outcome through
the session callback. The database then closes and the entire retained census
is rehashed normally. Native read failures, resource-guard failures, poisoned
sessions, or input changes still fail without a final rejection receipt.

After successful post-close revalidation the driver rehashes any preceding
provisional target receipts and its bound evidence and plan. It fsyncs a
no-clobber `metadata-rejection.json` beside the configured output receipt, then
exits nonzero. The receipt includes the exact queried family/key/raw value,
the strict planner error, bounded pinned-layout decode (or explicit decode
error), exact executable/plan/admission/source bindings, preceding target
receipts, and native session accounting. That reserved filename cannot alias
another planned output or an existing file. Output/free-space limits remain
unchanged.

`native_session_complete: true` describes only the successfully closed and
revalidated diagnostic read session. `full_target_census_complete: false`
explicitly denies complete acquisition of all 18,283 targets. The driver does
not create its final candidates receipt on this path. Source completeness,
historical liveness, authenticated runtime clock, hidden PoH recovery, runtime
promotion, replay, publication and remote/R2 mutation all remain unauthorized.
No final rejection receipt means that this post-close evidence is unproven.

Tests cover exact retention of disconnected metadata, unchanged connected
query planning, malformed/missing/wrong-key/wrong-family rejection, and an
actual disposable native/WAL fixture. The latter checks that a planner rejection
returned as data receives post-close revalidation, while an input mutation after
that rejection prevents session success. Synthetic fixtures are not evidence
about the historical database. A source fix or fixture success alone does not
authorize launching a new attempt: seal the exact binary, qualify the actual
sandbox and fresh admission, preserve the failed attempt, and bind the new
invocation to fleet/repair tracking. Never blindly retry the old binary or
relax connectivity based solely on a recorded bit.
