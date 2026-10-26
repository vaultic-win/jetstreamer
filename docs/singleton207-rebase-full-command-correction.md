The first fresh cycle 440 bridge capture failed on 2026-10-26 at 05:35 UTC with
`207 guard effective executable/plan differs`. Preparation had succeeded, but no
bridge, switch, or complete handoff receipt was issued. The original guard
selector was never changed and no capacity credit was granted.

The rebase reader passed `history.expected_exec_start`, a complete PID1
`{ path=... ; argv[]=... ; ignore_errors=no ; start_time=... }` property, to
`private_prefix::same_command`. That function expects only the argument prefix
before ` ; ignore_errors=`. It therefore rejected the unchanged original guard
before the bridge was evaluated. This is a comparator contract mismatch rather
than an executable, argument, or guard-plan substitution.

The correction uses the existing `pipeline_status::same_exec_start` comparator
for the two complete properties, matching the completed-guard history reader.
It permits only the existing PID1 display metadata normalization and preserves
exact executable/argument/ignore-errors identity. The receipt directory and
immutable guard executable checks remain together in the same production gate.
All current service, typed empty-property, guard-plan, producer identity, latest
completed firing, freshness, timer, bridge continuity, resource, and handoff
checks remain unchanged.

Three pure regression tests call this production gate with the actual original
guard property and the complete expected property copied byte-for-byte from its
genuine saved launch history. Fixture provenance binds those saved records. The
tests demonstrate the original comparator rejection, accept the unchanged
command and its PID1 metadata reset, and reject changed executable, plan path,
plan digest, guard digest, arguments, ignore-errors setting, arbitrary suffix,
receipt directory, and history executable. They perform no service/resource
queries or operational actions.

There is also a separate unit rendering requirement: the completed-history
reader authenticates the full command in PID1's finished-job message. A
persistent guard unit must therefore use `Description=[systemd-run] ` followed
by its exact complete `ExecStart` command. The original reviewed persistent
bridge template had a human description. Description-only corrected controls
were separately sealed for review and were not installed. Their cycle 440 plan
paths are examples of the required rendering, not reusable controls for another
preparation. This comparator correction does not relax that history gate.

Source base is `749a50b8464e7ee39a85030ab93e7f9787bbc955`. This handoff is source
preparation only: no compilation or tests have been run for the correction.
The root must qualify a combined source generation. Every capture must use the
same issuer SHA as its preparation, so a corrected helper requires a completely
fresh preparation and genuine fresh accepted context. Do not reuse or modify
the failed cycle 440 preparation, capture spec, journals, or earlier evidence.
