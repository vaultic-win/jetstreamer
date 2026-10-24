# Exact historical native25 input for epoch223

`jetstreamer-epoch223-tail-exact-evidence` captures metadata from the already
successful isolated477-slot tail at96767523..96767999. It does not restore a
Bank, replay entries, observe current producers, scan an archive, contact R2,
promote a runtime, qualify a handoff or close the223 repair.

The closed evidence set binds the root-owned sealed native25 launch, producer
NDJSON, exact segment manifest, independent full tail reread, hard-fork snapshot
metadata and preserved rounded terminal summary. The tool rehashes every input
and its own sealed executable, accepts only a root-owned immutable plan, and
writes a root-private no-clobber fsynced receipt. No input path or digest can be
substituted by the plan. Use a separate immutable deployment from the native
Rust sealer; keep every historical source unchanged.

The plan contains only:

```json
{
  "schema": "jetstreamer-epoch223-tail-exact-evidence-plan-v1",
  "output": "/var/lib/jetstreamer/EXACT-PRIVATE-OUTPUT/capture.json"
}
```

Create the output parent root-owned0700, seal the plan0444 and executable0555,
then execute as root with three positional arguments: the absolute sealed plan,
its SHA256, and the executable SHA256. Compilation does not create evidence;
root owns the actual capture and later operational use.

The receipt checks a unique initialized marker, bootstrap checkpoint, terminal
checkpoint and PID1 clean-success event for invocation
`20dc145d1e8c41fdbc682046b6fe4289`, producer PID3452507 and exact tail unit. It
requires ordered line numbers and realtime clocks, the initialized slot/hash,
ticks_per_slot64 and initialized cursor107266983592. All checkpoint numbers are
parsed directly as u64, never float or JavaScript numbers. Bootstrap writes0,
slot-complete status, the full consensus tuple and both cursors must match the
sealed segment. The independent reread binds the477-slot span, archive digest,
worker, native25 revision and normalized manifest digest. Fork metadata binds
the exact96767522 snapshot and all four required fork markers with count1;
metadata alone remains no Bank-restore or replay qualification.

The preserved terminal summary has two rounded values. Retain that file and its
digest unchanged. The new receipt explicitly corrects them from the exact raw
journal and segment:

| Field | Preserved rounded summary | Exact u64 |
| --- | ---: | ---: |
| Bootstrap capitalization | 504095069290845100 | 504095069290845150 |
| Terminal capitalization | 504095067970690000 | 504095067970689961 |

The emitted raw cursor range is107266983592..107268320809, end exclusive.
These cursors belong to this independently restored native25 validator. Do not
equate them to a native20 prefix cursor or treat the bootstrap cursor as a
global event count. Future assembly must prove each segment's contiguous
emitted range, apply an explicit checked mapping, and preserve all events with
overflow and coverage checks. Consensus handoff equality excludes local raw
cursor equality and still requires the independently verified native20 prefix.

Every publication, prefix, handoff, assembly, normalization and repair-closure
authority remains false. The exact historical receipt is comparison input;
the normal full-prefix reread, consensus handoff, checked assembly, full/plugin
and boundary verification, authenticated upload/readback and sidecar gates
remain open. A second ignored native25 Bank test is a dormant contingency only;
do not run it merely to reformat evidence already preserved here.
