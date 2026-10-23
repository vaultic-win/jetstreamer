# Epoch207 independent singleton qualification

See [the exact root-metadata unblock and independent 209–212 preparation](epoch207-root-metadata-unblock.md)
after the native bootstrap proof passes. The missing 89523820 MD5 remains a separate
authenticated-generation metadata gate.

The retained complete-span focused plan enters epoch208 through slot90,287,519.
That route includes the known missing source boundaries at89,856,117/89,856,121.
Its failure to qualify does not require epoch207 itself to include that interval.

The separate `epoch207-singleton-qualification` node build admits only a private,
explicitly verified, candidate-opted-in root cohort for epoch207. It starts from
the retained canonical snapshot89,423,444, preserves both canonical root checks
at89,523,820 and89,855,469, records all432,000epoch slots89,424,000–89,855,999,
and uses the existing native terminal/ordered-chain/cohort publication gates for
the final530slots after the second root. There is no epoch208input, prefix
assembly or checkpoint restart in this route. The normal compatibility registry
still rejects epoch207. The generation profile is separately labeled
`epoch207-singleton-qualification-v1`; other private node modes cannot be
combined with this build.

The read-only `--epoch207-singleton-preflight` mode executes the same exact CLI,
private-path, runtime and cohort-manifest checks and exits before cohort-run,
input staging, worker creation or snapshot restore. It is not resource admission,
native input qualification, replay success, archive verification or publication
authority.

## Immutable metadata preparation

The Rust `jetstreamer-epoch207-singleton-prepare` tool reads only the exact sealed
v2preflight and207snapshot-bindings file in
`/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2`.
It rechecks both file digests and the independently recorded old manifest
fingerprint. It preserves the207cohort's bootstrap and both root identities,
including generation, CRC32C and size, in a fresh v4singleton report. Known
bootstrap/terminal MD5s come from the separately bound snapshot-binding receipt.
The first root's v2metadata has no MD5 field; its explicit v4null follows the
existing offline v2conversion convention and is recorded as unobserved legacy
MD5, not a claim that the current GCS object is composite. Re-observe that exact
generation before admitting the full singleton cohort restore or replay; never
invent a digest. This unresolved first-root metadata does not block the separate
bootstrap-only native check against its exact retained, hash-bound inputs.

Run the sealed helper as root with a fresh output file
`/var/lib/jetstreamer/horizon-207-singleton-*/preflight207-singleton.json`,
whose canonical parent is precreated root0700:

```sh
/sealed/jetstreamer-epoch207-singleton-prepare OUTPUT --self-sha256 HELPER_SHA
```

It takes no resource observation, starts no worker, performs no network access,
and fsyncs a no-clobber mode0400report and its parent. Seal the report into a
readable immutable deployment before supplying it to the unprivileged node.
Do not feed JavaScript-rounded consensus numbers or a hand-edited fingerprint
to the node.

## Dormant runtime candidate

Reuse the already sealed capped v1.6.16 worker:

```text
/var/lib/jetstreamer/horizon-v1616-shrink-budget-worker-003fe15-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget
sha256 4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc
```

The full command is a single epoch207 `--verify --root-checkpoint-cohort` with
the newly sealed v4report/fingerprint and exact retained snapshot override.
Set the candidate opt-in and that exact worker override; pin
`JETSTREAMER_PRIVATE_RUN_ROOT` beneath the same new owner-private
`/home/ubuntu/.jetstreamer-private/qualification-207-singleton-*` run root.
Destination is its precreated mode0700 `output/` child. Legacy focused CLI,
alternative snapshots, recovery, inherited leases, directory loading and
another epoch are rejected. Add `--epoch207-singleton-preflight` only for the
planning proof, and never mistake that proof for a replay.

This preparation changes no running job or R2object. Before a real attempt,
the campaign owner must bind a fresh complete fleet/resource sample, the current
twice-average-.jet century floor, every protected remaining-growth claim and
all active auxiliaries. The300GB century scratch assumption is separate from
output, copies and margin. An exact invocation-bound guard must protect both
private cohort state and output, with its first actual worker fire proven.
Native bootstrap, both canonical root checks, complete native terminal/output,
independent full/current-plugin checks and authenticated upload/readback/sidecar
commit remain separate required evidence. Keep the epoch208source incident open.

## Optimized native input stage

The ignored `runtime::tests::native_epoch207_cold_input_matches_canonical_accounts_commitment`
test uses the unchanged capped v1.6.16 runtime and exact rustc1.51.0 release
profile. It accepts only an empty owner-private
`/home/ubuntu/.jetstreamer-private/native-input207-v1616-capped-*/scratch`,
passed as `JETSTREAMER_EPOCH207_V1616_TEST_SCRATCH`. It hashes the exact retained
8,474,139,490-byte bootstrap and20,144-byte genesis before loading, restores into
that private scratch and freezes only bootstrap slot89,423,444. It requires the
canonical accounts hash, no bootstrap writes, and unchanged write cursor,
capitalization and transaction count. No entry replay occurs.

Build this test in a separate target cache with `cargo +1.51.0 test --release
--locked --offline -p jetstreamer-historical-worker-v1-6-16 --no-run`.
Capture the compiler artifact's optimized test executable and list the exact
ignored test with `--exact --ignored --list` before any execution. A listed
test is not a native input proof. Do not substitute an old debug harness.

Native cold planning uses128GiB hard/112GiB high memory,300GB decimal disk
planning,8explicitly bound CPUs,2700seconds, no restart/network and zero entries.
Root must coordinate fresh complete-fleet admission before the actual job,
including any live native227disk-growth and128GiB memory claim. Use a separately
sealed closed207profile of the shared exact MainPID/executable/VMA native guard;
never rename this executable to `historical-worker` or borrow227's sealed guard.
The approved-native pipeline status origin must bind the exact unit/invocation,
canonical matching UTC/Unix clocks, sealed inputs and current guard/admission
evidence. Its dashboard phase is `verification`; every qualification/publication
gate remains closed. The89523820MD5/auth incident remains separate from this
bootstrap-only check.

### Dormant admission and registry contract

The separate guard build enables `epoch207-native-main-guard`, which implies
`epoch227-native-main-guard` so the normal all-features CI build stays valid.
It retains the existing observer and complete 227 tuple. A 207 plan must bind
all four exact values together:

| Binding | Exact value |
| --- | --- |
| Unit | `archive-207-v1616-native-input-actual-v1.service` |
| Run root | `/home/ubuntu/.jetstreamer-private/native-input207-v1616-capped-v1` |
| Executable | `/var/lib/jetstreamer/horizon-207-native-input-optimized-3a2a-v1/native-input-test` |
| SHA-256 | `3a2a21e2987ee7c66785bfc64f1caaf4dfc000871ef692278ed83b3f63c65948` |

Mixed tuples, unknown units, PID 1, alternative disk/VMA caps and bounded-canary
or measurement exceptions are rejected. The guard additionally binds the actual
systemd invocation and MainPID, unique cgroup owner, mapped executable inode and
hash. Build and seal a separate guard package; never replace the sealed 227 guard.

The dormant service template is [epoch207-native-input-service.service](epoch207-native-input-service.service).
Before launch, the campaign owner must supply the latest accepted complete-fleet
observer and ledger paths/digests, century floor, remaining-growth claims and
memory reservations including every native auxiliary. The 300 GB scratch bound
is a maximum planning claim, separate from already occupied input files. The
native job's 128 GiB hard memory cap and 112 GiB high watermark are explicit
claims; they do not imply capacity on a stale observation. Require an empty
owner-private scratch root, sealed input/harness/service digests and no prior
live owner of the exact unit or run root. Actual invocation/MainPID bindings
can only be finalized after the owner's coordinated launch; seal and prove
the guard's first actual sandboxed no-trip fire immediately thereafter.

Register the native origin through the existing approved-native pipeline status
publisher. It must bind the actual invocation, unit, origin path/digest and
canonical matching `recorded_unix_seconds` / `sampled_at_utc` clocks, with
`resource_samples_taken: 0`, `entry_replay: false`, `publication_authorized: false`,
`remote_mutations: false` and `r2_mutations: false`. Preserve current admission
and guard evidence in the claim. The absent zero-output archive is
`origin.parent/epoch-207.jet`; verify absence rather than creating an empty file.
Use the initial launch event to bind the origin and carry the claim into the
central fleet ledger. Publish wire phase `verification` and an inclusive
definite sidecar ETA through the owner's existing 30-minute observation cycle.
The private pipeline claim phase is `private-cold-snapshot-verification`.
The status model sets `origin_launch` to the immutable origin, `peer_units` to
an empty list and `expected_jet_size_bytes` to zero; its unit, invocation and
expected `ExecStart` must match the actual launch exactly. Elapsed time comes
from the unique PID1 producer start, not the later intent capture. The dedicated
`fleet::native207` registry binds the exact harness, bootstrap, guard, schema
and bootstrap-only scope. Do not borrow another epoch's validator or infer
approval from the generic reader accepting JSON.
Neither the service template, origin registration, guard success nor status
publication opens a replay, root-metadata or archive-publication gate.

### Native-only command protocol

Integrate, review and seal the `jetstreamer-r2` helper before calling
`admit-native207-input` or `capture-native207-input`. Both take
`SPEC --spec-sha256 SHA --self-sha256 SHA` as root. Neither starts a job,
refreshes GCloud, takes a routine resource observation, nor contacts R2.

The admission spec schema is `jetstreamer-private-epoch207-native-admission-spec-v1`.
It contains `mode: "native-cold"`, `observer`, `fleet`, `cold_plan`,
`resource_plan`, `protected_guards`, and `output`. Every binding is an absolute
`{ "path": "...", "sha256": "..." }` pair. `protected_guards` maps every
live replay and native 227 unit to its latest exact guard binding. Native 223
uses its central registered claim and cgroup memory controls. `cold_plan`
binds the sealed native plan above. Output is a fresh
`/var/lib/jetstreamer/horizon-207-native-admission-*/admission.json`.

The fresh resource plan schema is
`jetstreamer-private-epoch207-native-resource-plan-v1`. Its fields are:

- `epoch: 207`, `mode: "native-cold"`, and the exact profile's `unit`, `run_root`,
  `test_sha256`, `snapshot_sha256`, `genesis_sha256`, `guard_sha256`, and
  `cold_plan` binding.
- `candidate_incremental_peak_bytes: 300000000000`,
  `maximum_scratch_bytes: 300000000000`, `maximum_memory_bytes: 137438953472`.
- `guard_minimum_free_bytes`: accepted twice-average century floor plus all
  protected remaining-growth claims. `required_initial_free_bytes`: that floor
  plus 300000000000.
- All eight authority flags false: `entry_replay`, `replay_launch_authorized`,
  `runtime_promotion_authorized`, `full_epoch_qualified`,
  `canonical_sidecar_authorized`, `publication_authorized`, `remote_mutations`,
  `r2_mutations`.

Admission rehashes the actual harness, guard, bootstrap and genesis; requires
empty owner-private scratch; recomputes the authenticated century floor;
brackets all live owners and caps; reserves remaining hard cgroup memory for
native 223/227; and brackets mutable disk accounting with actual free space.
It rejects unknown profiles, incomplete samples, occupied epoch 207, stale
receipts, pressure or insufficient capacity. Current native RSS never replaces
its remaining hard memory claim.

After successful admission the owner may coordinate the exact dormant native
service, bind its actual invocation/MainPID into the guard plan, and arm
`horizon-native207-protective-v1.service` and its timer. The protective service
uses the separately sealed 207 guard, a 1 GiB memory cap, 256 tasks, one CPU,
no network/restarts, and writes only its private receipt directory. Capture
requires its first actual sandboxed no-trip fire, the exact plan digest, and
one successful PID1 completion. The old `ab66` guard package is retained as
superseded evidence: its generic namespace gate rejected native jobs before
the specific profile check. Use only the separately sealed corrected guard
bound by the current `native207` registry; never alter an older sealed package.

The capture spec schema is `jetstreamer-private-epoch207-native-capture-spec-v1`.
Fields are `mode`, `admission`, `guard`, `guard_plan`, and `output`.
`running` writes a fresh
`/var/lib/jetstreamer/horizon-207-native-capture-*/intent.json`; `qualified`
writes a fresh `native.json` there after clean termination. Capture binds the
effective native and guard sandboxes, exact owner, invocation and original
start clock. Qualification additionally requires the ordered exact-IID
canonical accounts marker, one passed test, and successful PID1 completion;
large consensus integers remain exact strings in the marker. Both receipts
retain every full replay, metadata and publication gate.

For initial fleet registration, append only this running pipeline claim and
tracked unit; set `metadata_event` to its exact origin and keep the same
observer, bound prior fleet, old owners, diagnostic evidence and gate states.
Epoch 207 remains `failed-needs-repair` or `blocked-qualification`. Publish
through `status-publish-pipeline`, with the generic native model described
above, `verification`, an absent sibling `epoch-207.jet`, and a positive
evidence-backed estimate through final sidecar commit. Keep the model's reserved
`model_sha256` slot empty until publication. Further refreshes share the normal
30-minute replay observation cycle. No extra resource poll or archive object
is needed merely to register or publish this origin.
