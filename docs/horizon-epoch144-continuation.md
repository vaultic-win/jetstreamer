# Private epoch 144 checkpoint continuation

The `epoch144-checkpoint-continuation-diagnostic` node build is restricted to
the retained epoch-144 prefix through slot 62,639,490 and its remaining 509
slots, 62,639,491–62,639,999. It is not the epoch-213 build, an ordinary replay
mode, an import path, or publication authority.

The runner independently rereads the complete retained prefix, pins its segment
manifest, original worker, genesis, restart snapshot and successful native-only
comparison by SHA-256, and authenticates its actual systemd invocation. In the
worker that executes the suffix, it freezes the restored checkpoint before any
entry and checks all consensus fields, zero bootstrap writes, 64 ticks per slot
and the worker's unchanged initialized write cursor. The historical worker's
pinned protocol uses legacy accounts hashes; there is no selectable hash-kind
override. Native and retained-prefix write cursors are deliberately independent.

The final V4 assembly records both source generations and explicit raw-to-archive
write-version mappings. It preserves complete, contiguous canonical epoch
coverage, including the prefix's trusted root. Neither source is modified.

## Invocation and required evidence

Build separately:

```sh
cargo build --release -p jetstreamer-node --bin jetstreamer-node \
  --features epoch144-checkpoint-continuation-diagnostic
```

After separately sealing, capability-testing and freshly admitting that exact
binary, a persistent non-restarting service uses:

```sh
/absolute/sealed/jetstreamer-node 144 /absolute/private-run/ledger --verify \
  --checkpoint-continuation-plan=/absolute/sealed/plan.json \
  --checkpoint-continuation-plan-sha256=PLAN_SHA256
```

Consult `checkpoint_continuation144.rs` for the strict plan schema and pinned
input identities. The run root must be a fresh owner-only UID-1001 directory
directly below `/home/sol/.jetstreamer-private`, named
`checkpoint-continuation-144-*`. The ledger destination must be its `ledger`
child. An invocation-bound reserve/VMA guard must pass under its deployed
sandbox before the job is left unattended.

The required admission schema is
`jetstreamer-epoch144-continuation-admission-v2`. It binds the executing node,
prefix, snapshot, native result, original worker, 509-slot remainder, protected
existing claims and complete incremental peak, and expires after 900 seconds.
The implementation requires at least 192 GiB for the experimental peak; this
is a minimum envelope, **not a qualified measured peak**. A reviewed admission
writer and evidence-backed full-path budget are still required. Do not invent
an admission JSON or reuse the 40-GiB native-only receipt. The 8.2-GB native
scratch measurement does not bound suffix, assembly or verification work.

The R2 tool's `prepare-continuation144-protection` command prepares a separate
accounting receipt for the completed epoch-198 reservation. It pins the original
protection policy, audited century floor and original whole-object R2 receipt,
requires a fresh accepted v2 observer/fleet pair, authenticates stable live owners
and dormant epoch-198 owners, and revalidates the remote ready pair twice. Only
the old 768-GiB epoch-198 future-growth claim is subtracted; all other claims,
floor, margin and original slack remain. It does not sample resources, mutate
R2, delete local files, change guards or authorize admission. Its `--check-only`
mode reads bound evidence without service or remote observations or output.
The revised runner additionally binds the exact successful accounting release as
`protection_release: {path, sha256}` in its sealed plan. It requires that same
binding in the full-path admission, and does not accept a different released epoch
or arbitrary lower floor. The released baseline is 3,916,063,202,758 bytes.

`admit-continuation144` consumes a fresh accepted four-lane sample, the exact
accounting release, native result, immutable node and full-path resource policy.
Its 192-GiB experimental envelope reserves 40 GiB for native copy/restore/indexes,
8 GiB for suffix output/growth, 112 GiB for assembly output, 16 GiB for independent
verification scratch and 16 GiB of incremental margin. This is not a full-cold
peak qualification. Admission revalidates the epoch-198 and audited epoch-201
ready pairs, stable current owners, actual free bytes, memory reserve and host
VMA ceiling. Existing lanes must be advancing with zero new OOM/max events and
remain below their VMA bound. Exact-node capability and the actual bound guard
remain separate launch prerequisites; the writer never launches a service.
The runner checks admission freshness both before and after its prefix reread.
The actual guard must protect the greater of the retained baseline and sampled
actual free bytes minus the complete 192-GiB experimental envelope. This deliberately
counts other fleet allocations against the experiment too, so a mistaken peak
cannot consume older claims. An oversized suffix stays private and must be
requalified rather than assembled under the smaller reservation.

The exact continuation fleet profile keeps native-only, original-prefix and
continuation histories separate. `prepare-continuation144-layout` creates only
the empty isolated owner-only run root and a safely owned, unoccupied shared
lease; it never truncates a preexisting file or retires prior work. The producer
must receive only its run root and that exact lease as writable private paths.
`capture-continuation144-launch` authenticates the actual non-restarting unit,
immutable plan/admission, measured native environment and current command before
writing a private receipt and invocation-bound guard plan. The separate fleet
preparer requires a real successful one-worker guard invocation under its deployed
sandbox. Its same-sample event appends the new claim without replacing prior
diagnostics. Runtime/observer handoff qualification and ordinary publication gates
remain separate; these commands never launch replay or mutate R2.

## Gates that remain separate

Source tests and native-only comparison do not establish a successful suffix or
assembled archive. Outputs stay private and checksum-free. Independently verify
the assembled archive and current plugin against the same final digest, qualify
the restarted V4 provenance for canonical import, then use the normal upload,
whole-object readback and sidecar gates. Adjacent-boundary evidence remains
necessary for local retirement, not for upload. Do not restart the validated
prefix, borrow another epoch's build, or weaken these gates to obtain an ETA.

Record prefix validation, native restore/barrier, suffix, assembly, independent
final/plugin verification and delivery as distinct timing phases. Until the
actual continuation is admitted and running, do not publish a replay countdown
for epoch 144.
