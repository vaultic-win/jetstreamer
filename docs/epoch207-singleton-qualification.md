# Epoch207 independent singleton qualification

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
generation before admitting a restore or replay; never invent a digest.

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
