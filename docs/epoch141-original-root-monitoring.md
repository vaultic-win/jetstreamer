# Private epoch 141 original-entry root qualification

The fleet reader has a separate, closed contract for
`horizon-qualify-141-original-entry-root-20261023-v1.service`. This is a private
qualification from bootstrap slot 60911751 through root 61328765. It is not a
complete epoch 141 archive and must never acquire an ordinary replay claim or
publication authority. Active qualification still needs the separate operational
dashboard countdown described in [the141 status model](horizon-epoch141-status-estimates.md);
a root-only ETA is not a time-to-sidecar projection. The epoch remains `failed-needs-repair` while this
diagnostic runs and until a verified ready pair eventually closes the repair.

The contract pins the sealed parent, v1.4.25 worker, complete original-entry
index/data hashes, snapshot, both checkpoint expectations, private paths and
exact command. The checkpoint input contains the two snapshot filenames from
the preserved, hash-verified epoch 141 preflight; these encode legacy accounts
hashes, not Bank hashes. The original source manifest and snapshot provenance
remain separate from any claim of successful execution.

Fleet adoption requires hash-bound launch, plan, admission and actual one-worker
guard first-fire evidence. It checks the invocation, zero restarts, canonical
private scratch, command, service sandbox, reserve floor and worker VMA bound.
Same-sample admission preserves the previous diagnostic history. A new profile
cannot borrow the older native-ledger acquisition contracts or replace the
retained epoch 144 diagnostic history. The reader only observes; it neither
launches services nor grants replay, publication, sidecar or retirement authority.

The minimum protected floor in the contract is a lower bound, not admission
evidence. Fresh admission must protect the century floor and all live growth
claims, allow a conservative 768 GiB candidate increment, and meet the actual
guard floor if higher. A successful reader test is not admission, a canonical
root result, a resource qualification, or a throughput measurement.

The routine helper can adopt a hash-bound same-sample fleet event with
`--prepare-next-original141 SPEC --handoff-sha256 HEX`. It adds the private owner
to the existing observer's diagnostic census and preserves the exact retained
144 row. Both diagnostics stay outside the production ETA model. An unavailable
diagnostic remains explicit unresolved evidence; the complete fleet census and
guard remain responsible for actual failure and ownership transitions.

Before launching, complete and qualify the admission/launch capture tooling and
the actual routine observer/fleet handoff using this contract. Seal the tooling and plans,
prove exact unprivileged input capability, and bind the real invocation to its
guard before leaving it unattended. Preserve the five healthy owners. This
source change alone does not satisfy those remaining operational gates.

The reviewed Rust operational commands are deliberately separate:

- `prepare-original141-layout --self-sha256 HEX` stages only a fresh private
  layout and a digest-verified cached genesis. It does not use gcloud or launch.
- `admit-original141 SPEC --spec-sha256 HEX --self-sha256 HEX [--check-only]`
  binds the accepted five-lane observer/fleet/plan, century floor, current guards,
  private layout and retained growth claims. The check-only path reads existing
  evidence without sampling resources, contacting R2 or writing admission.
  Actual admission additionally checks current owners, free disk, available
  memory, CPU quotas and VMA limits, and authenticates the century-floor pair.
- `capture-original141-launch SPEC --spec-sha256 HEX --self-sha256 HEX`
  records an already running, guarded owner. It never starts the service.

A fresh sample may require a renewed admission before any producer launches.
Keep every previous receipt. Write the renewal as
`admission-YYYYMMDDTHHMMSSZ.json` in the same private admission directory, with
the timestamp at or after that sample and no later than fresh admission, and bind its exact digest into the launch
plan. Never replace `admission.json` or an earlier sample's receipt.
The writable layout includes the loader's internal `.jetstreamer-private`
directory beneath the run root as well as destination, output and scratch;
private receipts remain outside all writable mounts. Set the cached genesis's
final mode explicitly to 0444 because the service umask otherwise reduces it to 0400.

Admission requires ordered `growth_extension_observers` linking each retained
growth receipt's final sample to the current accepted sample. Only the sealed
controller-only recovery mapping may bridge changed controller identities;
producer, worker and scratch identities must remain unchanged. Compaction cannot
reduce the previous maximum: the extended minimum remains twice the maximum
physical scratch observed over all retained windows plus twice the verified
maximum archive size. The original live controllers' claims are never edited.

The capture specification supplies both `first_guard_source` and `first_guard`.
The former identifies the exact `sample-INVOCATION.json` emitted beneath
`/var/lib/jetstreamer/horizon-original141-root-guard-20261023-v1`; the latter is
the fixed private `receipts/first-guard.json`. Both digests must match. Capture
requires a successful actual timer invocation of
`horizon-original141-root-guard-20261023-v1.service`, the exact sealed guard
command and sandbox, a recent one-worker no-trip sample, and absence of stop
intents. It pins the original bytes with no-clobber publication and fsyncs the
file and parent directory. A manual guard run cannot substitute for the timer
trigger evidence. Preserve a pin if a later capture step rejects; investigate
that rejection rather than replacing existing evidence.
