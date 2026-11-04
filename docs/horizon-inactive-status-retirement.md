# Inactive epoch status retirement

`jetstreamer-r2 status-retire-inactive PLAN --plan-sha256 HEX [--check-only]`
implements the inactive-status lifecycle separately from completion-only
`status-delete`. It never removes an archive, sidecar, local artifact or repair
record, and never establishes archive completion.

Seal a root-owned plan with schema
`jetstreamer-horizon-inactive-status-plan-v1` and these fields:

- `epoch`: one assigned epoch;
- `fleet`: `{path, sha256}` of the fresh complete-range fleet receipt;
- `terminal_fleet`: `{path, sha256}` of preserved terminal owner evidence;
- `publication`: `{path, sha256}` of the owner's latest canonical status receipt;
- `repair_backlog`: `{path, sha256}` of the matching open
  `jetstreamer-horizon-open-epoch-repair-v1` record and concrete next action;
- `public_archive_directory`: the canonical local public archive directory;
- `status_receipt_directory`: its absolute private receipt directory;
- `intent` and `completion`: distinct absolute paths in one existing canonical,
  root-owned, owner-only directory;
- `exclusive_local_epoch_ownership`: explicitly `true` after checking assignment;
- `authenticated_other_host_handoffs`: an explicitly empty array;
- optional `prior_intent`: `{path, sha256}` for interrupted cleanup recovery.

`terminal_fleet` normally names an earlier fleet receipt with the exact original
controller and producer at loaded terminal states. It can also bind the existing
sealed `jetstreamer-horizon-terminal-failed-replay-evidence-v1` contract: original
controller launch, exact stopped retry-controller generation, collected original
producer, preserved mismatch/journal identity and stopped retry path are mandatory.
This accommodates an authenticated failed controller that restarted before its
retry path was stopped; a different live invocation is never accepted.

The latest fleet must include both old owner units, even if collected. It must
have no live replay, diagnostic or delivery claim for the epoch, and classify it
as failed, qualification-blocked or not yet staged. A staged admission, active
downstream claim, ambiguous handoff or complete pair requires another workflow.
Both the fleet sample and receipt must be at most 30 minutes old. Cleanup uses
the existing coordinated observation, not an additional replay poll.

The command derives owner identities from the digest-bound publication observer,
then repeats the complete systemd census, unbound-producer discovery, queued-job
checks and owner-trigger checks. The census must still equal the bound fleet.
Canonical local artifacts, a remote pair/staged archive, or an exact-key
multipart upload block cleanup; reconcile delivery instead. The open repair
record remains hash-bound in the intent and is never changed by this command.
It authenticates the exact current status bytes and ETag, fsyncs a no-clobber
intent, repeats its live-claim checks, and deletes only
`epoch-N.epoch-status.json` with `If-Match`. It never retries a precondition failure
without that precondition. It authenticates absence and repeats the census before
fsyncing completion. A newly observed live claim requires gated status repair;
it does not authorize an unconditional second delete.

Always run `--check-only` in the intended sandbox first. It makes no remote or
receipt mutation. Do not claim a stale object was removed until the mutating
invocation and authenticated completion receipt both succeed.

An interrupted exact attempt can resume from its existing intent. If its fleet
has aged out, seal a new plan using fresh coordinated fleet evidence, new receipt
paths and the exact `prior_intent` binding. Recovery retains the old epoch,
bucket, key, owner identities, status payload, ETag and publication receipt.
Absence without an exact prior intent fails closed. Preserve every intent and
completion receipt, and keep the epoch in the open repair backlog until a
qualified recovery reaches a verified R2 ready pair.
