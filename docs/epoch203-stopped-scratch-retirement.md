# Exact stopped epoch-203 disk scratch retirement

`jetstreamer-epoch203-stopped-scratch-retire` supports only the original
reserve-stopped `root-prefix-resource-203-v1` attempt. Its independently pinned
read-only prerequisite is `299580e8…`, produced by the sealed `cb886043…`
checker. It is not a generic deletion tool, a replay launcher, or publication
authority. The original checker remains read-only and unchanged in deployment.

The strict `jetstreamer-epoch203-stopped-scratch-retire-plan-v1` binds
`original_check`, `checker`, and `check_plan` as absolute path/SHA-256 pairs;
separate `check_unit` and `execute_unit` names; a direct root-private
`/var/lib/jetstreamer/horizon-203-stopped-scratch-retire-*` receipt directory;
and `authority`. Only `local_scratch_retirement_authorized` and
`preserve_partial_archive_and_inputs` may be true. Archive deletion, replay,
publication, remote mutations and R2 mutations must be explicitly false.

Seal the binary and plan with the native deployment sealer. Run each phase
from a separately installed root-owned immutable oneshot unit with the exact
command `BINARY PLAN --plan-sha256 HASH --self-sha256 HASH --check-only`
or `--execute`. The binary authenticates its MainPID, invocation, command,
fragment and non-restarting/no-trigger role. Initially install only the check
unit; its execute counterpart must still be absent. Neither a plan nor a
successful original checker authorizes execution without this new check.

Check-only rehashes the preserved partial and inputs, revalidates the original
failed owner and stopped guard, and rejects live or staged consumers. It binds
the unchanged 695,948-entry scratch catalog to a root-private, no-clobber,
fsynced `ledger.json` and `check.json`. The check receipt denies deletion.
Only after inspecting that result install and run the separate execute unit.
Use persistent installed units and `systemctl start --no-block`; do not put
the scratch target in a still-running launcher command line.

Execution requires the prior check unit to have cleanly succeeded, rehashes
and fsyncs the preserved artifacts, revalidates the ledger and consumer gates,
then fsyncs `intent.json` before any unlink. The descriptor-relative walker
rejects symlinks, hardlinked files, foreign devices/owners, writable peers,
special files and replaced entries. Legacy 0755 directories and 0644 files
are permitted only by this separate disk profile; RAM retirement policy is
unchanged. The original empty scratch root is retained as a sandbox mount
point. Directory fsync is batched once per changed directory.

An interrupted execution can resume only with the identical binary, plan,
check and ledger and the intent's exact retained scope. Remaining entries
must be an identity-matching subset; replacements or new files fail closed.
Completion rehashes preserved artifacts, rechecks consumers, proves the root
empty, and records available bytes before/after. No filesystem-wide flush is
used. Provision sufficient memory for the complete ledger (up to 1 GiB on
disk), read-only access to retained inputs, and write access only to the
exact scratch and receipt directories. No network or credentials are needed.

Keep the partial archive, bootstrap, node/worker, genesis, checkpoint inputs,
failed producer unit, guard and all incident/check/intent/completion evidence.
Reclaiming scratch does not repair epoch 203, establish an in-place resume,
admit a retry, or close its repair backlog. A new replay still needs fresh
resource, compatibility, guard, verification and publication gates.
