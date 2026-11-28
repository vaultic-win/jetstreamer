# Epoch166 retry6 scratch retirement

Profile derived from `horizon_retry4_170_scratch_retire_20261118_v1`.
The copied `stopped_tree.rs` and `process_references.rs` remain byte-identical to
that reviewed predecessor. Main owns qualification, deployment, Git publication
and all capacity accounting. Qualification history is recorded below.

The only removal target is the contents of the exact stopped retry6 run's
`scratch` directory, device64512/inode103678021. The profile preserves that
directory, run inode103678018 and every ancestor. It binds the original producer
unit/invocation and the four supplied stop/admission/protection digests. It keeps
`archives/epoch-166.jet` inode103678035 (56,173,984,550 bytes) in local mode, every input, and
`cohort-state.json` inode103678019 (222 bytes). The exact run, destination,
receipt paths and artifact hashes are constants in `src/main.rs`.

The program takes the existing local-mutation lock inode101135013 followed by
the destination's `locks/epoch-166.lock` inode103678014. Both are existing
device64512 uid1001/gid1003 mode0600 files; it never creates, truncates, replaces
or removes either. Their handles remain held through completion. A receipt
directory lock and the predecessor's scratch-directory lock serialize this
lifecycle. Locks and ancestor identities are rechecked before deletion and
before publishing completion.

The check captures an unchanged descriptor-relative scratch ledger and hashes
every retained regular file. Execution checks retained identities, performs
only ledger-authorized deletion, then hashes retained contents again. Ordinary
gates do not repeatedly hash the 56GB archive. New/changed entries, symlinks,
hardlinks, foreign owners/devices, new run members, root replacement and nested
mounts/bind aliases fail closed. Host and helper mount namespaces are both
inspected. Consumer scans cover only the old retry6 destination, so independent
epoch166 retry8 and epoch167 destinations remain eligible to run.

No R2 operations, archive deletion, promise ending, resource credit or replay
launch are provided. The existing 309,237,645,312-byte retry6 DATA promise must
remain until Main separately qualifies physical reclamation and changes its
accounting through the established path.

## No-resume evidence still required

The peer review is `/tmp/epoch166-retry6-no-resume-review-20261119.txt`, with four
retained source copies in `/tmp/epoch166-retry6-no-resume-source-20261119-v1`.
It verifies the exact sealed node and worker, original command, package seal,
manifest and cohort state. That source at `e6f48efe2749d35d6875fdd3cbd7f6f4379adf75`
restarts at the original bootstrap; its resume option reuses scaffolding rather
than restoring the interrupted native bank or archive cursor.

**The peer did not locate exact original production build/source-image proof.**
Its capability receipt establishes source lineage, which this profile does not
silently promote into production build proof. `NoResumeReview` requires a
positively established exact source/image binding plus separately hash-bound
original build evidence. Known capability/seal/source/artifact digests are
rejected as stand-alone substitutes. Locate and review that evidence before
claiming this gate passed. A boolean or an invented replacement receipt is not
qualification. Preserve any newly discovered export/continuation evidence and
reassess the review before retirement.

Main must seal root-owned, no-symlink copies of the text analysis and the four
source copies. `NoResumeReview` (schema
`horizon-retry6-166-no-resume-review-v1`) binds:

- Exact run/scratch, epoch166, original unit and invocation.
- `original_native`, `original_argv`, `stop_completion`, `node`, `worker`,
  `manifest`, `package_seal`, `source_lineage`: the exact `Bound {path, sha256}`
  constants from `main.rs`.
- `source_commit` above and `cohort_state_sha256`
  `ef63e2a2e443375f84b1c851c8d0ffc51454d3ef0f5bea03124f8ce3cd73e47a`.
- `exact_source_image_evidence`, `reviewed_source_evidence`, `analysis`.
  The source evidence must include all four exact digests in
  `REVIEWED_SOURCE_SHAS`; references must survive local retirement.
- True, independently supported conclusions for
  `exact_source_image_binding_established`, `no_admitted_scratch_continuation`,
  `no_native_bank_or_writer_cursor`,
  `original_invocation_restarts_from_bootstrap`,
  `snapshot_exports_and_indirect_readers_reviewed`, and
  `preserve_partial_archive_and_inputs`.

## Plan and fresh dependency closure

`Plan` is a deny-unknown-fields structure in `main.rs`; the complete shape is
also shown by the pure fixture in `src/tests.rs::plan`. Populate it with real
evidence, never the test fixture's synthetic paths/digests. Required bindings
are the four exact historical receipts, sealed `no_resume_review`, fresh
`dependency_review` and the two exact shared-lock identities. All preservation
flags must be true and every credit/mutation/launch/release field must be zero
or false.

`DependencyReview` in `src/references.rs` has schema
`horizon-retry6-166-scratch-dependency-review-v1`. It binds the same target and
no-resume review, is at most1800 seconds old, covers every listed
`DEFINITION_ROOTS` entry, and retains hash-bound evidence of terminal,
compiled/indirect, dormant/staged and future-reopening closure. It explicitly
requires retained resource promises and no unreviewed continuation/export
evidence. The runtime additionally performs native unit, process, mount and
staged-definition checks before destructive work.

`allowed_terminal_definitions` contains only exact hash-bound installed unit
files or their drop-ins, each tied to its inactive, unqueued owner. Other
references to the old destination fail. Masked root-owned units pointing to
`/dev/null` are recognized. Dangling aliases fail closed and require independent
diagnosis; this profile does not infer that they are harmless. No blanket
requirement closes active166 retry8 or167 units.

The initial plan and every replacement dependency review are independently
hash-bound. `scope_sha256` excludes only `dependency_review`, allowing an
interrupted deletion to resume with fresh consumer evidence while retaining
the exact original ledger, no-resume proof and authority. Original CHECK and
INTENT receipts are never overwritten. An existing COMPLETE receipt causes a
repeat execution to stop before work. Receipts publish through fsynced,
descriptor-relative `renameat2(RENAME_NOREPLACE)`.

## Main's qualification and operation sequence

1. Resolve the build-proof limitation. Review the exact retained inputs,
   continuation/export census and shared-lock identities; preserve all evidence.
2. Run package formatting, offline locked tests, strict all-target Clippy and
   the production build in Main's admitted build scope. The inherited tree and
   process fixtures plus new tests cover wrong profile/receipts/authority,
   review substitution, stale closure, sibling content changes, mount/bind
   aliases and staged references. No test results are claimed by this handoff.
3. Perform an isolated positive/negative/interrupted/repeated lifecycle test
   under the final service identity and filesystem capabilities. Cover private
   evidence traversal, both held locks, nested mounts, staged definitions,
   foreign root/ledger/protected sibling, and cleanup restart with a fresh
   dependency review. Do not point qualification at production scratch.
4. Publish the source to `origin/account-updates`, bind the exact production
   artifact to that source/build, and use the normal Rust sealer. The immutable
   runtime path must be
   `/usr/local/lib/jetstreamer/horizon-retry6-166-scratch-retire-20261119-v2/retire`.
5. Precreate root-owned0700
   `/var/lib/jetstreamer/epoch166-retry6-scratch-retirement-20261119-v2` and admit
   ledger/log/hash I/O and execution resources without consuming promised
   replay growth. Keep all retained evidence readable by the final sandbox.
   A direct bind mount at/below scratch is intentionally rejected; qualify the
   sandbox's parent mounts and exact writable scope accordingly.
6. Run `retire PLAN --plan-sha256 SHA --self-sha256 SHA --check-only` under fresh
   closure. Review its CHECK/LEDGER and the complete retained-file digest set.
   The check itself does not authorize execution.
7. With Main's separately qualified transition and fresh closure, use the same
   command ending in `--execute`. If interrupted, preserve INTENT/LEDGER and
   re-enter with the same scope and freshly bound dependency review. Reject
   substituted/new scratch contents. After success, preserve COMPLETE and
   independently account actual physical reclamation before any promise release
   or new admission.

Parent source qualification on 2026-11-19: all 21 ordinary tests passed in
`horizon-166-retry6-retire-tests-20261119-v1.service`; strict all-target Clippy
passed in `horizon-166-retry6-retire-clippy-20261119-v1.service` (invocation
`3ff7b0e2ccb14625ab428138ff6f0962`). No production deletion deployment or
scratch retirement was performed. The original-build evidence gap remains open;
closed partial-archive R2 holding is being qualified as an independent capacity
recovery route that preserves the bytes.

## Explicit held-partial mode in runtime v2

The v1 plan and no-resume schemas keep the original local archive requirement.
Both v2 schemas require the same `held_partial_completion: Bound`, pointing to
the exact retry6 partial-retirement completion under the host holding state.
Missing local output never selects held mode automatically.

Held mode checks the immutable completion, intent, move and unlink records;
the exact authenticated custody receipt; and genuine original park terminal
evidence. Inspection and terminal proof copies must be hash-bound in a versioned
retirement-evidence bundle. The completion must identify the original source,
inode, length and digest. It must preserve the current input identities, state,
run and ancestors. Every preservation check repeats these validations and binds
the proof into the CHECK/completion evidence. No-follow parent descriptors must
prove that both source and quarantine are absent and the preserved archives
directory is empty. Missing parents, aliases, extra entries or changed evidence
fail closed.

The exact original production build/no-resume gate remains required and
unresolved. Held-mode support grants no permission to remove the partial, delete
scratch, release promises, restore a job or launch another lane. The separate
partial-retirement workflow must complete first.

Runtime-v2 source qualification on 2026-11-19: 28 tests passed, including seven
held-mode regressions; strict all-target Clippy and the optimized build passed.
The two JSON test fixtures are exact non-sensitive custody/terminal evidence;
synthetic lifecycle fixtures are not operational receipts. No production scratch
retirement was performed by this qualification.

## Original build investigation at 11:20 UTC

The exact node image `a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65`
embeds revision `3de96e71010a8a2f5e629f666227b137483bff7b`. The capability lineage
and this helper's reviewed-source label instead name
`e6f48efe2749d35d6875fdd3cbd7f6f4379adf75`; do not describe that label as the
original compiler revision.

Surviving Cargo build output independently records `3de96e7`, rustc 1.98.0 and
`x86_64-unknown-linux-gnu`. The node fingerprint's build-script dependency matches
the retained run-build fingerprint, whose JSON points to that output. This proves
the association between cache records, not between complete compiler inputs and
the deployed executable. The fingerprints use `checksum:false`, and the original
`target/release/deps` directory is absent. All four reviewed no-resume source files
match at both revisions, but other build inputs, including `Cargo.lock` and
compatibility code, differ. Whole-build equivalence remains unproven.

Raw cache records, the four source files and the investigation report were retained
through the normal deployment sealer on `dev-samjohnson` under
`/var/lib/jetstreamer/holding166-retry6-retirement-evidence/original-build-investigation-20261119-v1`.
`REPORT.json` has SHA-256
`3f9362b27dd13ef910432d9cfc1d73e6ae308c258204cfc5da95b679f5130784`.
This evidence does not qualify scratch retirement or release the retained
309,237,645,312-byte DATA promise.

The next step is to locate an original compiler-input/output binding or separately
admit reproducibility qualification targeting the exact existing node and worker
hashes. A different newly built image cannot prove the old image's behavior. Any
future gate revision must distinguish the actual build revision from reviewed
equivalent source while preserving the existing proof requirements. Worker
production qualification must retain disabled `poh-force-soft`.
