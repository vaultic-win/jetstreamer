# Reserve-stopped scratch retirement

A controlled reserve stop is not replay divergence or archive completion. First preserve its
controller-before-producer intent/completion, original invocation IDs, archive, state, inputs and
logs. Keep the repair entry open after status cleanup and scratch retirement.

Retirement requires a review of the exact immutable node's build-bound source and retained state:
does a relaunch restore its sealed bootstrap, or can it genuinely continue the native bank from
scratch? Do not infer the answer from a directory named `scratch`, an empty systemd InvocationID,
or the existence of `JETSTREAMER_ROOT_COHORT_RESUME_RUN`. A cursor-free run-directory reuse path
can preserve old output while still restarting replay at the predecessor snapshot. Retain a
useful partial archive even when that mutable scratch has no in-place continuation path. Never
generalize the epoch-213 diagnostic continuation into another epoch's qualification.

## Rust singleton profile

`jetstreamer-r2 reserve-retire-scratch` currently supports the independent-singleton preparation
schema with an immutable packaged node/bootstrap and the exact `/home/sol/.jetstreamer-private/`
`epochN-singleton-.../lane-a/private/destination-.../work/root-cohort-N-N/run-PID-NONCE/scratch`
layout. It is not a generic tree remover, complete-archive retirer, or multi-epoch cleanup tool.
An unsupported host/layout needs its own reviewed, tested profile, not renamed state or fabricated
deployment metadata. The older sealed Python retirer remains usable only for an already-bound
workflow and its genuinely supported package schemas.

Build and test an optimized profile for whole-archive hashing; a debug build can make this
read-only qualification unnecessarily CPU-bound. Seal the Rust executable with the normal
deployment sealer. Seal a separately hash-bound
`jetstreamer-reserve-scratch-retirement-plan-v1` plan containing:

- Exact epoch, `run_uid`, run directory and its direct `scratch` child.
- `reserve_stop::Evidence`: controller/producer units and original invocation IDs, plus the
  hash-bound guard intent/completion.
- A fresh complete campaign `fleet`, the immutable `node`, `bootstrap`, `preparation`,
  `node_build`, and `operator_review` files, each with absolute path and SHA-256.
- Separate root-only, no-clobber `check_receipt`, `intent` and `completion` paths outside the run.
- Local scratch retirement and preservation of partial archive/inputs explicitly true; replay
  launch, archive deletion, remote mutation and R2 mutation explicitly false.

The review uses schema `jetstreamer-reserve-bootstrap-restart-review-v1`, binding epoch, run UID,
exact `run_directory` and `scratch`, `cohort_state_sha256`, node SHA-256 and the build receipt's
source commit. The run-name PID must equal the original producer PID in the guard's stop intent;
a different run for the same epoch/bootstrap is not interchangeable. The review must establish
`scratch_contains_replay_cursor: false`, `restarts_from_sealed_bootstrap: true`, and
`preserve_partial_archive_and_inputs: true`. A review is a scoped local-retirement decision,
not a replay/admission or publication receipt.

Run the immutable executable with the plan and independently supplied executable digest:

```sh
jetstreamer-r2 reserve-retire-scratch PLAN \
  --plan-sha256 PLAN_SHA256 --self-sha256 EXECUTABLE_SHA256 --check-only
```

Check-only hashes retained state/archive/input bytes and the immutable bootstrap/node, validates
the preparation/build/review bindings, checks the current complete claim census and terminal
owners, rejects queued launch triggers, and scans process commands/maps/cwd/root/exe/descriptors.
It rejects symlinks, foreign owners, hardlinked scratch files, special files, filesystem crossings
and nested bind mounts. Its durable check receipt authorizes no deletion by itself.

Only after that qualification passes, use the same invocation without `--check-only`. The tool
rechecks the evidence, fsyncs intent before unlinking, removes only the exact scratch tree, fsyncs
its parent, rehashes preserved work and writes completion. Record both measured physical bytes and
filesystem free space; concurrent replay allocation means their deltas need not agree. Preserve all
receipts and keep the stopped controller dormant until fresh admission and a proven guard exist.

## Interrupted retirement

Resume from the original intent; never delete it or manufacture a completion. The original
check/intent plan is independently rehashed. A new sealed plan may refresh **only** its fleet
evidence; the scope fingerprint pins every owner, target, UID, input, review, output path and
authority bit. The executable digest must remain identical. A replacement scratch inode, changed
preserved work, live replacement, unexpected process reference or ambiguous observation fails
closed. A dangling symlink is not absence. When bindings cannot be reconciled, preserve evidence
and qualify an explicit migration rather than weakening the current gates.
