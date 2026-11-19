# Singleton replay to delivery handoff

`tools/horizon_singleton_delivery_handoff.rs` captures the exact clean producer
exit and committed local output for Foundation singletons 247–251. It imports
the node's production `cohort_publication` module rather than duplicating its
receipt, transaction, namespace, checksum and rollback validation.

The sealed plan binds the original startup handoff, producer unit and invocation,
exact command, immutable singleton manifest, output directory device/inode,
original UID/GID, identity-bound batch receipt directory and independently
collected terminal block expectation. `check-plan` checks these static inputs
and executes an original-owner read preflight; it does not observe the producer
or treat a growing archive as complete.

`capture` requires a loaded, inactive producer with zero restarts, a successful
normal exit and its exact command. PID1 history must prove one start and one
clean exit for the bound invocation, with no replacement since that start.
The helper then drops to the source owner to validate the single committed
batch through the actual node validator. It compares bootstrap and canonical
root hashes with the sealed manifest and the native terminal slot/hash with
the independent expectation, including epoch 251's skipped final slots.
Private root-owned startup evidence stays with the privileged parent; the child
reads only the sealed plan/manifest and the original owner's source.

After repeating the producer check, the root parent writes and fsyncs
`terminal-handoff.json` without overwriting. The receipt retains exact source
paths, identities, checksum digest, root evidence and manager events. It
explicitly does **not** claim a whole-file hash or current-reader verification.
It grants no resource release, replay launch, upload or local deletion.

Invoke the root-owned sealed helper as:

```text
horizon-singleton-delivery-handoff check-plan PLAN --plan-sha256 HEX --self-sha256 HEX
horizon-singleton-delivery-handoff capture PLAN --plan-sha256 HEX --self-sha256 HEX
```

Do not run capture against a healthy producer as a polling mechanism. Run it
after terminal completion is observed by the campaign's existing cadence or an
authenticated completion event. Missing, failed, restarted or ambiguous owners
fail closed. Preserve unsuccessful attempts; never turn a missing receipt into
authority to restart or discard the replay.

Delivery still needs fresh capacity admission, serialization with other uploads,
the qualified current-reader plan, full local verification/plugin playback,
authenticated upload/readback, full remote plugin playback and final branch
revalidation. The new uploader performs those archive gates before committing
the readiness sidecar. Adjacent-boundary and local-retirement gates remain
separate. Existing legacy delivery watchers do not automatically adopt these
new singleton producers or plans.

The initial qualification passed 21 ordinary tests, including the imported
node publication tests, and two explicit root native tests. One native test
uses actual node publication to create a synthetic committed batch and proves
that source handoff rejects a replaced archive and a wrong manifest root. The
other creates a disjoint bounded systemd service, captures its actual PID1
history through the production terminal reader, rejects a different invocation,
then removes its timer. Neither is a canonical mainnet archive or production
handoff. Binary and test Clippy runs pass with warnings denied. Build/test
commands and journals are retained in Foundation's private
`horizon-singleton-delivery-handoff-20261119-v1` diagnostics directory.

Production capture and delivery remain unqualified until the actual singleton
finishes and the full operational gates pass. Static plan acceptance alone is
not an epoch landing or permission to free its files.

Foundation's source `7d809078` is deployed at
`/var/lib/jetstreamer/horizon-singleton-delivery-handoff-7d809078-20261119-v1`.
The executable SHA-256 is
`b90e9ca43b438ee6eb26e066a4ea6838f03f14b0dada0951913473195c878e95`.
The package includes the exact source, build/test commands, journals and five
producer-specific plans. All five deployed `check-plan` invocations passed,
including execution of the original-owner read preflight as UID/GID 1000.
No production terminal capture has run while these producers remain active.

For the integrated current-reader uploader, its observational `upload-readback`
claim may initially report the dashboard phase `verification`: full local
verification and plugin playback precede upload. Retain the same live uploader
identity and original producer clock as the phase advances to `upload` and
`readback`. This metadata allowance grants no archive publication authority.

## Foundation delivery transition

The qualified uploader with this status support is sealed at
`/var/lib/jetstreamer/horizon-pipeline-verification-status-ea36a4a6-20261119-v1/jetstreamer-r2`,
SHA-256 `dd75ef62021401022d6597fc94f1c77e95092e1065b26f694dced66a18463954`.
Its package retains the exact source build command and qualification journal;
26 focused pipeline-status tests passed. The reader plans remain under
`/var/lib/jetstreamer/horizon-reader-delivery247-251-db1c31fe-20261119-v2/epoch-N-plan.json`.
These paths identify prepared artifacts; they do not establish fresh admission.

At the actual completion event, use this sequence:

1. Capture the exact singleton's terminal handoff using its sealed plan and
   separately supplied hashes. Keep the producer's terminal unit loaded while
   consuming its identity evidence. Read the committed archive from the plan's
   `output_directory`; the former live `work/.../archives` path may have been
   cleaned by successful node publication.
2. Admit delivery against fresh hard reservations and disk growth. Count the
   independent epoch-205 audit's 7 GB reservation while it remains live. A clean
   producer receipt alone does not release its reservation: prove its cgroup has
   drained, retain the evidence, then account for the new delivery service and
   readback scratch separately. The prepared reader plans reserve a maximum
   300 GB archive and retain a 3 TB minimum free-space check. Reconcile those
   bounds with all other live growth before launch; never infer capacity merely
   from producer RSS or an estimated finish time.
3. Fetch `origin/account-updates`, verify required source containment and exact
   reader equivalence, and select a currently loaded keychain SSH agent. Run the
   sealed uploader's `sync` command for exactly `N-N`, with the committed output
   directory, private receipt directory, and separately hash-bound current-reader
   plan. Supply only named credentials. Use a persistent non-restarting service
   and serialize canonical deliveries. Do not use overwrite, repair or deletion
   options. The command owns full local verification, local plugin playback,
   upload, authenticated readback, remote plugin playback and sidecar commitment.
4. Name the service `horizon-upload-N-singleton-...service`, track it in the full
   fleet census, and bind the actual invocation and complete effective command
   to an `upload-readback` claim. The claim begins with dashboard phase
   `verification`. Use an authenticated replay status receipt as `origin_launch`
   to preserve the original producer clock; a terminal handoff is not a substitute
   for that publisher input. Bind a fresh coordinated observer/fleet and concrete
   remaining-time evidence before calling `status-publish-pipeline`. Advance the
   phase only from actual uploader progress, never merely from service start.
5. After durable ready-pair and full remote-playback evidence, use a compatible
   status cleanup helper with the exact latest publication receipt. Complete the
   adjacent-boundary and no-consumer gates, then promptly retire eligible local
   epoch data. Preserve the durable receipts and needed lineage evidence.

Register future delivery unit names in the next fleet plan before launch; this
does not create live pipeline claims. Do not reuse the old legacy watchers or
publish a pipeline claim with an anticipated invocation ID. A failed gate retains
the complete local output and its evidence for diagnosis and an isolated retry.

## Terminal process drain

After actual terminal handoff, `capture-drain` records the separate process
evidence needed by the next admission:

```text
horizon-singleton-delivery-handoff capture-drain PLAN --plan-sha256 HEX --self-sha256 HEX --terminal-sha256 HEX
```

The last digest binds that plan's existing `terminal-handoff.json`. The helper
requires the original nondelegated, non-restarting, control-group-contained
producer and repeats its clean PID1 history check. It rejects a control PID,
queued job, activation trigger or changed cgroup. In PID1's cgroup namespace,
it checks every remaining cgroup descendant for zero populated state, processes
and threads, then scans `/proc` for any process still in that exact cgroup or a
descendant. It repeats both census and manager checks before writing the
no-clobber, fsynced `terminal-drain.json`.

This is point-in-time evidence, not a capacity grant. The admission must recheck
the exact terminal owner and drain, preserve the complete fleet history, and
reserve delivery/readback and any replacement separately. Existing disk files
and growth obligations are not removed by a process drain. No unit, archive,
reservation ledger or R2 object is mutated by this command.

Qualification passed 24 ordinary tests, three native tests and binary/test
Clippy with warnings denied. The drain native test rejects a live disjoint
systemd service, then accepts its normal exit and empty cgroup. A test-only
target retains the completed unit's original properties. The initial fixture
failure is retained in the private qualification journal; no production owner
was stopped or used as a terminal fixture.

The qualified retention fixture uses only `After=` references. Starting its
target leaves the test producer unstarted; restarting the target after the
producer exits preserves the original single invocation and clean terminal
evidence without replaying the command. This matters because PID1 can collect
an otherwise unreferenced inactive unit and discard its original exit fields.

`tools/horizon-foundation-terminal-retention.target` applies those ordering-only
references to the original five Foundation singletons. It has no `Wants=`,
`Requires=`, `BindsTo=`, `Upholds=` or boot installation section. Before activating
its sealed copy, bind the exact original producer identities and unchanged unit
files; capture them again afterward and require the target to be active with no
activation dependencies. Retain the target until the actual terminal handoff,
drain and downstream consumers have preserved their required manager evidence.
The target does not grant capacity, archive success or publication authority.
