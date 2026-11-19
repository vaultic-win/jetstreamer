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
