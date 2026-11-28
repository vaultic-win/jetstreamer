# Private epoch 225 v1.6.25 comparison

The sealed vote audit brackets the reconstructed Bank divergence between slots
97,199,876 and 97,199,877. The latter contains a signed canonical transaction
that marks its invoked and passed SPL Token program writable. The exact signed
wire fixture is retained in `historical-runtime/fixtures/epoch225-writable-token-program.base58`.
Tests in both pinned workspaces demonstrate the difference: v1.6.20 treats that
program key as writable; v1.6.25 demotes it. This is not actual replay/root proof.

The explicit `epoch225-v1-6-25-diagnostic` feature selects the unchanged pinned
upstream v1.6.25 semantics in a separately built node and worker. Default builds,
ordinary registry bounds, active deployments and all publication gates remain
unchanged. The node requires only focused private epoch 225, snapshot 97,199,617,
explicit verification, checkpoint input and the underlying canonical terminal
root 97,631,459. It rejects ordinary replay, cohorts, recovery and inherited leases
before destination setup. Combining unrelated diagnostic features is a build error.

The worker admits only the exact bootstrap and entries 97,199,618 through
97,202,599. It records frozen Bank/account-delta components at parent slots
97,199,876–97,199,878 for comparison with canonical votes. This is a hard bounded
diagnostic, not permission to execute a whole epoch or cross a runtime boundary.

The existing Rust bounded runner has the same opt-in feature. It pins the exact
new worker digest, selects only the v1.6.25 environment variable, removes the
other worker override and retains the original snapshot, genesis, private root,
target 97,202,500, underlying canonical root and resource limits. A controlled
target stop must still capture resources before shutdown. The worker's bound is
not a successful canonical-root checkpoint. Success must retain
`full_cold_epoch_peak_qualified: false`, `runtime_promotion_authorized: false`,
and every publication/sidecar/R2 authority as false.

Before any launch: pass source tests, publish the commits, seal exact parent,
worker, runner and inputs, exercise exact-package focused/identity capability,
and admit its full incremental budget from fresh coordinated evidence. Protect
all older remaining-growth claims, the complete epoch 213 budget and century
floor. Install and prove the exact invocation's bounded reserve/VMA guard before
leaving it unattended. Keep earlier attempts and receipts; never restart or mutate
a healthy ordinary producer. Any mismatch remains fatal. Even a matching Bank at
the diagnostic boundary requires full checkpoint/plugin qualification before era
promotion or archive publication.

## Bounded comparison result, 2026-10-20

Invocation `a7523ee4cdb54cbfa59a0cc9ed4428b4` reached the target and was
controlled-stopped at observed slot `97,202,504`. The frozen parent Bank at
`97,199,877` was
`3uMcx4shPW8rToYyXRQgiD9DSzx5qDCv2uFw9NanuWPK`, matching canonical votes;
v1.6.20 had produced
`G6BFd1oz8QNkVMdPsrqkJBEF8UBpeGsbfWEEdP4ysJiJ`. The v1.6.25 run passed
the formerly failing successful vote at `97,199,878`. This is evidence of an
actual version-dependent replay improvement, not yet causal isolation of one
upstream change or canonical-root qualification.

The resource receipt SHA-256 is
`c9f7de000bb2495bf6e687de21e7f32ac1d2ab608f33bdbb0ee9b9055f0a8ea4`.
It retains actual child exit 1 after the authenticated target-stop, no external
signal, no OOM kill, and matching pre-shutdown capture. The complete journal and
outcome receipts are preserved in a root-sealed private evidence bundle. No
canonical sidecar was created and no runtime/publication gate was promoted.

The underlying canonical root `97,631,459` is itself 540 slots before the end of
epoch 225. Even reproducing that root would not make this prefix a complete
epoch 225 archive. Full cold-resource admission and a separately qualified
complete-span or checkpoint-continuation path remain necessary.
