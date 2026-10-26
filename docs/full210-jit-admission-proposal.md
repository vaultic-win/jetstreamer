# Full 210 admission with in-process guard selection

Status: source implementation against `7c557e91`, awaiting final independent
review and parent compiler/runtime qualification. This document grants no
service, archive, snapshot, replay, or R2 authority.

## Problem and available implementation

The cycle 436 admission selected guard receipts at 03:45:15 UTC. The bounded
admission began at 03:45:33 and finished at 03:45:40. The 207 guard completed a
new invocation at 03:45:33.500195. Correct existing admission rejected the old
binding. Agent messaging, root review, sealing, and tool dispatch consumed the
quiet interval before admission began.

There is no existing public CLI that both intrinsically selects completed guards
and invokes Full 210 admission. Reuse the existing Rust
`warmup223::completed_guard_binding` selector. It delegates to
`warmup223::guard_receipt::select`, which authenticates the latest PID 1 Finished
job, matching start/stdout/deactivation/finish sequence, boot, immutable receipt,
executable and command. It rejects a latest failed job rather than falling back
to an older success. A script selecting the greatest Deactivated event is not a
replacement for this implementation.

## Proposed entry point and exact scope

Add `admit-singleton210-jit SPEC --spec-sha256 SHA --self-sha256 SHA` to the Rust
helper. Keep ordinary `admit-singleton210` behavior unchanged. The immutable JIT
spec binds the accepted observer and fleet, existing resource plan, capability,
small native terminal proof, exact bounded caller unit and fragment, executable
and deployment seal, and one new root-private output directory under
`/var/lib/jetstreamer/horizon-210-singleton-admission-*`.

Derive the complete supported active roster from the immutable accepted fleet.
The current legacy profiles are 207 and 225, using their existing closed
producer IIDs, guard services and receipt directories. Registered generic 209
Full/plugin/upload peers obtain their selection profile from the same
`completed_archive_phase::peer` reader used by ordinary capacity. That reader
revalidates the captured launch, spec, admitted guard plan, immutable receipt
namespace and source qualification. Its profile binds the exact owner IID,
guard unit, plan and executable SHA, and authenticated launch. No JIT wire field
accepts guard choices or peer exemptions.

Require every accepted active owner to resolve to exactly one supported profile,
all provider records to be consumed, and every supported live raw census owner
to remain represented. Preserve and revalidate the complete derived profile map
with the selected histories. The ordinary core still independently validates
all current owners, native processes, guards and full resource envelopes. Other
ordinary profile families remain an explicit unsupported limitation for this
JIT issuer; they fail closed until an equally authenticated selector adapter is
reviewed. There is no universal owner-name or zero-resource exemption.

Authenticate the calling metadata service before input validation, immediately
before selection, and before output commit. Bind its live PID, process start
ticks, systemd IID, boot, argv, executable hash, root credentials, exact cgroup,
zero restarts, and effective unit/fragment. Require the reviewed bounded service
profile (20 GiB memory, zero swap, 512 tasks, 800% CPU, 600 seconds, root-only
writable output directory, private network, read-only home, strict filesystem,
no authority-bearing hooks or ambient environment sources). Reuse typed native
empty-array proofs for properties omitted by systemctl, through a narrow exact
210 issuer scope rather than accepting absence as empty.

## Execution order and evidence

1. Validate immutable JIT spec, self/deployment, exact issuer, complete observer
   and accepted fleet context, roster, output custody, candidate inactivity, and
   existing capability/native/resource plan.
2. Reuse the existing stable-file input validators, including the 8.579 GB
   snapshot rehash, before guard selection. Factor existing input checks into a
   shared private function so JIT execution does not rehash the snapshot again
   after selection. Ordinary admission retains the same checks and order.
3. Recheck issuer identity, unchanged immutable context and complete roster.
   Select every supported owner’s latest completed guard receipt intrinsically using the existing
   Rust selector with the exact coordinated sample minimum and existing age
   bound. Preserve the complete selected history and bound receipt for each.
4. Write a no-clobber, fsynced root-owned immutable effective ordinary admission
   spec in the same private attempt directory. Its resource basis contains the
   selected exact bindings. Bind it to the JIT spec, helper self hash, issuer
   identity, and selection histories through a separate immutable issuer receipt.
5. Invoke the existing internal Full 210 admission implementation directly in
   this same process, after the already-completed shared input gate. No process
   restart, external invocation, parent/agent message, new sealing step, or
   timer operation intervenes between selection and capacity computation.
6. Existing complete capacity logic still reselects and requires the same latest
   completed guards at both resource brackets. It preserves native 223 terminal
   proof, exact active owners, guard timers and caps, century floor, all remaining
   disk/memory growth, actual and sampled availability, pressure, RSS and VMA
   gates. A new guard fire during those brackets remains a failure.
7. Issue the ordinary admission receipt only after all gates pass, additionally
   binding the JIT issuer evidence. Existing capture/producer launch reads the
   same ordinary admitted schema and effective spec. No replay, guard, R2,
   canonical sidecar, or publication authority is added by the new command.

A failure preserves the effective spec, selection/issuer evidence, actual
terminal outcome and earlier failures. It issues no admission and performs no
automatic retry. The issuer does not stop timers, retain an older guard while
ignoring a newer completion, wait in a polling loop, or change freshness gates.
A future explicit invocation must use a distinct no-clobber attempt directory.

## Source changes and required verification

Expected production changes: small private refactor in
`singleton210_admission.rs`, a separate `singleton210_admission/jit.rs`, narrow
issuer/typed-property support, and the fleet/main command dispatch. No shared
resource arithmetic or guard selector semantics need to change.

Meaningful tests should establish:

- Snapshot/input validation precedes intrinsic selection and executes once;
  failure prevents selection and admission.
- Selection and admission occur in the same issuer, with an effective immutable
  spec binding the exact guarded resource context and source spec.
- Changed PID/ticks/IID/boot/argv/cgroup/executable, arbitrary guard paths,
  duplicate/missing owners or an unregistered generic 209 competitor reject;
  a genuinely captured generic 209 peer remains fully included.
- The existing no-fallback latest-job selector remains authoritative, and a guard
  advancing before either capacity bracket produces no admission receipt.
- The ordinary admission route and downstream capture schema retain their gates;
  no JIT failure can launch a producer or turn a pending spec into admission.

Parent owns exact source review, compiler/cache lease, Clippy/tests, production
capture and sealing, native role qualification, fresh runtime execution, and any
subsequent producer launch. No runtime readiness is claimed by this proposal.
