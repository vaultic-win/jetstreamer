# Epoch 248 reboot recovery launcher

This one-shot Rust launcher prepares and starts a fresh epoch 248 replay while the
exact epoch 247 reboot generation remains healthy. It preserves the stopped old
248 attempt. It uses the independently authenticated 248 snapshot, node, worker,
manifest and the original sealed epoch 248 unit templates. It cannot publish or
retire archives or mutate R2.

## Resource and owner gates

The candidate keeps the original 506,191,984,640-byte root cap, 251,041,591,296-byte
MemoryMax, 167,361,060,864-byte MemoryHigh, 800% CPU quota and CPUs 96–111.
Its guard has 1 GiB MemoryMax and a 3,500,000 VMA limit. The admission must book
both replay lanes and their control allocations against actual host memory.
The admission retains the prior fleet's 980,221,169,664-byte memory obligation
and 2,666,773,615,088-byte root obligation without claiming credit for stopped
workers. Initial free space must cover that root obligation plus the full
candidate root cap. The source admission is deliberately unaccepted.

The admission binds the current boot, campaign controller, observer, complete
native census, capacity, the stopped old 248 attempt and the immutable 247
startup handoff. The launcher independently checks the live 247 service's exact
invocation, cgroup membership, historical worker and active protective timer.
Only that live replay and its guard may coexist with candidate preparation.
Its producer, guard, token and evidence namespaces are all new and one-shot.

## Immutable inputs and namespaces

See REQUIRED-PATHS.txt for retained input locations. Candidate namespaces are:

- Producer: horizon-qualify-248-reboot-20261117-v1.service
- Guard: horizon-248-reboot-20261117-protective-v1.service
- Timer: horizon-248-reboot-20261117-protective-v1.timer
- Root: /home/ubuntu/.jetstreamer-private/qualification-248-reboot-20261117-v1
- State: /var/lib/jetstreamer/horizon248-reboot-20261117-state-v1
- Static seal: /var/lib/jetstreamer/horizon248-reboot-20261117-static-v1
- Guard seal: /var/lib/jetstreamer/horizon248-reboot-20261117-guard-v1
- Tokens: /var/lib/jetstreamer/horizon248-reboot-20261117-tokens-v1
- Guard receipts: /var/lib/jetstreamer/horizon248-reboot-20261117-receipts-v1

The original 60-second start-pre sleep and 50-second dynamic launch deadline
remain. The actual first guard timer firing and sample must pass before the
invocation token is sealed. A failed launch preserves its state and never retries
automatically. Check the actual unit and guard state before any follow-up.

## Qualification and operation

Build and test offline with at most two Cargo jobs. emit-source-templates DIR
writes an unaccepted admission and source launch plan. Seal the release binary
and exact launch plan with jetstreamer-seal-deployment. Main then creates fresh,
root-owned, hash-bound evidence and an admission that binds the sealed plan.
The commands are:

    horizon-reboot248-launch inspect PLAN PLAN_SHA256 SELF_SHA256
    horizon-reboot248-launch prepare PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256
    horizon-reboot248-launch preflight-launch PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256
    horizon-reboot248-launch launch PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256

inspect and preflight-launch are read-only. prepare creates the fresh root and
installs an inactive producer. launch starts it once. After its guarded startup
handoff, Main must observe useful transaction replay and update fleet and
dashboard evidence. Existing full/plugin/boundary/R2 delivery gates still apply.
