# Epoch 249 reboot recovery launcher

This one-shot Rust launcher prepares and starts a fresh epoch 249 replay while the
exact epoch 247 and 248 reboot generations remain healthy. It preserves the stopped
old 249 attempt. It uses the independently authenticated 249 snapshot, node,
worker, manifest, sealed compact-index cache and original sealed epoch 249 unit
templates. It cannot publish or retire archives or mutate R2.

## Resource and owner gates

The candidate keeps the original 506,191,984,640-byte root cap, 251,041,591,296-byte
MemoryMax, 167,361,060,864-byte MemoryHigh, 800% CPU quota and CPUs 64–79.
Its guard has 1 GiB MemoryMax and a 3,500,000 VMA limit. The admission must book
all three replay lanes and their control allocations against actual host memory.
The admission retains the prior fleet's 980,221,169,664-byte memory obligation
and 2,666,773,615,088-byte root obligation without claiming credit for stopped
workers. Initial free space must cover that root obligation plus the full
candidate root cap. The source admission is deliberately unaccepted.

The admission binds the current boot, campaign controller, observer, complete
native census, capacity, the stopped old 249 attempt and the immutable 247 and
248 startup handoffs. The launcher independently checks both live services' exact
invocations, cgroup membership, historical workers and active protective timers.
Only those two live replays and their guards may coexist with candidate preparation.
Its producer, guard, token and evidence namespaces are all new and one-shot.

## Immutable inputs and namespaces

See REQUIRED-PATHS.txt for retained input locations. Candidate namespaces are:

- Producer: horizon-qualify-249-reboot-20261117-v1.service
- Guard: horizon-249-reboot-20261117-protective-v1.service
- Timer: horizon-249-reboot-20261117-protective-v1.timer
- Root: /home/ubuntu/.jetstreamer-private/qualification-249-reboot-20261117-v1
- State: /var/lib/jetstreamer/horizon249-reboot-20261117-state-v1
- Static seal: /var/lib/jetstreamer/horizon249-reboot-20261117-static-v1
- Guard seal: /var/lib/jetstreamer/horizon249-reboot-20261117-guard-v1
- Tokens: /var/lib/jetstreamer/horizon249-reboot-20261117-tokens-v1
- Guard receipts: /var/lib/jetstreamer/horizon249-reboot-20261117-receipts-v1

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

    horizon-reboot249-launch inspect PLAN PLAN_SHA256 SELF_SHA256
    horizon-reboot249-launch prepare PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256
    horizon-reboot249-launch preflight-launch PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256
    horizon-reboot249-launch launch PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256

inspect and preflight-launch are read-only. prepare creates the fresh root and
installs an inactive producer. launch starts it once. After its guarded startup
handoff, Main must observe useful transaction replay and update fleet and
dashboard evidence. Existing full/plugin/boundary/R2 delivery gates still apply.
