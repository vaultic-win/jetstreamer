# Epoch 223 bounded bootstrap estimate

`jetstreamer-epoch223-bootstrap-estimate PLAN PLAN_SHA256 SELF_SHA256`
is a read-only incident-specific estimate helper for the independently restarted
223 invocation. It does not weaken the normal measured-rate estimator.

Run only from a root-owned immutable deployment sealed by the native deployment
sealer. Its strict plan binds the current v2 observer, historical v2 observer,
prior ETA model, exact singleton launch receipt and private no-clobber output.
The historical observer, prior model and launch digests are independently pinned
in source. The current ordinary census must contain only the exact zero-restart
223 invocation, one stable bound worker, and no progress markers. Native D-Bus
start evidence binds elapsed time to that running invocation; a sample older than
30 minutes or startup elapsed of one hour or more is rejected.

Before current replay rates exist, use the historical same-worker epoch-223
rate as an explicitly labeled prior. Include the full 432,461 warmup/replay
slots, the unspent part of the one-hour bootstrap allowance, and the prior
first-in-queue 8,779-second downstream allowance. Do not reuse the old cohort's
last-in-queue penalty. The resulting integer is time to verified sidecar commit,
not time to replay terminal. This is a best guess, not measured current speed.
Once current markers exist, this helper rejects: construct the ordinary
current-rate model instead. Do not extend this prior to conceal a stalled restore.

Output is a fsynced private estimate receipt only. Publication still uses the
normal observer/identity-bound authenticated `status-publish` command, conditional
replacement and readback. No replay, archive, sidecar, service or R2 mutation is
performed by this helper. Tests cover wrong/restarted owners, changed worker,
current progress, wrong historical epoch, invalid rates, startup expiry and the
complete startup/replay/downstream arithmetic; native start-binding tests are
reused from the production estimator.
