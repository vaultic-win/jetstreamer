# Routine metadata child diagnostics

A sealed recovery plan may set `delayed_schedule_utc` to the original observer
deadline only when the actual observation started 1–300 seconds later. Its
`sample_target_utc` and all derived metadata must retain the actual receipt time;
the unchanged observer configuration must bind the original scheduled deadline.
The original deadline must still be exactly one qualified predecessor interval
later, and the receipt must prove the actual elapsed interval. This does not
permit another scan, timestamp rewriting, stale publication, or a cadence bypass.
Offline successor preparation clears the recovery field and schedules from the
accepted actual observation time, preserving the 1,800-second minimum.

The fixed October22 narrative review may update only the exact superseded
`next_action` strings for epochs203,205,227. Bind its immutable path and
SHA-256 in each affected epoch's `additional_gate_evidence`. The coordinator
authenticates the ordinary predecessor template unchanged, then applies this
exact compiled-in review while deriving the new fleet plan. It preserves states,
owner/claim census, resource protection, repair history and all integrity gates;
newer actions and ready/live downstream states are never replaced. In particular,
lane-local `memory.high` events alone do not demonstrate host-global saturation,
and a retired redundant download cache is not the retained deployed input.
This is narrative correction only, not admission or replay authority. Do not
substitute a manually edited predecessor template: the exact prior ledger's
template path and digest must still match during preflight.

The separately bound October21 epoch203 capacity-stop incident may replace only
its exact stale natural-root task with an open `failed-needs-repair` gate. The
coordinator authenticates the fixed immutable incident, exact failed invocation,
guard reason, last/required slots and denial of cleanup/retry/publication rights.
Other gates, diagnostic history and tracked units remain unchanged. This is an
idempotent incident recording, not a generic gate-edit API or scratch-retirement
authority. A newer reviewed task is never overwritten. The ordinary fresh
observer, full fleet census, R2 inventory and status gates still run independently.

## Offline successor preparation (explicit campaign profiles)

After a cycle has an accepted `completion.json`, a separately sealed candidate
may be invoked with the current sealed plan and its exact bindings:

```sh
jetstreamer-horizon-routine-cycle CURRENT_PLAN --plan-sha256 HEX --self-sha256 HEX --prepare-next
```

This mode needs no credentials and makes no subprocess, systemd, resource or
remote observation. It consumes the exact accepted observer/model/estimate/
fleet/status receipts, rejects a newer fleet, and preserves all owner IDs,
diagnostic claims, gates, additional evidence and tool pins. It advances by
exactly1800seconds and increments only the canonical observer generation.
An out-of-band observation, changed auxiliary scope or an inconsistent/partial
completion fails closed for manual review.

The 101–200 profile has its own preparation root,
`/var/lib/jetstreamer/horizon-next-preparations-101-200-v2`, owner-only `TIMESTAMP-v2`
stages, and `jetstreamer-horizon-routine-next-preparation-101-200-v2` receipts.
It accepts only this host's exact `sample-TIMESTAMP.json` observer namespace
and its hash-bound manual `horizon-control-seven-HHMM-DATE-v1` config or a
previously prepared config. Generated immutable destinations are
`/var/lib/jetstreamer/horizon-next-observer-101-200-TIMESTAMP-v2` and
`/var/lib/jetstreamer/horizon-routine-plan-101-200-TIMESTAMP-v2`; observer,
cycle, estimate and fleet outputs retain the existing 101–200 namespaces.
Private epoch-144 diagnostic owners stay unchanged and never become ETA claims.
Previously added observational units must already occur in the accepted fleet
template; the next supplemental list then names only the new metadata owner,
while the template retains prior tracked units. This avoids an indefinitely
growing bounded supplemental list without removing history. All other gates,
tool pins and receipts are preserved. The 201–300 generation rules are unchanged.

Precreate the selected profile's root with root ownership and mode0700:
`/var/lib/jetstreamer/horizon-next-preparations-v1` for 201–300, or
`/var/lib/jetstreamer/horizon-next-preparations-101-200-v2` for 101–200. The tool writes one
no-clobber `TIMESTAMP-v1/` child containing `observer.json`, `cycle-plan.json`,
their two separate deployment-sealer plans, and `preparation.json`. No
preparation receipt means no completed preparation. Preserve an interrupted
partial directory for explicit recovery; do not overwrite it or retry into it.

Preparation is not deployment or scheduling authority. Separately seal both
plans, run the ordinary credential-aware `--check-only` preflight, authenticate
the current owner chain and timer uniqueness, then arm the single next observer
and metadata owner at the normal deadlines. Existing sealed destinations and
already-armed owners must not be replaced or duplicated. An offline probe may
prepare the same future time as an already-armed manual cycle for comparison,
but its generated plans must then remain unused. Do not migrate the actual
cycle executor merely to use this planning mode.

The routine-cycle coordinator remains a single, non-restarting metadata owner
for one already-completed 30-minute observation. It does not sample resources,
launch replay, upload archives, create sidecars, or delete objects. A failed
cycle still requires evidence-led recovery; child receipts do not authorize
automatic retry or a second owner.

Before accepting or rejecting each completed child process, the coordinator
fsyncs a private no-clobber JSON result:

- `child-sealer.json`
- `child-estimator.json`
- `child-status-N.json`, one per claimed production epoch
- `child-fleet.json`

Each result binds the executable path and digest, exit code or signal, and the
length, SHA-256, and first 1 MiB of each stdout/stderr stream. Oversized output
remains fatal and is explicitly marked truncated. Captured child output stays
inside the root-private cycle directory; neither inherited environment nor
storage credentials are serialized. A spawn failure is included in the cycle's
ordinary durable failure record. Existing result files are never replaced.

The privileged ignored regression
`tests::privileged_real_sealer_child_records_success_and_failures` exercises the
actual coordinator child path against a separately pinned immutable sealer. Run
only the sealed test binary in the production-equivalent non-restarting
systemd sandbox, including `UMask=0077`, with read/write access restricted to
the precreated root-private `/var/lib/jetstreamer/horizon-routine-child-probes`.
Bind `HORIZON_PROBE_SEALER` and `HORIZON_PROBE_SEALER_SHA256` to the reviewed
sealer; no R2 credentials are needed. It preserves its unique attempt directory
and checks wrong-plan rejection, successful local sealing, and no-clobber
rejection. No campaign archive or replay tree is opened.

The first real sandbox probe reproduced the previously opaque child failure:
creation mode `0444` was filtered to `0400` by the restrictive service umask,
and the sealer correctly rejected its generated receipt's final mode. The
sealer now explicitly sets `0444` through the open descriptor before fsync and
validation, as it already does for declared deployment members. Keep the
restrictive service umask. An isolated subprocess regression verifies both
generated files and the declared member retain exact immutable modes under
`0077`, without changing the test runner's process-wide umask.

Passing the probe is not a complete campaign-cycle result. Before rearming a
metadata owner, separately seal the corrected coordinator, corrected sealer,
fresh exact predecessor/model/fleet plan and service; run its check-only gate;
and preserve its real scheduled completion. Never replace live immutable
deployments, fork the fleet predecessor chain, or duplicate a manual cycle.

## Explicit 101–200 profile (dormant until separately qualified)

The existing v1 plan remains restricted to 201–300. This host uses the separate
`jetstreamer-horizon-routine-cycle-101-200-plan-v2` schema and requires a
`scope_101_200` object containing `diagnostic_ranges`. The latter is empty or
contains the exact private epoch-144 loader unit, its range `144`, controller
and producer unit names, and both invocation IDs. Observed/configured census
lengths must equal production model ranges plus that explicit diagnostic set.
Missing, extra, restarted or identity-changing diagnostics fail closed; they
are never converted into production status claims or inactive cleanup evidence.
An optional `additional_tracked_units` list in `scope_101_200` may add up to 128
distinct constrained `horizon-`/`jetstreamer-` service names to the next fleet
observation. It cannot remove prior tracked units, start a service, or add an ETA
claim; all normal fleet identity/command/claim gates remain independent.

The service name is `horizon-routine-cycle-101-200-TIMESTAMP-v2.service`.
Cycle state belongs beneath
`/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/TIMESTAMP-v2`.
Fleet output and predecessor checks use only the existing root-private
`/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-TIMESTAMP.json`
chain. A later same-sample recording also invalidates a pending cycle. The
model must bind the exact owner-only status receipt directory
`/home/sol/.jetstreamer-private/r2-status-receipts` with UID 1001; children still
run as the privileged reader/writer and their new receipts must be root-owned.
Do not change that directory's ownership or permissions to fit the other host.

The v2 derivation preserves all historical model evidence and appends the exact
previous estimates and new observer bindings rather than overwriting reserved
array positions. It retains the v1 constraints on immutable tool/model/fleet
bindings, exact predecessor hashes, ordinary production identities, terminal
slots, integer estimates, authenticated status readbacks, full fleet reconciliation,
bounded non-restarting service identity and no-clobber child results. Neither
profile samples resources, starts replay, uploads archives, creates sidecars,
deletes objects or automatically retries a failed/partially published cycle.

Keep this profile dormant until source tests, a sealed privileged child/sealer
probe (including actual `UMask=0077` behavior), exact local template check-only
and least-privilege sandbox access have passed. The current manual cycle and
scheduled observer remain the sole owners until an explicit successful handoff;
do not arm both metadata paths for the same sample.

The first 101–200 production cycle exposed a second sandbox boundary: the older
R2 publisher chmodded the existing campaign-user-owned receipt directory only
after authenticated remote readback. With `CAP_DAC_OVERRIDE` but not `CAP_FOWNER`,
that chmod failed, leaving epoch 152's status committed without its local receipt.
Its exact same-sample recovery performed authenticated readback without another
PutObject, then durably recovered the receipt. Do not retry a whole cycle or grant
broad capabilities to repair such a partial result.

Qualify a publisher that preflights receipt-directory writes before remote
mutation and does not chmod an already-private foreign-owned directory. Owned
directories may still be initialized to 0700; symlinks and non-private foreign
directories fail closed. The dedicated ignored R2 regression
`tests::status_receipt_foreign_private_directory_needs_no_fowner` must run in a
sealed root sandbox with effective DAC_OVERRIDE and no FOWNER, against a dedicated
UID-1001-owned 0700 probe directory, with networking disabled. It proves durable
root-owned receipts without changing the directory's owner or permissions.
Also qualify the canonical `root-cohort-160-160` layout when the observer's claim
is the scalar `160`; both literal and canonical bounds remain tied to that exact
authenticated claim, never another cohort or final import destination.
