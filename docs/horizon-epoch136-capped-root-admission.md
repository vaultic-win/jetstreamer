# Epoch 136 bounded repair admission

This closed profile stages and admits one private corrected-worker root experiment on
`dev-samjohnson`. It has no replay launch API. The coordinating operator retains launch,
timer arming, complete-fleet adoption and all later verification/publication decisions.

The exact input capability is
`/home/sol/.jetstreamer-private/epoch136-capped-input-capability-20261023-v1/receipts/capability.json`,
SHA-256 `aaf10afade9fcb8cd86384187dc5dddc945b45bdd84b440b12a23520307b682f`.
It binds node `d0c784a4…`, corrected capped v1.4.25 worker `fce05d55…`, the
bootstrap at 58,751,483 and trusted checkpoint at 59,183,944. Admission independently
rehashes every immutable package member, including the original failure and cold snapshot.

The experiment must strictly reexecute the former failure at slot 59,183,097,
entry 197, transaction 113. Successful input qualification, admission, launch or a
guard fire does not prove that transaction passed. The trusted root covers 431,945
output slots from 58,752,000; another 55 slots remain outside this experiment.
The original repair stays open until a fully verified canonical R2 pair exists.

The fixed envelope is a **512 GiB whole-root experimental stop** and five-day
runtime stop, CPU quota eight cores, eight Rayon threads, 32 ripget threads,
MemoryHigh 128 GiB, MemoryMax 192 GiB, no swap, TasksMax 512. The hard memory
limits are separate from the scheduling reservation, which is exactly the current
100-century RSS ceiling `floor(3 * maximum_valid_lane_rss / 2)`. No 200–300
scratch assumption applies. This is not a qualified full-cold peak or a guarantee
that the experiment can finish within its cap.

## Preparation and fresh admission

Seal a new `jetstreamer-r2` deployment through the native sealer before invoking
these commands. Preserve old deployments and use the actual new executable hash.

`prepare-epoch136-capped-layout --self-sha256 HEX` requires the candidate dormant,
rehashes the exact inputs and creates only its absent private root and genesis.
It writes root-owned immutable `receipts/layout.json`; it starts no service.
Interrupted preparation retains its partial layout and fails closed for review.

`admit-epoch136-capped SPEC --spec-sha256 HEX --self-sha256 HEX [--check-only]`
accepts the following exact spec shape; all paths and hashes are independently
reviewed and sealed before use:

```json
{
  "schema": "jetstreamer-epoch136-capped-root-admission-spec-v2",
  "observer": {"path": "/accepted/sample.json", "sha256": "HEX"},
  "fleet": {"path": "/accepted/fleet.json", "sha256": "HEX"},
  "fleet_plan": {"path": "/accepted/fleet-plan.json", "sha256": "HEX"},
  "floor": {"path": "/sealed/century-floor.json", "sha256": "HEX"},
  "layout": {"path": "/home/sol/.jetstreamer-private/epoch136-capped-root-20261023-v1/receipts/layout.json", "sha256": "HEX"},
  "capability": {"path": "/home/sol/.jetstreamer-private/epoch136-capped-input-capability-20261023-v1/receipts/capability.json", "sha256": "aaf10afade9fcb8cd86384187dc5dddc945b45bdd84b440b12a23520307b682f"},
  "private141_launch": {"path": "/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1/receipts/launch.json", "sha256": "fddefbddec6d98f344f9b7c2411cfcf874fee365e1af9fa4a6b380745021e28f"},
  "growth": {
    "152-153": {"path": "/reviewed/growth-152-153.json", "sha256": "HEX"},
    "155-156": {"path": "/reviewed/growth-155-156.json", "sha256": "HEX"},
    "191-194": {"path": "/reviewed/growth-191-194.json", "sha256": "HEX"}
  },
  "growth_extension_observers": [{"path": "/accepted/sample.json", "sha256": "HEX"}],
  "guards": {
    "152-153": {"unit": "jetstreamer-adaptive-reserve-controller-rebind-152-153-20261023-v1.service", "command_sha256": "HEX", "intent": "/bound/intent.json", "completion": "/bound/completion.json"},
    "155-156": {"unit": "jetstreamer-adaptive-reserve-controller-rebind-155-156-20261023-v1.service", "command_sha256": "HEX", "intent": "/bound/intent.json", "completion": "/bound/completion.json"},
    "191-194": {"unit": "jetstreamer-adaptive-reserve-controller-rebind-191-194-20261023-v1.service", "command_sha256": "HEX", "intent": "/bound/intent.json", "completion": "/bound/completion.json"},
    "183-184": {"unit": "jetstreamer-adaptive-reserve-controller-rebind-183-184-20261023-v1.service", "command_sha256": "HEX", "intent": "/bound/intent.json", "completion": "/bound/completion.json"},
    "185-185": {"unit": "jetstreamer-adaptive-reserve-controller-rebind-185-185-20261023-v1.service", "command_sha256": "HEX", "intent": "/bound/intent.json", "completion": "/bound/completion.json"}
  },
  "output": "/var/lib/jetstreamer/horizon-epoch136-capped-root-admissions-20261023-v1/admission-TIMESTAMP.json"
}
```

The growth extension list must contain the complete hash-linked routine chain
from the exact reviewed growth bases through the selected current sample, with
at least 1,800 seconds between samples. The example's one-element list is only a
shape example. The three original growth digests, controller-only rebind proof,
five guard names and current private-141 invocation are closed in the binary.

Check-only validates the current accepted sample, complete range, live claims,
growth history, floor arithmetic, package bytes, layout and sampled resources.
It performs no new resource observation, R2 request, output receipt or launch.
It must fail when sampled disk cannot fit; a code deployment is not admission.

Real admission additionally requires the latest accepted complete 101–200 fleet,
fresh before/after discovery census, unchanged active/dormant owners, current
five production and private-141 guard fires and armed timers, CPU quota identities,
available memory and VMA settings, authenticated R2 floor sample revalidation and
absence of canonical epoch-136 objects. It writes one no-clobber receipt only.

Disk protection retains the five production claims, their historical maxima,
the independently audited century floor and prior baseline margin. It adds
private 141's `512 GiB - min(two scratch measurements)` remaining growth, giving
no consumption credit for its output or indexes. Current guard minima and an
additional 64 GiB margin may increase protection. The candidate's 512 GiB is
added separately. No terminal owner or reservation is released here.

At the accepted 2026-10-23 18:26 sample, the lower bound is
4,100,550,495,686 protected bytes plus 549,755,813,888 candidate bytes, against
3,851,812,921,344 available bytes: **798,493,388,230 bytes short**. Even verified
retirement of the retained 99,719,081,984-byte physical epoch-136 partial cannot
make this profile fit. Keep it staged until a real protection/space transition
passes fresh admission; never replace the deficit with an invented lower cap.

The 17:56 sample has valid century-100 RSS history but null host-global PSI.
This profile requires a clean comparable host-memory PSI window independently of
disk. Enable `host_global_pressure: true` through a normally sealed successor
observer, then retain two enabled observations at least 1,800 seconds apart.
The current parent plan preserves the armed 18:56 package, enables telemetry at
19:26, and expects the first comparable enabled window at 19:56. These are
planned telemetry events, not receipts or admission. Offline denial reports the
actual disk deficit and missing memory gate together; current protected-lane
telemetry does not substitute for absent host-wide PSI.

## Guard and launch attestation

The native replay unit is exactly
`horizon-qualify-136-capped-root-20261023-v1.service`, using the input package's
node and worker, `--verify`, `--qualification-end-slot=59183944`, the cold snapshot
and exact checkpoint file. Output and scratch remain under the distinct private
root; no original-entry override, ignored transaction, retry suppression or
ordinary cohort option is accepted.

The existing reviewed standalone guard executable, SHA-256
`35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc`,
is pinned. Its separately sealed plan must bind the newly created native
invocation, filesystem `/home/sol`, the admission's protected minimum free bytes,
whole root `/home/sol/.jetstreamer-private/epoch136-capped-root-20261023-v1`,
512 GiB root cap and 3,500,000 VMA stop. Bounded-canary and bounded-measurement
exceptions are forbidden. Prove the actual sandboxed timer fire and one real
worker before leaving the experiment unattended.

`capture-epoch136-capped-launch SPEC --spec-sha256 HEX --self-sha256 HEX`
uses schema `jetstreamer-epoch136-capped-root-launch-capture-spec-v2` with bound
`plan`, `admission`, `observer`, `previous_fleet`, `first_guard`, and
`first_guard_source` fields. The first guard source is the actual immutable
`sample-INVOCATION.json` below the distinct guard receipt directory; its identical
bytes are pinned no-clobber to the private root's `receipts/first-guard.json`.
The command verifies the exact live process command, complete sandbox, actual
PID1 start timestamp, admission freshness, zero restarts, timer provenance,
worker census and root/reserve/VMA protection, then rechecks identity before
writing `receipts/launch.json`. It never creates or starts a replay.

Fleet adoption must add this exact diagnostic and its real guard through the
existing same-sample admission transition, preserve every prior diagnostic and
keep gate 136 `failed-needs-repair`. The operator must adopt a valid dashboard
estimate for active execution through a separately qualified publisher. This
patch does not publish a guessed ETA or modify the active 141 status hook.

The full-root result, strict reexecution evidence, 55-slot suffix, complete-span
assembly/provenance, independent full/current-plugin checks, authenticated R2
readback and canonical sidecar commit remain separate required gates.
