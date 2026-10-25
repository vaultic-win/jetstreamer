# Epoch 227 next action from accepted cycle 398

This is source and immutable metadata preparation only. No new replay/resource
observation, admission, native input, replay, service, fleet or R2 action was
performed. The shared Cargo target remains with the epoch 205 owner.

The immediate code blocker is the no-worker capability reader, not missing
native-input evidence. Source baseline `24524cdd` still requires positive current
`ExecMainPID` and start/exit counters, although the genuine selection-v2
capability has collected zeros. The exact existing fix `ca0b3645` has been
rebased without conflict onto that baseline. It changes only the capability
reader and its closed evidence adapter, fixtures and documentation. The ordinary
positive-counter reader remains unchanged for every other receipt. This source
has passed direct rustfmt and diff checks, but has not been compiled or tested
on the current baseline and is not a qualified runtime artifact.

## Exact capability inputs

| Input | SHA-256 |
| --- | --- |
| Original private capability receipt | `a03d09115980dd7dac9859b7ca7f4ead616fc595759dbee44f527205065d3fae` |
| Sealed capability plan | `737c3f6fd0a36004b8e2ca4e569c635aa3cbb2d33383be1ab7cb565d045a4169` |
| Historical initial properties | `ebd5734d29dcce426908d05f41172b9e07b61976acc3abe692b263bd42bff8f4` |
| Historical collected terminal properties | `714210895fb9f00a02f71fcc5029a934613f54b49a6ea4963613ed71169364c6` |
| Complete sealed PID 1 journal | `830987be0aeec7ffee064fd8348212322b9d9da319071e199316b4e5a1883f24` |

All five files were independently rehashed from their existing durable paths.
The original receipt is
`/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-selection-v2-capability-v1/receipts/capability.json`.
The plan is
`/var/lib/jetstreamer/horizon-227-v1625-canary-capability-plan-selection-v2/capability-plan.json`.
The three historical files are `initial-properties.txt`,
`terminal-properties.txt` and `journal.jsonl` beneath
`/var/lib/jetstreamer/horizon-227-selection-capability-result-v2`.
The root-owned receipt copy is never substituted for the original private
UID 1000 / mode 0400 receipt. No capability retry is needed.

Actual admission must still authenticate current collected manager properties,
the installed exact unit and sandbox, empty cgroup, current boot and machine,
complete unfiltered unit journal and before/after stability. Existing files do
not establish those current conditions.

## Current planning basis

Accepted fleet:
`/var/lib/jetstreamer/horizon-campaign-fleet/20261025T075700Z-v398-three-replays-v1/fleet-ledger.json`,
SHA-256 `65421768b34ce3ac4724202e117ddb06dd229d9045909851e50708d58e6e5ba5`.
Bound observer:
`.codex/tmp-readiness/horizon-live-resource-sample-20261025T075700Z-diagnostics-v398.json`,
SHA-256 `19443762d6d0ef99d28f55519b8b877c5a65953edd2d6b7eba69a0888cda331a`.

That historical sample has three executing producers, epochs 207, 209 and
225–226, and a memory target of nine lanes. It records available disk of
2,457,869,930,496 bytes and available memory of 1,036,727,447,552 bytes.
The new canary reserves 300,016,777,216 disk bytes and 225,000,000,000 memory
bytes. Under the sample alone, its protected disk floor would therefore have
to be at most 2,157,853,153,280 bytes. This is a necessary inequality, not an
admission or proof of the full protected growth/memory/pressure requirements.
The old 2.35 TB provisional floor requires 2,650,016,777,216 bytes and does not
fit that recorded free space. Never lower a protected floor just to fit.

The selected actual owner is
`horizon-qualify-227-v1625-bounded-resource-d01adb19-selection-v2.service`,
root `/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-selection-v2`.
The old v1 actual resource plan, proposal and unit name are not launch inputs
for this selection-v2 owner. Fresh metadata must bind the selected node
`79963ff4872ad7470acced6b04b944a8744ec2de2acccd6d6e843584fcddcb92`
and runner `81a804e354fdb986d46ad847f9c687131513baee7858687be85eeb65a72b8500`,
the computed current protected floor, exact plan digest and matching unit argv.

## Practical next action

After the epoch 205 Cargo lease ends, incorporate the capability-only fix into
the next coherent source generation, including any separately qualified 205
guard correction. Run the focused capability tests, complete R2 suite and
strict all-target Clippy, then build and capture one frozen candidate. Root
independently reviews and Rust-seals it. Do not rebuild or rerun the historical
worker, native input or successful no-worker capability to repair this reader.

Root then derives and seals the selection-v2 actual plan/proposal/unit from
the next accepted complete fleet and exact protected guards, and performs fresh
`admit-canary227-v1625-output-metadata-v1` admission. A genuine fit and unchanged
owners are required before launch. The actual invocation, first completed
protective fire, active timer, launch capture, fleet registration and initial
supported dashboard status remain separate requirements.

Epoch 227 remains `failed-needs-repair`; preserve every original failure,
native proof and retained scratch. Reaching target slot 98091122 tests the
upstream comparison only. It does not qualify the final canonical root
98495291, remaining tail, full epoch, current plugin, boundary, upload or sidecar.
