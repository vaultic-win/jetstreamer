# Full 210 admission with the live native 223 floor and new guard

This isolated source correction starts at preserved full 210 qualification source
`b456559bd67d2dab996236e4ae50b26ac58c2b4c`, which produced sealed helper
`86693cddd7e5e6f272467ba8a7e33565d5efe0d444a7e943125033a63d7b155b`.
That helper's candidate calculation adds only the 225 GB producer cap, protected
remaining hard-memory growth and the 10% host baseline. It does not separately
reserve the new guard's 1 GiB hard cap or preserve native 223's internal 480 GiB
available-memory floor. The old helper therefore cannot establish this corrected
admission. No deployed helper or guard, healthy owner, frozen combined carrier,
input, receipt or actual resource state was changed.

The new closed `maintenance_capacity::check_singleton210` entry point fixes the
producer's disk and memory envelope from its existing constants and selects a
memory policy only for full 210. It runs inside the existing complete transaction,
including both sampled/current memory checks, complete owner/cap brackets,
completed protective-fire/timer checks and the final census. Other maintenance
and assembly callers retain their existing policy. No new spec flag, selectable
floor, external estimate or caller-supplied guard allowance is introduced.

For the exact current native 223 owner, admission now requires available memory
of at least:

```text
max(ceil(host_total_bytes / 10), 480 GiB)
  + all existing protected remaining hard-cgroup growth
  + 225000000000 producer bytes
  + 1073741824 new guard bytes
```

The 480 GiB floor and 10% host baseline are combined with `max`, not added
together. The preserved b456 peer implementation contributes only remaining
hard-cgroup growth; it does not already carry a native 223 floor top-up. Thus
this selected source counts the floor once. Porting to a carrier that already
adds a floor top-up requires an explicit integration review to avoid counting
that top-up twice; it must not silently change this closed source's arithmetic.
Both existing memory snapshots record the effective floor, exact original
native 223 invocation, producer and guard caps, complete growth reservation and
total required available bytes in `full210_memory_policy`.
The full 210 launch-binding and first-fire capture readers require and rederive
both corrected memory proofs. An old 8669 admission without these policies,
even if otherwise fresh, cannot be consumed as corrected full 210 admission.

The policy requires the original live native 223 IID
`e70aaf097e7c4583b216aba454145910`, its exact unit, loaded/running manager,
nonzero PID, zero restarts, matching raw unit census and the private-prefix
claim. The existing shared roster/launch/sandbox/guard code remains responsible
for its full original binding and for every other healthy owner. Missing,
replaced, duplicate, inactive or wrongly labeled native 223 work refuses the
new policy. A later legitimate native 223 terminal event requires its own typed
policy revision; this source does not silently release the floor. The three
healthy owners and all 204/205/227 terminal/failure history remain unchanged.

The producer disk cap remains 471798691840 bytes with a separate 33554432-byte
phase reservation: 471832246272 additional bytes total. All current growth,
century averages, existing guard floors and the live 223 internal/external 2 TB
floor remain protected. No future 213 retirement is credited as free space.
The guard remains the exact 210 profile, with 1 GiB hard memory, unchanged root
cap, VMAs, actual invocation and separately admitted minimum-free floor.

Six pure adversarial tests cover additive guard/growth/native-floor memory,
host-baseline dominance with ceiling arithmetic, omitted/terminal/duplicate
owners, changed identity/role/raw census including a matching replacement
owner, envelope substitution, arithmetic overflow and rejection of old or
under-reserved admission proofs at capture. They also check that raw
healthy/terminal/failure history is left intact. Existing transaction and other
caller tests remain. Direct rustfmt and diff checks pass; Cargo, Clippy and
production build/capture have not run. The shared Cargo lease belongs to the
other repair agent.

The next safe executable step is qualification of this exact final source under
an exclusive target grant, followed by a frozen R2-only production build and
actual dep-info/extern/native input capture, independent root review and a new
Rust-sealed helper. Use locked/offline release `-j2`, explicit shared absolute
target and incremental zero. Run focused `maintenance_capacity` and
`singleton210_admission` tests, the full all-features R2 binary suite and strict
all-target all-features release Clippy before the conditional build. Do not build
an observer executable or execute the mutable-target candidate.

After the actual 213 restore and its separate normal retirement complete, root
must obtain one fresh complete accepted observer/fleet and exact guard basis,
then use the newly sealed helper's `admit-singleton210 SPEC --spec-sha256 SHA
--self-sha256 NEW_HELPER_SHA` command. All original input/native proof, current
capacity and fresh race checks still apply. The old 8669 helper, stale admission
or 90% target cannot substitute for the corrected gate. Actual launch, first
protective fire, capture, full runtime/checkpoint/tail verification and separate
receipt-gated delivery remain later requirements. This source grants none of
those actions and authorizes no holding or archive retirement.
