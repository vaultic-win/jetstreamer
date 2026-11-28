# Private first-target PoH diagnostic

`jetstreamer-epoch141-poh-diagnostic` checks only acquired slot 60911776,
parent 60911771. It does not open the native database or change the connected
recovery route. Shared raw-input validation is also used by the byte-only driver;
existing sealed byte deployments and receipts remain unchanged.

The root-only driver binds the exact raw acquisition, finalized parent/final
hashes, original byte diagnostic, independently typed snapshot clock, and matching
native restore comparison by path and SHA-256. Embedded pinned Bank/worker source
digests establish clock inheritance: 64 ticks per slot and 12500 hashes per tick
are not fitted to decoded counts. Both inputs retain their original authority.

Invoke an immutable sealed binary with:

```text
PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]
```

The strict plan schema is
`jetstreamer-epoch141-first-target-poh-diagnostic-plan-v1`, with hash-bound
`acquisition`, `finalized_target`, `byte_diagnostic`, `clock`, `native_clock`, and
an `output` named `poh.json` directly beneath a fresh root-private
`/var/lib/jetstreamer/horizon-epoch141-first-target-poh-diagnostic-*` directory.
Check-only validates the inputs and terminal native owner without writes or PoH
computation. Actual execution writes a no-clobber fsynced intent, recomputes at
most four million hashes with a 90-second deadline, revalidates inputs and native
terminal identity, and writes an explicit durable success/failure result.

Use a non-restarting, network-isolated oneshot with read-only home/system, only
the exact output directory writable, CAP_DAC_OVERRIDE for private traversal,
CPUQuota=200%, MemoryHigh=256M, MemoryMax=512M, MemorySwapMax=0, TasksMax=256,
and TimeoutStartSec=2min. Prove check-only in the same sandbox before actual use.
Retain actual invocation identity with RemainAfterExit=yes; do not combine that
property with systemd-run --wait.

Success verifies five distinct ordered PoH boundaries (four hidden) for this
single private diagnostic. It does not establish connected ancestry, complete
source/live state, the full 18283-target census, full epoch recovery, runtime
boundary-input eligibility, replay/promotion, retirement, publication, or R2
authority. Original connectivity stays false and the strict connected assembler
must still reject it. Never transcribe diagnostic hashes into runtime input or
mark epoch 141 recovered from this result.

Tests include strict plan rejection, independent clock/native binding mutation
checks, and an explicitly ignored root read-only retained-input chain test.
Full-target work must use a separately qualified bounded batched native session
and final source rehash, not one complete input reopen/rehash per target.
