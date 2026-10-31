# Corrected capped v1.4.25 epoch 141 qualification

The bounded vote-prefix run completed through 60912005 and stopped before a
later Bank. Its strict parent entered the subsequent batch beginning at
60912005entry452, after the previously failing entry 388transaction378. The
worker froze 60912005 with Bank hash
`6KxEDBFrwyVfuGxqkG8SgYmdncoRUw7xSzCSbCx7qagy`. Its parent 60912004again
matched the later vote's expected hash and all 2640finalized RPC rewards.
The sealed result is
`horizon-epoch141-vote-prefix-result-20261023-v1/result.json`, SHA256
`2947b49f24aaeb731cb7ea102c55726bb065545ffba5e1c585bbddd7dcd06972`.
The incident remains open until a verified ready pair exists.

The rebuilt worker without diagnostic features is
`c536dcf360b7866b3aa99e0ff6d7d927dcf5db27bfbbb8f73887eb4bb7d87344`,
sealed in`horizon-v1425-corrected-default-candidate-20261023-v1`. It retains
the current upstream-correct additional-builtin table; all 19 runtime tests
passed before the separate shrink feature was added. The old deployed
worker's missing upgradeable-builtin label remains a provenance lead, not
complete proof of its embedded table or the sole causal difference.

The optional`capped-shrink-candidate` feature caps consumed shrink debt after
`process_stale_slot_with_budget`, matching the pinned v1.4.25
AccountsBackgroundService. Default workers retain their uncapped behavior.
No healthy producer is replaced. The debt regression covers extreme and
ordinary debt, account-write cursor, balance, capitalization, last blockhash,
and frozen Bank hash. Capped and default profiles each passed 20 runtime tests
with one ignored; the capped release suite passed 49 tests with 2 ignored plus
the framed-protocol integration test. Exact Rust 1.46.0, offline locked builds,
jobs 2, debug 0, CPU 200%, MemoryHigh 12 GiB / Max 16 GiB, zero swap, 512 tasks,
PrivateNetwork and read-only source were used.

The capped release worker is
`fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759`,
sealed in`horizon-v1425-capped-candidate-20261023-v1` and combined with the
unchanged original-entry parent in`horizon-epoch141-capped-parent-20261023-v1`.
A separately sealed protocol-only harness authenticated the exact corrected
default and capped workers and passed HELLO/PING/SHUTDOWN for both without
initializing a Bank. Those probes do not qualify canonical replay.

The new private profile uses unit
`horizon-qualify-141-original-entry-capped-root-20261023-v1.service` and root
`/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1`.
It has a512 GiB whole-root physical stop, including scratch, compact indices,
and private archive output, plus a5 day runtime stop. This is a bounded
qualification envelope, not an adopted full-cold-epoch peak. The 200–300
century's 300 GB scratch seed is not applied. The service uses 8CPU cores,
MemoryHigh 128 GiB / Max 192 GiB, zero swap, 512 tasks and the3500000worker-VMA stop.
Compact-index download threads are limited to 32 within the same task budget.
The separate scheduling memory allowance remains 128 GiB with one 64 GiB host
reserve; existing invocation-bound growth and the verified century floor
must survive fresh admission independently.

The bootstrap remains 60911751 and the canonical target 61328765, with expected
accounts hash`8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY`. This worker has
no 60912004or60912005 diagnostic stop. Root success would cover the 416766 slot
prefix beginning 60912000; 15234epoch141 suffix slots remain outside that
qualification. Complete-span provenance, full/current-plugin checks, and
normal publication gates remain mandatory. No canonical sidecar, runtime
promotion or R2 archive mutation is authorized by preparation, protocol
tests, admission, resource measurements, or private root success.

The closed reader and routine handoff require the exact terminal vote-prefix
invocation and sealed result, retain all earlier roots and ledger claims,
and preserve the 144observer. Fresh protected admission, immediate actual
invocation guard, a real sandboxed one-worker timer fire, launch capture and
authenticated fleet handoff remain separate requirements before leaving a
new run unattended.
