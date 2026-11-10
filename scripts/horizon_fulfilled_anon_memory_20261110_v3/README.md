# Fulfilled anonymous memory in finite admission accounting

This Rust check prevents already resident, zero-swap anonymous memory inside an existing producer's hard cap from being charged again against `MemAvailable`. It preserves every hard promise, the candidate's 68 GiB actor and 1 GiB guard, and 16 GiB of additional host headroom. It subtracts only the smaller of two anonymous-memory readings, less an extra 1 GiB per producer. RSS, file cache, shared pages and other cgroups contribute no credit.

The check binds the exact five producer invocations and cgroup envelopes before and after capture, the complete Root resource authority, the original 01:00 fleet, two persistent background owners, its own funded sandbox and normally sealed image. It rejects swaps, OOM events, changed ownership, duplicate or malformed counters, changed evidence and expired contexts. Its no-clobber receipt grants no replay, publication, retirement or resource-release authority.

Four compiler configurations and six tests passed. The final V3 image also passed the genuine epoch 171 admission check: required remaining growth was 698,644,242,432 bytes against 727,522,947,072 available bytes. The check preserved 645,972,897,792 bytes of existing hard promises and added the separate 69 GiB candidate plus host headroom in its arithmetic. `QUALIFICATION.json` binds the exact source, compiler, seal and native evidence.

This generation supports only its original qualification and epoch 171 admission purposes. Its original freshness window has expired; it cannot authorize another lane, be relabeled for a later observation, or be reused after the sixth owner was admitted. A successor needs independent source, sealing and qualification.
