# Private retained-prefix verifier 157

This is read-only qualification of the preserved first segment, not production
replay, full-epoch verification or a public ETA. It uses the exact literal-name
validator and original segment; no 123 GB copy or rename is needed.

The pinned Rust R2 tool owns four offline preparation steps:

1. `prepare-private-prefix157 SPEC --spec-sha256 HEX --self-sha256 HEX --admit`
   consumes fresh, hash-bound observer/fleet/planning evidence and writes the
   no-clobber pre-launch admission. It preserves the 4,740,696,923,590-byte
   protection plus 1 MiB of new receipts and 128 GiB reserve plus the 8 GiB cap.
   It rechecks older live producer identities and refuses an already-live verifier.
2. Launch only the exact read-only verifier after that admission, with root,
   Type=exec, Restart=no, RuntimeMaxSec=21600, CPUQuota=400%, MemoryHigh=4G,
   MemoryMax=8G, zero swap, PrivateNetwork=yes, ProtectSystem=strict,
   ProtectHome=read-only and only its exact private receipt root writable.
   `--launch` then authenticates the live invocation, complete command and actual
   sandbox limits and writes an immutable, fsynced launch receipt.
3. Ordinary preparation (without an extra mode) consumes that receipt and the
   accepted fleet plan to emit a Rust-sealer plan for one same-sample admission
   fleet. Existing claims and the complete campaign remain intact; the new
   active entry is `private-verification`, with no ordinary replay/ETA authority.
   This event may perform authenticated inventory reads but takes no new resource
   sample. An exact launch/admission chain replaces the replay/VMA guard contract
   only for this non-replay verifier; it is not a zero-worker replay exemption.
4. After the event is durable, `--routine-spec` emits a bound fold spec. The
   qualified routine helper's `--prepare-next-prefix157 SPEC --handoff-sha256 HEX`
   consumes the genuine completed ordinary cycle and this event head, preserves
   all original ETA formulas and observers, and prepares a distinct `prefix157-v1`
   namespace. It clears the consumed one-time admission marker in the next normal
   fleet, while retaining the verifier claim/history. Seal and check the next
   helper/config/plan and neutralize obsolete metadata timers before migration.

Every mode self-authenticates its sealed executable and writes only private,
no-clobber preparation/evidence. The real verifier and all remote reads remain
separate. None of these steps authorize replay, archive/sidecar publication,
runtime promotion or data retirement. A passing prefix receipt does not cover
the v1.5.8 root segment, final 171 slots, assembly or complete epoch/plugin gates.
