# Fixed epoch 140 serialized snapshot clock

The separate `jetstreamer-epoch140-snapshot-clock` binary is available only with
the old workspace's explicit `epoch140-snapshot-clock-diagnostic` feature. It
uses exact Rust 1.46.0 and the pinned v1.4.25 runtime. No ordinary worker protocol,
runtime registry, snapshot route or replay limit changes. Existing sealed
workers remain untouched.

Build and test from `historical-runtime/v1_4_25`, not the modern workspace root:

```text
cargo test --locked --offline --manifest-path worker/Cargo.toml \
  --features epoch140-snapshot-clock-diagnostic \
  --bin jetstreamer-epoch140-snapshot-clock private_clock::tests
cargo build --release --locked --offline --manifest-path worker/Cargo.toml \
  --features epoch140-snapshot-clock-diagnostic \
  --bin jetstreamer-epoch140-snapshot-clock
```

Give native serialization tests `RUST_MIN_STACK=134217728` and a bounded
`SOLANA_RAYON_THREADS` environment. The differential regression serializes an
actual pinned Bank with the runtime's `add_snapshot` writer and compares its
clock/hash fields. It does not claim to execute the excluded vendored crate's
own unit suite.

The read-only executable is fixed to the retained 60911751 snapshot path,
generation-bound whole-file SHA256, compressed size, device and inode. Its
usage is:

```text
jetstreamer-epoch140-snapshot-clock --output ABSOLUTE_NEW_RECEIPT \
  MINIMUM_PROTECTED_FREE_BYTES --self-sha256 EXACT_EXECUTABLE_SHA256
```

Freshly admit and seal the executable and exact launch intent first. Protect all
older claims, the century floor and the 64 MiB live census reservation; the tool
cannot lower its retained minimum 5153080892870 byte stop floor. Reserve bounded
receipt/log space independently above that sum. Use a persistent non-restarting
private-network oneshot with CPU/memory/task ceilings, read-only home/system
mounts, only required traversal capability and the exact root-private output
directory writable. The internal900-second/runtime/free-space guard runs on
every compressed read, including the full digest pass. Bind and verify the
actual `initial-guard.json` invocation/digest before leaving the job unattended.
Never reuse an output directory after a failed initial-guard/final write.

The tool hashes its own running executable and the full compressed snapshot,
checks the compile-bound pinned `future.rs` layout source hash, then uses the
existing hardened snapshot tar framing/layout/duplicate/size limits. It writes
no accounts or extracted files. It rejects unsupported snapshot versions and
requires the exact bank member plus status-cache presence. It decodes the
**actual** pinned `DeserializableVersionedBank` type through a feature-scoped
runtime helper; no hand-rolled substitute layout or genesis-derived clock is
used. The remaining Bank-file bytes are independently hashed, all tar members
are censused, the compression trailer is drained, and source identity is
rechecked before the fsynced no-clobber receipt is written.

The receipt provides serialized clock fields and an unpacked logical/stored
footprint census. It does not reconstruct Bank/AccountsDb, recompute or verify
the Bank hash, recover an accounts hash, compare validator-local write cursors,
or decode/validate the status-cache contents or every appendvec. It therefore
cannot prove a native checkpoint match or authorize suffix replay, PoH runtime
input promotion, assembly, import, sidecars, publication or local retirement.
Those gates stay independent, including the actual executing suffix worker's
native tuple comparison and a complete retained-prefix reread/hash. Preserve
the snapshot, original 140archive and all 141repair evidence on diagnostic failure.

## Original failed-cohort bootstrap comparison

The distinct `epoch140-original-bootstrap-clock-diagnostic` feature builds only
`jetstreamer-epoch140-original-bootstrap-clock` for the retained 60479583 bootstrap
used by the original 140–143cohort. Its compile-bound input is a separate sealed
root 0400 copy, not the user-owned original. It pins size 3238609546, SHA256
`350464cd9a2341c94edde7544fcb8958a968ea9f322d38a8daec145e1a2bb48b`, device 2304
and inode 6322697. The source's MD5/CRC32C match the original sealed generation
1634786593623999 preflight. Neither the original snapshot nor any live lane is
modified. This profile is mutually exclusive with both earlier clock profiles.

It retains the same typed layout, full compressed hash/census, no-extraction,
identity, no-clobber and 900 second guards. Its minimum 3984782679494 byte data-floor
protection is the current delivery-only older-claim/guard envelope, not a
change to an existing live guard or to either earlier profile's minimum.
Fresh complete admission and an exact sandbox remain required before execution.
Before opening the snapshot, this profile additionally checks 130 GiB available
memory (128 GiB protected plus a2 GiB hard reader envelope) and retains 100 GiB OS
free plus 64 MiB output/log headroom. It repeats these checks before committing
the final receipt and records their exact values. Output is fixed to the new
root-private OS directory's `clock.json`; older profiles keep their old scope.

Only this diagnostic profile may report serialized `hashes_per_tick: 0` as an
observation rather than reject it; missing/disabled work is the hypothesis being
tested. Its distinct schema is
`jetstreamer-epoch140-original-bootstrap-serialized-clock-v1`. It does not
authenticate a runtime clock, prove the original live Bank's in-memory clock,
or authorize changing work checks. In particular, enabled per-entry checks in
the immutable failed worker make it necessary to inspect its actual bootstrap
clock before borrowing the separate epoch 208 reconstruction explanation.
Native restore, exact source/Bank differential, root, plugin and publication
gates remain independent regardless of the observed value.

The epoch 141 PoH clock consumer preserves the original reviewed worker source
as an exact repository fixture from commit `a6e0d6ab`, with SHA-256
`ae01b0813fa1564511e450acc693941268076659e4d741aae085fb288d0fd2ac`.
`worker_runtime_source_sha256` continues to identify that reviewed source.
The current trace/capped-storage candidate is pinned separately as
`current_worker_runtime_source_sha256`; neither source may set hashes per tick,
and the vendor Bank must still inherit both clock values from its parent.
Future worker changes require a reviewed current-source pin update. Do not
replace the historical fixture, rewrite the old native receipt, or relabel a
new candidate as the source measured by the old proof. This repair changes no
clock value or deployed worker and keeps both full-source hash gates active.
