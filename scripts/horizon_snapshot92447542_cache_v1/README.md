# Slot 92447542 cache lifecycle candidate

`jetstreamer-snapshot92447542-cache` handles only the compressed snapshot with
generation `1629744948337785` in `mainnet-beta-ledger-us-ny5`. It never selects
another file, launches replay, or writes cloud objects. This is a source
candidate; no deployed lifecycle qualification or cache eviction is established
by adding the binary.

The foreground operations are `check`, `evict CHECK_SHA256`, and
`restore CHECK_SHA256`. All require an independently hash-bound private plan,
a Root-owned sealed executable, and the exact helper's lifecycle qualification.
The check preserves the original acquisition receipt, verifies generation
metadata and all three payload digests, and binds the original inode. Eviction
uses a no-clobber move into Root-private quarantine and verifies that moved
inode before unlinking. Restore requires its own fresh capacity admission and
publishes a new inode and receipt without replacing an existing destination.

Qualification must precede operational use:

- Review the complete deployed consumer, interpreter, launcher and input
  readsets. Authenticate nonlaunchable dispositions and effective drop-ins;
  merely finding no literal filename is insufficient.
- Prove the actual service identity, capabilities, SDK identity/configuration,
  resource limits and complete process/reference inspection. Preserve the
  original acquisition's clean terminal evidence.
- Exercise the actual quarantine rename in the final sandbox. Two writable
  bind mounts can produce `EXDEV` despite matching device numbers. Never widen
  the whole filesystem to make this test pass.
- Exercise recovery after every durable transition, failed-transfer shutdown,
  floor/timeout/size failure, destination/receipt collisions, and an isolated
  restore round trip through the same engine. Qualification receipts must bind
  genuine results, not replace missing tests with asserted flags.
- Bind the normal production artifact's actual sources, features and compiler
  flags and seal it. Source tests do not qualify an executable deployment.

The ordinary test scope is the entire `snapshot92447542_cache::` module,
including `retained_metadata_fixture`. Filtering only `::tests` omits the
retained metadata and real SDK-process-group controls. The retained 796-byte
metadata fixture contains `bucket`; a separate derivative checks normalization
without that field. The process-group control uses a disposable shell and
descendant, without calling gcloud or accessing credentials.

Local source qualification may use a bound standalone projection of the crate
with pinned dependency versions. Preserve its complete transitive modules and
report its actual Cargo features; this does not establish the normal workspace
artifact or operational qualification. No canonical archive, sidecar, receipt,
or R2 object is eligible for deletion through this candidate.
