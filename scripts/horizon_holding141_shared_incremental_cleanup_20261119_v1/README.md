# Holding141 shared incremental cleanup

Retire recognizable compiler products under exactly `/tmp/holding141-target/debug/incremental`, device 2304/inode 6695985. The previous single-link cleanup left about 302 MB of internally linked outputs. This separate profile uses the qualified group-unlink implementation to remove a group only when every hardlink is within the selected tree and recognized as a compiler product. Preserve external links, unknown members, diagnostics, sources, fingerprints, locks, all directories and the working executable outside this tree.

The shared DATA mutation lock and all three existing Cargo locks remain held across fresh no-builder, process, staged/cron, mount and consumer checks. The actual working executable still must match its independently sealed retry6 image. No source dependency, runtime, R2 object or DATA promise is released by this profile.

The seven-class consumer review must cover both the previous completed incremental cleaner and later holding141/169/166 runtimes. Historical receipts alone do not establish current absence: the cleaner rechecks actual owners, staged definitions and process references. Source and all dependencies must be committed, contained in account-updates, and bound in the normally sealed artifact proof. Check-only and execute use separate fixed no-clobber outputs; prior results are never overwritten.

38 tests are expected, including an incremental fixture with two internal hardlink groups, an external link and preserved metadata. Source preparation itself grants no deletion authority. Qualify tests, strict Clippy, production image and complete review before check/execute.
