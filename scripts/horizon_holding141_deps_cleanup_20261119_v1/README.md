# Holding141 dependency cache cleanup

Exact source successor to the historical compiler cleaner. Only
`/tmp/holding141-target/debug/deps` (device2304/inode6695982) is selected.
The existing shared mutation lock on DATA and Cargo lock on root are preserved.
The selector keeps external hardlinks, the top-level working executable and its
alias, all `.d` files, unknown files, sources, locks and directories. No R2 actions.

Production requires the existing positive consumer review, native check and
separate execute gates. Three completed holding169 build/test definitions must
be durably captured and unloaded before checking. The completed holding141
incremental helpers inspect the deps directory, so their non-reopening lifecycle
must also be included. The next holding166 retirement build uses this target;
finish and seal that build before qualification and cleanup, then forbid builds
until the cleanup completion is reconciled. Do not claim the preliminary
3,052,756,992-byte count as fresh physical capacity.

The inherited mutation, mount, source, staged/process and no-builder gates remain.
The source map now binds this package and retained current R2/observer sources;
original cache build provenance is not claimed. The exact sealed holding169
production image remains retained. The working image is now the qualified166
successor, device2304/inode6714227, with two links. Its bytes must match the
independent normally sealed retry6 production image before any cache cleanup.
37 tests are defined; run tests and strict Clippy before production sealing.

Parent qualification on 2026-11-19: all 36 tests passed, strict all-target
Clippy passed, and the production build passed under serial 1 CPU / 1 GiB
units. No deployment or deletion occurred. Before deployment, bind the final
working-image identity after the pending holding166 R2 build, retain its sealed
production copy, and complete the actual consumer review.
